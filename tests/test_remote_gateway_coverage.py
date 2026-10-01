"""Gateway token binding, current authorization and stream ownership tests."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from aiohttp import ClientSession, WSMessage, WSMsgType, web
from aiohttp.test_utils import make_mocked_request
from multidict import MultiDict

from northgate_rmm.operator_api import OperatorApplication
from northgate_rmm.remote_gateway import (
    COOKIE,
    LeaseState,
    RemoteGateway,
    encrypt_connection,
)
from northgate_rmm.remote_policy import RemoteLease
from tests.test_remote_access import PRINCIPAL, TARGET


def gateway_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[RemoteGateway, LeaseState]:
    operation = MagicMock()
    operation._store.get_endpoint.return_value.display_name = (
        "<script>untrusted</script>"
    )
    gateway = RemoteGateway(
        cast(OperatorApplication, operation),
        {TARGET.endpoint_id: (TARGET, {"username": "operator", "domain": "LAB"})},
        bytes(16),
        "https://operator.test",
    )
    now = datetime.now(UTC)
    lease = RemoteLease(
        uuid4(),
        TARGET.endpoint_id,
        TARGET.identity_id,
        PRINCIPAL.subject,
        PRINCIPAL.session_id,
        now,
        now + timedelta(minutes=5),
    )
    state = LeaseState(
        lease,
        auth_data="ticket",
        auth_token=uuid4().hex,
        authorization="Bearer fixture",
        method="rdp",
    )
    gateway.leases["cookie"] = state
    gateway.receipt_store.create(lease, "rdp", "")
    monkeypatch.setattr(gateway, "principal", AsyncMock(return_value=PRINCIPAL))
    monkeypatch.setattr(gateway, "audit", AsyncMock())
    return gateway, state


def request(
    path: str = "/guacamole/", method: str = "GET", **headers: str
) -> web.Request:
    return make_mocked_request(
        method, path, headers={"Cookie": COOKIE + "=cookie", **headers}
    )


@pytest.mark.parametrize(
    "mode,code",
    [
        ("large", 413),
        ("method", 405),
        ("origin", 403),
        ("unavailable", 503),
        ("parameters", 403),
        ("tunnel", 403),
        ("duplicate_token", 403),
        ("conflicting_token", 403),
        ("wrong_token", 403),
        ("duplicate_form", 403),
        ("wrong_body_token", 403),
        ("wrong_ticket", 403),
        ("websocket_origin", 403),
        ("websocket_active", 403),
    ],
)
def test_proxy_rejects_unowned_protocol_routes_tokens_and_streams(
    monkeypatch: pytest.MonkeyPatch, mode: str, code: int
) -> None:
    async def scenario() -> None:
        gateway, state = gateway_fixture(monkeypatch)
        upstream = MagicMock()
        gateway.client = cast(ClientSession, upstream)
        path, method = "/guacamole/", "GET"
        headers: dict[str, str] = {}
        fields = MultiDict[str]()
        if mode == "large":
            headers["Content-Length"] = "65537"
        elif mode == "method":
            method = "PUT"
        elif mode == "origin":
            method = "POST"
        elif mode == "unavailable":
            gateway.client = None
        elif mode in {"parameters", "tunnel"}:
            path += mode
        elif mode == "duplicate_token":
            path += f"?token={state.auth_token}&token={state.auth_token}"
        elif mode == "conflicting_token":
            path += f"?token={state.auth_token}"
            headers["Guacamole-Token"] = "other"
        elif mode == "wrong_token":
            path += "?token=other"
        elif mode in {"duplicate_form", "wrong_body_token", "wrong_ticket"}:
            path += "api/tokens"
            method = "POST"
            headers["Origin"] = gateway.origin
            if mode == "duplicate_form":
                fields.add("token", state.auth_token)
                fields.add("token", state.auth_token)
            elif mode == "wrong_body_token":
                fields["token"] = uuid4().hex
            else:
                state.auth_token = ""
                fields["data"] = "other"
        elif mode.startswith("websocket"):
            headers["Upgrade"] = "websocket"
            if mode == "websocket_active":
                headers["Origin"] = gateway.origin
                state.websocket = cast(web.WebSocketResponse, MagicMock())
        req = request(path, method, **headers)
        monkeypatch.setattr(req, "post", AsyncMock(return_value=fields))
        with pytest.raises(web.HTTPException) as rejected:
            await gateway.proxy(req)
        assert rejected.value.status == code
        upstream.request.assert_not_called()
        upstream.ws_connect.assert_not_called()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "mode", ["page", "token", "ticket", "oversized", "no_content_type"]
)
def test_proxy_forwards_only_current_lease_and_limits_backend_output(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    async def scenario() -> None:
        gateway, state = gateway_fixture(monkeypatch)
        response = MagicMock(
            status=200,
            headers={} if mode == "no_content_type" else {"Content-Type": "text/html"},
        )
        original = state.auth_token
        renewed = uuid4().hex
        data = b"<body>content</body>"
        if mode in {"token", "ticket"}:
            data = json.dumps({"authToken": renewed}).encode()
        elif mode == "oversized":
            data = b"x" * (8 * 1024 * 1024 + 1)

        async def chunks(size: int) -> AsyncIterator[bytes]:
            assert size == 65536
            yield data

        response.content.iter_chunked = chunks
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=response)
        client = MagicMock()
        client.request.return_value = context
        gateway.client = cast(ClientSession, client)
        path, method = "/guacamole/", "GET"
        headers: dict[str, str] = {"Guacamole-Token": state.auth_token}
        fields = MultiDict[str]()
        if mode in {"token", "ticket"}:
            path += "api/tokens"
            method = "POST"
            headers.update(
                {
                    "Origin": gateway.origin,
                    "Content-Type": "application/x-www-form-urlencoded",
                }
            )
            if mode == "ticket":
                state.auth_token = ""
                headers.pop("Guacamole-Token")
                fields["data"] = "ticket"
            else:
                fields["token"] = state.auth_token
        req = request(path, method, **headers)
        monkeypatch.setattr(req, "post", AsyncMock(return_value=fields))
        monkeypatch.setattr(req, "read", AsyncMock(return_value=b""))
        if mode == "oversized":
            with pytest.raises(web.HTTPBadGateway):
                await gateway.proxy(req)
        else:
            received = await gateway.proxy(req)
            assert isinstance(received, web.Response)
            assert received.status == 200
            if mode == "page":
                assert isinstance(received.body, bytes)
                assert b"/remote/session.js" in received.body
            if mode in {"token", "ticket"}:
                assert state.auth_token == renewed
                assert client.request.call_args.kwargs["data"] == (
                    ("token=" + original).encode()
                    if mode == "token"
                    else b"data=ticket"
                )
            if mode == "ticket":
                assert not state.auth_data
            assert received.headers["Cache-Control"] == "no-store"
        assert client.request.call_args.args[1] == "http://127.0.0.1:8088" + path
        assert client.request.call_args.kwargs["allow_redirects"] is False

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "mode",
    [
        "case_missing",
        "case_denied",
        "secret_missing",
        "secret_denied",
        "login_changed",
        "no_cookie",
        "valid",
    ],
)
def test_current_lease_rechecks_case_secret_and_login(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    async def scenario() -> None:
        gateway, state = gateway_fixture(monkeypatch)
        if mode.startswith("case"):
            state.case_id = "case-1"
            if mode == "case_denied":
                gateway.case_authorizer = AsyncMock(side_effect=web.HTTPForbidden())
        if mode.startswith("secret"):
            state.secret_id = str(uuid4())
            if mode == "secret_denied":
                gateway.secret_authorizer = AsyncMock(side_effect=web.HTTPForbidden())
        if mode == "login_changed":
            monkeypatch.setattr(
                gateway,
                "principal",
                AsyncMock(return_value=replace(PRINCIPAL, session_id="other")),
            )
        req = request() if mode != "no_cookie" else make_mocked_request("GET", "/")
        if mode != "valid":
            with pytest.raises(web.HTTPForbidden):
                await gateway.checked_lease(req)
        else:
            gateway.case_authorizer = AsyncMock()
            gateway.secret_authorizer = AsyncMock()
            state.case_id, state.secret_id = "case-1", "secret-1"
            checked, principal = await gateway.checked_lease(
                req, authorization="Bearer current"
            )
            assert checked is state and principal == PRINCIPAL
            assert state.authorization == "Bearer current"
            gateway.case_authorizer.assert_awaited_once()
            gateway.secret_authorizer.assert_awaited_once()
            assert (await gateway.keepalive(req)).status == 204
            script = await gateway.session_script(req)
            assert "20000" in (script.text or "")

    asyncio.run(scenario())


def test_expired_receipts_and_remote_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    gateway, state = gateway_fixture(monkeypatch)
    now = datetime.now(UTC)
    state.lease = replace(
        state.lease,
        created_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=5),
    )
    gateway.purge()
    assert gateway.leases == {}
    assert (
        gateway.receipt_store.list(TARGET.endpoint_id, TARGET.identity_id)[0]["status"]
        == "expired"
    )
    with pytest.raises(web.HTTPNotFound):
        gateway.method_target(TARGET.endpoint_id, "ssh")
    with pytest.raises(ValueError):
        encrypt_connection(bytes(15), {})
    with pytest.raises(ValueError):
        RemoteGateway(
            cast(OperatorApplication, MagicMock()), {}, bytes(16), "http://bad.test"
        )

    async def scenario() -> None:
        req = make_mocked_request(
            "GET", "/sessions", match_info={"endpoint": str(TARGET.endpoint_id)}
        )
        response = await gateway.sessions(req)
        value = json.loads(response.text or "")
        assert value["methods"] == ["rdp"]
        assert value["sessions"][0]["outcome"] == "authorization_expired"
        bad = make_mocked_request("GET", "/", match_info={"endpoint": "invalid"})
        for handler in (gateway.sessions, gateway.desktop_file, gateway.landing):
            with pytest.raises(web.HTTPNotFound):
                await handler(bad)
        end = request("/remote/end", "POST", Origin=gateway.origin)
        with pytest.raises(web.HTTPForbidden):
            await gateway.end(end)

    asyncio.run(scenario())


@pytest.mark.parametrize("fail", [False, True])
def test_websocket_streams_forward_and_close_owned_lease(
    monkeypatch: pytest.MonkeyPatch, fail: bool
) -> None:
    async def scenario() -> None:
        gateway, state = gateway_fixture(monkeypatch)
        sockets: list[MagicMock] = []
        for _ in range(2):
            socket = MagicMock()
            socket.prepare = AsyncMock()
            socket.close = AsyncMock()
            socket.send_str = AsyncMock()
            socket.send_bytes = AsyncMock()
            socket.__aiter__.return_value = [
                WSMessage(WSMsgType.TEXT, "frame", ""),
                WSMessage(WSMsgType.BINARY, b"binary", ""),
                WSMessage(WSMsgType.CLOSE, 1000, ""),
            ]
            sockets.append(socket)
        browser, upstream = sockets
        monkeypatch.setattr(web, "WebSocketResponse", MagicMock(return_value=browser))
        context = MagicMock()
        context.__aenter__ = AsyncMock(
            side_effect=OSError("backend unavailable") if fail else None,
            return_value=upstream,
        )
        client = MagicMock()
        client.ws_connect.return_value = context
        gateway.client = cast(ClientSession, client)
        req = request("/guacamole/websocket-tunnel")
        if fail:
            with pytest.raises(OSError, match="backend unavailable"):
                await gateway.websocket(req, state, PRINCIPAL)
        else:
            assert await gateway.websocket(req, state, PRINCIPAL) is browser
            browser.send_str.assert_awaited_once_with("frame")
            upstream.send_bytes.assert_awaited_once_with(b"binary")
        browser.close.assert_awaited_once()
        assert "cookie" not in gateway.leases
        receipt = gateway.receipt_store.list(TARGET.endpoint_id, TARGET.identity_id)[0]
        assert receipt["status"] == "closed"
        assert receipt["outcome"] == (
            "connection_failed" if fail else "transport_closed"
        )

    asyncio.run(scenario())


def test_gateway_entry_points_fail_closed_without_scope_or_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway, state = gateway_fixture(monkeypatch)

    async def scenario() -> None:
        remote = cast(web.Request, MagicMock(remote="192.0.2.1", headers={}))
        with pytest.raises(web.HTTPForbidden):
            await RemoteGateway.principal(gateway, remote, TARGET.endpoint_id)
        local = cast(web.Request, MagicMock(remote="127.0.0.1", headers={}))
        with pytest.raises(web.HTTPNotFound):
            await RemoteGateway.principal(gateway, local, uuid4())
        with pytest.raises(web.HTTPForbidden):
            await gateway.end(
                request("/remote/end", "POST", Origin="https://other.test")
            )
        with pytest.raises(web.HTTPServiceUnavailable):
            await gateway.websocket(request(), state, PRINCIPAL)
        target_path = f"/remote/{TARGET.endpoint_id}"
        for suffix, expected in (
            ("?case_id=invalid!", web.HTTPBadRequest),
            ("?case_id=valid", web.HTTPForbidden),
        ):
            req = make_mocked_request(
                "GET",
                target_path + suffix,
                match_info={"endpoint": str(TARGET.endpoint_id)},
            )
            with pytest.raises(expected):
                await gateway.landing(req)
        for index in range(32):
            gateway.forms[str(index)] = (
                PRINCIPAL.subject,
                PRINCIPAL.session_id,
                TARGET.endpoint_id,
                datetime.now(UTC) + timedelta(minutes=5),
                "rdp",
                "",
            )
        req = make_mocked_request(
            "GET", target_path, match_info={"endpoint": str(TARGET.endpoint_id)}
        )
        with pytest.raises(web.HTTPTooManyRequests):
            await gateway.landing(req)
        gateway.targets[TARGET.endpoint_id][1]["username"] = "invalid\nname"
        with pytest.raises(web.HTTPServiceUnavailable):
            await gateway.desktop_file(req)

    asyncio.run(scenario())
