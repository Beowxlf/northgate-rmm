"""Fail-closed provider parsing, configuration and human HTTP boundary tests."""

from __future__ import annotations

import asyncio
import io
import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path
from typing import Literal, cast
from uuid import UUID, uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request

from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.secrets_api import (
    SecretRecord,
    SecretRequest,
    SecretsAPI,
    SecretState,
    load_config,
    validate_fields,
)
from northgate_rmm.secrets_vault import MAX_RESPONSE, OpenBaoKV, VaultError
from tests.test_secrets_api import Provider, fixture
from tests.test_secrets_vault import client


class ProviderResponse:
    def __init__(self, body: bytes, error: Exception | None = None) -> None:
        self.body, self.error = body, error
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float) -> io.BytesIO:
        self.requests.append(request)
        if self.error:
            raise self.error
        return io.BytesIO(self.body)


def response(provider: OpenBaoKV, body: object) -> ProviderResponse:
    opener = ProviderResponse(json.dumps(body).encode())
    provider.opener = cast(urllib.request.OpenerDirector, opener)
    return opener


def test_provider_metadata_read_and_lifecycle_contract(tmp_path: Path) -> None:
    provider = client(tmp_path)
    response(provider, {"data": {"current_version": 2, "versions": {"2": {}}}})
    assert provider.metadata("endpoint/secret")["current_version"] == 2
    opener = response(
        provider, {"data": {"metadata": {}, "data": {"fields": {"token": "synthetic"}}}}
    )
    assert provider.read("endpoint/secret", 2) == {"token": "synthetic"}
    assert opener.requests[0].full_url.endswith("?version=2")
    opener = response(provider, {})
    provider.configure_metadata("endpoint/secret", "test", "api")
    provider.versions("endpoint/secret", "delete", [1, 2])
    provider.versions("endpoint/secret", "undelete", [2])
    assert len(opener.requests) == 3
    metadata = json.loads(cast(bytes, opener.requests[0].data))
    assert metadata["cas_required"] is True and metadata["max_versions"] == 20
    assert json.loads(cast(bytes, opener.requests[1].data)) == {"versions": [1, 2]}


@pytest.mark.parametrize(
    "body",
    [
        None,
        {"current_version": -1},
        {"current_version": True},
        {"current_version": 1, "versions": []},
        {"current_version": 1, "versions": {"1": False}},
    ],
)
def test_metadata_requires_valid_version_map(tmp_path: Path, body: object) -> None:
    provider = client(tmp_path)
    response(provider, {"data": body})
    with pytest.raises(VaultError):
        provider.metadata("endpoint/secret")


@pytest.mark.parametrize(
    "body,status",
    [
        ({"metadata": None, "data": {}}, 502),
        ({"metadata": {}, "data": None}, 502),
        ({"metadata": {"destroyed": True}, "data": {}}, 404),
        ({"metadata": {"deletion_time": "deleted"}, "data": {}}, 404),
        ({"metadata": {}, "data": {"fields": []}}, 502),
        ({"metadata": {}, "data": {"fields": {"token": 42}}}, 502),
    ],
)
def test_secret_read_rejects_unavailable_or_malformed_values(
    tmp_path: Path, body: object, status: int
) -> None:
    provider = client(tmp_path)
    response(provider, {"data": body})
    with pytest.raises(VaultError) as error:
        provider.read("endpoint/secret")
    assert error.value.status == status


@pytest.mark.parametrize(
    "mode",
    [
        "oversize",
        "invalid-json",
        "network",
        "denied",
        "health-invalid",
        "health-oversize",
        "empty",
    ],
)
def test_provider_transport_failures_never_expose_diagnostics(
    tmp_path: Path, mode: str
) -> None:
    provider = client(tmp_path)
    body = b"{}"
    error: Exception | None = None
    if mode == "oversize":
        body = b"x" * (MAX_RESPONSE + 1)
    elif mode == "invalid-json":
        body = b"provider internal diagnostic"
    elif mode == "network":
        error = urllib.error.URLError("private diagnostic")
    elif mode == "denied":
        error = urllib.error.HTTPError(
            "https://vault.test", 403, "private", Message(), io.BytesIO(b"sensitive")
        )
    elif mode.startswith("health"):
        raw = b"[]" if mode == "health-invalid" else b" " * 16385
        error = urllib.error.HTTPError(
            "https://vault.test", 503, "sealed", Message(), io.BytesIO(raw)
        )
    elif mode == "empty":
        body = b""
    provider.opener = cast(urllib.request.OpenerDirector, ProviderResponse(body, error))
    if mode == "empty":
        assert provider.health() == {
            "initialized": False,
            "sealed": True,
            "standby": False,
        }
    else:
        with pytest.raises(VaultError, match=r"^Secret provider request failed$"):
            provider.health() if mode.startswith("health") else provider.read("secret")


def test_provider_rejects_invalid_local_values_before_transport(tmp_path: Path) -> None:
    provider = client(tmp_path)
    opener = response(provider, {})
    for version in (0, -1):
        with pytest.raises(ValueError, match="version"):
            provider.read("secret", version)
    for action, versions in (
        ("destroy", [1]),
        ("delete", []),
        ("delete", [0]),
        ("delete", list(range(1, 22))),
    ):
        with pytest.raises(ValueError, match="lifecycle"):
            provider.versions("secret", action, versions)
    with pytest.raises(ValueError, match="write"):
        provider.write("secret", {}, cas=-1)
    with pytest.raises(ValueError, match="limit"):
        provider.write("secret", {"token": "x" * 65536}, cas=0)
    provider.token_file.write_text("not a token")
    with pytest.raises(VaultError):
        provider.read("secret")
    assert opener.requests == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", 2),
        ("prefix", "../escape"),
        ("grants", {}),
        ("grants", [{"subject": "owner"}]),
        ("grants", [{"subject": "", "endpoints": {}, "permissions": []}]),
        ("grants", [{"subject": "owner", "endpoints": [], "permissions": []}]),
        (
            "grants",
            [{"subject": "owner", "endpoints": {"bad": "bad"}, "permissions": []}],
        ),
        ("grants", [{"subject": "owner", "endpoints": {}, "permissions": ["destroy"]}]),
    ],
)
def test_secret_grant_configuration_rejects_invalid_authority(
    tmp_path: Path, field: str, value: object
) -> None:
    _, _, config, path, _, _, _ = fixture(tmp_path)
    encoded = dict(config)
    encoded[field] = value
    path.write_text(json.dumps(encoded))
    with pytest.raises(ValueError):
        load_config(path)


def test_secret_state_and_nonce_limits(tmp_path: Path) -> None:
    endpoint, _, _, _, gateway, _, api = fixture(tmp_path)
    link = tmp_path / "state-link"
    link.symlink_to(tmp_path / "target")
    with pytest.raises(ValueError, match="symbolic"):
        SecretState(link)
    with pytest.raises(ValueError, match="table"):
        api.state.get(cast(Literal["records"], "arbitrary"), "identifier")
    with pytest.raises(web.HTTPNotFound):
        api.record("not-a-uuid", endpoint, endpoint)
    expiry = datetime.now(UTC) + timedelta(minutes=1)
    api.forms = {str(i): ("owner", "s", str(endpoint), expiry) for i in range(256)}
    with pytest.raises(web.HTTPTooManyRequests):
        api.token(gateway.user, endpoint)


def test_secret_http_rejects_bad_requests_and_serves_authorized_assets(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        endpoint, _, _, config_path, gateway, _, api = fixture(tmp_path)
        app = web.Application()
        api.register(app)
        base = f"/remote/{endpoint}/secrets"
        headers = {"Origin": gateway.origin}
        async with TestClient(TestServer(app)) as http:
            for suffix in ("/ui", "/assets.js", "/assets.css"):
                result = await http.get(base + suffix)
                assert result.status == 200
                assert result.headers["Cache-Control"] == "no-store"
            assert (await http.get(base + "/assets.txt")).status == 404
            assert (await http.get("/remote/invalid/secrets/state")).status == 404
            assert (await http.post(base + "/action", json={})).status == 403
            assert (
                await http.post(base + "/action", data="{}", headers=headers)
            ).status == 400
            bodies: tuple[object, ...] = (
                [],
                {"action": "unsupported"},
                {"action": "reveal"},
                {"action": "create", "pad": "x" * 65536},
            )
            for body in bodies:
                result = await http.post(base + "/action", json=body, headers=headers)
                assert result.status in {400, 403}
            config_path.unlink()
            assert (await http.get(base + "/state")).status == 503

    asyncio.run(scenario())


@contextmanager
def rejects_http(exception: type[web.HTTPException], message: str) -> Iterator[None]:
    with pytest.raises(exception) as error:
        yield
    assert message in (error.value.text or "")


def saved_record(endpoint: UUID, identity: UUID, *, kind: str = "rdp") -> SecretRecord:
    identifier = str(uuid4())
    return {
        "id": identifier,
        "endpoint_id": str(endpoint),
        "identity_id": str(identity),
        "label": "Synthetic credential",
        "kind": kind,
        "retired": False,
        "use_for_remote": True,
        "path": "secret/" + identifier,
    }


def test_native_secret_export_rechecks_permissions_and_remote_binding(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        endpoint, identity, config, path, gateway, provider, api = fixture(tmp_path)
        request = make_mocked_request(
            "GET", "/", match_info={"endpoint": str(endpoint)}
        )
        target = gateway.targets[endpoint][0]
        await api.guard_legacy_reveal(target)
        with rejects_http(web.HTTPConflict, "saved RDP"):
            await api.resolve_native_export(request, gateway.user, target)
        record = saved_record(endpoint, identity)
        api.state.save_record(record)
        provider.write(
            record["path"], {"username": "synthetic", "password": "synthetic"}, cas=0
        )
        result = await api.resolve_native_export(request, gateway.user, target)
        assert result["__rmm_secret_id"] == record["id"]
        assert gateway.audits[-1][0] == "secret.native_encrypted_export"
        await api.authorize_remote_use(request, endpoint, record["id"])
        await api.authorize_remote_use(
            request, endpoint, record["id"], principal=gateway.user
        )
        config["grants"][0]["permissions"].remove("reveal")
        path.write_text(json.dumps(config))
        with pytest.raises(web.HTTPForbidden):
            await api.resolve_native_export(request, gateway.user, target)
        duplicate = saved_record(endpoint, identity)
        api.state.save_record(duplicate)
        with rejects_http(web.HTTPConflict, "ambiguous"):
            await api.resolve_remote(request, gateway.user, target, "rdp")
        record["retired"] = True
        api.state.save_record(record)
        with rejects_http(web.HTTPForbidden, "revoked"):
            await api.authorize_remote_use(request, endpoint, record["id"])

    asyncio.run(scenario())


def test_secret_reference_mutations_reject_duplicate_retired_or_ambiguous_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        endpoint, identity, config, _, gateway, _, api = fixture(tmp_path)
        request = make_mocked_request(
            "POST", "/", match_info={"endpoint": str(endpoint)}
        )
        record = saved_record(endpoint, identity, kind="api")
        api.state.save_record(record)
        with rejects_http(web.HTTPConflict, "exists"):
            await api.perform(
                request,
                endpoint,
                identity,
                gateway.user,
                config,
                "create",
                {"request_id": record["id"]},
            )
        with pytest.raises(ValueError):
            await api.perform(
                request,
                endpoint,
                identity,
                gateway.user,
                config,
                "edit",
                {"secret_id": record["id"], "label": "test", "use_for_remote": True},
            )
        record["retired"] = True
        api.state.save_record(record)
        with rejects_http(web.HTTPConflict, "retired"):
            await api.perform(
                request,
                endpoint,
                identity,
                gateway.user,
                config,
                "reveal",
                {"secret_id": record["id"]},
            )
        record.update({"retired": False, "kind": "rdp"})
        api.state.save_record(record)
        other = saved_record(endpoint, identity)
        api.state.save_record(other)
        with rejects_http(web.HTTPConflict, "binding"):
            await api.perform(
                request,
                endpoint,
                identity,
                gateway.user,
                config,
                "edit",
                {"secret_id": record["id"], "label": "test", "use_for_remote": True},
            )
        with pytest.raises(ValueError):
            await api.perform(
                request,
                endpoint,
                identity,
                gateway.user,
                config,
                "unsupported",
                {"secret_id": record["id"]},
            )
        monkeypatch.setattr(
            api.state, "records", lambda endpoint, identity: [record] * 1000
        )
        with rejects_http(web.HTTPConflict, "limit"):
            await api.perform(
                request,
                endpoint,
                identity,
                gateway.user,
                config,
                "create",
                {"request_id": str(uuid4())},
            )
        with rejects_http(web.HTTPConflict, "not configured"):
            await api.recovery_context(request, endpoint, identity)

    asyncio.run(scenario())


@pytest.mark.parametrize("label", [None, "", "\n", "x" * 121])
def test_secret_label_is_printable_and_bounded(label: object) -> None:
    with pytest.raises(ValueError):
        SecretsAPI.label(label)


def test_secret_fields_aggregate_and_individual_bounds() -> None:
    with pytest.raises(ValueError, match="60 KB"):
        validate_fields("account", {"username": "u" * 32768, "password": "p" * 32768})
    with pytest.raises(ValueError, match="Incomplete"):
        validate_fields("api", {"token": "x" * 32769})


class RotationStub:
    def __init__(self, provider: Provider, record: SecretRecord, mode: str) -> None:
        self.provider, self.record, self.mode = provider, record, mode
        self.bound = False

    def bind(self, api: SecretsAPI) -> None:
        self.bound = True

    async def prepare(self, **kwargs: object) -> dict[str, object]:
        return {"prepared": True}

    async def apply(self, **kwargs: object) -> dict[str, object]:
        if self.mode == "invalid":
            return {"status": "not-an-executor-status"}
        fields = cast(dict[str, str], kwargs["fields"])
        if self.mode in {"already-committed", "conflict"}:
            self.provider.write(
                self.record["path"],
                fields if self.mode == "already-committed" else {"token": "different"},
                cas=1,
            )
        return {"status": "verified", "job_id": ""}

    async def check(self, **kwargs: object) -> dict[str, object]:
        return {"status": "verified", "job_id": ""}


@pytest.mark.parametrize("mode", ["already-committed", "conflict", "invalid"])
def test_rotation_reconciles_verified_provider_commit_without_overwriting(
    tmp_path: Path, mode: str
) -> None:
    async def scenario() -> None:
        endpoint, identity, config, path, gateway, provider, api = fixture(tmp_path)
        record = saved_record(endpoint, identity, kind="api")
        record["use_for_remote"] = False
        api.state.save_record(record)
        provider.write(record["path"], {"token": "old"}, cas=0)
        executor = RotationStub(provider, record, mode)
        api = SecretsAPI(
            cast(RemoteGateway, gateway),
            path,
            state_path=tmp_path / "state.sqlite",
            rotation_executor=executor,
            provider_factory=lambda config: provider,
        )
        assert executor.bound
        request = make_mocked_request(
            "POST", "/", match_info={"endpoint": str(endpoint)}
        )
        body: SecretRequest = {
            "rotation_id": str(uuid4()),
            "fields": {"token": "new"},
            "expected_version": 1,
        }
        if mode == "invalid":
            with pytest.raises(web.HTTPBadGateway):
                await api.rotate(
                    request,
                    gateway.user,
                    endpoint,
                    record,
                    provider,
                    config,
                    body,
                    "rotate",
                )
        else:
            result = await api.rotate(
                request,
                gateway.user,
                endpoint,
                record,
                provider,
                config,
                body,
                "rotate",
            )
            assert result["status"] == (
                "completed" if mode == "already-committed" else "commit_conflict"
            )
            assert provider.metadata(record["path"])["current_version"] == 2
        with rejects_http(web.HTTPConflict, "already exists"):
            await api.rotate(
                request,
                gateway.user,
                endpoint,
                record,
                provider,
                config,
                body,
                "rotate",
            )
        if mode != "already-committed":
            body["rotation_id"] = str(uuid4())
            with rejects_http(web.HTTPConflict, "existing rotation"):
                await api.rotate(
                    request,
                    gateway.user,
                    endpoint,
                    record,
                    provider,
                    config,
                    body,
                    "rotate",
                )
        body["rotation_id"] = str(uuid4())
        with pytest.raises(web.HTTPNotFound):
            await api.rotate(
                request,
                gateway.user,
                endpoint,
                record,
                provider,
                config,
                body,
                "resume_rotation",
            )

    asyncio.run(scenario())
