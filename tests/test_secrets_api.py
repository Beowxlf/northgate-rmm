from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from aiohttp import ClientResponse, web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request

from northgate_rmm.management import Management as RealManagement
from northgate_rmm.operator_api import OperatorApplication, OperatorPrincipal
from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.remote_policy import RemoteTarget
from northgate_rmm.secrets_api import (
    RotationExecutor,
    SecretRequest,
    SecretsAPI,
    SecretsConfiguration,
    validate_fields,
)
from northgate_rmm.secrets_vault import (
    OpenBaoKV,
    VaultConfiguration,
    VaultError,
    VaultMetadata,
    VaultProvider,
    relative_path,
)

# Synthetic test credentials, never real access secrets.
# ruff: noqa: S105


class Provider:
    def __init__(self) -> None:
        self.values: dict[str, list[dict[str, str]]] = {}
        self.deleted: set[tuple[str, int]] = set()
        self.reads = 0

    def health(self) -> dict[str, bool]:
        return {"initialized": True, "sealed": False, "standby": False}

    def metadata(self, path: str) -> VaultMetadata:
        values = self.values.get(path, [])
        return {
            "current_version": len(values),
            "versions": {
                str(i + 1): {
                    "created_time": "2026-09-09T00:00:00Z",
                    "deletion_time": "deleted" if (path, i + 1) in self.deleted else "",
                    "destroyed": False,
                }
                for i in range(len(values))
            },
        }

    def configure_metadata(self, path: str, label: str, kind: str) -> None:
        pass

    def read(self, path: str, version: int | None = None) -> dict[str, str]:
        self.reads += 1
        values = self.values.get(path, [])
        version = version or len(values)
        if not values or (path, version) in self.deleted:
            raise VaultError(404)
        return dict(values[version - 1])

    def write(self, path: str, fields: dict[str, str], *, cas: int) -> int:
        values = self.values.setdefault(path, [])
        if cas != len(values):
            raise VaultError(400)
        values.append(dict(fields))
        return len(values)

    def versions(self, path: str, action: str, versions: list[int]) -> None:
        for version in versions:
            if action == "delete":
                self.deleted.add((path, version))
            else:
                self.deleted.discard((path, version))


class Gateway:
    user: OperatorPrincipal
    audits: list[tuple[str, str]]
    targets: dict[UUID, tuple[RemoteTarget, dict[str, str]]]
    operation: OperatorApplication
    key: bytes
    method_target: Callable[[UUID, str], tuple[RemoteTarget, dict[str, str]]]
    origin = "https://operator.test"

    async def principal(self, *args: object, **kwargs: object) -> OperatorPrincipal:
        return self.user

    async def audit(
        self, p: OperatorPrincipal, ep: UUID, action: str, identifier: str | UUID
    ) -> None:
        self.audits.append((action, str(identifier)))


def fixture(
    tmp_path: Path, *, executor: RotationExecutor | None = None
) -> tuple[UUID, UUID, SecretsConfiguration, Path, Gateway, Provider, SecretsAPI]:
    endpoint, identity = uuid4(), uuid4()
    now = datetime.now(UTC)
    principal = OperatorPrincipal(
        "https://idp.test",
        "lab",
        "owner",
        "s",
        "rmm",
        ("remote_operator",),
        now - timedelta(minutes=1),
        now + timedelta(hours=1),
        True,
    )
    config: SecretsConfiguration = {
        "schema": 1,
        "provider": {
            "origin": "https://vault.test",
            "mount": "rmm",
            "ca_file": "unused-ca",
            "token_file": "unused-token",
        },
        "prefix": "northgate-rmm",
        "grants": [
            {
                "subject": "owner",
                "endpoints": {str(endpoint): str(identity)},
                "permissions": ["metadata", "use", "reveal", "rotate", "admin"],
            }
        ],
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)

    gateway, provider = Gateway(), Provider()
    gateway.targets = {endpoint: (RemoteTarget(endpoint, identity, "10.0.0.10"), {})}
    gateway.user, gateway.audits = principal, []
    api = SecretsAPI(
        cast(RemoteGateway, gateway),
        config_path,
        state_path=tmp_path / "state.sqlite",
        rotation_executor=executor,
        provider_factory=lambda _: provider,
    )
    return endpoint, identity, config, config_path, gateway, provider, api


def test_secret_crud_permissions_redaction_versions_and_csrf(tmp_path: Path) -> None:
    async def scenario() -> None:
        endpoint, _identity, config, config_path, gateway, provider, api = fixture(
            tmp_path
        )
        app = web.Application()
        api.register(app)
        base = f"/remote/{endpoint}/secrets"
        async with TestClient(TestServer(app)) as client:

            async def state() -> dict[str, Any]:
                response = await client.get(base + "/state")
                assert response.status == 200
                return cast(dict[str, Any], await response.json())

            async def action(**body: object) -> ClientResponse:
                nonce = (await state())["nonce"]
                return await client.post(
                    base + "/action",
                    json={"nonce": nonce, **body},
                    headers={"Origin": gateway.origin},
                )

            identifier = str(uuid4())
            created = await action(
                action="create",
                request_id=identifier,
                label="Desktop login",
                kind="rdp",
                fields={"username": "lab", "password": "synthetic-sensitive"},
            )
            assert created.status == 200
            snapshot = await state()
            assert "synthetic-sensitive" not in json.dumps(snapshot)
            assert provider.reads == 0
            assert snapshot["records"][0]["current_version"] == 1
            nonce = snapshot["nonce"]
            assert (
                await client.post(
                    base + "/action",
                    json={"action": "reveal", "secret_id": identifier, "nonce": nonce},
                    headers={"Origin": "https://other.test"},
                )
            ).status == 403
            assert provider.reads == 0
            assert (
                await client.post(
                    base + "/action",
                    json={"action": "reveal", "secret_id": identifier, "nonce": nonce},
                    headers={"Origin": gateway.origin},
                )
            ).status == 200
            assert (
                await client.post(
                    base + "/action",
                    json={"action": "reveal", "secret_id": identifier, "nonce": nonce},
                    headers={"Origin": gateway.origin},
                )
            ).status == 403
            reveal = await action(action="reveal", secret_id=identifier)
            assert (await reveal.json())["fields"]["password"] == "synthetic-sensitive"
            assert reveal.headers["Cache-Control"] == "no-store"
            update = await action(
                action="replace",
                secret_id=identifier,
                expected_version=1,
                fields={"username": "lab", "password": "synthetic-next"},
            )
            assert update.status == 200
            stale = await action(
                action="replace",
                secret_id=identifier,
                expected_version=1,
                fields={"username": "lab", "password": "synthetic-stale"},
            )
            assert stale.status == 409
            assert (
                await action(action="delete_version", secret_id=identifier, version=2)
            ).status == 200
            assert (await action(action="reveal", secret_id=identifier)).status == 404
            assert (
                await action(action="restore_version", secret_id=identifier, version=2)
            ).status == 200
            gateway.user = replace(
                gateway.user, authenticated_at=datetime.now(UTC) - timedelta(minutes=6)
            )
            assert (await action(action="reveal", secret_id=identifier)).status == 403
            gateway.user = replace(gateway.user, authenticated_at=datetime.now(UTC))
            assert (
                await action(
                    action="rotate",
                    secret_id=identifier,
                    rotation_id=str(uuid4()),
                    expected_version=2,
                    fields={"username": "lab", "password": "not-applied"},
                )
            ).status == 409
            assert (
                await action(
                    action="edit",
                    secret_id=identifier,
                    label="Browser login",
                    use_for_remote=True,
                )
            ).status == 200
            resolved = await api.resolve_remote(
                make_mocked_request("POST", "/"),
                gateway.user,
                gateway.targets[endpoint][0],
                "rdp",
            )
            assert resolved["password"] == "synthetic-next"
            assert "synthetic-sensitive" not in (
                tmp_path / "state.sqlite"
            ).read_bytes().decode(errors="ignore")
            assert "synthetic-next" not in json.dumps(gateway.audits)
            config["grants"][0]["permissions"] = ["metadata"]
            config_path.write_text(json.dumps(config))
            assert (await action(action="reveal", secret_id=identifier)).status == 403
            with pytest.raises(web.HTTPForbidden):
                await api.resolve_remote(
                    make_mocked_request("POST", "/"),
                    gateway.user,
                    gateway.targets[endpoint][0],
                    "rdp",
                )
            config["grants"] = []
            config_path.write_text(json.dumps(config))
            assert (await client.get(base + "/state")).status == 403

    asyncio.run(scenario())


def test_staged_rotation_requires_verification_and_survives_service_rebuild(
    tmp_path: Path,
) -> None:
    class Executor:
        calls = 0

        async def apply(self, **kwargs: object) -> dict[str, object]:
            self.calls += 1
            return {"job_id": str(uuid4()), "status": "pending"}

        async def check(self, **kwargs: object) -> dict[str, object]:
            return {"job_id": kwargs["job_id"], "status": "verified"}

    async def scenario() -> None:
        executor = Executor()
        endpoint, _identity, config, config_path, gateway, provider, api = fixture(
            tmp_path, executor=executor
        )
        identifier, rid = str(uuid4()), str(uuid4())
        request = make_mocked_request("POST", "/")
        await api.perform(
            request,
            endpoint,
            _identity,
            gateway.user,
            config,
            "create",
            {
                "request_id": identifier,
                "label": "Account",
                "kind": "rdp",
                "fields": {"username": "u", "password": "old"},
            },
        )
        record = api.state.get("records", identifier)
        assert record is not None
        result = await api.perform(
            request,
            endpoint,
            _identity,
            gateway.user,
            config,
            "rotate",
            {
                "secret_id": identifier,
                "rotation_id": rid,
                "expected_version": 1,
                "fields": {"username": "u", "password": "next"},
            },
        )
        assert result["status"] == "pending"
        assert provider.read(record["path"])["password"] == "old"
        reopened = SecretsAPI(
            cast(RemoteGateway, gateway),
            config_path,
            state_path=tmp_path / "state.sqlite",
            rotation_executor=executor,
            provider_factory=lambda _: provider,
        )
        result = await reopened.perform(
            request,
            endpoint,
            _identity,
            gateway.user,
            config,
            "resume_rotation",
            {"secret_id": identifier, "rotation_id": rid},
        )
        assert result["status"] == "completed"
        assert provider.read(record["path"])["password"] == "next"
        assert executor.calls == 1
        again = await reopened.perform(
            request,
            endpoint,
            _identity,
            gateway.user,
            config,
            "resume_rotation",
            {"secret_id": identifier, "rotation_id": rid},
        )
        assert again["status"] == "completed"
        assert len(provider.values[record["path"]]) == 2

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "origin",
    [
        "http://vault.test",
        "https://user:pass@vault.test",
        "https://vault.test/path",
        "https://vault.test?x=y",
        "https://vault.test#bad",
    ],
)
def test_provider_rejects_unsafe_origins(origin: str) -> None:
    with pytest.raises(ValueError):
        OpenBaoKV(
            {
                "origin": origin,
                "mount": "rmm",
                "ca_file": "unused",
                "token_file": "unused",
            }
        )


@pytest.mark.parametrize(
    "path", ["../secrets", "/secret", "secret//value", "x?token=a", "x%2fy", "x\\y"]
)
def test_provider_paths_cannot_escape_configured_mount(path: str) -> None:
    with pytest.raises(ValueError):
        relative_path(path)


def test_secret_fields_require_expected_credential_schema() -> None:
    with pytest.raises(ValueError):
        validate_fields("rdp", {"username": "u", "password": "p", "hostname": "other"})


def test_retired_binding_blocks_legacy_and_enrollment_changes_deny(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        endpoint, identity, config, _path, gateway, _provider, api = fixture(tmp_path)
        identifier, request = str(uuid4()), make_mocked_request("POST", "/")
        target = gateway.targets[endpoint][0]
        assert await api.resolve_remote(request, gateway.user, target, "rdp") == {}
        await api.perform(
            request,
            endpoint,
            identity,
            gateway.user,
            config,
            "create",
            {
                "request_id": identifier,
                "label": "Desktop",
                "kind": "rdp",
                "fields": {"username": "user", "password": "synthetic"},
            },
        )
        await api.perform(
            request,
            endpoint,
            identity,
            gateway.user,
            config,
            "edit",
            {
                "secret_id": identifier,
                "label": "Desktop",
                "use_for_remote": True,
            },
        )
        await api.perform(
            request,
            endpoint,
            identity,
            gateway.user,
            config,
            "retire",
            {
                "secret_id": identifier,
            },
        )
        with pytest.raises(web.HTTPConflict):
            await api.resolve_remote(request, gateway.user, target, "rdp")
        with pytest.raises(web.HTTPConflict):
            await api.guard_legacy_reveal(target)
        with pytest.raises(web.HTTPNotFound):
            api.record(identifier, endpoint, uuid4())
        gateway.targets[endpoint] = (RemoteTarget(endpoint, uuid4(), "10.0.0.10"), {})
        with pytest.raises(web.HTTPForbidden):
            api.check_grant(gateway.user, endpoint, "reveal", fresh=True)

    asyncio.run(scenario())


def test_unknown_rotation_does_not_promote_or_redispatch(tmp_path: Path) -> None:
    class Executor:
        calls = 0

        async def apply(self, **kwargs: object) -> dict[str, object]:
            self.calls += 1
            raise RuntimeError("synthetic executor failure with sensitive detail")

        async def check(self, **kwargs: object) -> dict[str, object]:
            raise RuntimeError("synthetic reconciliation failure with sensitive detail")

    async def scenario() -> None:
        executor = Executor()
        endpoint, identity, config, _path, gateway, provider, api = fixture(
            tmp_path,
            executor=executor,
        )
        identifier, rid, request = (
            str(uuid4()),
            str(uuid4()),
            make_mocked_request("POST", "/"),
        )
        await api.perform(
            request,
            endpoint,
            identity,
            gateway.user,
            config,
            "create",
            {
                "request_id": identifier,
                "label": "Desktop",
                "kind": "rdp",
                "fields": {"username": "u", "password": "old"},
            },
        )
        body: SecretRequest = {
            "secret_id": identifier,
            "rotation_id": rid,
            "expected_version": 1,
            "fields": {"username": "u", "password": "new"},
        }
        first = await api.perform(
            request, endpoint, identity, gateway.user, config, "rotate", body
        )
        again = await api.perform(
            request, endpoint, identity, gateway.user, config, "resume_rotation", body
        )
        assert first["status"] == again["status"] == "unknown"
        assert "sensitive" not in json.dumps([first, again])
        record = api.state.get("records", identifier)
        assert record is not None
        assert provider.read(record["path"])["password"] == "old"
        assert executor.calls == 1

    asyncio.run(scenario())


def test_unavailable_provider_still_returns_metadata_and_paginates(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        endpoint, identity, _config, _path, _gateway, _provider, api = fixture(tmp_path)
        for i in range(23):
            api.state.save_record(
                {
                    "id": str(uuid4()),
                    "endpoint_id": str(endpoint),
                    "identity_id": str(identity),
                    "label": f"Credential {i}",
                    "kind": "api",
                    "retired": False,
                    "use_for_remote": False,
                    "path": f"northgate-rmm/synthetic-{i}",
                }
            )

        def unavailable(_: VaultConfiguration) -> VaultProvider:
            raise VaultError()

        api.provider_factory = unavailable
        app = web.Application()
        api.register(app)
        async with TestClient(TestServer(app)) as client:
            url = f"/remote/{endpoint}/secrets/state"
            first = await client.get(url)
            assert first.status == 200
            result = await first.json()
            assert len(result["records"]) == 20
            assert result["next_offset"] == 20 and result["total"] == 23
            assert all(not r["available"] for r in result["records"])
            assert result["health"]["sealed"]
            last = await (await client.get(url + "?offset=20")).json()
            assert len(last["records"]) == 3 and last["next_offset"] is None
            assert (await client.get(url + "?offset=-1")).status == 400

    asyncio.run(scenario())


@pytest.mark.parametrize("source_action", ["bitlocker.escrow", "recovery.rotate"])
def test_recovery_import_preserves_protection_custody_and_idempotency(
    tmp_path: Path, source_action: str
) -> None:
    from northgate_rmm.management_store import ManagementStore

    async def scenario() -> None:
        endpoint, identity, _config, _path, gateway, provider, api = fixture(tmp_path)
        gateway.user = replace(
            gateway.user, roles=("remote_operator", "recovery_operator")
        )
        policy = SimpleNamespace(permits=lambda *_: True)
        gateway.operation = cast(OperatorApplication, SimpleNamespace(_policy=policy))
        store = ManagementStore(tmp_path / "management", b"x" * 32)

        class Management:
            store: ManagementStore

            async def context(
                self, request: web.Request
            ) -> tuple[UUID, OperatorPrincipal, SimpleNamespace]:
                return endpoint, gateway.user, SimpleNamespace(identity_id=identity)

        api.management = cast(RealManagement, Management())
        api.management.store = store
        job_id = store.add(
            endpoint, identity, gateway.user, source_action, {}, "synthetic"
        )
        assert store.dispatch(job_id)
        recovery_password = "-".join(["123456"] * 8)
        value = (
            {
                "username": "ng-rmm-recovery",
                "password": "synthetic-escrow-password",
                "expires": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            }
            if source_action == "recovery.rotate"
            else {
                "volumes": [
                    {
                        "mount_point": "C:",
                        "recovery_passwords": [
                            {
                                "protector_id": str(uuid4()),
                                "recovery_password": recovery_password,
                            }
                        ],
                    }
                ]
            }
        )
        store.result(
            endpoint,
            identity,
            job_id,
            {
                "state": "completed",
                "exit_code": 0,
                "output": json.dumps(value),
                "execution_identity": "SYSTEM",
                "truncated": False,
            },
        )
        app = web.Application()
        api.register(app)
        base = f"/remote/{endpoint}/secrets"
        async with TestClient(TestServer(app)) as client:

            async def snapshot() -> dict[str, Any]:
                return cast(
                    dict[str, Any], await (await client.get(base + "/state")).json()
                )

            async def perform() -> ClientResponse:
                state = await snapshot()
                return await client.post(
                    base + "/action",
                    headers={"Origin": gateway.origin},
                    json={
                        "nonce": state["nonce"],
                        "action": "import_recovery",
                        "job_id": job_id,
                        "label": "Recovery copy",
                    },
                )

            before = await snapshot()
            assert before["recovery_jobs"][0]["id"] == job_id
            assert "synthetic-escrow-password" not in json.dumps(before)
            gateway.user = replace(gateway.user, roles=("remote_operator",))
            assert (await perform()).status == 403
            gateway.user = replace(
                gateway.user, roles=("remote_operator", "recovery_operator")
            )
            policy.permits = lambda *_: False
            assert (await perform()).status == 403
            policy.permits = lambda *_: True
            gateway.user = replace(
                gateway.user, authenticated_at=datetime.now(UTC) - timedelta(minutes=6)
            )
            assert (await perform()).status == 403
            gateway.user = replace(gateway.user, authenticated_at=datetime.now(UTC))
            response = await perform()
            assert response.status == 200, await response.text()
            receipt = await response.json()
            identifier = receipt["id"]
            record = api.state.get("records", identifier)
            assert record is not None
            secret = provider.read(record["path"])
            if source_action == "recovery.rotate":
                assert secret["password"] == "synthetic-escrow-password"
            else:
                assert recovery_password in secret["key"]
            assert (await perform()).status == 200
            assert len(provider.values[record["path"]]) == 1
            after = await snapshot()
            for forbidden in ("synthetic-escrow-password", recovery_password):
                assert forbidden not in json.dumps([receipt, after, gateway.audits])
                assert (
                    forbidden.encode() not in (tmp_path / "state.sqlite").read_bytes()
                )
            with store.connect() as db:
                db.execute(
                    "UPDATE jobs SET identity=? WHERE id=?", (str(uuid4()), job_id)
                )
            assert (await perform()).status == 404

    asyncio.run(scenario())
