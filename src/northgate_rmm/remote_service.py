"""Loopback-only executable for the lab remote desktop gateway."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from aiohttp import web

from northgate_rmm.agent_service import _require_unprivileged_process, load_database_dsn
from northgate_rmm.capture_store import CaptureStore
from northgate_rmm.capture_ui import CaptureUI
from northgate_rmm.fleet import Fleet
from northgate_rmm.inspection import InspectionStore, InspectionUI
from northgate_rmm.management import Management
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.operator_api import OperatorApplication
from northgate_rmm.operator_service import load_operator_service_configuration
from northgate_rmm.operator_verifier import MTLSOperatorSessionVerifier
from northgate_rmm.persistence import PostgresControlPlane
from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.remote_policy import parse_remote_targets
from northgate_rmm.remote_workspace import RemoteWorkspace, open_credentials
from northgate_rmm.secure_files import regular_file_reference


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operator-config", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--credentials", type=Path)
    parser.add_argument("--management-listener-config", type=Path)
    parser.add_argument("--operations-dsn-credential", type=Path)
    parser.add_argument("--wazuh-intake-registry", type=Path)
    parser.add_argument("--secrets-config", type=Path)
    parser.add_argument("--credential-rotation-config", type=Path)
    parser.add_argument("--service-runbooks", type=Path)
    parser.add_argument(
        "--integration-registry",
        type=Path,
        default=os.environ.get("NORTHGATE_RMM_INTEGRATION_REGISTRY"),
    )
    args = parser.parse_args()
    if args.credential_rotation_config and not args.secrets_config:
        parser.error("--credential-rotation-config requires --secrets-config")
    _require_unprivileged_process()
    config = load_operator_service_configuration(args.operator_config)
    store = PostgresControlPlane(load_database_dsn(config.database_dsn_credential))
    store.verify_schema_state()
    operation = OperatorApplication(
        store, MTLSOperatorSessionVerifier(config.verifier), config.policy
    )
    with regular_file_reference(
        args.targets,
        label="remote targets",
        maximum_bytes=4 * 1024 * 1024,
        private=True,
    ) as path:
        value = json.loads(path.read_text())
    with regular_file_reference(
        args.key, label="remote gateway key", maximum_bytes=64, private=True
    ) as path:
        key = bytes.fromhex(path.read_text().strip())
    if len(key) != 16:
        raise ValueError("invalid remote configuration")
    targets = parse_remote_targets(value)
    from northgate_rmm.remote_sessions import RemoteSessionStore

    gateway = RemoteGateway(
        operation,
        targets,
        key,
        args.origin,
        receipt_store=RemoteSessionStore(
            Path("/var/lib/northgate-rmm-remote/remote-sessions.sqlite3")
        ),
    )
    app = gateway.application()
    credentials = {}
    if args.credentials:
        with regular_file_reference(
            args.credentials,
            label="saved remote credentials",
            maximum_bytes=16 * 1024 * 1024,
            private=True,
        ) as path:
            credentials = open_credentials(key, path.read_bytes())
    RemoteWorkspace(gateway, credentials).register(app)
    capture = CaptureUI(
        gateway,
        CaptureStore(Path("/var/lib/northgate-rmm-remote/captures")),
        setup=True,
    )
    capture.register(app)
    management = Management(
        gateway, ManagementStore(Path("/var/lib/northgate-rmm-remote/management"), key)
    )
    management.register(app)
    from northgate_rmm.capture_setup import CaptureSetup

    CaptureSetup(management).register(app)
    fleet = Fleet(management)
    fleet.register(app)
    if args.management_listener_config:
        from northgate_rmm.listener import (
            AgentListenerConfiguration,
            build_server_ssl_context,
        )

        with regular_file_reference(
            args.management_listener_config,
            label="management listener configuration",
            maximum_bytes=16384,
            private=True,
        ) as path:
            settings = json.loads(path.read_text())
        listener = AgentListenerConfiguration(
            bind_address=settings["bind_address"],
            port=settings["port"],
            authority=settings["authority"],
            server_certificate=Path(settings["server_certificate"]),
            server_private_key=Path(settings["server_private_key"]),
            endpoint_ca_certificate=Path(settings["endpoint_ca_certificate"]),
        )
        ssl_context = build_server_ssl_context(listener)

        async def management_lifecycle(application):
            runner = web.AppRunner(management.worker_application(), access_log=None)
            await runner.setup()
            site = web.TCPSite(
                runner,
                host=listener.bind_address,
                port=listener.port,
                ssl_context=ssl_context,
                shutdown_timeout=10,
            )
            try:
                await site.start()
                yield
            finally:
                await runner.cleanup()

        app.cleanup_ctx.append(management_lifecycle)
    inspection = InspectionUI(
        gateway,
        InspectionStore(Path("/var/lib/northgate-rmm-remote/inspection.sqlite3")),
    )
    inspection.register(app)
    ops = None
    if args.operations_dsn_credential:
        from northgate_rmm.operations import Operations
        from northgate_rmm.operations_store import OperationsStore

        ops = Operations(
            management,
            fleet,
            OperationsStore.postgres(
                load_database_dsn(args.operations_dsn_credential),
                Path("/var/lib/northgate-rmm-remote/operations-evidence"),
                key,
            ),
            inspection=inspection,
            capture=capture,
            wazuh_registry=args.wazuh_intake_registry,
        )
        ops.register(app)
    if args.secrets_config:
        from northgate_rmm.secrets_api import SecretsAPI

        rotation_executor = None
        if args.credential_rotation_config:
            from northgate_rmm.credential_rdp import FreeRDPNLAVerifier
            from northgate_rmm.credential_rotation import (
                CredentialRotationExecutor,
                load_rotation_configuration,
            )

            rotation_config = load_rotation_configuration(
                args.credential_rotation_config
            )
            rotation_executor = CredentialRotationExecutor(
                management,
                FreeRDPNLAVerifier(
                    rotation_config["executable"],
                    rotation_config["executable_sha256"],
                    timeout_seconds=rotation_config["timeout_seconds"],
                    xvfb_executable=rotation_config.get("xvfb_executable"),
                    xvfb_sha256=rotation_config.get("xvfb_sha256"),
                ),
            )
        SecretsAPI(
            gateway,
            args.secrets_config,
            state_path=Path("/var/lib/northgate-rmm-remote/secrets.sqlite3"),
            management=management,
            rotation_executor=rotation_executor,
        ).register(app)
    native = None
    if args.integration_registry:
        from northgate_rmm.native_api import NativeAPI

        native = NativeAPI(
            management,
            fleet,
            capture,
            inspection,
            args.integration_registry,
            operations=ops,
        )
        native.register(app)
    from northgate_rmm.service_runbooks import ServiceRunbooks
    from northgate_rmm.tool_catalog import ToolCatalog

    async def case_authorizer(principal, endpoint, case_id):
        if ops is None:
            raise web.HTTPConflict(text="Operations workspace is not configured")
        record = await asyncio.to_thread(
            ops.authorized_record, principal, "case", case_id, "case.manage"
        )
        if str(endpoint) not in record["value"]["endpoints"]:
            raise web.HTTPForbidden(text="Device is not linked to the selected case")
        if record["value"]["status"] == "closed":
            raise web.HTTPConflict(text="Reopen the case before starting an operation")

    gateway.case_authorizer = case_authorizer

    async def case_linker(principal, endpoint, case_id, job):
        from uuid import NAMESPACE_URL, uuid5

        job_id = job["id"] if isinstance(job, dict) else str(job)
        await case_authorizer(principal, endpoint, case_id)
        await asyncio.to_thread(
            ops.dispatch,
            principal,
            "note",
            {
                "kind": "case",
                "id": case_id,
                "text": "Tool operation requested. Job: "
                + job_id
                + ". Completion must be verified in its result.",
                "request_id": str(
                    uuid5(NAMESPACE_URL, "case-job/" + case_id + "/" + job_id)
                ),
            },
        )

    ToolCatalog(
        management, case_authorizer=case_authorizer, case_linker=case_linker
    ).register(app)

    async def retain_runbook_result(entry, case_id, job_id):
        if ops is None:
            raise ValueError("Linked case evidence requires operations workspace")
        from uuid import NAMESPACE_URL, uuid5

        return await ops.native_call(
            entry,
            "pin_job",
            {
                "case": case_id,
                "job": job_id,
                "request_id": str(
                    uuid5(NAMESPACE_URL, "runbook-evidence/" + case_id + "/" + job_id)
                ),
            },
        )

    async def authorize_runbook_case(entry, plan):
        if ops is None:
            raise ValueError("Linked case execution requires operations workspace")
        if not {"ops.view", "case.manage", "evidence.manage"}.issubset(
            entry["actions"]
        ):
            raise web.HTTPForbidden(
                text="Runbook identity requires case and evidence permissions"
            )
        result = await ops.native_call(
            entry, "record", {"kind": "case", "id": plan["case_id"]}
        )
        case = result["record"]["value"]
        if not set(plan["endpoints"]).issubset(case["endpoints"]):
            raise web.HTTPForbidden(
                text="Runbook devices must belong to the linked case"
            )
        if case["status"] == "closed":
            raise web.HTTPConflict(text="Reopen the case before running its runbook")

    ServiceRunbooks(
        management,
        fleet,
        native,
        args.service_runbooks,
        evidence_sink=retain_runbook_result,
        case_authorizer=authorize_runbook_case,
    ).register(app)
    web.run_app(app, host="127.0.0.1", port=8451, access_log=None, print=None)


if __name__ == "__main__":
    main()
