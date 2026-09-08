"""Loopback-only executable for the lab remote desktop gateway."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import UUID

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
from northgate_rmm.remote_policy import RemoteTarget
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
    args = parser.parse_args()
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
    if not isinstance(value, list) or not 1 <= len(value) <= 4096 or len(key) != 16:
        raise ValueError("invalid remote configuration")
    targets = {}
    for item in value:
        target = RemoteTarget(
            UUID(item["endpoint_id"]),
            UUID(item["identity_id"]),
            item["address"],
            item["protocol"],
            item["port"],
        )
        if target.endpoint_id in targets:
            raise ValueError("duplicate remote target")
        parameters = item["parameters"]
        allowed = {
            "username",
            "password",
            "domain",
            "security",
            "cert-fingerprints",
            "server-layout",
            "resize-method",
            "color-depth",
            "private-key",
            "host-key",
        }
        if not isinstance(parameters, dict) or not set(parameters) <= allowed:
            raise ValueError("invalid remote connection parameters")
        if any(type(v) is not str or len(v) > 8192 for v in parameters.values()):
            raise ValueError("invalid remote parameter value")
        targets[target.endpoint_id] = (target, parameters)
    gateway = RemoteGateway(operation, targets, key, args.origin)
    app = gateway.application()
    credentials = {}
    if args.credentials:
        with regular_file_reference(
            args.credentials,
            label="saved remote credentials",
            maximum_bytes=65536,
            private=True,
        ) as path:
            credentials = open_credentials(key, path.read_bytes())
    RemoteWorkspace(gateway, credentials).register(app)
    CaptureUI(
        gateway, CaptureStore(Path("/var/lib/northgate-rmm-remote/captures"))
    ).register(app)
    management = Management(
        gateway, ManagementStore(Path("/var/lib/northgate-rmm-remote/management"), key)
    )
    management.register(app)
    Fleet(management).register(app)
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
    InspectionUI(
        gateway,
        InspectionStore(Path("/var/lib/northgate-rmm-remote/inspection.sqlite3")),
    ).register(app)
    web.run_app(app, host="127.0.0.1", port=8451, access_log=None, print=None)


if __name__ == "__main__":
    main()
