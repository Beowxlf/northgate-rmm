"""Loopback-only browser qualification against actual operations/catalog handlers.

Authentication and device/worker transport are synthetic. Record validation,
scope, CSRF, persistence, evidence hashing and job submission use product code.
No lab connection or executable is launched by this fixture.
"""

import asyncio
import json
import secrets
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from aiohttp import web

from northgate_rmm.management import Management
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.operations import Operations
from northgate_rmm.operations_store import OperationsStore
from northgate_rmm.tool_catalog import ToolCatalog


async def main():
    token = secrets.token_urlsafe(24)
    actor = SimpleNamespace(
        subject="owner",
        session_id="browser-test",
        mfa=True,
        roles={"viewer", "remote_operator"},
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    endpoint = UUID("11111111-1111-4111-8111-111111111111")
    identity = UUID("22222222-2222-4222-8222-222222222222")
    device = SimpleNamespace(
        identity_id=identity,
        platform=SimpleNamespace(value="linux"),
        architecture="amd64",
        lifecycle=SimpleNamespace(value="active"),
    )
    devices = [
        {
            "id": str(endpoint),
            "identity": str(identity),
            "name": "Browser Linux",
            "platform": "linux",
            "architecture": "amd64",
            "lifecycle": "active",
        }
    ]

    async def principal(request, *args, **kwargs):
        if request.headers.get("Authorization") != "Bearer " + token:
            raise web.HTTPForbidden()
        return actor

    async def audit(*args):
        pass

    policy = SimpleNamespace(
        subject="owner",
        admits=lambda s: s == "owner",
        permits=lambda s, e, p: s == "owner" and str(e) == str(endpoint),
    )
    gateway = SimpleNamespace(
        key=b"B" * 16,
        origin="",
        targets={endpoint: None},
        principal=principal,
        audit=audit,
        operation=SimpleNamespace(
            _policy=policy, _store=SimpleNamespace(get_endpoint=lambda e: device)
        ),
    )
    source = Path(__file__).resolve().parents[1] / "src" / "northgate_rmm"
    with tempfile.TemporaryDirectory(prefix="northgate-browser-") as temporary:
        root = Path(temporary)
        management = Management(
            gateway, ManagementStore(root / "management", gateway.key)
        )
        management.store.worker = lambda _: {
            "ready": True,
            "identity": str(identity),
            "capabilities": {
                "features": {"tool_catalog": True, "diagnostic_lane": True}
            },
        }
        fleet = SimpleNamespace(
            principal=principal, admin=lambda p: p.subject == "owner"
        )
        store = OperationsStore.sqlite_for_tests(
            root / "ops.db", root / "artifacts", gateway.key
        )
        ops = Operations(management, fleet, store)

        async def authorize_case(p, e, case):
            record = ops.authorized_record(p, "case", case, "case.manage")
            if str(e) not in record["value"]["endpoints"]:
                raise web.HTTPForbidden(text="Device is not linked to this case")

        catalog = ToolCatalog(management, case_authorizer=authorize_case)
        app = web.Application(client_max_size=3 * 1024 * 1024)
        ops.register(app)
        catalog.register(app)

        async def index(request):
            await principal(request)
            content = """<!doctype html><html><head><meta charset='utf-8'>
            <link rel='stylesheet' href='/remote/fleet/assets/fleet.css'>
            <link rel='stylesheet' href='/remote/fleet/assets/operations_ui.css'>
            <script src='/remote/fleet/assets/operations_ui.js'></script></head>
            <body style='padding:24px'><nav id='fixture-nav'></nav>
            <main id='fixture-root'></main>
            <script>window.fixtureErrors=[];window.fixtureDevices=DEVICES;
            function mount(page){
            NorthGateOps.mount(document.querySelector('#fixture-root'),{
            page,devices:window.fixtureDevices,openDevice:()=>{},
            notify:m=>window.fixtureErrors.push(m)})}
            for(const page of ['cases','infrastructure','knowledge','tools']){
            const b=document.createElement('button');b.textContent=page;
            b.onclick=()=>mount(page);
            document.querySelector('#fixture-nav').append(b)}mount('cases');</script></body></html>"""
            return web.Response(
                text=content.replace("DEVICES", json.dumps(devices)),
                content_type="text/html",
            )

        async def asset(request):
            name = request.match_info["name"]
            if name not in {
                "operations_ui.js",
                "operations_ui.css",
                "fleet.css",
                "tool_catalog_ui.js",
            }:
                raise web.HTTPNotFound()
            return web.Response(
                body=(source / name).read_bytes(),
                content_type="text/javascript" if name.endswith(".js") else "text/css",
            )

        async def jobs(request):
            await principal(request)
            return web.json_response(
                {
                    "jobs": [
                        management.store.job(j["id"], private=True)
                        for j in management.store.list(endpoint)
                    ]
                }
            )

        app.router.add_get("/", index)
        app.router.add_get("/fixture/jobs", jobs)
        app.router.add_get("/remote/fleet/assets/{name}", asset)

        async def terminal(request):
            await principal(request)
            return web.Response(
                text=(
                    "<html><body><p id='ready'>Synthetic terminal document</p>"
                    "<script>window.sessionMarker=crypto.randomUUID()</script>"
                    "</body></html>"
                ),
                content_type="text/html",
            )

        app.router.add_get("/remote/{endpoint}/manage", terminal)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        gateway.origin = "http://127.0.0.1:" + str(
            site._server.sockets[0].getsockname()[1]
        )
        print(json.dumps({"origin": gateway.origin, "token": token}), flush=True)
        try:
            await asyncio.Event().wait()
        finally:
            await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
