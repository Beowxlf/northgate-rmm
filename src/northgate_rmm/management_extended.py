"""Release distribution and evidence correlation for the management workspace."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from northgate_rmm.management import Management

import asyncio
import hashlib
import ipaddress
import json
import re
import time
from uuid import UUID, uuid4

from aiohttp import web

from northgate_rmm.management_protocol import seal, unseal
from northgate_rmm.secure_files import regular_file_reference


class ExtendedManagement:
    def __init__(self, management: Management) -> None:
        self.m = management
        self.catalog = management.store.root / "releases"
        with management.store.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS infrastructure_baselines "
                "(endpoint TEXT PRIMARY KEY, created REAL NOT NULL, "
                "payload BLOB NOT NULL)"
            )

    def register(self, app: web.Application) -> None:
        app.router.add_get("/remote/{endpoint}/manage/catalog", self.releases)
        app.router.add_get(
            "/remote/{endpoint}/manage/infrastructure", self.infrastructure
        )
        app.router.add_post("/remote/{endpoint}/manage/infrastructure", self.baseline)
        app.router.add_post(
            "/remote/{endpoint}/manage/capture-evidence", self.capture_evidence
        )

    async def releases(self, request: web.Request) -> web.Response:
        _, _, e = await self.m.context(request)
        entries = []
        if self.catalog.exists():
            for path in sorted(self.catalog.glob("*.json"))[:100]:
                with regular_file_reference(
                    path, label="release manifest", maximum_bytes=4096, private=True
                ) as ref:
                    entry = json.loads(ref.read_text())
                if entry["manifest"]["platform"] == e.platform.value:
                    entries.append(entry)
        return web.json_response({"releases": entries}, headers=self.m.headers())

    async def download_release(self, request: web.Request) -> web.Response:
        await self.m.worker_identity(request)
        digest = request.match_info["digest"]
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise web.HTTPNotFound()
        path = self.catalog / digest
        try:
            with regular_file_reference(
                path,
                label="signed release",
                maximum_bytes=64 * 1024 * 1024,
                private=True,
            ) as ref:
                data = await asyncio.to_thread(ref.read_bytes)
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("Release integrity failure")
        except (OSError, ValueError):
            raise web.HTTPNotFound() from None
        return web.Response(
            body=data,
            content_type=("application/octet-stream"),
            headers=self.m.headers(),
        )

    def observations(
        self, endpoint: UUID | str, identity: UUID | str, subject: str
    ) -> list[dict[str, Any]]:
        # Capture history is already filtered to the authorized operator and enrollment.
        from northgate_rmm.capture_store import CaptureStore

        captures = CaptureStore(self.m.store.root.parent / "captures")
        rows = captures.history(endpoint, identity, subject)
        assets = {}
        for row in reversed(rows):
            job = json.loads(row["payload"])
            for asset in (job.get("report") or {}).get("assets", []):
                address = asset.get("ip") or asset.get("address")
                try:
                    address = str(ipaddress.ip_address(address))
                except (TypeError, ValueError):
                    continue
                match = []
                for eid, (target, _) in self.m.gateway.targets.items():
                    if str(target.address) == address:
                        match.append(str(eid))
                assets[address] = {
                    "address": address,
                    "macs": asset.get("macs", []),
                    "roles": asset.get("roles", []),
                    "capture": job["id"],
                    "observed_at": row["updated"],
                    "candidate_endpoints": match,
                    "confidence": "address-only candidate" if match else "unmapped",
                }
        return sorted(assets.values(), key=lambda a: a["address"])

    async def infrastructure(self, request: web.Request) -> web.Response:
        endpoint, p, e = await self.m.context(request)
        current = self.observations(endpoint, e.identity_id, p.subject)
        with self.m.store.connect() as db:
            row = db.execute(
                "SELECT * FROM infrastructure_baselines WHERE endpoint=?",
                (str(endpoint),),
            ).fetchone()
        old = (
            unseal(
                self.m.gateway.key, row["payload"], str(endpoint) + "/infrastructure"
            )
            if row
            else None
        )
        if old and old.get("identity") != str(e.identity_id):
            old = None
        old_assets = {a["address"]: a for a in old["assets"]} if old else {}
        now_assets = {a["address"]: a for a in current}
        changed = [
            a
            for a in now_assets.keys() & old_assets.keys()
            if (now_assets[a]["macs"], now_assets[a]["roles"])
            != (old_assets[a]["macs"], old_assets[a]["roles"])
        ]
        return web.json_response(
            {
                "assets": current,
                "baseline_saved": row["created"] if row and old else None,
                "added": sorted(now_assets.keys() - old_assets.keys()),
                "not_observed": sorted(old_assets.keys() - now_assets.keys()),
                "changed": sorted(changed),
                ("coverage"): (
                    "Latest retained captures visible to this operator. IP "
                    "matches are candidates, not identity proof; DHCP reuse, "
                    "NAT, packet loss and capture scope can change results. "
                    "Not observed does not mean offline."
                ),
            },
            headers=self.m.headers(),
        )

    async def baseline(self, request: web.Request) -> web.Response:
        endpoint, p, e = await self.m.context(request)
        v = await self.m.body(request)
        self.m.csrf(request, p, endpoint, v.get("csrf"))
        assets = self.observations(endpoint, e.identity_id, p.subject)
        if not assets:
            raise web.HTTPBadRequest(
                text="Capture infrastructure before saving a baseline"
            )
        await self.m.gateway.audit(
            p, endpoint, "management.infrastructure.baseline.saved", uuid4()
        )
        with self.m.store.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO infrastructure_baselines VALUES (?,?,?)",
                (
                    str(endpoint),
                    time.time(),
                    seal(
                        self.m.gateway.key,
                        {"identity": str(e.identity_id), "assets": assets},
                        str(endpoint) + "/infrastructure",
                    ),
                ),
            )
        return web.json_response({"saved": True}, headers=self.m.headers())

    async def capture_evidence(self, request: web.Request) -> web.Response:
        endpoint, p, e = await self.m.context(request)
        v = await self.m.body(request)
        self.m.csrf(request, p, endpoint, v.get("csrf"))
        from northgate_rmm.capture_store import CaptureStore

        try:
            identifier = str(UUID(v["capture"]))
            exercise = v["exercise"]
            if (
                not isinstance(exercise, str)
                or not 1 <= len(exercise) <= 64
                or any(ord(c) < 32 for c in exercise)
            ):
                raise ValueError()
            row = CaptureStore(self.m.store.root.parent / "captures").get(
                endpoint, e.identity_id, p.subject, identifier
            )
            if row is None:
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise web.HTTPBadRequest(
                text="Select an existing capture and exercise ID"
            ) from None
        job = json.loads(row["payload"])
        detail = {
            "capture": identifier,
            "subject": p.subject,
            "artifacts": job.get("artifacts", []),
            "findings": (job.get("report") or {}).get("findings", []),
        }
        await self.m.gateway.audit(
            p, endpoint, "management.exercise.capture.linked", UUID(identifier)
        )
        self.m.store.event(exercise, str(endpoint), "capture.linked", detail)
        return web.json_response({"linked": True}, headers=self.m.headers())
