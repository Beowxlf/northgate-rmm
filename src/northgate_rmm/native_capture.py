"""Signed capture operations for an explicitly granted integration identity."""

import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from uuid import UUID

from northgate_rmm.capture_ui import PRESETS, TERMINAL, validate_job
from northgate_rmm.management_protocol import canonical


async def call_capture(api, entry, endpoint, device, operation, args):
    ui = api.capture
    if operation == "capture_history":
        await api.audit(entry, endpoint, "capture.history")
        with ui.store.connect() as db:
            rows = db.execute(
                "SELECT payload FROM jobs WHERE endpoint=? AND identity=? "
                "ORDER BY created DESC LIMIT 20",
                (str(endpoint), str(device.identity_id)),
            ).fetchall()
        return {"captures": [json.loads(row[0]) for row in rows]}
    api.endpoint(entry, str(endpoint), "capture.control", online=True)
    target, parameters = api.m.gateway.targets[endpoint]
    if operation == "capture_capabilities":
        principal = api.auth.principal(entry, "capabilities")
        envelope = ui.envelope(target, principal, "capabilities")
        await api.audit(entry, endpoint, "capture.capabilities")
        return await ui.runner(
            target, parameters, device.platform.value, envelope, None
        )
    async with api.lock:
        if operation == "capture_start":
            identifier = str(UUID(args["request_id"]))
            fields = dict(
                interface=str(args["interface"]),
                preset=args.get("preset", "dns"),
                seconds=args.get("seconds", 60),
                max_bytes=args.get("max_mib", 16) * 1024 * 1024,
                snaplen=1536,
                host=args.get("host", ""),
                port=args.get("port", 0),
            )
            if fields["host"]:
                fields["host"] = str(ipaddress.ip_address(fields["host"]))
            if (
                not fields["interface"].isdigit()
                or not 1 <= int(fields["interface"]) <= 256
            ):
                raise ValueError("Invalid capture interface")
            for name, low, high in [
                ("seconds", 5, 300),
                ("max_bytes", 1048576, 33554432),
                ("port", 0, 65535),
            ]:
                if type(fields[name]) is not int or not low <= fields[name] <= high:
                    raise ValueError("Capture bounds exceeded")
            if fields["preset"] not in PRESETS:
                raise ValueError("Unknown capture preset")
            digest = hashlib.sha256(canonical(fields)).hexdigest()
            principal = api.auth.principal(entry, identifier)
            row = ui.store.get(
                endpoint, device.identity_id, principal.subject, identifier
            )
            if row:
                old = json.loads(row["payload"])
                if old.get("native_request_digest") != digest:
                    raise ValueError("Capture request identifier conflict")
                return old
            await api.audit(entry, endpoint, "capture.start", UUID(identifier))
            api.endpoint(entry, str(endpoint), "capture.control", online=True)
            ui.store.add(
                endpoint,
                device.identity_id,
                principal,
                dict(
                    id=identifier,
                    endpoint_id=str(endpoint),
                    identity_id=str(device.identity_id),
                    state="starting",
                    started=datetime.now(UTC).isoformat(),
                    preset=fields["preset"],
                    native_request_digest=digest,
                    reason="Capture start reserved before dispatch",
                ),
            )
            action = "start"
        elif operation in {"capture_status", "capture_stop"}:
            identifier = str(UUID(args["job"]))
            row = ui.store.get(
                endpoint, device.identity_id, "integration:" + entry["id"], identifier
            )
            if row is None:
                raise ValueError("Capture is not owned by this integration")
            old = json.loads(row["payload"])
            digest = old.get("native_request_digest")
            principal = api.auth.principal(entry, row["session"])
            fields = {}
            action = "status" if operation == "capture_status" else "stop"
            await api.audit(entry, endpoint, "capture." + action, UUID(identifier))
        else:
            raise ValueError("Unknown capture operation")
        envelope = ui.envelope(target, principal, action, UUID(identifier), **fields)
        result = await ui.runner(
            target, parameters, device.platform.value, envelope, None
        )
        api.endpoint(entry, str(endpoint), "capture.control")
        validate_job(result, identifier, endpoint, device.identity_id)
        if action == "status" and result["state"] not in TERMINAL:
            # Check the actual state before renewing: the capture may have finished
            # since the previous poll. Completion can also race the renewal itself.
            lease = ui.envelope(target, principal, "keepalive", UUID(identifier))
            try:
                await ui.runner(target, parameters, device.platform.value, lease, None)
            except ValueError:
                result = await ui.runner(
                    target, parameters, device.platform.value, envelope, None
                )
                validate_job(result, identifier, endpoint, device.identity_id)
                if result["state"] not in TERMINAL:
                    raise ValueError(
                        "Active capture lease could not be renewed"
                    ) from None
            api.endpoint(entry, str(endpoint), "capture.control")
        result["native_request_digest"] = digest
        ui.store.update(result)
        return result
