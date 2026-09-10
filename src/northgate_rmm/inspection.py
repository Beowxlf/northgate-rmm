"""Read-only inspection jobs and baseline comparisons over the pinned lab SSH path."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
import sqlite3
import tempfile
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from uuid import UUID, uuid4

from aiohttp import web

from northgate_rmm.presentation import STYLE_SOURCE, document

CATEGORIES = {
    "processes": "Processes",
    "services": "Services",
    "network": "Connections",
    "users": "Local accounts",
    "software": "Installed software",
    "tasks": "Scheduled tasks",
    "startup": "Startup configuration",
    "storage": "Storage diagnostic",
    "health": "System diagnostic",
}
LIMIT = 1024 * 1024


def validate_result(value: object, category: str) -> dict:
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ValueError("Unsupported inspection response")
    if value.get("category") != category or value.get("platform") not in {
        "windows",
        "linux",
    }:
        raise ValueError("Unexpected inspection response")
    if value.get("status") not in {"ok", "partial", "error"}:
        raise ValueError("Invalid inspection status")
    rows = value.get("records")
    if not isinstance(rows, list) or len(rows) > 2000:
        raise ValueError("Inspection row limit exceeded")
    for row in rows:
        if not isinstance(row, dict) or not 1 <= len(row) <= 16 or not row.get("id"):
            raise ValueError("Invalid inspection row")
        if any(
            not isinstance(k, str)
            or not isinstance(v, str)
            or len(k) > 80
            or len(v) > 4096
            for k, v in row.items()
        ):
            raise ValueError("Invalid inspection value")
    for key in ["collected_at", "agent_version", "error"]:
        if not isinstance(value.get(key), str) or len(value[key]) > 1024:
            raise ValueError("Invalid inspection metadata")
    stamp = datetime.fromisoformat(value["collected_at"].replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Inspection timestamp must include timezone")
    if (
        type(value.get("exit_code")) is not int
        or type(value.get("duration_ms")) is not int
    ):
        raise ValueError("Invalid inspection execution metadata")
    return value


def compare(before: list[dict], after: list[dict]) -> dict[str, list]:
    def group(rows):
        result = defaultdict(list)
        for row in rows:
            result[row["id"]].append(row)
        return {
            k: sorted(v, key=lambda r: json.dumps(r, sort_keys=True))
            for k, v in result.items()
        }

    old, new = group(before), group(after)
    return {
        "added": [new[k] for k in sorted(new.keys() - old.keys())],
        "removed": [old[k] for k in sorted(old.keys() - new.keys())],
        "changed": [
            {"id": k, "before": old[k], "after": new[k]}
            for k in sorted(old.keys() & new.keys())
            if old[k] != new[k]
        ],
    }


class InspectionStore:
    """Private, bounded lab history; monitoring's PostgreSQL schema is unchanged."""

    def __init__(self, path: Path):
        self.path = path
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, endpoint TEXT NOT NULL, identity TEXT NOT NULL,
                    category TEXT NOT NULL, operator TEXT NOT NULL,
                    recorded TEXT NOT NULL,
                    payload TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS run_lookup
                    ON runs(endpoint,identity,category,recorded);
                CREATE TABLE IF NOT EXISTS baselines (
                    endpoint TEXT NOT NULL, identity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    run_id TEXT NOT NULL, saved TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY(endpoint,identity,category));
            """)
        path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA max_page_count=65536")
        try:
            with db:
                yield db
        finally:
            db.close()

    def add(self, endpoint, identity, category, operator, result):
        validate_result(result, category)
        id = str(uuid4())
        payload = json.dumps(result)
        if len(payload.encode()) > LIMIT:
            raise ValueError("Inspection output too large")
        with self.connect() as db:
            db.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?,?)",
                (
                    id,
                    str(endpoint),
                    str(identity),
                    category,
                    operator,
                    datetime.now(UTC).isoformat(),
                    payload,
                ),
            )
            db.execute(
                "DELETE FROM runs WHERE id IN (SELECT id FROM runs "
                "ORDER BY recorded DESC LIMIT -1 OFFSET 100)"
            )
        return id

    def history(self, endpoint, identity, category):
        with self.connect() as db:
            rows = db.execute(
                (
                    "SELECT * FROM runs WHERE endpoint=? AND identity=? "
                    "AND category=? ORDER BY recorded DESC LIMIT 10"
                ),
                (str(endpoint), str(identity), category),
            ).fetchall()
        return [dict(row) for row in rows]

    def baseline(self, endpoint, identity, category):
        with self.connect() as db:
            row = db.execute(
                (
                    "SELECT * FROM baselines WHERE endpoint=? AND "
                    "identity=? AND category=?"
                ),
                (str(endpoint), str(identity), category),
            ).fetchone()
        return dict(row) if row else None

    def save_baseline(self, endpoint, identity, category, id, operator):
        with self.connect() as db:
            row = db.execute(
                (
                    "SELECT payload FROM runs WHERE id=? AND endpoint=? "
                    "AND identity=? AND category=?"
                ),
                (id, str(endpoint), str(identity), category),
            ).fetchone()
            if row is None or json.loads(row[0])["status"] != "ok":
                raise ValueError("Only a successful inspection can become a baseline")
            db.execute(
                "INSERT OR REPLACE INTO baselines VALUES (?,?,?,?,?,?,?)",
                (
                    str(endpoint),
                    str(identity),
                    category,
                    id,
                    datetime.now(UTC).isoformat(),
                    operator,
                    row[0],
                ),
            )


async def run_inspection(target, parameters, platform, category):
    """Only fixed agent invocations are allowed; no command text comes from HTTP."""
    if category not in CATEGORIES or platform not in {"windows", "linux"}:
        raise ValueError("Unsupported inspection")
    username = parameters.get("username", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        raise ValueError("Invalid configured SSH user")
    key, host = parameters.get("private-key", ""), parameters.get("host-key", "")
    if not key or not host or len(host.splitlines()) != 1:
        raise ValueError("Pinned SSH inspection configuration is missing")
    if len(host.split()) < 3:
        raise ValueError("Invalid SSH host pin")
    algorithm = host.split()[1]
    if algorithm not in {"ecdsa-sha2-nistp256", "ssh-ed25519", "ssh-rsa"}:
        raise ValueError("Unsupported host key")
    if platform == "windows":
        script = (
            "& 'C:\\Program Files\\NorthGate RMM\\northgate-rmm-agent.exe' "
            "--inspect " + category + "; exit $LASTEXITCODE"
        )
        command = "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
        command += base64.b64encode(script.encode("utf-16-le")).decode()
    else:
        command = "/usr/libexec/northgate-rmm/northgate-rmm-agent --inspect " + category
    with tempfile.TemporaryDirectory(prefix="rmm-inspect-") as directory:
        path = Path(directory)
        for name, content in [("key", key), ("known_hosts", host + "\n")]:
            p = path / name
            p.write_text(content)
            p.chmod(0o600)
        proc = await asyncio.create_subprocess_exec(
            "/usr/bin/ssh",
            "-T",
            "-n",
            "-F",
            "/dev/null",
            "-i",
            str(path / "key"),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(path / "known_hosts"),
            "-o",
            "HostKeyAlgorithms=" + algorithm,
            "-o",
            "ConnectTimeout=8",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
            username + "@" + target.address,
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            async with asyncio.timeout(40):
                chunks = []
                size = 0
                while True:
                    chunk = await proc.stdout.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > LIMIT:
                        raise ValueError("Inspection output limit exceeded")
                    chunks.append(chunk)
                code = await proc.wait()
                if code != 0:
                    raise ValueError(
                        "SSH or agent inspection failed; verify the agent "
                        "version and remote account access"
                    )
                return validate_result(
                    json.loads(b"".join(chunks).decode("utf-8-sig")), category
                )
        finally:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()


class InspectionUI:
    def __init__(self, gateway, store, runner=run_inspection):
        self.gateway, self.store, self.runner = gateway, store, runner
        self.forms = {}
        self.busy = set()

    def register(self, app):
        app.router.add_get("/remote/{endpoint}/inspect", self.handle)
        app.router.add_post("/remote/{endpoint}/inspect", self.handle)

    async def handle(self, request):
        try:
            endpoint = UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None
        category = request.query.get("category", "services")
        if category not in CATEGORIES:
            raise web.HTTPBadRequest(text="Unknown inspection category")
        principal = await self.gateway.principal(
            request, endpoint, require_online=request.method == "POST"
        )
        target, parameters = self.gateway.targets[endpoint]
        now = time.monotonic()
        self.forms = {k: v for k, v in self.forms.items() if v[4] > now}
        if request.method == "POST":
            if request.headers.get("Origin") != self.gateway.origin:
                raise web.HTTPForbidden()
            form = await request.post()
            claim = self.forms.pop(str(form.get("nonce", "")), None)
            if claim is None or claim[:4] != (
                principal.subject,
                principal.session_id,
                endpoint,
                category,
            ):
                raise web.HTTPForbidden(
                    text="This form expired; reload the inspection page"
                )
            action = form.get("action")
            if action not in {"collect", "baseline"}:
                raise web.HTTPBadRequest()
            if endpoint in self.busy or len(self.busy) >= 4:
                raise web.HTTPConflict(
                    text="An inspection is already running; return to this page shortly"
                )
            correlation = uuid4()
            await self.gateway.audit(
                principal, endpoint, "inspection." + action + ".requested", correlation
            )
            self.busy.add(endpoint)
            try:
                if action == "baseline":
                    try:
                        await asyncio.to_thread(
                            self.store.save_baseline,
                            endpoint,
                            target.identity_id,
                            category,
                            str(form.get("run", "")),
                            principal.subject,
                        )
                    except ValueError as error:
                        raise web.HTTPBadRequest(text=str(error)) from None
                else:
                    record = await asyncio.to_thread(
                        self.gateway.operation._store.get_endpoint, endpoint
                    )
                    platform = (
                        record.platform.value
                        if hasattr(record.platform, "value")
                        else record.platform
                    )
                    start = time.monotonic()
                    try:
                        result = await self.runner(
                            target, parameters, platform, category
                        )
                        validate_result(result, category)
                    except (ValueError, OSError, TimeoutError):
                        result = {
                            "schema": 1,
                            "category": category,
                            "platform": platform,
                            "agent_version": "unknown",
                            "collected_at": datetime.now(UTC).isoformat(),
                            "duration_ms": int((time.monotonic() - start) * 1000),
                            "exit_code": -1,
                            "status": "error",
                            "error": (
                                "Inspection unavailable or timed out. Check agent "
                                "version and remote-account permissions."
                            ),
                            "records": [],
                        }
                    await self.gateway.principal(request, endpoint)
                    await asyncio.to_thread(
                        self.store.add,
                        endpoint,
                        target.identity_id,
                        category,
                        principal.subject,
                        result,
                    )
                await self.gateway.audit(
                    principal,
                    endpoint,
                    "inspection." + action + ".completed",
                    correlation,
                )
            finally:
                self.busy.discard(endpoint)
            raise web.HTTPSeeOther(f"/remote/{endpoint}/inspect?category={category}")
        history = await asyncio.to_thread(
            self.store.history, endpoint, target.identity_id, category
        )
        baseline = await asyncio.to_thread(
            self.store.baseline, endpoint, target.identity_id, category
        )
        selected = request.query.get("run")
        current = (
            next((r for r in history if r["id"] == selected), None)
            if selected
            else (history[0] if history else None)
        )
        if selected and current is None:
            raise web.HTTPNotFound()
        if request.query.get("download") == "1" and current:
            return web.Response(
                text=current["payload"],
                content_type="application/json",
                headers={
                    "Cache-Control": "no-store",
                    "Content-Disposition": 'attachment; filename="inspection.json"',
                },
            )
        if len(self.forms) >= 128:
            raise web.HTTPTooManyRequests()
        nonce = secrets.token_urlsafe(32)
        self.forms[nonce] = (
            principal.subject,
            principal.session_id,
            endpoint,
            category,
            now + 300,
        )
        return web.Response(
            text=self.render(endpoint, category, nonce, history, current, baseline),
            content_type="text/html",
            headers={
                "Cache-Control": "no-store",
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Security-Policy": (
                    "default-src 'none'; frame-ancestors 'self'; base-uri "
                    "'none'; form-action 'self'; style-src "
                )
                + STYLE_SOURCE,
            },
        )

    def render(self, endpoint, category, nonce, history, current, baseline):
        base = f"/remote/{endpoint}/inspect?category={category}"

        def form(action, label, extra=""):
            return (
                f'<form method="post" action="{base}"><input '
                f'type="hidden" name="nonce" value="{nonce}"><input '
                f'type="hidden" name="action" '
                f'value="{action}">{extra}<button class="button" '
                f'type="submit">{label}</button></form>'
            )

        content = (
            f'<a href="/endpoints/{endpoint}">Back to '
            f"endpoint</a><h1>Inspection and "
            f"diagnostics</h1><p>Read-only tools run as the "
            f"dedicated remote account. Saved results remain "
            f"available offline. Collection is limited to what "
            f"that account can see.</p><nav>"
        )
        content += (
            " · ".join(
                f'<a href="/remote/{endpoint}/inspect?category={k}">{v}</a>'
                for k, v in CATEGORIES.items()
            )
            + "</nav>"
        )
        content += (
            f'<section class="panel"><div '
            f'class="panel-heading"><div><h2>{CATEGORIES[category]}</h2>'
        ) + form("collect", "Run check / refresh")
        content += (
            "<p>Windows: local accounts, machine-wide software, "
            "visible tasks and current-account Run entries. "
            "Linux: local/NSS accounts, Debian packages and "
            "systemd tasks/startup units. These are scoped views, "
            "not an exhaustive persistence audit.</p>"
        )
        if not current:
            content += "<p>No results yet. Run the check to collect this category.</p>"
        else:
            value = json.loads(current["payload"])
            content += (
                "<p>"
                + escape(
                    f"Status: {value['status']} · Collected: "
                    f"{value['collected_at']} · Received: "
                    f"{current['recorded']} · Agent: "
                    f"{value['agent_version']} · Account: "
                    f"{value.get('execution_identity', 'unknown')} · Duration: "
                    f"{value['duration_ms']} ms · Exit: "
                    f"{value['exit_code']}"
                )
                + "</p>"
            )
            content += "<p>" + escape(value["error"]) + "</p>"
            content += (
                f"<a "
                f'href="{base}&amp;run={current["id"]}&amp;download=1">Download '
                f"full result</a>"
            )
            if value["status"] == "ok":
                content += form(
                    "baseline",
                    "Save this result as baseline",
                    f'<input type="hidden" name="run" value="{current["id"]}">',
                )
            if baseline:
                content += (
                    "<h3>Baseline comparison</h3><p>Baseline saved "
                    + escape(baseline["saved"])
                    + ". Saving again replaces this category baseline.</p>"
                )
                if value["status"] != "ok":
                    content += (
                        "<p>Comparison unavailable: the current collection "
                        "failed or is incomplete.</p>"
                    )
                else:
                    diff = compare(
                        json.loads(baseline["payload"])["records"], value["records"]
                    )
                    for kind, rows in diff.items():
                        content += (
                            f"<details><summary>{kind.title()}: {len(rows)}"
                            "</summary><pre>"
                            + escape(json.dumps(rows[:100], indent=2))
                            + "</pre></details>"
                        )
                    content += (
                        "<p>Process IDs, connections, free space and memory "
                        "change during normal operation. A difference is not "
                        "automatically malicious. Detail is capped at 100 "
                        "changes per group; full results can be "
                        "downloaded.</p>"
                    )
            rows = value["records"]
            columns = sorted({key for row in rows for key in row})
            content += (
                (
                    f"<h3>Collected records ({len(rows)})</h3><div "
                    f'class="table-scroll"><table><thead><tr>'
                )
                + "".join("<th>" + escape(k) + "</th>" for k in columns)
                + "</tr></thead><tbody>"
            )
            for row in rows[:200]:
                content += (
                    "<tr>"
                    + "".join(
                        "<td>" + escape(row.get(k, "")) + "</td>" for k in columns
                    )
                    + "</tr>"
                )
            content += (
                "</tbody></table></div><p>Showing up to 200 rows. "
                "Download the result for all collected rows.</p>"
            )
        content += "<h3>Recent checks</h3><ul>"
        for row in history:
            content += (
                f'<li><a href="{base}&amp;run={row["id"]}">'
                + escape(row["recorded"])
                + "</a> · "
                + escape(json.loads(row["payload"])["status"])
                + "</li>"
            )
        content += (
            "</ul><p>History retains the latest 100 checks across "
            "the lab. Saved baselines are retained separately and "
            "bound to the enrollment "
            "identity.</p></div></div></section>"
        )
        return document(
            "Endpoint inspection", content, updated=datetime.now(UTC).isoformat()
        )
