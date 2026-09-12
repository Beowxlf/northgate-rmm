"use strict";
(() => {
  const esc = (value) =>
    String(value ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  const label = (value) => String(value || "").replaceAll("_", " ");
  const date = (value) =>
    value
      ? new Date(
          typeof value === "number" ? value * 1000 : value,
        ).toLocaleString()
      : "Not set";
  const localInput = (value) => {
    if (!value) return "";
    const d = new Date(value);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000)
      .toISOString()
      .slice(0, 16);
  };
  const button = (text, op, id = "", kind = "", style = "") =>
    `<button type="button" class="button ${style}" data-ops="${esc(op)}" data-id="${esc(id)}" data-kind="${esc(kind)}">${esc(text)}</button>`;
  const badge = (text) => `<span class="badge">${esc(label(text))}</span>`;
  const empty = (title, detail) =>
    `<div class="ops-empty"><strong>${esc(title)}</strong><p>${esc(detail)}</p></div>`;
  const plural = {
    case: "cases",
    asset: "assets",
    service: "services",
    network: "networks",
    relationship: "relationships",
    document: "documents",
    change: "changes",
    exercise: "exercises",
    alert: "alerts",
  };
  const ui = {
    root: null,
    context: null,
    data: null,
    controller: null,
    dialog: null,
    cleanup: null,
    selected: null,
    category: "asset",
    query: "",
    caseFilter: "open",
    generation: 0,
    endpoint: "",
    dock: null,
  };
  const rows = (kind) => ui.data?.[plural[kind]] || [];
  const record = (kind, id) => rows(kind).find((r) => r.id === id);
  const endpointName = (id) =>
    ui.context.devices.find((d) => d.id === id)?.name || id;
  const recordName = (kind, id) => record(kind, id)?.value.name || id;
  const options = (items, selected = "") =>
    items
      .map(
        ([value, text]) =>
          `<option value="${esc(value)}" ${String(value) === String(selected) ? "selected" : ""}>${esc(text)}</option>`,
      )
      .join("");
  const input = (name, text, value = "", type = "text", extra = "") =>
    `<label>${esc(text)}<input name="${esc(name)}" type="${esc(type)}" value="${esc(value)}" ${extra}></label>`;
  const textarea = (name, text, value = "", extra = "") =>
    `<label>${esc(text)}<textarea name="${esc(name)}" ${extra}>${esc(value)}</textarea></label>`;
  const select = (name, text, items, value = "") =>
    `<label>${esc(text)}<select name="${esc(name)}">${options(items, value)}</select></label>`;
  const listSelect = (name, text, items, selected = []) =>
    `<label>${esc(text)}<select name="${esc(name)}" multiple>${items.map(([value, title]) => `<option value="${esc(value)}" ${selected.includes(value) ? "selected" : ""}>${esc(title)}</option>`).join("")}</select><small>Use Ctrl or Command to select several.</small></label>`;
  const values = (object) =>
    Object.entries(object || {})
      .map(
        ([key, value]) =>
          `${key}=${typeof value === "object" ? JSON.stringify(value) : value}`,
      )
      .join("\n");
  const parseValues = (text) =>
    Object.fromEntries(
      text
        .split("\n")
        .filter((s) => s.trim())
        .map((line) => {
          const n = line.indexOf("=");
          if (n < 1) throw new Error("Use one property=value per line.");
          return [line.slice(0, n).trim(), line.slice(n + 1).trim()];
        }),
    );
  async function request(path, body, csrf = ui.data?.csrf) {
    const response = await fetch(path, {
      method: body ? "POST" : "GET",
      headers: body
        ? { "Content-Type": "application/json", "X-CSRF-Token": csrf || "" }
        : {},
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: ui.controller.signal,
    });
    const isJSON = response.headers
      .get("content-type")
      ?.includes("application/json");
    const result = isJSON ? await response.json() : null;
    if (!response.ok) {
      const reason =
        !isJSON && response.headers.get("content-type")?.includes("text/plain")
          ? (await response.text()).slice(0, 500)
          : "";
      throw new Error(
        result?.error ||
          reason ||
          (response.status === 403
            ? "Your session or permissions changed. Refresh your sign-in."
            : `The operation could not be completed (${response.status}).`),
      );
    }
    if (!result)
      throw new Error(
        "The server returned an unexpected response. Refresh your sign-in.",
      );
    return result;
  }
  const mutate = (operation, value, id = crypto.randomUUID()) =>
    request(`/remote/ops/api/${operation}`, { ...value, request_id: id });
  async function uploadEvidence(caseId, file, key, node) {
    if (file.size > 128 * 1024 * 1024) throw new Error("File exceeds 128 MiB.");
    const bytes = new Uint8Array(await file.arrayBuffer()),
      digest = await hash(bytes);
    const storageKey = `northgate-upload:${caseId}:${encodeURIComponent(file.name)}:${digest}`;
    let remembered = null;
    try {
      remembered = JSON.parse(sessionStorage.getItem(storageKey));
    } catch {}
    if (remembered && Date.now() - remembered.created > 23 * 3600000)
      remembered = null;
    const intent = remembered || { requestId: key, created: Date.now() };
    const remember = () => {
      try {
        sessionStorage.setItem(storageKey, JSON.stringify(intent));
      } catch {}
    };
    remember();
    const acceptedTypes = [
      "application/octet-stream",
      "application/json",
      "text/plain",
      "text/csv",
      "application/x-ndjson",
      "application/zip",
      "application/vnd.tcpdump.pcap",
    ];
    const media = acceptedTypes.includes(file.type)
      ? file.type
      : "application/octet-stream";
    let start = intent.upload
      ? await request(
          `/remote/ops/api/upload/${encodeURIComponent(intent.upload)}`,
        )
      : await mutate(
          "upload_begin",
          {
            case: caseId,
            name: file.name,
            size: file.size,
            sha256: digest,
            media_type: media,
            redacted: true,
          },
          intent.requestId,
        );
    if (["cancelled", "purged"].includes(start.upload?.state)) {
      delete intent.upload;
      intent.requestId = crypto.randomUUID();
      intent.created = Date.now();
      remember();
      start = await mutate(
        "upload_begin",
        {
          case: caseId,
          name: file.name,
          size: file.size,
          sha256: digest,
          media_type: media,
          redacted: true,
        },
        intent.requestId,
      );
    }
    const upload =
      typeof start.upload === "string"
        ? start.upload
        : start.upload?.id || start.id;
    if (!upload) throw new Error("Upload identifier was not returned.");
    intent.upload = upload;
    remember();
    if (start.upload?.state === "complete") {
      if (start.upload.sha256 !== digest || start.upload.size !== bytes.length)
        throw new Error("The retained upload does not match this file.");
      try {
        sessionStorage.removeItem(storageKey);
      } catch {}
      return;
    }
    for (
      let offset = 0, index = 0;
      offset < bytes.length;
      offset += 1048576, index++
    ) {
      const chunk = bytes.subarray(offset, offset + 1048576);
      // Replaying an identical indexed chunk adopts already durable data. The
      // service independently checks its digest and collector identity.
      await mutate("upload_chunk", {
        upload,
        index,
        data: base64(chunk),
        sha256: await hash(chunk),
      });
      if (node.isConnected)
        node.querySelector("progress").value = Math.round(
          (Math.min(bytes.length, offset + chunk.length) / bytes.length) * 100,
        );
    }
    await mutate("upload_finish", { upload });
    try {
      sessionStorage.removeItem(storageKey);
    } catch {}
  }
  async function load() {
    const generation = ui.generation;
    if (["tools", "secrets"].includes(ui.context.page)) {
      await renderEndpointTool();
      return;
    }
    if (ui.context.page === "runbooks") {
      await renderRunbooks();
      return;
    }
    const data = await request("/remote/ops/api/state");
    if (generation !== ui.generation) return;
    ui.data = data;
    if (ui.selected) await showRecord(ui.selected.kind, ui.selected.id);
    else renderList();
  }
  function can(permission) {
    return (
      ui.data?.capabilities?.[permission] === true ||
      ui.data?.capabilities?.permissions?.includes(permission) ||
      ui.data?.capabilities?.admin === true
    );
  }
  function renderList() {
    ui.root.classList.remove("ops-session-layout");
    const page = ui.context.page;
    let kind =
      page === "cases"
        ? ui.category === "alert"
          ? "alert"
          : "case"
        : ui.category;
    if (
      page === "knowledge" &&
      !["document", "change", "exercise"].includes(kind)
    )
      kind = "document";
    if (
      page === "infrastructure" &&
      !["asset", "service", "network", "relationship"].includes(kind)
    )
      kind = "asset";
    ui.category = kind;
    const tabs =
      page === "cases"
        ? [
            ["case", "Cases"],
            ["alert", "Security alert intake"],
          ]
        : page === "knowledge"
          ? [
              ["document", "Articles & runbooks"],
              ["change", "Changes"],
              ["exercise", "Lab exercises"],
            ]
          : [
              ["asset", "Assets"],
              ["service", "Services"],
              ["network", "Networks"],
              ["relationship", "Dependencies"],
            ];
    let list = rows(kind).filter((r) =>
      JSON.stringify(r.value).toLowerCase().includes(ui.query.toLowerCase()),
    );
    if (kind === "case")
      list = list.filter(
        (r) =>
          ui.caseFilter === "all" ||
          (ui.caseFilter === "open"
            ? !["closed", "resolved"].includes(r.value.status)
            : r.value.status === ui.caseFilter),
      );
    const metrics =
      kind === "case"
        ? `<div class="ops-metrics">${[
            [
              "Open",
              rows("case").filter(
                (r) => !["closed", "resolved"].includes(r.value.status),
              ).length,
            ],
            [
              "Critical",
              rows("case").filter(
                (r) =>
                  r.value.priority === "critical" &&
                  r.value.status !== "closed",
              ).length,
            ],
            [
              "Unassigned",
              rows("case").filter(
                (r) => !r.value.assignee && r.value.status !== "closed",
              ).length,
            ],
          ]
            .map(
              ([name, count]) =>
                `<div class="ops-metric">${esc(name)}<strong>${count}</strong></div>`,
            )
            .join("")}</div>`
        : "";
    const permission =
      kind === "case"
        ? "case.manage"
        : kind === "alert"
          ? "not-editable"
          : "infrastructure.manage";
    ui.root.innerHTML = `${metrics}<div class="ops-tabs">${tabs.map(([id, name]) => `<button class="button" data-ops="category" data-id="${id}" aria-pressed="${id === kind}">${name}</button>`).join("")}</div><div class="ops-toolbar"><input type="search" data-ops-search placeholder="Search ${esc(plural[kind])}" aria-label="Search records" value="${esc(ui.query)}">${
      kind === "case"
        ? `<select data-ops-case-filter aria-label="Case status">${options(
            [
              ["open", "Open cases"],
              ["all", "All cases"],
              ["resolved", "Resolved"],
              ["closed", "Closed"],
            ],
            ui.caseFilter,
          )}</select>`
        : ""
    }${button("Refresh", "refresh")}${can(permission) ? button(`New ${kind}`, "new", "", kind, "primary") : ""}</div>${list.length ? `<div class="panel table-scroll"><table class="ops-table"><thead><tr><th>${kind === "case" ? "Case" : "Record"}</th><th>Type / status</th><th>Owner / team</th><th>Related devices</th><th>Updated</th></tr></thead><tbody>${list.map((r) => `<tr><td><button class="ops-link" data-ops="open" data-kind="${kind}" data-id="${esc(r.id)}">${esc(r.value.name)}</button><small>${esc(r.value.detection_id || r.id.slice(0, 8))}${r.value.detection_version ? ` v${esc(r.value.detection_version)}` : ""} · revision ${r.revision}</small></td><td>${badge(r.value.intake_status || r.value.status || r.value.asset_type || r.value.document_type || r.value.confidence || kind)} ${r.value.priority || r.value.severity ? badge(r.value.priority || r.value.severity) : ""}</td><td>${esc(r.value.case_id ? "Linked SOC case" : r.value.assignee || r.value.owner || "Unassigned")}<small>${esc(r.value.team)}</small></td><td>${(r.value.endpoints || []).map(endpointName).map(esc).join(", ") || "Intake health"}</td><td>${esc(date(r.updated))}</td></tr>`).join("")}</tbody></table></div>` : empty(`No ${plural[kind]} match`, "Create a record or adjust the filters. Records are limited to your authorized scope.")}`;
    ui.root.querySelector("[data-ops-search]").oninput = (e) => {
      ui.query = e.target.value;
      const start = e.target.selectionStart;
      renderList();
      const input = ui.root.querySelector("[data-ops-search]");
      input.focus();
      input.setSelectionRange(start, start);
    };
    ui.root
      .querySelector("[data-ops-case-filter]")
      ?.addEventListener("change", (e) => {
        ui.caseFilter = e.target.value;
        renderList();
      });
  }
  async function showRecord(kind, id, before = null) {
    const generation = ui.generation;
    const detail = await request(
      `/remote/ops/api/record/${encodeURIComponent(kind)}/${encodeURIComponent(id)}${before ? "?before=" + encodeURIComponent(before) : ""}`,
    );
    if (generation !== ui.generation) return;
    if (ui.selected && (ui.selected.kind !== kind || ui.selected.id !== id)) {
      ui.root.querySelector("#ops-session-dock")?.replaceChildren();
      ui.root.classList.remove("ops-session-layout");
    }
    ui.selected = { kind, id };
    const r = detail.record || detail,
      v = r.value;
    const events = detail.timeline || detail.events || [],
      evidence = detail.evidence || [];
    const editing =
      kind !== "alert" &&
      can(kind === "case" ? "case.manage" : "infrastructure.manage");
    const taskHTML = (v.tasks || [])
      .map(
        (task) =>
          `<div class="ops-task"><div class="grow"><strong>${esc(task.title)}</strong><small>${esc(task.assignee || "Unassigned")} · ${esc(label(task.status))}</small>${task.verification ? `<small>${esc(task.verification)}</small>` : ""}</div>${editing ? button("Update", "task", task.id, kind, "small") : ""}</div>`,
      )
      .join("");
    const timeline = events.length
      ? `<ol class="ops-timeline">${events.map(timelineEntry).join("")}</ol>`
      : "<p class='subtle'>No timeline entries.</p>";
    const markup = `<div class="ops-detail-title"><div>${button("← Back to records", "back")}<h2>${esc(v.name)}</h2>${badge(v.status || kind)} ${v.priority ? badge(v.priority) : ""}<p class="ops-note">${esc(id)} · revision ${r.revision}</p></div><div class="actions">${button("Refresh", "refresh")}${editing ? button("Edit details", "edit", id, kind) : ""}${kind === "case" && editing ? button("Update status", "transition", id, kind, "primary") : ""}</div></div><div class="ops-grid"><div><section class="ops-card"><h3>Description</h3><p>${esc(v.description || "No description recorded.")}</p>${v.content ? `<article class="ops-document">${esc(v.content)}</article>` : ""}${v.intended || v.observed ? `<div class="ops-inline-data"><section><strong>Intended</strong><pre class="ops-document">${esc(values(v.intended))}</pre></section><section><strong>Observed</strong><pre class="ops-document">${esc(values(v.observed))}</pre></section></div>` : ""}${[
      "implementation",
      "rollback",
      "verification",
      "cleanup_verification",
      "outcome",
    ]
      .filter((key) => v[key])
      .map((key) => `<h4>${esc(label(key))}</h4><p>${esc(v[key])}</p>`)
      .join(
        "",
      )}</section>${kind === "case" ? `<section class="ops-card"><div class="ops-toolbar"><h3>Tasks</h3>${editing ? button("Add task", "task", "", kind) : ""}</div>${taskHTML || "<p class='subtle'>No tasks yet.</p>"}</section><section class="ops-card"><div class="ops-toolbar"><h3>Evidence</h3>${can("evidence.manage") && editing ? button("Attach evidence", "attach", id, kind) : ""}${can("evidence.manage") && editing ? button("Retain job result", "pin-job", id, kind) : ""}</div>${evidence.length ? evidence.map((e) => `<div class="ops-task"><div class="grow"><strong>${esc(e.name)}</strong><small>${esc(e.state)} · ${esc(e.size)} bytes · ${e.retained ? "Held for case" : "Standard retention"}</small><small>SHA-256 ${esc(e.sha256)}</small></div>${e.state === "complete" || e.state === "completed" ? button("Download", "download", e.id, kind, "small") : e.state === "uploading" && editing && can("evidence.manage") ? button("Cancel upload", "cancel-upload", e.id, kind, "small") : ""}</div>`).join("") : "<p class='subtle'>Attach reviewed files or retain a diagnostic result. Secrets belong in Access & secrets.</p>"}</section>` : ""}<section class="ops-card"><div class="ops-toolbar"><h3>Timeline</h3>${editing ? button("Add note", "note", id, kind) : ""}</div>${timeline}</section><section class="ops-card"><h3>Revision history</h3>${(detail.versions || []).map((rev) => `<details><summary>Revision ${rev.revision} · ${esc(date(rev.created))} · ${esc(rev.subject)}</summary><pre class="ops-document">${esc(JSON.stringify(rev.value || rev.payload || {}, null, 2))}</pre></details>`).join("") || "<p class='subtle'>No prior versions.</p>"}</section></div><aside><section class="ops-card"><h3>Context</h3><dl><dt>Owner</dt><dd>${esc(v.assignee || v.owner || "Unassigned")}</dd><dt>Team</dt><dd>${esc(v.team || "Unassigned")}</dd><dt>Response due</dt><dd>${esc(date(v.response_due))}</dd><dt>Resolve due</dt><dd>${esc(date(v.resolve_due))}</dd></dl>${(v.endpoints || []).map((endpoint) => `<div class="ops-task"><div class="grow"><strong>${esc(endpointName(endpoint))}</strong></div>${button("Open", "device", endpoint, "", "small")}</div><div class="actions">${button("System tools", "dock-manage", endpoint, "", "small")}${button("SSH", "dock-ssh", endpoint, "", "small")}${ui.context.devices.find((d) => d.id === endpoint)?.platform === "windows" ? button("Desktop", "dock-desktop", endpoint, "", "small") : ""}</div>`).join("")}<p class="ops-note">Actions still require device permission. Session context does not expand access.</p></section><section class="ops-card"><h3>Related infrastructure</h3>${["asset", "service", "network"].map((k) => (v[plural[k]] || []).map((ref) => `<p>${button(recordName(k, ref), "open", ref, k, "small")}</p>`).join("")).join("") || "<p class='subtle'>No relationships recorded.</p>"}${kind === "asset" && editing ? button("Link enrollment", "reconcile", id, kind) : ""}</section></aside></div><section id="ops-session-dock"></section>`;
    let recordHost = ui.root.querySelector("#ops-record-content");
    if (!recordHost) {
      ui.root.innerHTML =
        '<div id="ops-record-content"></div><section id="ops-session-dock"></section>';
      recordHost = ui.root.querySelector("#ops-record-content");
    }
    recordHost.innerHTML = markup.replace(
      '<section id="ops-session-dock"></section>',
      "",
    );
    ui.detail = { ...detail, record: r };
    if (kind === "case" && editing) {
      const bar = document.createElement("div");
      bar.className = "ops-toolbar";
      bar.innerHTML = button("Link security alert", "link-alert", id, kind);
      recordHost.prepend(bar);
    }
    if (kind === "alert" && can("case.manage")) {
      const bar = document.createElement("div");
      bar.className = "ops-toolbar";
      bar.innerHTML = v.case_id
        ? button("Open SOC case", "open", v.case_id, "case", "primary")
        : button("Create SOC case", "case-from-alert", id, kind, "primary");
      recordHost.prepend(bar);
    }
    if (detail.next_before) {
      const older = document.createElement("div");
      older.innerHTML = button(
        "Older timeline entries",
        "older",
        String(detail.next_before),
        kind,
      );
      recordHost.append(older);
    }
  }
  function dialog(title, fields, submit, text = "Save") {
    ui.dialog?.remove();
    const node = document.createElement("dialog");
    node.className = "ops-dialog";
    node.innerHTML = `<form class="ops-form"><header><h2>${esc(title)}</h2><button type="button" class="icon-button" data-close aria-label="Close dialog">×</button></header>${fields}<p class="ops-error" role="alert"></p><footer><button type="button" class="button" data-close>Cancel</button><button type="submit" class="button primary">${esc(text)}</button></footer></form>`;
    document.body.append(node);
    ui.dialog = node;
    node
      .querySelectorAll("[data-close]")
      .forEach((b) => (b.onclick = () => node.close()));
    node.addEventListener("close", () => node.remove());
    node.addEventListener("cancel", (event) => {
      if (node.dataset.saving) event.preventDefault();
    });
    const requestId = crypto.randomUUID();
    node.querySelector("form").onsubmit = async (event) => {
      event.preventDefault();
      const b = node.querySelector("[type=submit]");
      if (b.disabled) return;
      b.disabled = true;
      node.dataset.saving = "true";
      node
        .querySelectorAll("[data-close]")
        .forEach((item) => (item.disabled = true));
      node.querySelector(".ops-error").textContent = "";
      try {
        await submit(new FormData(event.target), requestId, node);
        if (node.isConnected) node.close();
        if (ui.root) await load();
      } catch (error) {
        if (error.name !== "AbortError")
          node.querySelector(".ops-error").textContent = error.message;
      } finally {
        delete node.dataset.saving;
        node
          .querySelectorAll("[data-close]")
          .forEach((item) => (item.disabled = false));
        if (b.isConnected) b.disabled = false;
      }
    };
    node.showModal();
  }
  function edit(kind, r = null, sourceAlert = null) {
    const v = r?.value || {},
      id = r?.id || crypto.randomUUID();
    let fields =
      input("name", "Title", v.name, "text", 'required maxlength="256"') +
      textarea("description", "Description", v.description) +
      `<div class="ops-two">${input("owner", "Owner", v.owner)}${input("team", "Team", v.team)}</div>`;
    fields += listSelect(
      "endpoints",
      "Related devices",
      ui.context.devices
        .filter((d) => d.lifecycle === "active")
        .map((d) => [d.id, d.name]),
      v.endpoints || [],
    );
    fields += `<details><summary>Asset, service and network links</summary>${[
      "asset",
      "service",
      "network",
    ]
      .map((k) =>
        listSelect(
          plural[k],
          label(plural[k]),
          rows(k).map((r) => [r.id, r.value.name]),
          v[plural[k]] || [],
        ),
      )
      .join("")}</details>`;
    fields += input(
      "tags",
      "Tags (comma separated)",
      (v.tags || []).join(", "),
    );
    if (kind === "case")
      fields += `<div class="ops-two">${select(
        "type",
        "Case type",
        [
          ["it", "IT incident"],
          ["soc", "SOC investigation"],
          ["problem", "Recurring problem"],
          ["request", "Service request"],
        ],
        v.type || "it",
      )}${select(
        "priority",
        "Priority",
        ["low", "normal", "high", "critical"].map((x) => [x, label(x)]),
        v.priority || "normal",
      )}</div>${input("assignee", "Assignee", v.assignee)}<div class="ops-two">${input("response_due", "Response due", localInput(v.response_due), "datetime-local")}${input("resolve_due", "Resolve due", localInput(v.resolve_due), "datetime-local")}</div>`;
    if (kind === "asset")
      fields += `<div class="ops-two">${select(
        "asset_type",
        "Asset type",
        [
          "workstation",
          "server",
          "hypervisor",
          "firewall",
          "switch",
          "printer",
          "other",
        ].map((x) => [x, label(x)]),
        v.asset_type || "workstation",
      )}${input("site", "Site / location", v.site)}${input("environment", "Environment", v.environment)}${select(
        "criticality",
        "Criticality",
        ["standard", "important", "critical"].map((x) => [x, label(x)]),
        v.criticality || "standard",
      )}</div>${input("external_id", "Hardware / VM reference", v.external_id)}`;
    if (["asset", "service", "network"].includes(kind))
      fields += `<div class="ops-two">${textarea("intended", "Intended properties (property=value)", values(v.intended))}${textarea("observed", "Observed properties (property=value)", values(v.observed))}</div>${textarea("provenance", "Observation sources (property=value)", values(v.provenance))}`;
    if (kind === "network")
      fields += `<div class="ops-two">${input("cidr", "Network CIDR", v.cidr)}${input("vlan", "VLAN", v.vlan, "number", 'min="1" max="4094"')}</div>`;
    if (kind === "relationship") {
      const refs = ["asset", "service", "network"].flatMap((k) =>
        rows(k).map((r) => [k + ":" + r.id, label(k) + " · " + r.value.name]),
      );
      fields +=
        select(
          "source",
          "Source",
          refs,
          v.source ? `${v.source.kind}:${v.source.id}` : "",
        ) +
        select(
          "target",
          "Target",
          refs,
          v.target ? `${v.target.kind}:${v.target.id}` : "",
        ) +
        select(
          "relation",
          "Relationship",
          [
            "hosted_on",
            "depends_on",
            "connected_to",
            "member_of",
            "protected_by",
            "backs_up_to",
          ].map((x) => [x, label(x)]),
          v.relation || "depends_on",
        ) +
        select(
          "confidence",
          "Evidence strength",
          ["candidate", "observed", "verified"].map((x) => [x, label(x)]),
          v.confidence || "candidate",
        ) +
        input("source_ref", "Supporting evidence reference", v.source_ref);
    }
    if (kind === "document")
      fields +=
        select(
          "document_type",
          "Document type",
          ["article", "runbook", "design", "procedure"].map((x) => [
            x,
            label(x),
          ]),
          v.document_type || "article",
        ) +
        textarea(
          "content",
          "Article / procedure",
          v.content,
          'maxlength="32768"',
        ) +
        input("source_ref", "Authoritative document reference", v.source_ref) +
        input(
          "review_due",
          "Review due",
          v.review_due ? new Date(v.review_due).toISOString().slice(0, 10) : "",
          "date",
        );
    if (["change", "exercise"].includes(kind)) {
      fields +=
        select(
          "status",
          "Status",
          [
            "planned",
            "approved",
            "running",
            "review",
            "closed",
            "cancelled",
          ].map((x) => [x, label(x)]),
          v.status || "planned",
        ) +
        select(
          "case_id",
          "Related case",
          [
            ["", "No linked case"],
            ...rows("case").map((r) => [r.id, r.value.name]),
          ],
          v.case_id || "",
        );
      if (kind === "change")
        fields +=
          textarea("implementation", "Implementation steps", v.implementation) +
          textarea("rollback", "Rollback steps", v.rollback) +
          textarea(
            "verification",
            "Verification / observed result",
            v.verification,
          );
      else
        fields +=
          textarea(
            "techniques",
            "Technique references (one per line)",
            (v.techniques || []).join("\n"),
          ) +
          textarea(
            "allowed_activities",
            "Authorized activities (one per line)",
            (v.allowed_activities || []).join("\n"),
          ) +
          textarea(
            "expected_detections",
            "Expected detections (one per line)",
            (v.expected_detections || []).join("\n"),
          ) +
          textarea(
            "cleanup_verification",
            "Cleanup verification",
            v.cleanup_verification,
          );
    }
    dialog(
      r ? `Edit ${kind}` : `New ${kind}`,
      fields,
      async (form, requestId) => {
        const value = {};
        for (const [key, item] of form.entries()) value[key] = String(item);
        for (const key of ["endpoints", "assets", "services", "networks"])
          value[key] = form.getAll(key);
        value.tags = String(form.get("tags") || "")
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean);
        for (const key of ["intended", "observed", "provenance"])
          if (form.has(key)) value[key] = parseValues(String(form.get(key)));
        for (const key of [
          "techniques",
          "allowed_activities",
          "expected_detections",
        ])
          if (form.has(key))
            value[key] = String(form.get(key))
              .split("\n")
              .filter((x) => x.trim());
        for (const key of ["response_due", "resolve_due", "review_due"])
          if (form.has(key))
            value[key] = form.get(key)
              ? new Date(String(form.get(key))).toISOString()
              : null;
        if (form.has("vlan")) {
          if (form.get("vlan")) value.vlan = Number(form.get("vlan"));
          else delete value.vlan;
        }
        for (const key of ["source", "target"])
          if (form.has(key)) {
            const [k, ref] = String(form.get(key)).split(":");
            value[key] = { kind: k, id: ref };
          }
        const saved = await mutate(
          "save",
          { kind, id, revision: r?.revision || 0, value },
          requestId,
        );
        ui.selected = { kind, id };
        if (sourceAlert)
          await mutate("link_alert", {
            id,
            revision: saved.record.revision,
            alert: sourceAlert,
          });
      },
    );
  }
  async function renderEndpointTool() {
    ui.cleanup?.();
    ui.cleanup = null;
    const available = ui.context.devices.filter(
      (d) => d.lifecycle === "active",
    );
    if (!available.some((d) => d.id === ui.endpoint))
      ui.endpoint = available[0]?.id || "";
    ui.root.innerHTML = `<div class="ops-toolbar"><label>Device <select data-tool-endpoint>${options(
      available.map((d) => [d.id, d.name]),
      ui.endpoint,
    )}</select></label></div><section data-tool-host></section>`;
    const host = ui.root.querySelector("[data-tool-host]");
    if (!ui.endpoint) {
      host.innerHTML = empty(
        "No authorized devices",
        "Enroll a device or review its access scope.",
      );
      return;
    }
    ui.root.querySelector("[data-tool-endpoint]").onchange = (e) => {
      ui.endpoint = e.target.value;
      renderEndpointTool().catch((error) => ui.context.notify(error.message));
    };
    if (ui.context.page === "secrets") {
      const frame = document.createElement("iframe");
      frame.title = "Access and secrets";
      frame.className = "ops-dock";
      frame.src = `/remote/${ui.endpoint}/secrets/ui`;
      host.append(frame);
      return;
    }
    await loadTools();
    if (host.isConnected)
      ui.cleanup = window.NorthGateTools.mount(host, ui.endpoint);
  }
  async function renderRunbooks() {
    const generation = ui.generation,
      data = await request("/remote/runbooks/state");
    if (generation !== ui.generation) return;
    ui.runbooks = data;
    ui.root.innerHTML = `<div class="ops-toolbar">${button("Refresh", "refresh")}<span class="ops-note">Plans use deployment-approved service identities. Pausing stops new work and requests cancellation.</span></div>${data.error ? `<p class="ops-error">${esc(data.error)}</p>` : ""}${
      data.plans.length
        ? data.plans
            .map(
              (plan) =>
                `<section class="ops-card"><div class="ops-detail-title"><div><h2>${esc(plan.name)}</h2>${badge(plan.paused ? "paused" : plan.ready ? "ready" : "unavailable")}<p class="ops-note">Every ${Math.round(plan.interval / 60)} minutes · ${Object.keys(plan.endpoints).length} devices</p></div><div class="actions">${button("Run now", "run-plan", plan.id, "", plan.ready ? "primary" : "")}${button(plan.paused ? "Resume" : "Pause", plan.paused ? "resume-plan" : "pause-plan", plan.id)}</div></div><p>${esc(plan.reason)}</p><ol>${plan.steps.map((step) => `<li>${esc(step.name)} <small>${esc(step.action)}</small></li>`).join("")}</ol>${plan.runs
                  .map(
                    (run) =>
                      `<details><summary>${esc(date(run.created))} · ${esc(run.state)}</summary><p>${esc(run.error)}</p>${Object.entries(
                        run.devices,
                      )
                        .map(
                          ([id, d]) =>
                            `<p>${esc(endpointName(id))}: ${esc(d.state)} · ${d.step} completed steps ${esc(d.error || "")}</p>`,
                        )
                        .join("")}</details>`,
                  )
                  .join("")}</section>`,
            )
            .join("")
        : empty(
            "No approved service runbooks",
            "Add a reviewed runbook and its exact service grant through deployment configuration. Browser sessions are not converted into permanent credentials.",
          )
    }`;
  }
  async function action(op, id, kind) {
    const r = ui.detail?.record;
    if (op === "refresh") return load();
    if (op === "category") {
      ui.category = id;
      ui.query = "";
      renderList();
      return;
    }
    if (op === "back") {
      ui.selected = null;
      renderList();
      return;
    }
    if (op === "open") return showRecord(kind, id);
    if (op === "new") return edit(kind);
    if (op === "edit") return edit(kind, r);
    if (op === "device") {
      ui.context.openDevice(id);
      return;
    }
    if (op.startsWith("dock-")) {
      ui.root.classList.add("ops-session-layout");
      const host = ui.root.querySelector("#ops-session-dock");
      host.replaceChildren();
      const frame = document.createElement("iframe");
      frame.className = "ops-dock";
      frame.title = `${op.slice(5)} — ${endpointName(id)}`;
      frame.src = `/remote/${id}${op === "dock-manage" ? "/manage" : op === "dock-desktop" ? "/desktop" : ""}${ui.selected?.kind === "case" ? "?case_id=" + encodeURIComponent(ui.selected.id) : ""}`;
      host.innerHTML = `<div class="ops-toolbar"><h3>${esc(endpointName(id))}</h3>${button("Close session panel", "close-dock")}</div>`;
      host.append(frame);
      host.scrollIntoView({ behavior: "smooth", block: "nearest" });
      return;
    }
    if (op === "close-dock") {
      ui.root.classList.remove("ops-session-layout");
      ui.root.querySelector("#ops-session-dock").replaceChildren();
      return;
    }
    if (op === "note")
      return dialog(
        "Add note",
        textarea(
          "text",
          "Observation or decision",
          "",
          'required maxlength="8192"',
        ),
        (form, key) =>
          mutate("note", { kind, id, text: form.get("text") }, key),
      );
    if (op === "transition") {
      const next =
        {
          new: ["triage", "in_progress", "waiting"],
          triage: ["in_progress", "waiting", "resolved"],
          in_progress: ["waiting", "resolved"],
          waiting: ["triage", "in_progress", "resolved"],
          resolved: ["closed", "in_progress"],
          closed: ["in_progress"],
        }[r.value.status] || [];
      return dialog(
        "Update case status",
        select(
          "status",
          "New status",
          next.map((s) => [s, label(s)]),
        ) +
          textarea("outcome", "Outcome", r.value.outcome) +
          textarea(
            "verification",
            "How was the outcome verified?",
            r.value.verification,
          ),
        (form, key) =>
          mutate(
            "case_transition",
            {
              id,
              revision: r.revision,
              status: form.get("status"),
              outcome: form.get("outcome"),
              verification: form.get("verification"),
            },
            key,
          ),
      );
    }
    if (op === "task") {
      const task = (r.value.tasks || []).find((t) => t.id === id) || {};
      return dialog(
        id ? "Update task" : "New task",
        input("title", "Task", task.title, "text", "required") +
          input("assignee", "Assignee", task.assignee) +
          select(
            "status",
            "Status",
            ["todo", "in_progress", "done", "cancelled"].map((s) => [
              s,
              label(s),
            ]),
            task.status || "todo",
          ) +
          textarea(
            "verification",
            "Completion verification",
            task.verification,
          ),
        (form, key) =>
          mutate(
            "case_task",
            {
              id: r.id,
              revision: r.revision,
              task: {
                id: task.id || crypto.randomUUID(),
                title: form.get("title"),
                assignee: form.get("assignee"),
                status: form.get("status"),
                verification: form.get("verification"),
              },
            },
            key,
          ),
      );
    }
    if (op === "older") return showRecord(kind, r.id, id);
    if (op === "link-alert")
      return dialog(
        "Link security alert",
        select(
          "alert",
          "Alert",
          rows("alert").map((a) => [
            a.id,
            a.value.name || a.value.description || a.id,
          ]),
        ),
        (form, key) =>
          mutate(
            "link_alert",
            { id, revision: r.revision, alert: form.get("alert") },
            key,
          ),
      );
    if (op === "case-from-alert")
      return edit(
        "case",
        {
          id: crypto.randomUUID(),
          revision: 0,
          value: {
            name:
              r.value.name || r.value.description || "Security investigation",
            description: r.value.description || "",
            endpoints: r.value.endpoints,
            type: "soc",
            priority: r.value.priority || "normal",
          },
        },
        r.id,
      );
    if (op === "pin-job")
      return dialog(
        "Retain a diagnostic result",
        input("job", "Job ID", "", "text", "required") +
          '<p class="ops-note">Only authorized results from a device linked to this case can be retained. Recovery secret results are excluded.</p>',
        (form, key) =>
          mutate("pin_job", { case: id, job: form.get("job") }, key),
      );
    if (op === "reconcile")
      return dialog(
        "Link current enrollment",
        select(
          "endpoint",
          "Enrolled device",
          ui.context.devices
            .filter((d) => d.lifecycle === "active")
            .map((d) => [d.id, d.name]),
        ) +
          textarea("reason", "Identity verification evidence", "", "required"),
        (form, key) => {
          const d = ui.context.devices.find(
            (d) => d.id === form.get("endpoint"),
          );
          return mutate(
            "reconcile",
            {
              asset: id,
              endpoint: d.id,
              identity: d.identity,
              reason: form.get("reason"),
            },
            key,
          );
        },
      );
    if (op === "attach")
      return dialog(
        "Attach reviewed evidence",
        '<label>File<input type="file" name="file" required></label><label class="ops-check"><input type="checkbox" name="redacted" required>I reviewed this file and removed credentials and recovery secrets.</label><p class="ops-note">Maximum 128 MiB. Uploads use resumable chunks and retain a SHA-256 digest.</p><progress class="ops-progress" max="100" value="0"></progress>',
        async (form, key, node) =>
          uploadEvidence(id, form.get("file"), key, node),
        "Upload and retain",
      );
    if (op === "cancel-upload") {
      await mutate("upload_cancel", { upload: id });
      return load();
    }
    if (op === "download") {
      const item = ui.detail.evidence.find((e) => e.id === id);
      const chunks = [];
      for (let index = 0; index < Math.ceil(item.size / 1048576); index++) {
        const chunk = await request(
          `/remote/ops/api/evidence/${encodeURIComponent(id)}/chunks/${index}`,
        );
        const bytes = Uint8Array.from(atob(chunk.data), (c) => c.charCodeAt(0));
        if ((await hash(bytes)) !== chunk.sha256)
          throw new Error("Evidence chunk integrity check failed.");
        chunks.push(bytes);
      }
      const blob = new Blob(chunks, {
        type: item.media_type || "application/octet-stream",
      });
      if ((await hash(await blob.arrayBuffer())) !== item.sha256)
        throw new Error("Evidence integrity check failed.");
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = item.name || "evidence";
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return;
    }
    if (["run-plan", "pause-plan", "resume-plan"].includes(op)) {
      await request(
        "/remote/runbooks/action",
        {
          plan: id,
          action: {
            "run-plan": "run",
            "pause-plan": "pause",
            "resume-plan": "resume",
          }[op],
          request_id: crypto.randomUUID(),
        },
        ui.runbooks.csrf,
      );
      await renderRunbooks();
    }
  }
  async function hash(bytes) {
    return Array.from(
      new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    )
      .map((n) => n.toString(16).padStart(2, "0"))
      .join("");
  }
  function timelineEntry(event) {
    const titles = {
      "case.transition": "Case status updated",
      "case.task": "Task updated",
      "record.saved": "Record saved",
      "note.added": "Note added",
      "evidence.upload.started": "Evidence upload started",
      "evidence.upload.cancelled": "Evidence upload cancelled",
      "evidence.upload.expired": "Incomplete upload expired",
      "evidence.retained": "Evidence retained",
      "evidence.chunk.read": "Evidence downloaded",
      "alert.linked": "Security alert linked",
    };
    const value = event.value || {};
    const message =
      value.text ||
      value.note ||
      value.outcome ||
      value.verification ||
      value.name ||
      ("revision" in value ? "Saved revision " + value.revision : "");
    return `<li><strong>${esc(titles[event.action] || label(event.action).replaceAll(".", " "))}</strong><small>${esc(date(event.created))} · ${esc(event.subject)}</small>${message ? `<pre>${esc(message)}</pre>` : `<details><summary>Details</summary><pre>${esc(JSON.stringify(value, null, 2))}</pre></details>`}</li>`;
  }
  function base64(bytes) {
    let text = "";
    for (let i = 0; i < bytes.length; i += 32768)
      text += String.fromCharCode(...bytes.subarray(i, i + 32768));
    return btoa(text);
  }
  function unmount() {
    ui.root?.classList.remove("ops-session-layout");
    ui.generation++;
    ui.controller?.abort();
    ui.cleanup?.();
    ui.cleanup = null;
    ui.dialog?.close();
    ui.dialog?.remove();
    ui.dialog = null;
    ui.root = null;
  }
  function mount(root, context) {
    const oldPage = ui.context?.page;
    unmount();
    ui.root = root;
    ui.context = context;
    ui.controller = new AbortController();
    if (oldPage !== context.page) {
      ui.selected = null;
      ui.query = "";
    }
    root.innerHTML =
      '<div class="loading"><span class="spinner"></span>Loading operations…</div>';
    root.onclick = async (event) => {
      const target = event.target.closest("[data-ops]");
      if (!target || target.disabled) return;
      target.disabled = true;
      try {
        await action(
          target.dataset.ops,
          target.dataset.id,
          target.dataset.kind,
        );
      } catch (error) {
        if (error.name !== "AbortError") context.notify(error.message);
      } finally {
        if (target.isConnected) target.disabled = false;
      }
    };
    load().catch((error) => {
      if (error.name !== "AbortError" && ui.root === root)
        root.innerHTML = empty("Operations unavailable", error.message);
    });
  }
  let toolsLoading = null;
  async function loadTools() {
    if (window.NorthGateTools) return;
    if (!toolsLoading)
      toolsLoading = new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = "/remote/fleet/assets/tool_catalog_ui.js";
        script.onload = resolve;
        script.onerror = () => {
          toolsLoading = null;
          script.remove();
          reject(new Error("Tool interface could not be loaded"));
        };
        document.head.append(script);
      });
    await toolsLoading;
  }
  window.NorthGateOps = {
    mount,
    unmount,
    loadTools,
    updateDevices: (devices) => {
      if (ui.context) ui.context.devices = devices;
    },
    active: () => ui.root !== null,
  };
})();
