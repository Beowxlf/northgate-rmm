"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const h = (value) =>
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
  const state = {
    data: null,
    page: "overview",
    selected: new Set(),
    query: "",
    platform: "",
    health: "",
    group: "",
    history: false,
    sort: "name",
    descending: false,
    offset: 0,
    alertFilter: "active",
    preview: null,
    busy: false,
    refreshing: false,
    lastRefresh: 0,
  };
  const pages = {
    overview: [
      "Overview",
      "Your devices, outstanding work and operational health.",
      "YOUR WORKSPACE",
    ],
    devices: [
      "Devices",
      "Find an endpoint, inspect its health, or start a controlled operation.",
      "DEVICE MANAGEMENT",
    ],
    alerts: [
      "Alerts",
      "Prioritize issues, assign attention and track recovery.",
      "MONITORING",
    ],
    groups: [
      "Device groups",
      "Organize devices by site or purpose. Child groups inherit parent policy scope.",
      "FLEET ORGANIZATION",
    ],
    policies: [
      "Policies",
      "Reusable operations with platform scope, maintenance windows and rollout controls.",
      "CONFIGURATION",
    ],
    automations: [
      "Automations",
      "Recurring policies run only while their approving session remains authorized.",
      "SCHEDULED OPERATIONS",
    ],
    patches: [
      "Updates & software",
      "Inspect update readiness and deploy software through staged policies.",
      "PATCH MANAGEMENT",
    ],
    jobs: [
      "Activity",
      "Track canaries, deployment progress and individual device outcomes.",
      "OPERATIONS",
    ],
    recovery: [
      "Recovery",
      "See recovery coverage and open protected recovery tools for each endpoint.",
      "DEVICE RESILIENCE",
    ],
    exercises: [
      "Exercises",
      "Connect activity, baselines and observations to a repeatable lab exercise.",
      "SECURITY LAB",
    ],
    settings: [
      "Workspace health",
      "Review session access, scheduler health and endpoint prerequisites.",
      "ASSURANCE",
    ],
  };
  const records = (kind) => state.data?.records[kind] || [];
  const devices = () => state.data?.devices || [];
  const active = () => devices().filter((d) => d.lifecycle === "active");
  const nameOf = (kind, id) =>
    records(kind).find((r) => r.id === id)?.value.name ||
    (id ? "Unavailable group" : "All devices");
  const badge = (label, tone = "") =>
    `<span class="badge ${h(tone)}">${h(label)}</span>`;
  const tone = (status) =>
    ["online", "ready", "completed", "closed", "resolved"].includes(status)
      ? "good"
      : ["failed", "offline", "critical", "expired"].includes(status)
        ? "bad"
        : [
              "warning",
              "canary",
              "scheduled",
              "awaiting_review",
              "paused",
              "snoozed",
            ].includes(status)
          ? "warn"
          : "blue";
  const when = (value) =>
    value ? new Date(value * 1000).toLocaleString() : "Not reported";
  const ago = (value) => {
    if (!value) return "Never";
    const n = Math.max(0, Math.round(Date.now() / 1000 - value));
    return n < 60
      ? `${n}s ago`
      : n < 3600
        ? `${Math.floor(n / 60)}m ago`
        : n < 86400
          ? `${Math.floor(n / 3600)}h ago`
          : `${Math.floor(n / 86400)}d ago`;
  };
  const button = (label, action, id = "", extra = "") =>
    `<button class="button ${extra}" data-action="${h(action)}" data-id="${h(id)}">${h(label)}</button>`;
  const empty = (title, description, action = "") =>
    `<div class="empty"><div class="empty-symbol" aria-hidden="true">◇</div><strong>${h(title)}</strong><p>${h(description)}</p>${action}</div>`;
  const panel = (title, description, body, actions = "") =>
    `<section class="panel"><div class="panel-header"><div><h2>${h(title)}</h2>${description ? `<p>${h(description)}</p>` : ""}</div>${actions}</div>${body}</section>`;
  const selectOptions = (pairs, value) =>
    pairs
      .map(
        ([id, label]) =>
          `<option value="${h(id)}" ${String(id) === String(value) ? "selected" : ""}>${h(label)}</option>`,
      )
      .join("");
  const groups = () => [
    ["", "All devices"],
    ...records("group").map((r) => [r.id, r.value.name]),
  ];
  function notify(message) {
    $("toast").textContent = message;
    $("toast").hidden = false;
    clearTimeout(notify.timer);
    notify.timer = setTimeout(() => ($("toast").hidden = true), 6500);
  }
  async function api(operation, value) {
    const controller = new AbortController(),
      timeout = setTimeout(() => controller.abort(), 45000);
    try {
      const response = await fetch(`/remote/fleet/api/${operation}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": state.data.csrf,
        },
        body: JSON.stringify(value),
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        signal: controller.signal,
      });
      const type = response.headers.get("content-type") || "";
      const data = type.includes("json") ? await response.json() : null;
      if (!response.ok)
        throw new Error(
          data?.error ||
            (response.status === 403
              ? "Your session or permission changed. Refresh or sign in again."
              : `Operation failed (${response.status}). Refresh and retry.`),
        );
      if (!data)
        throw new Error(
          "The server returned an unexpected response. Sign in again.",
        );
      return data;
    } finally {
      clearTimeout(timeout);
    }
  }
  async function refresh(manual = false) {
    if (state.refreshing) return;
    state.refreshing = true;
    $("refresh").disabled = true;
    const controller = new AbortController(),
      timeout = setTimeout(() => controller.abort(), 45000);
    try {
      const response = await fetch("/remote/fleet/api/state", {
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        signal: controller.signal,
      });
      if (
        !response.ok ||
        !response.headers.get("content-type")?.includes("json")
      )
        throw new Error(
          "Workspace unavailable. Refresh your sign-in to continue.",
        );
      state.data = await response.json();
      state.lastRefresh = Date.now();
      const valid = new Set(devices().map((d) => d.id));
      state.selected = new Set(
        [...state.selected].filter((id) => valid.has(id)),
      );
      $("connection-banner").hidden = true;
      $("refresh-state").textContent = "Updated just now";
      $("session-status").textContent =
        `Session expires ${when(state.data.session_expires)} · Local display times`;
      if (
        !document.querySelector("dialog[open]") &&
        !document.activeElement?.matches("input,textarea,select")
      )
        render();
      if (manual) notify("Workspace refreshed");
    } catch (error) {
      $("connection-banner").textContent =
        error.name === "AbortError"
          ? "The workspace took too long to respond. Displayed data may be out of date."
          : error.message;
      $("connection-banner").hidden = false;
      $("connection-banner").className = "banner error";
      $("refresh-state").textContent = "Connection interrupted";
      if (!state.data)
        $("page-content").innerHTML = empty(
          "Unable to load the workspace",
          "Check your session and refresh. No endpoint action has been sent.",
          '<a class="button primary" href="/oauth2/sign_in?rd=%2Fremote%2Ffleet%2Fui">Sign in</a>',
        );
    } finally {
      clearTimeout(timeout);
      state.refreshing = false;
      $("refresh").disabled = false;
    }
  }
  function render() {
    if (!state.data) return;
    const [title, description, eyebrow] = pages[state.page];
    $("page-title").textContent = title;
    $("crumb").textContent = title;
    $("page-description").textContent = description;
    $("eyebrow").textContent = eyebrow;
    document.querySelectorAll("nav [data-page]").forEach((a) => {
      if (a.dataset.page === state.page) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    $("nav-devices").textContent = active().length;
    $("nav-alerts").textContent = records("alert").filter(
      (a) => !["resolved", "snoozed"].includes(a.value.state),
    ).length;
    $("page-actions").innerHTML =
      state.page === "devices"
        ? button("Export inventory", "export-devices")
        : ["groups", "policies", "automations", "exercises"].includes(
              state.page,
            ) && state.data.admin
          ? button(
              `Create ${state.page === "policies" ? "policy" : state.page.slice(0, -1)}`,
              "create",
              state.page === "policies" ? "policy" : state.page.slice(0, -1),
              "primary",
            )
          : state.page === "jobs"
            ? button("Export activity", "export-evidence")
            : state.page === "alerts" && state.data.admin
              ? button("Alert rules", "rules")
              : "";
    renderMetrics();
    const views = {
      overview: overview,
      devices: deviceTable,
      alerts: alertPage,
      groups: () => cards("group"),
      policies: () => cards("policy"),
      automations: () => cards("automation"),
      patches: patchPage,
      jobs: jobPage,
      recovery: recoveryPage,
      exercises: () => cards("exercise"),
      settings: settingsPage,
    };
    $("page-content").innerHTML = views[state.page]();
    bindPage();
  }
  function renderMetrics() {
    const list = active(),
      alerts = records("alert").filter(
        (a) => !["resolved", "snoozed"].includes(a.value.state),
      );
    const items =
      state.page === "patches"
        ? [
            ["Managed devices", list.length, "Active inventory", "▣"],
            [
              "Package ready",
              list.filter(
                (d) => d.capabilities.features?.packages && d.worker_ready,
              ).length,
              "Reported by current workers",
              "⊕",
            ],
            [
              "Needs prerequisites",
              list.filter(
                (d) => d.worker_ready && !d.capabilities.features?.packages,
              ).length,
              "Package tooling unavailable",
              "◇",
            ],
            [
              "Update runs",
              records("rollout").filter((r) =>
                r.value.action.startsWith("patches."),
              ).length,
              "Recorded rollout activity",
              "↻",
            ],
          ]
        : state.page === "recovery"
          ? [
              ["Active devices", list.length, "Current enrollments", "▣"],
              [
                "Managed recovery",
                list.filter((d) => d.capabilities.recovery_account?.managed)
                  .length,
                "Account reported by worker",
                "◈",
              ],
              [
                "Saved receipts",
                list.filter((d) => d.recovery_receipts?.length).length,
                "Collection is not restore proof",
                "▤",
              ],
              [
                "Baseline drift",
                list.filter((d) => d.changes.length).length,
                "Reported changes since baseline",
                "◇",
              ],
            ]
          : [
              [
                "Active devices",
                list.length,
                `${list.filter((d) => d.platform === "windows").length} Windows · ${list.filter((d) => d.platform === "linux").length} Linux`,
                "▣",
              ],
              [
                "Online",
                list.filter((d) => d.health === "online").length,
                "Reporting to monitoring",
                "●",
              ],
              [
                "Needs attention",
                alerts.length,
                `${alerts.filter((a) => a.value.severity === "critical").length} critical alerts`,
                "◇",
              ],
              [
                "Active operations",
                records("rollout").filter(
                  (r) =>
                    !["completed", "failed", "cancelled", "expired"].includes(
                      r.value.state,
                    ),
                ).length,
                "Canaries, scheduled and running",
                "↻",
              ],
            ];
    $("metrics").innerHTML = items
      .map(
        ([label, value, caption, icon]) =>
          `<article class="metric"><div class="metric-top">${h(label)}<span class="metric-icon" aria-hidden="true">${icon}</span></div><strong class="metric-value">${h(value)}</strong><span class="metric-caption">${h(caption)}</span></article>`,
      )
      .join("");
  }
  function overview() {
    const alerts = records("alert")
      .filter((a) => !["resolved", "snoozed"].includes(a.value.state))
      .sort(
        (a, b) =>
          (b.value.severity === "critical") - (a.value.severity === "critical"),
      )
      .slice(0, 5);
    const attention = alerts.length
      ? alerts
          .map(
            (a) =>
              `<div class="list-item"><span class="status-dot ${tone(a.value.severity)}"></span><div class="grow"><strong>${h(a.value.name)}</strong><p>${h(a.value.device)} · ${h(ago(a.value.first_seen))}</p></div>${badge(a.value.severity, tone(a.value.severity))}${button("Review", "open-device", a.value.endpoint, "small")}</div>`,
          )
          .join("")
      : empty(
          "No active alerts",
          "The configured rules have no outstanding issues. This does not establish complete security or patch coverage.",
        );
    const recent =
      records("rollout")
        .slice(0, 5)
        .map(
          (r) =>
            `<div class="list-item"><div class="grow"><strong>${h(r.value.name)}</strong><p>${h(r.value.targets.length)} devices · ${h(ago(r.created))}</p></div>${badge(r.value.state.replaceAll("_", " "), tone(r.value.state))}</div>`,
        )
        .join("") ||
      empty(
        "Your activity starts here",
        "Select devices and preview an operation to create a tracked rollout.",
        button("View devices", "navigate", "devices", "primary"),
      );
    const fleet =
      active()
        .slice(0, 6)
        .map(
          (d) =>
            `<div class="list-item"><span class="device-icon">${d.platform === "windows" ? "⊞" : "▱"}</span><div class="grow"><button class="text-button" data-action="open-device" data-id="${h(d.id)}">${h(d.name)}</button><p>${h(d.metadata.site || "No site assigned")} · ${h(d.platform)}</p></div>${badge(d.health, tone(d.health))}<span class="subtle">${h(ago(d.last_seen))}</span></div>`,
        )
        .join("") ||
      empty(
        "No devices enrolled",
        "Enrolled devices appear here once your account has access.",
      );
    return `<div class="split">${panel("Needs your attention", "Prioritized from configured monitoring rules", attention, button("All alerts", "navigate", "alerts", "small"))}${panel("Recent operations", "Every rollout retains its device outcomes", recent)}</div>${panel("Device overview", "Your active Windows and Linux endpoints", fleet, button("Open inventory", "navigate", "devices", "small"))}`;
  }
  function groupContains(id, wanted) {
    if (!wanted) return true;
    const seen = new Set();
    while (id && !seen.has(id)) {
      if (id === wanted) return true;
      seen.add(id);
      id = records("group").find((g) => g.id === id)?.value.parent;
    }
    return false;
  }
  function filtered() {
    return devices()
      .filter(
        (d) =>
          (state.history || d.lifecycle === "active") &&
          (!state.platform || d.platform === state.platform) &&
          (!state.health || d.health === state.health) &&
          groupContains(d.metadata.group, state.group) &&
          [
            d.name,
            d.id,
            d.metadata.site,
            d.metadata.owner,
            ...(d.metadata.tags || []),
          ]
            .join(" ")
            .toLowerCase()
            .includes(state.query.toLowerCase()),
      )
      .sort((a, b) => {
        const first =
          state.sort === "last_seen"
            ? a.last_seen || 0
            : String(a[state.sort] || "").toLowerCase();
        const second =
          state.sort === "last_seen"
            ? b.last_seen || 0
            : String(b[state.sort] || "").toLowerCase();
        return (
          (first < second ? -1 : first > second ? 1 : 0) *
          (state.descending ? -1 : 1)
        );
      });
  }
  function deviceTable() {
    const list = filtered();
    state.offset = Math.min(
      state.offset,
      Math.max(0, Math.floor((list.length - 1) / 25) * 25),
    );
    const slice = list.slice(state.offset, state.offset + 25);
    const toolbar = `<div class="toolbar"><input id="search" type="search" aria-label="Search devices" placeholder="Search name, site, owner or tag…" value="${h(state.query)}"><select id="filter-platform" aria-label="Filter platform">${selectOptions(
      [
        ["", "All platforms"],
        ["windows", "Windows"],
        ["linux", "Linux"],
      ],
      state.platform,
    )}</select><select id="filter-health" aria-label="Filter health">${selectOptions(
      [
        ["", "All health"],
        ["online", "Online"],
        ["stale", "Stale"],
        ["offline", "Offline"],
      ],
      state.health,
    )}</select><select id="filter-group" aria-label="Filter group">${selectOptions(groups(), state.group)}</select><label class="check-field"><input id="history" type="checkbox" ${state.history ? "checked" : ""}> History</label>${button("Save view", "save-view", "", "small")}<select id="saved-view" aria-label="Load saved view"><option value="">Saved views</option>${records(
      "view",
    )
      .map((v) => `<option value="${h(v.id)}">${h(v.value.name)}</option>`)
      .join("")}</select></div>`;
    const selectBar = state.selected.size
      ? `<div class="selection-bar"><strong>${state.selected.size} selected</strong>${button("Run operation", "bulk", "", "small primary")}${state.data.admin ? button("Assign group", "assign-group", "", "small") : ""}${button("Clear selection", "clear-selection", "", "small")}</div>`
      : "";
    const body = slice
      .map(
        (d) =>
          `<tr><td><input type="checkbox" data-select="${h(d.id)}" aria-label="Select ${h(d.name)}" ${state.selected.has(d.id) ? "checked" : ""} ${d.lifecycle !== "active" ? "disabled" : ""}></td><td><div class="device-name"><span class="device-icon">${d.platform === "windows" ? "⊞" : "▱"}</span><div><button class="text-button" data-action="open-device" data-id="${h(d.id)}">${h(d.name)}</button><small>${h(d.metadata.site || "No site")} ${d.metadata.tags?.length ? "· " + d.metadata.tags.map((t) => h(t)).join(", ") : ""}</small></div></div></td><td>${h(d.platform)}<small>${h(d.architecture)}</small></td><td>${h(nameOf("group", d.metadata.group) || "Ungrouped")}</td><td>${badge(d.lifecycle === "active" ? d.health : d.lifecycle, tone(d.health))}</td><td>${badge(d.worker_ready ? "Ready" : "Unavailable", d.worker_ready ? "good" : "warn")}<small>${h(d.capabilities.version || "Not installed")}</small></td><td>${h(ago(d.last_seen))}<small>${h(when(d.last_seen))}</small></td><td>${button("Open", "open-device", d.id, "small")}</td></tr>`,
      )
      .join("");
    return panel(
      "Device inventory",
      `${list.length} matching devices`,
      toolbar +
        selectBar +
        (slice.length
          ? `<div class="table-scroll"><table><thead><tr><th><input id="select-page" type="checkbox" aria-label="Select devices on this page" ${slice.filter((d) => d.lifecycle === "active").every((d) => state.selected.has(d.id)) ? "checked" : ""}></th><th><button class="sort-button" data-sort="name">Device name ↕</button></th><th><button class="sort-button" data-sort="platform">Platform ↕</button></th><th>Group</th><th><button class="sort-button" data-sort="health">Health ↕</button></th><th>Management</th><th><button class="sort-button" data-sort="last_seen">Last seen ↕</button></th><th></th></tr></thead><tbody>${body}</tbody></table></div>`
          : empty(
              "No matching devices",
              "Change your filters or clear the search.",
            )) +
        `<div class="table-footer"><span>Showing ${list.length ? state.offset + 1 : 0}–${Math.min(state.offset + 25, list.length)} of ${list.length} · Times in your local timezone</span><div class="actions">${button("Previous", "previous", "", "small")}${button("Next", "next", "", "small")}</div></div>`,
    );
  }
  function alertPage() {
    const list = records("alert").filter((r) =>
      state.alertFilter === "all" || state.alertFilter === "active"
        ? !["resolved", "snoozed"].includes(r.value.state) ||
          state.alertFilter === "all"
        : r.value.state === state.alertFilter,
    );
    const tabs = `<div class="toolbar"><select id="alert-filter" aria-label="Filter alerts">${selectOptions(
      [
        ["active", "Active alerts"],
        ["acknowledged", "Acknowledged"],
        ["snoozed", "Snoozed"],
        ["resolved", "Resolved"],
        ["all", "All history"],
      ],
      state.alertFilter,
    )}</select><span class="subtle">Alerts resolve automatically when the observed condition clears.</span></div>`;
    return panel(
      "Alert inbox",
      `${list.length} alerts`,
      tabs +
        (list.length
          ? `<div class="table-scroll"><table><thead><tr><th>Severity</th><th>Issue</th><th>Device</th><th>Status</th><th>First observed</th><th>Actions</th></tr></thead><tbody>${list.map((r) => `<tr><td>${badge(r.value.severity, tone(r.value.severity))}</td><td><strong>${h(r.value.name)}</strong><small>${h(r.value.note || r.value.condition.replaceAll("_", " "))}</small></td><td><button class="text-button" data-action="open-device" data-id="${h(r.value.endpoint)}">${h(r.value.device)}</button></td><td>${badge(r.value.state, tone(r.value.state))}</td><td>${h(ago(r.value.first_seen))}<small>${h(when(r.value.first_seen))}</small></td><td><div class="actions">${button("Update", "edit-alert", r.id, "small")}</div></td></tr>`).join("")}</tbody></table></div>`
          : empty(
              "No alerts in this view",
              "New observations will appear as your configured rules detect them.",
            )),
    );
  }
  function cards(kind) {
    const list = records(kind);
    if (!list.length)
      return panel(
        "Get organized",
        "",
        empty(
          `No ${kind === "policy" ? "policies" : kind + "s"} yet`,
          kind === "group"
            ? "Create a group for a site, platform or exercise, then assign devices from inventory."
            : "Create your first record to make this workflow reusable.",
          state.data.admin
            ? button("Create " + kind, "create", kind, "primary")
            : "",
        ),
      );
    return `<div class="grid">${list
      .map((r) => {
        const v = r.value;
        let info = "",
          actions = "";
        if (kind === "group") {
          info = `<p>${h(v.description || "Organize related devices; group targeting includes child groups.")}</p>${badge(`${devices().filter((d) => groupContains(d.metadata.group, r.id)).length} devices`, "blue")}<p>Parent: ${h(v.parent ? nameOf("group", v.parent) : "None")}</p>`;
          actions = button("View devices", "view-group", r.id, "small");
        }
        if (kind === "policy") {
          info = `<p>${h(state.data.actions[v.action] || v.action)}</p>${badge(v.platform, "blue")}<p>${h(nameOf("group", v.group))} · ${v.canary} canary · ${v.concurrency} concurrent</p><p>Window: ${h(v.window.start)}–${h(v.window.end)} UTC</p>`;
          actions = button("Preview run", "run-policy", r.id, "small primary");
        }
        if (kind === "automation") {
          info = `<p>${h(nameOf("policy", v.policy))}</p>${badge(v.enabled ? "Enabled" : "Disabled", v.enabled ? "good" : "")}<p>Every ${Math.round(v.interval / 60)} minutes · ${h(nameOf("group", v.group))}</p><p>Arm for up to one hour within your authenticated session.</p>`;
          actions = v.enabled
            ? button("Preview & arm", "arm", r.id, "small primary")
            : "";
        }
        if (kind === "exercise") {
          info = `<p>${h(v.description || "No exercise description yet")}</p>${badge(v.status, tone(v.status))}<p>${h(v.technique || "Technique not assigned")}</p><p>${h(v.outcome || "Outcome not recorded")}</p>`;
          actions = button("Export evidence", "export-exercise", r.id, "small");
        }
        return `<article class="record-card"><h2>${h(v.name)}</h2>${info}<div class="actions">${actions}${state.data.admin ? button("Edit", "edit", `${kind}:${r.id}`, "small") + button("Delete", "delete", `${kind}:${r.id}`, "small") : ""}</div></article>`;
      })
      .join("")}</div>`;
  }
  function jobPage() {
    const list = records("rollout");
    return panel(
      "Rollout activity",
      "A paused rollout stops new dispatches; already running jobs finish unless cancelled.",
      list.length
        ? `<div class="table-scroll"><table><thead><tr><th>Operation</th><th>Status</th><th>Progress</th><th>Created</th><th>Controls</th></tr></thead><tbody>${list
            .map((r) => {
              const v = r.value,
                p = v.progress || {};
              return `<tr><td><strong>${h(v.name)}</strong><small>${h(state.data.actions[v.action] || v.action)} · ${h(v.targets.length)} devices</small></td><td>${badge(v.state.replaceAll("_", " "), tone(v.state))}</td><td><div class="progress"><progress value="${Number(p.completed || 0)}" max="${Math.max(1, Number(p.total || v.targets.length))}"></progress><span>${p.completed || 0}/${p.total || v.targets.length}</span></div><small>${p.failed || 0} failed · ${p.active || 0} active</small></td><td>${h(when(r.created))}</td><td><div class="actions">${button("Details", "run-detail", r.id, "small")}${["paused", "awaiting_review"].includes(v.state) ? button(v.state === "awaiting_review" ? "Approve canary" : "Resume", "resume", r.id, "small primary") : ["running", "canary", "scheduled", "waiting_capacity"].includes(v.state) ? button("Pause", "pause", r.id, "small") : ""}${!["completed", "failed", "cancelled", "expired"].includes(v.state) ? button("Cancel", "cancel", r.id, "small danger") : ""}</div></td></tr>`;
            })
            .join("")}</tbody></table></div>`
        : empty(
            "No rollout activity",
            "Operations started from this workspace will appear here with device-level outcomes.",
            button("Select devices", "navigate", "devices", "primary"),
          ),
    );
  }
  function patchPage() {
    return `<div class="banner info">Update readiness is reported by the privileged worker. A successful inventory or scan is not proof that every update is installed.</div>${panel(
      "Software and update readiness",
      "Use policies to preview, stage and track changes.",
      `<div class="table-scroll"><table><thead><tr><th>Device</th><th>Platform</th><th>Package tooling</th><th>Latest operation</th><th>Action</th></tr></thead><tbody>${active()
        .map(
          (d) =>
            `<tr><td><button class="text-button" data-action="open-device" data-id="${h(d.id)}">${h(d.name)}</button></td><td>${h(d.platform)}</td><td>${badge(d.worker_ready && d.capabilities.features?.packages ? "Ready" : "Needs attention", d.worker_ready && d.capabilities.features?.packages ? "good" : "warn")}<small>${h(d.capabilities.features?.package_requirement || (!d.worker_ready ? "Worker unavailable" : ""))}</small></td><td>${h(d.last_job?.action || "No operation recorded")}<small>${h(d.last_job?.state || "")}</small></td><td>${d.permissions.includes("patch") ? button("Scan updates", "scan", d.id, "small") : badge("View only")}</td></tr>`,
        )
        .join("")}</tbody></table></div>`,
      state.data.admin
        ? button("Create update policy", "new-patch", "", "primary")
        : "",
    )}`;
  }
  function recoveryPage() {
    return `<div class="banner info">A saved receipt shows that data was collected. Recovery readiness requires a verified sign-in or restore drill. Recovery secrets are revealed only through the protected device tools.</div>${panel(
      "Recovery coverage",
      "Existing key protectors and managed recovery accounts",
      `<div class="table-scroll"><table><thead><tr><th>Device</th><th>Recovery account</th><th>Saved recovery records</th><th>Baseline</th><th>Actions</th></tr></thead><tbody>${active()
        .map(
          (d) =>
            `<tr><td><strong>${h(d.name)}</strong><small>${h(d.platform)}</small></td><td>${badge(d.capabilities.recovery_account?.managed ? "Managed" : "Not verified", d.capabilities.recovery_account?.managed ? "good" : "warn")}</td><td>${d.recovery_receipts?.length ? d.recovery_receipts.map((r) => `<small>${h(r.kind)} · ${h(when(r.collected))}</small>`).join("") : "No visible records"}</td><td>${d.baseline ? h(when(d.baseline)) : "Not saved"}<small>${d.changes.length ? `${d.changes.length} fields changed` : "No observed drift"}</small></td><td>${button("Open tools", "open-system", d.id, "small")}</td></tr>`,
        )
        .join("")}</tbody></table></div>`,
    )}`;
  }
  function settingsPage() {
    const missing = active().filter(
      (d) =>
        !d.worker_ready ||
        d.capabilities.features?.npcap_driver_installed === false ||
        d.capabilities.features?.packages === false,
    );
    return `<div class="split">${panel("Session & access", "Deployment-owned permissions are rechecked on each operation.", `<div class="panel-body"><dl class="facts"><dt>Operator</dt><dd>${h(state.data.subject)}</dd><dt>Roles</dt><dd>${state.data.roles.map((r) => badge(r, "blue")).join(" ")}</dd><dt>Fleet administration</dt><dd>${state.data.admin ? "Allowed" : "Not granted"}</dd><dt>Session expiry</dt><dd>${h(when(state.data.session_expires))}</dd><dt>Access changes</dt><dd>Managed through the identity provider and protected deployment configuration.</dd></dl></div>`)}${panel("Scheduler", "Approved sessions authorize bounded rollout execution.", `<div class="panel-body"><dl class="facts"><dt>Last reconciliation</dt><dd>${h(when(state.data.scheduler.last_tick))}</dd><dt>Status</dt><dd>${state.data.scheduler.error ? badge("Needs attention", "bad") : state.data.scheduler.last_tick ? badge("Running", "good") : badge("Starting", "warn")}</dd><dt>Run lifetime</dt><dd>Up to one hour, limited by the approving session</dd><dt>Concurrency</dt><dd>Up to 16 endpoints per run</dd><dt>Recovery custody</dt><dd>Fleet records share the encrypted management database backup. Verify full restore separately.</dd></dl>${state.data.scheduler.error ? `<p class="danger-text">${h(state.data.scheduler.error)}</p>` : ""}</div>`)}</div>${panel("Prerequisites requiring attention", "Reported capabilities, not assumed installation success", missing.length ? missing.map((d) => `<div class="list-item"><span class="status-dot warn"></span><div class="grow"><strong>${h(d.name)}</strong><p>${h(!d.worker_ready ? "Management worker unavailable" : [d.capabilities.features?.npcap_driver_installed === false ? "Npcap capture driver missing" : "", d.capabilities.features?.packages === false ? "Package manager unavailable under worker identity" : ""].filter(Boolean).join(" · "))}</p></div>${button("Open device", "open-device", d.id, "small")}</div>`).join("") : empty("No reported prerequisite gaps", "Only dependencies reported by current workers are evaluated."))}`;
  }
  function bindPage() {
    $("search")?.addEventListener("input", (e) => {
      state.query = e.target.value;
      state.offset = 0;
      clearTimeout(bindPage.timer);
      bindPage.timer = setTimeout(() => {
        if (state.page !== "devices" || !$("search")) return;
        const start = $("search")?.selectionStart;
        render();
        $("search").focus();
        $("search").setSelectionRange(start, start);
      }, 220);
    });
    for (const [id, key] of [
      ["filter-platform", "platform"],
      ["filter-health", "health"],
      ["filter-group", "group"],
    ])
      $(id)?.addEventListener("change", (e) => {
        state[key] = e.target.value;
        state.offset = 0;
        render();
      });
    $("history")?.addEventListener("change", (e) => {
      state.history = e.target.checked;
      state.offset = 0;
      render();
    });
    $("alert-filter")?.addEventListener("change", (e) => {
      state.alertFilter = e.target.value;
      render();
    });
    $("saved-view")?.addEventListener("change", (e) => {
      const v = records("view").find((r) => r.id === e.target.value)?.value;
      if (v) {
        Object.assign(state, {
          query: v.query,
          group: v.group,
          health: v.health,
          platform: v.platform,
          offset: 0,
        });
        render();
      }
    });
    document.querySelectorAll("[data-select]").forEach((input) =>
      input.addEventListener("change", () => {
        input.checked
          ? state.selected.add(input.dataset.select)
          : state.selected.delete(input.dataset.select);
        render();
      }),
    );
    $("select-page")?.addEventListener("change", (e) => {
      filtered()
        .slice(state.offset, state.offset + 25)
        .filter((d) => d.lifecycle === "active")
        .forEach((d) =>
          e.target.checked
            ? state.selected.add(d.id)
            : state.selected.delete(d.id),
        );
      render();
    });
    document.querySelectorAll("[data-sort]").forEach((b) =>
      b.addEventListener("click", () => {
        state.descending =
          state.sort === b.dataset.sort ? !state.descending : false;
        state.sort = b.dataset.sort;
        render();
      }),
    );
  }
  function field(name, label, value = "", options = {}) {
    const type = options.type || "text",
      full = options.full ? " full" : "";
    let input =
      type === "select"
        ? `<select name="${h(name)}">${selectOptions(options.options, value)}</select>`
        : type === "textarea"
          ? `<textarea name="${h(name)}" ${options.required ? "required" : ""}>${h(value)}</textarea>`
          : type === "checkbox"
            ? `<input name="${h(name)}" type="checkbox" ${value ? "checked" : ""}>`
            : `<input name="${h(name)}" type="${h(type)}" value="${h(value)}" ${options.required ? "required" : ""} ${options.min !== undefined ? `min="${options.min}"` : ""} ${options.max !== undefined ? `max="${options.max}"` : ""} maxlength="${options.maxlength || 4096}">`;
    return `<label class="field${full}">${h(label)}${input}${options.help ? `<small>${h(options.help)}</small>` : ""}</label>`;
  }
  let submitEditor = null;
  function editor(title, fields, callback, label = "Save changes") {
    $("editor-title").textContent = title;
    $("editor-fields").innerHTML = fields;
    $("editor-error").textContent = "";
    $("editor-form").querySelector("[type=submit]").textContent = label;
    submitEditor = callback;
    $("editor").showModal();
  }
  function commonPolicy(v = {}) {
    const window = v.window || {
      days: [0, 1, 2, 3, 4, 5, 6],
      start: "00:00",
      end: "00:00",
    };
    return (
      field("name", "Policy name", v.name || "", { required: true }) +
      field("action", "Operation", v.action || "posture", {
        type: "select",
        options: Object.entries(state.data.actions),
      }) +
      field("platform", "Platform", v.platform || "all", {
        type: "select",
        options: [
          ["all", "Windows and Linux"],
          ["windows", "Windows"],
          ["linux", "Linux"],
        ],
      }) +
      field("group", "Target group", v.group || "", {
        type: "select",
        options: groups(),
      }) +
      '<div id="action-params" class="field full"></div>' +
      field("concurrency", "Concurrent devices", v.concurrency ?? 3, {
        type: "number",
        min: 1,
        max: 16,
      }) +
      field("canary", "Canary devices", v.canary ?? 1, {
        type: "number",
        min: 1,
        max: 10,
      }) +
      field("failure_limit", "Stop after failures", v.failure_limit ?? 1, {
        type: "number",
        min: 1,
        max: 100,
      }) +
      field(
        "review_canary",
        "Pause for canary review",
        v.review_canary ?? true,
        { type: "checkbox" },
      ) +
      field("days", "Days (0 = Monday, 6 = Sunday)", window.days.join(","), {
        help: "Comma-separated days. Maintenance times use UTC.",
      }) +
      field("window_start", "Window starts (UTC)", window.start, {
        type: "time",
      }) +
      field("window_end", "Window ends (UTC)", window.end, {
        type: "time",
        help: "Matching start and end means all day on the selected days.",
      })
    );
  }
  function actionParams(action, params = {}) {
    let content = "";
    if (
      ["package.install", "package.remove", "service.control"].includes(action)
    )
      content += field(
        "param_name",
        action === "service.control" ? "Service name" : "Package identifier",
        params.name || "",
        { required: true },
      );
    if (action === "service.control")
      content += field(
        "param_operation",
        "Service action",
        params.operation || "restart",
        {
          type: "select",
          options: [
            ["start", "Start"],
            ["stop", "Stop"],
            ["restart", "Restart"],
          ],
        },
      );
    if (action === "reboot")
      content += field(
        "param_delay",
        "Restart delay (seconds)",
        params.delay ?? 60,
        { type: "number", min: 30, max: 300 },
      );
    if (["script.run", "update.install"].includes(action))
      content += field(
        "param_json",
        action === "script.run"
          ? "Reviewed script ID, version and inputs"
          : "Signed release parameters",
        JSON.stringify(params, null, 2),
        {
          type: "textarea",
          full: true,
          help: "Use the reviewed script or signed release catalog from a device's System tools. The server validates the exact contract.",
        },
      );
    $("action-params").innerHTML =
      content ||
      '<small class="subtle">This operation has no additional parameters.</small>';
  }
  function readPolicy(form) {
    const v = Object.fromEntries(new FormData(form)),
      action = v.action;
    let params = {};
    if (v.param_name !== undefined) params.name = v.param_name;
    if (v.param_operation !== undefined) params.operation = v.param_operation;
    if (v.param_delay !== undefined) params.delay = Number(v.param_delay);
    if (v.param_json !== undefined) params = JSON.parse(v.param_json);
    return {
      name: v.name,
      action,
      params,
      platform: v.platform,
      group: v.group,
      concurrency: Number(v.concurrency),
      canary: Number(v.canary),
      failure_limit: Number(v.failure_limit),
      review_canary: form.elements.review_canary.checked,
      window: {
        days: v.days.split(",").map((s) => Number(s.trim())),
        start: v.window_start,
        end: v.window_end,
      },
    };
  }
  function editRecord(kind, id = "", preset = {}) {
    const record = records(kind).find((r) => r.id === id),
      v = record?.value || preset;
    let fields = field("name", "Name", v.name || "", { required: true });
    if (kind === "group")
      fields +=
        field("parent", "Parent group", v.parent || "", {
          type: "select",
          options: [
            ["", "No parent"],
            ...records("group")
              .filter((r) => r.id !== id)
              .map((r) => [r.id, r.value.name]),
          ],
        }) +
        field("description", "Description", v.description || "", {
          type: "textarea",
          full: true,
        });
    if (kind === "policy") fields = commonPolicy(v);
    if (kind === "automation")
      fields +=
        field("policy", "Policy", v.policy || records("policy")[0]?.id || "", {
          type: "select",
          options: records("policy").map((r) => [r.id, r.value.name]),
        }) +
        field("group", "Target group", v.group || "", {
          type: "select",
          options: groups(),
        }) +
        field("interval", "Repeat every (minutes)", (v.interval || 3600) / 60, {
          type: "number",
          min: 5,
          max: 10080,
        }) +
        field("enabled", "Enabled", v.enabled || false, {
          type: "checkbox",
          help: "Enabled automations still require an approved, time-limited run.",
        });
    if (kind === "exercise")
      fields +=
        field("status", "Status", v.status || "planned", {
          type: "select",
          options: ["planned", "running", "review", "closed"].map((x) => [
            x,
            x,
          ]),
        }) +
        field("technique", "Technique / scenario", v.technique || "") +
        field("description", "Exercise objective", v.description || "", {
          type: "textarea",
          full: true,
        }) +
        field("outcome", "Observed outcome", v.outcome || "", {
          type: "textarea",
          full: true,
        });
    if (kind === "rule")
      fields +=
        field("condition", "Condition", v.condition || "offline", {
          type: "select",
          options: [
            "offline",
            "worker_missing",
            "capture_dependency",
            "package_dependency",
            "recovery_missing",
            "job_failed",
            "baseline_drift",
          ].map((x) => [x, x.replaceAll("_", " ")]),
        }) +
        field("severity", "Severity", v.severity || "warning", {
          type: "select",
          options: ["info", "warning", "critical"].map((x) => [x, x]),
        }) +
        field("group", "Target group", v.group || "", {
          type: "select",
          options: groups(),
        }) +
        field(
          "delay",
          "Condition duration before alert (seconds)",
          v.delay ?? 120,
          { type: "number", min: 0, max: 86400 },
        ) +
        field(
          "escalate",
          "Escalate warning after (minutes)",
          (v.escalate || 3600) / 60,
          { type: "number", min: 1, max: 10080 },
        ) +
        field("enabled", "Enabled", v.enabled ?? true, { type: "checkbox" });
    editor((id ? "Edit " : "Create ") + kind, fields, async (form) => {
      let value =
        kind === "policy"
          ? readPolicy(form)
          : Object.fromEntries(new FormData(form));
      if (kind === "automation") {
        value.interval = Number(value.interval) * 60;
        value.enabled = form.elements.enabled.checked;
      }
      if (kind === "rule") {
        value.delay = Number(value.delay);
        value.escalate = Number(value.escalate) * 60;
        value.enabled = form.elements.enabled.checked;
      }
      await api("save", {
        kind,
        id: id || undefined,
        revision: record?.revision || 0,
        value,
      });
      notify("Changes saved");
    });
    if (kind === "policy") {
      actionParams(v.action || "posture", v.params || {});
      $("editor-form").elements.action.addEventListener("change", (e) =>
        actionParams(e.target.value),
      );
    }
  }
  function bulk(preset = {}) {
    editor(
      "Run a fleet operation",
      commonPolicy({ name: "Fleet operation", ...preset }) +
        field("exercise", "Link to exercise", "", {
          type: "select",
          options: [
            ["", "No exercise"],
            ...records("exercise").map((r) => [r.id, r.value.name]),
          ],
        }),
      async (form) => {
        const policy = readPolicy(form);
        await makePreview(
          {
            operation: policy,
            endpoints: [...state.selected],
            exercise: form.elements.exercise.value,
          },
          false,
        );
      },
      "Preview targets",
    );
    actionParams(preset.action || "posture", preset.params || {});
    $("editor-form").elements.action.addEventListener("change", (e) =>
      actionParams(e.target.value),
    );
  }
  async function makePreview(value, show = true) {
    state.preview = await api("preview", value);
    const p = state.preview;
    $("preview-content").innerHTML =
      `<div class="banner ${p.window_open ? "info" : ""}">${h(p.policy.name)} · ${h(state.data.actions[p.policy.action])}. ${p.window_open ? "Within the maintenance window." : "Will wait for the configured maintenance window."}</div><p>${p.targets.length} eligible devices · ${p.excluded.length} excluded · ${p.policy.canary} canary · Stop after ${p.policy.failure_limit} failure(s).</p><p class="subtle">Approval lasts up to one hour and ends with your authenticated session. Targets and enrollment identities are fixed by this preview.</p><div class="table-scroll"><table><thead><tr><th>Device</th><th>Platform</th><th>Outcome</th></tr></thead><tbody>${p.targets.map((r, i) => `<tr><td>${h(r.name)}</td><td>${h(r.platform)}</td><td>${badge(i < p.policy.canary ? "Canary" : "Eligible", i < p.policy.canary ? "blue" : "good")}</td></tr>`).join("")}${p.excluded.map((r) => `<tr><td>${h(r.name)}</td><td>—</td><td>${h(r.reason)}</td></tr>`).join("")}</tbody></table></div>`;
    $("approve-run").disabled = !p.targets.length;
    if (show) $("preview").showModal();
  }
  function mountInspection(pane, device) {
    let data = null, category = "services", run = "", pending = false, error = "", query = "", offset = 0;
    let categories = {services:"Services"};
    const endpoint = `/remote/${encodeURIComponent(device.id)}/inspect`;
    const displayTime = value => value ? new Date(value).toLocaleString() : "Not collected";
    async function load(action = "") {
      if (pending) return;
      pending = true; error = ""; render();
      const controller = new AbortController();
      const close = () => controller.abort();
      const dialog = $("device-dialog");
      dialog.addEventListener("close", close, {once:true});
      const timeout = setTimeout(close, action ? 125000 : 30000);
      async function request(url, options = {}) {
        const response = await fetch(url, {credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,...options});
        if (!response.ok) throw new Error(response.status === 403
          ? "Your session or this form expired. Refresh results, or sign in again."
          : `The request could not be completed (${response.status}). Refresh results before trying again.`);
        if (!(response.headers.get("content-type") || "").includes("application/json"))
          throw new Error("Sign in again, then reopen this device.");
        return response.json();
      }
      try {
        const params = new URLSearchParams({category,format:"json"});
        if (action) {
          await request(`${endpoint}?${params}`, {method:"POST",body:new URLSearchParams({action,nonce:data.nonce,run:data.current?.id || ""})});
          if (action === "collect") run = "";
        }
        if (run) params.set("run", run);
        data = await request(`${endpoint}?${params}`); categories = data.categories;
        query = ""; offset = 0;
      } catch (e) {
        error = e.name === "AbortError"
          ? "The request timed out or was interrupted. Refresh results to check whether collection finished."
          : e.message;
      } finally {
        clearTimeout(timeout); dialog.removeEventListener("close", close);
        pending = false; render();
      }
    }
    function renderRows() {
      const host = pane.querySelector("[data-inspection-records]");
      if (!host) return;
      const all = data?.current?.result.records || [];
      const rows = all.filter(row => Object.values(row).some(value => String(value).toLowerCase().includes(query.toLowerCase())));
      const columns = [...new Set(all.flatMap(row => Object.keys(row)))].sort();
      if (offset >= rows.length) offset = 0;
      host.innerHTML = rows.length
        ? `<div class="table-scroll"><table><thead><tr>${columns.map(k=>`<th>${h(k.replaceAll("_"," "))}</th>`).join("")}</tr></thead><tbody>${rows.slice(offset,offset+50).map(row=>`<tr>${columns.map(k=>`<td>${h(row[k] ?? "—")}</td>`).join("")}</tr>`).join("")}</tbody></table></div><div class="inspection-pagination"><span>${offset+1}–${Math.min(offset+50,rows.length)} of ${rows.length} matching records</span><button class="button" data-record-prev ${offset ? "" : "disabled"}>Previous</button><button class="button" data-record-next ${offset+50 < rows.length ? "" : "disabled"}>Next</button></div>`
        : `<p class="empty">${data?.current ? "No records match this view." : "No saved results for this category. Collect a snapshot to see this device’s data."}</p>`;
      host.querySelector("[data-record-prev]")?.addEventListener("click",()=>{offset-=50;renderRows();});
      host.querySelector("[data-record-next]")?.addEventListener("click",()=>{offset+=50;renderRows();});
    }
    function render() {
      if (!pane.isConnected) return;
      const current = data?.current, result = current?.result;

      pane.innerHTML = `<div class="inspection-native">
        <div class="inspection-heading"><div><h2>Inventory & diagnostics</h2><p class="subtle">Saved device snapshots and changes over time. Collection uses the existing remote account.</p></div><div class="actions"><button class="button" data-inspection-refresh ${pending?"disabled":""}>Refresh results</button><button class="button primary" data-inspection-collect ${pending || !data || device.health!=="online" ? "disabled":""}>${pending?"Working…":"Collect snapshot"}</button></div></div>
        ${error?`<div class="banner" role="alert">${h(error)}</div>`:""}
        ${device.health!=="online"?'<div class="banner info">Device was offline at the last fleet refresh. Saved results are still available; refresh the workspace before collecting.</div>':""}
        <div class="inspection-controls"><label>Category<select data-inspection-category ${pending?"disabled":""}>${Object.entries(categories).map(([key,label])=>`<option value="${h(key)}" ${key===category?"selected":""}>${h(label)}</option>`).join("")}</select></label><label>Snapshot<select data-inspection-history ${pending?"disabled":""}><option value="">Latest result</option>${(data?.history || []).map(item=>`<option value="${h(item.id)}" ${item.id===run?"selected":""}>${h(displayTime(item.recorded))} · ${h(item.status)}</option>`).join("")}</select></label></div>
        <div role="status" aria-live="polite">${pending?'<p class="subtle">Loading device records…</p>':""}</div>
        ${result?`<div class="inspection-summary">${badge(result.status,tone(result.status))}<span>Collected ${h(displayTime(result.collected_at))}</span><span>${h(result.records.length)} records</span><span>Account: ${h(result.execution_identity || "Not reported")}</span><span>${h(result.duration_ms)} ms</span></div>${result.error?`<div class="banner">${h(result.error)}</div>`:""}<div class="actions"><button class="button" data-inspection-baseline ${pending || result.status!=="ok"?"disabled":""}>Save snapshot as baseline</button><a class="button" href="${endpoint}?${new URLSearchParams({category,run:current.id,download:"1"})}">Download JSON</a></div>`:""}
        ${data?.baseline?`<section class="inspection-comparison"><h3>Changes since baseline</h3><p class="subtle">Baseline saved ${h(displayTime(data.baseline.saved))}. Saving again replaces this category’s baseline. Changes can be normal system activity.</p>${data.comparison?Object.entries(data.comparison).map(([kind,change])=>`<details><summary>${h(kind)}: ${h(change.count)}</summary><pre class="code">${h(JSON.stringify(change.records,null,2))}</pre></details>`).join(""):'<p>Comparison requires a complete, successful snapshot.</p>'}</section>`:""}
        <section class="panel"><div class="panel-header"><h3>${h(categories[category] || category)}</h3><label>Search records<input type="search" data-inspection-search placeholder="Find a name, state or value" value="${h(query)}"></label></div><div data-inspection-records></div></section>
        <p class="section-note">Results reflect what the remote account can read. Saved snapshots remain available offline; they are not continuous monitoring or a complete persistence audit.</p>
      </div>`;
      pane.querySelector("[data-inspection-category]").onchange=e=>{category=e.target.value;run="";data=null;load();};
      pane.querySelector("[data-inspection-history]").onchange=e=>{run=e.target.value;load();};
      pane.querySelector("[data-inspection-refresh]").onclick=()=>load();
      pane.querySelector("[data-inspection-collect]").onclick=()=>load("collect");
      pane.querySelector("[data-inspection-baseline]")?.addEventListener("click",()=>load("baseline"));
      pane.querySelector("[data-inspection-search]").oninput=e=>{query=e.target.value;offset=0;renderRows();};
      renderRows();
    }
    load();
  }
  function openDevice(id, tab = "overview") {
    const d = devices().find((r) => r.id === id);
    if (!d) return;
    const dialog = $("device-dialog");
    $("device-title").textContent = d.name;
    $("device-subtitle").textContent =
      `${d.platform} · ${d.architecture} · ${d.health}`;
    const tabs = [
      ["overview", "Overview"],
      ...(d.permissions.includes("manage") ? [["manage", "System tools"]] : []),
      ...(d.permissions.includes("remote")
        ? [
            ["workspace", "SSH & files"],
            ["capture", "Network capture"],
            ["inspect", "Inventory & diagnostics"],
          ]
        : []),
    ];
    $("device-tabs").innerHTML = tabs
      .map(
        ([key, label]) =>
          `<button role="tab" id="tab-${h(key)}" data-device-tab="${h(key)}" aria-controls="pane-${h(key)}" aria-selected="false">${h(label)}</button>`,
      )
      .join("");
    const facts = [
      ["Device ID", d.id],
      ["Site", d.metadata.site || "Unassigned"],
      ["Owner", d.metadata.owner || "Unassigned"],
      ["Group", nameOf("group", d.metadata.group)],
      ["Last heartbeat", when(d.last_seen)],
      [
        "Management",
        d.worker_ready
          ? d.capabilities.execution_identity
          : "Worker unavailable",
      ],
      ["Agent version", d.capabilities.versions?.agent || "Not reported"],
      ["Worker version", d.capabilities.version || "Not installed"],
      ["Capture version", d.capabilities.versions?.wxlfgar || "Not reported"],
    ];
    $("device-body").innerHTML =
      `<section id="pane-overview" role="tabpanel" aria-labelledby="tab-overview"><div class="split">${panel("Device details", "", `<div class="panel-body"><dl class="facts">${facts.map(([k, v]) => `<dt>${h(k)}</dt><dd>${h(v)}</dd>`).join("")}</dl></div>`)}${panel("Baseline & context", "Snapshot compares reported versions and feature readiness.", `<div class="panel-body"><p class="subtle">${d.baseline ? `Saved ${h(when(d.baseline))}` : "No baseline saved yet"}</p>${d.changes.length ? `<pre class="code">${h(JSON.stringify(d.changes, null, 2))}</pre>` : "<p>No observed changes against a saved baseline.</p>"}<div class="actions">${d.permissions.includes("manage") ? button("Save current baseline", "baseline", d.id, "small") : ""}${state.data.admin ? button("Edit device details", "edit-device", d.id, "small") : ""}</div><p class="section-note">${h(d.metadata.notes || "")}</p></div>`)}</div><div class="actions"><a class="button" href="/endpoints/${h(d.id)}">Open full device record</a>${d.platform === "windows" && d.permissions.includes("remote") ? `<a class="button" href="/remote/${h(d.id)}/desktop.rdp">Download RDP connection</a>` : ""}</div></section>` +
      tabs
        .filter(([key]) => key !== "overview")
        .map(
          ([key]) =>
            `<section id="pane-${h(key)}" role="tabpanel" aria-labelledby="tab-${h(key)}" hidden></section>`,
        )
        .join("");
    function select(key) {
      for (const [name, label] of tabs) {
        const pane = $("pane-" + name),
          selected = name === key;
        pane.hidden = !selected;
        $("tab-" + name).setAttribute("aria-selected", String(selected));
        $("tab-" + name).tabIndex = selected ? 0 : -1;
        if (selected && name === "inspect" && !pane.dataset.nativeInspection) {
          pane.dataset.nativeInspection = "true";
          mountInspection(pane, d);
        }
        if (selected && name === "workspace" && !pane.dataset.remoteWorkspace) {
          pane.dataset.remoteWorkspace = "true";
          pane.innerHTML = `<div class="device-remote-grid"><section class="panel"><div class="panel-header"><div><h2>SSH terminal</h2><p>Connect using this device's saved SSH key.</p></div><a class="button small" target="_blank" rel="noopener" href="/remote/${h(d.id)}">Open separately</a></div><iframe title="SSH terminal — ${h(d.name)}" src="/remote/${h(d.id)}"></iframe></section><section class="panel"><div class="panel-header"><div><h2>Files & saved access</h2><p>Transfers go to NorthGateRMM-Ops.</p></div></div><iframe title="Files and saved access — ${h(d.name)}" src="/remote/${h(d.id)}/tools"></iframe></section></div>`;
        }
        if (selected && name === "workspace") pane.querySelectorAll("iframe").forEach(bindToolTheme);
        if (selected && !["overview", "inspect", "workspace"].includes(name) && !pane.querySelector("iframe")) {
          const iframe = document.createElement("iframe");
          iframe.title = label + " — " + d.name;
          iframe.src = `/remote/${d.id}/${name}`;
          bindToolTheme(iframe);
          pane.append(iframe);
        }
      }
    }
    $("device-tabs")
      .querySelectorAll("button")
      .forEach((b) =>
        b.addEventListener("click", () => select(b.dataset.deviceTab)),
      );
    $("device-tabs").onkeydown = (event) => {
      const keys = ["ArrowLeft", "ArrowRight", "Home", "End"];
      if (!keys.includes(event.key)) return;
      const index = tabs.findIndex(
        ([key]) => key === event.target.dataset.deviceTab,
      );
      if (index < 0) return;
      event.preventDefault();
      const next =
        event.key === "Home"
          ? 0
          : event.key === "End"
            ? tabs.length - 1
            : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) %
              tabs.length;
      select(tabs[next][0]);
      $("tab-" + tabs[next][0]).focus();
    };
    if (!dialog.open) dialog.showModal();
    select(tabs.some(([key]) => key === tab) ? tab : "overview");
  }
  function editDevice(id) {
    const d = devices().find((r) => r.id === id),
      v = d.metadata;
    editor(
      "Edit device details",
      field("name", "Display name", d.name, { required: true }) +
        field("group", "Device group", v.group || "", {
          type: "select",
          options: [
            ["", "Ungrouped"],
            ...records("group").map((r) => [r.id, r.value.name]),
          ],
        }) +
        field("site", "Site", v.site || "") +
        field("owner", "Responsible owner", v.owner || "") +
        field("criticality", "Criticality", v.criticality || "standard", {
          type: "select",
          options: ["standard", "important", "critical"].map((x) => [x, x]),
        }) +
        field("tags", "Tags", (v.tags || []).join(", "), {
          help: "Comma-separated labels",
        }) +
        field("notes", "Operational notes", v.notes || "", {
          type: "textarea",
          full: true,
        }),
      async (form) => {
        const value = Object.fromEntries(new FormData(form));
        value.tags = value.tags
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        await api("save", {
          kind: "asset",
          id,
          revision: d.metadata_revision || 0,
          value,
        });
        notify("Device details saved");
      },
    );
  }
  function download(name, value) {
    const blob = new Blob([JSON.stringify(value, null, 2)], {
        type: "application/json",
      }),
      url = URL.createObjectURL(blob),
      link = document.createElement("a");
    link.href = url;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }
  async function action(name, id) {
    if (name === "navigate") {
      location.hash = id;
      return;
    }
    if (name === "open-device") {
      openDevice(id);
      return;
    }
    if (name === "open-system") {
      openDevice(id, "manage");
      return;
    }
    if (name === "edit-device") {
      editDevice(id);
      return;
    }
    if (name === "create") {
      editRecord(id);
      return;
    }
    if (name === "edit") {
      const [kind, key] = id.split(":");
      editRecord(kind, key);
      return;
    }
    if (name === "view-group") {
      state.group = id;
      location.hash = "devices";
      return;
    }
    if (name === "bulk") {
      bulk();
      return;
    }
    if (name === "new-patch") {
      editRecord("policy", "", {
        name: "Scheduled update scan",
        action: "patches.scan",
      });
      return;
    }
    if (name === "scan") {
      await makePreview({
        operation: {
          name: "Scan for updates",
          action: "patches.scan",
          params: {},
        },
        endpoints: [id],
      });
      return;
    }
    if (name === "clear-selection") {
      state.selected.clear();
      render();
      return;
    }
    if (name === "previous" || name === "next") {
      state.offset = Math.max(0, state.offset + (name === "next" ? 25 : -25));
      render();
      return;
    }
    if (name === "run-policy") {
      await makePreview({
        policy: id,
        group: records("policy").find((r) => r.id === id).value.group,
      });
      return;
    }
    if (name === "arm") {
      const a = records("automation").find((r) => r.id === id);
      await makePreview({
        policy: a.value.policy,
        group: a.value.group,
        automation: id,
      });
      return;
    }
    if (name === "baseline") {
      await api("baseline", { endpoint: id });
      notify("Baseline saved from current worker data");
      await refresh();
      return;
    }
    if (["pause", "resume", "cancel"].includes(name)) {
      const r = records("rollout").find((r) => r.id === id);
      await api("run-control", { id, action: name, revision: r.revision });
      notify("Run updated");
      await refresh();
      return;
    }
    if (name === "delete") {
      const [kind, key] = id.split(":"),
        r = records(kind).find((r) => r.id === key);
      editor(
        "Delete " + r.value.name,
        `<p class="field full">Remove this ${h(kind)}? Dependent records must be reassigned first. Existing rollout snapshots are retained.</p>`,
        async () => {
          await api("delete", { kind, id: key, revision: r.revision });
          notify("Record deleted");
        },
        "Delete record",
      );
      return;
    }
    if (name === "save-view") {
      editor(
        "Save inventory view",
        field("name", "View name", "", { required: true }),
        async (form) => {
          await api("save", {
            kind: "view",
            value: {
              name: form.elements.name.value,
              query: state.query,
              platform: state.platform,
              health: state.health,
              group: state.group,
            },
          });
          notify("View saved");
        },
      );
      return;
    }
    if (name === "assign-group") {
      editor(
        "Assign selected devices",
        field("group", "Device group", "", {
          type: "select",
          options: [
            ["", "Ungrouped"],
            ...records("group").map((r) => [r.id, r.value.name]),
          ],
        }),
        async (form) => {
          let count = 0;
          for (const id of state.selected) {
            const d = devices().find((r) => r.id === id);
            const saved = await api("save", {
              kind: "asset",
              id,
              revision: d.metadata_revision || 0,
              value: { ...d.metadata, group: form.elements.group.value },
            });
            d.metadata = saved.value;
            d.metadata_revision = saved.revision;
            state.selected.delete(id);
            count++;
          }
          notify(`${count} devices assigned`);
        },
      );
      return;
    }
    if (name === "edit-alert") {
      const r = records("alert").find((r) => r.id === id);
      editor(
        "Update alert",
        field("state", "Status", r.value.state, {
          type: "select",
          options: ["open", "acknowledged", "snoozed", "resolved"].map((s) => [
            s,
            s,
          ]),
        }) +
          field("minutes", "Snooze duration (minutes)", 60, {
            type: "number",
            min: 1,
            max: 1440,
          }) +
          field("note", "Triage note", r.value.note || "", {
            type: "textarea",
            full: true,
          }),
        async (form) => {
          await api("alert", {
            id,
            revision: r.revision,
            state: form.elements.state.value,
            note: form.elements.note.value,
            seconds: Number(form.elements.minutes.value) * 60,
          });
          notify("Alert updated");
        },
      );
      return;
    }
    if (name === "rules") {
      editor(
        "Alert rules",
        `<div class="field full">${records("rule")
          .map(
            (r) =>
              `<div class="list-item"><div class="grow"><strong>${h(r.value.name)}</strong><p>${h(r.value.condition.replaceAll("_", " "))} · ${r.value.delay}s threshold</p></div>${badge(r.value.enabled ? "Enabled" : "Disabled", r.value.enabled ? "good" : "")}${button("Edit", "edit-rule", r.id, "small")}</div>`,
          )
          .join(
            "",
          )}${button("Add rule", "create-rule", "", "small primary")}</div>`,
        async () => {},
        "Done",
      );
      return;
    }
    if (name === "edit-rule" || name === "create-rule") {
      $("editor").close();
      editRecord("rule", name === "edit-rule" ? id : "");
      return;
    }
    if (name === "run-detail") {
      const r = records("rollout").find((r) => r.id === id),
        v = r.value;
      editor(
        v.name,
        `<div class="field full"><p>${badge(v.state, tone(v.state))} · Approved until ${h(when(v.expires))}</p><div class="table-scroll"><table><thead><tr><th>Target</th><th>Job reference</th><th>Dispatch issue</th></tr></thead><tbody>${v.targets.map((d) => `<tr><td>${h(d.name)}</td><td>${h(v.jobs[d.id] || "Not dispatched")}</td><td>${h(v.errors[d.id] || "—")}</td></tr>`).join("")}</tbody></table></div>${v.errors.authorization ? `<p class="danger-text">${h(v.errors.authorization)}</p>` : ""}<p class="subtle">Open the device's System tools for individual job results and protected output.</p></div>`,
        async () => {},
        "Done",
      );
      return;
    }
    if (name === "export-devices") {
      download("northgate-inventory.json", {
        generated: state.data.server_time,
        devices: filtered().map((d) => ({
          id: d.id,
          name: d.name,
          platform: d.platform,
          health: d.health,
          last_seen: d.last_seen,
          site: d.metadata.site,
          group: d.metadata.group,
          tags: d.metadata.tags,
        })),
      });
      return;
    }
    if (name === "export-exercise" || name === "export-evidence") {
      const value = await api("export", {
        exercise: name === "export-exercise" ? id : "",
      });
      download("northgate-evidence.json", value);
      notify("Evidence exported with a SHA-256 integrity reference");
      return;
    }
  }
  document.addEventListener("click", async (event) => {
    const close = event.target.closest(".close-dialog");
    if (close) {
      close.closest("dialog").close();
      return;
    }
    const target = event.target.closest("[data-action]");
    if (!target || state.busy) return;
    state.busy = true;
    target.disabled = true;
    try {
      await action(target.dataset.action, target.dataset.id);
    } catch (error) {
      notify(error.message);
    } finally {
      state.busy = false;
      if (target.isConnected) target.disabled = false;
    }
  });
  $("editor-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.target.querySelector("[type=submit]");
    if (submit.disabled) return;
    submit.disabled = true;
    $("editor-error").textContent = "";
    try {
      await submitEditor(event.target);
      $("editor").close();
      if (
        state.preview &&
        !$("preview").open &&
        submit.textContent === "Preview targets"
      )
        $("preview").showModal();
      await refresh();
    } catch (error) {
      $("editor-error").textContent = error.message;
    } finally {
      submit.disabled = false;
    }
  });
  $("approve-run").addEventListener("click", async () => {
    const button = $("approve-run");
    button.disabled = true;
    try {
      await api("start", { preview: state.preview.id, seconds: 3600 });
      $("preview").close();
      state.preview = null;
      location.hash = "jobs";
      notify("Rollout approved. Watch the canary and activity status.");
      await refresh();
    } catch (error) {
      notify(error.message);
    } finally {
      button.disabled = false;
    }
  });
  $("device-dialog").addEventListener("close", () => {
    if (!$("device-dialog").open) $("device-body").replaceChildren();
  });
  $("refresh").addEventListener("click", () => refresh(true));
  $("menu-toggle").addEventListener("click", () => {
    const open = document.querySelector(".rail").classList.toggle("open");
    $("menu-toggle").setAttribute("aria-expanded", String(open));
  });
  try {
    const theme = localStorage.getItem("northgate-theme");
    if (theme === "dark") document.documentElement.dataset.theme = "dark";
  } catch {
    /* Storage is optional; no server state depends on it. */
  }
  function bindToolTheme(iframe) {
    if (iframe.dataset.themeBound) return;
    iframe.dataset.themeBound = "true";
    iframe.addEventListener("load", () => syncToolTheme(iframe));
    syncToolTheme(iframe);
  }
  function syncToolTheme(iframe) {
    try {
      const root = iframe.contentDocument?.documentElement;
      if (root) root.dataset.theme = document.documentElement.dataset.theme || "light";
    } catch { /* A redirected sign-in page keeps its own appearance. */ }
  }
  $("theme").addEventListener("click", () => {
    const theme =
      document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = theme;
    $("device-body").querySelectorAll("iframe").forEach(syncToolTheme);
    try {
      localStorage.setItem("northgate-theme", theme);
    } catch {}
  });
  function navigate() {
    clearTimeout(bindPage.timer);
    const page = location.hash.slice(1) || "overview";
    state.page = pages[page] ? page : "overview";
    document.querySelector(".rail").classList.remove("open");
    $("menu-toggle").setAttribute("aria-expanded", "false");
    render();
  }
  addEventListener("hashchange", navigate);
  navigate();
  refresh();
  setInterval(() => {
    if (!document.hidden) refresh();
  }, 30000);
})();
