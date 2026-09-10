const { chromium } = require(process.env.RMM_PLAYWRIGHT_MODULE || "playwright");
const fs = require("fs");
const path = require("path");
const root = path.join(__dirname, "../src/northgate_rmm");
const output =
  process.env.RMM_REVIEW_OUTPUT || path.join(__dirname, "../outputs/review");
fs.mkdirSync(output, { recursive: true });
const now = Date.now() / 1000;
const errors = [];
const state = {
  devices: ["linux", "windows"].map((platform, i) => ({
    id: `11111111-1111-4111-8111-11111111111${i}`,
    identity: `22222222-2222-4222-8222-22222222222${i}`,
    name: i ? "Review Windows" : "Review Linux",
    platform,
    architecture: "amd64",
    lifecycle: "active",
    health: "online",
    last_seen: now,
    worker_ready: true,
    worker_seen: now,
    managed: true,
    permissions: ["remote", "manage", "patch", "recovery"],
    capabilities: {
      version: "fixture",
      execution_identity: i ? "SYSTEM" : "root",
      versions: { agent: "fixture", worker: "fixture", wxlfgar: "fixture" },
      features: { packages: true, npcap_driver_installed: true },
    },
    metadata: {},
    metadata_revision: 0,
    baseline: null,
    changes: [],
    last_job: null,
    recovery_receipts: [],
    snapshot: {},
  })),
  records: Object.fromEntries(
    [
      "group",
      "policy",
      "automation",
      "rule",
      "exercise",
      "view",
      "rollout",
      "alert",
    ].map((k) => [k, []]),
  ),
  csrf: "synthetic",
  subject: "Review owner",
  roles: ["viewer", "remote_operator", "recovery_operator"],
  admin: true,
  actions: {
    posture: "Collect security posture",
    "service.control": "Manage a service",
    "patches.scan": "Scan for updates",
  },
  server_time: now,
  session_expires: now + 3600,
  scheduler: { last_tick: now, error: null },
  limits: { preview_devices: 500, concurrency: 16, run_seconds: 3600 },
};
(async () => {
  const browser = await chromium.launch({ channel: "msedge", headless: true });
  try {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 1000 },
    });
    const page = await context.newPage();
    page.on("pageerror", (error) => errors.push(error.message));
    let failSecondAsset = false,
      assetSaves = 0;
    const inspectionCollected = new Set(["services"]), inspectionBaselines = new Set();
    let inspectionFailure = false;
    await page.route("https://operator.test/**", async (route) => {
      const request = route.request(),
        url = new URL(request.url());
      if (url.pathname === "/remote/fleet/api/state")
        return route.fulfill({ json: state });
      if (/^\/remote\/[^/]+\/inspect$/.test(url.pathname)) {
        const category = url.searchParams.get("category") || "services";
        if (inspectionFailure) {inspectionFailure = false;return route.fulfill({status:403,body:"Forbidden"});}
        if (request.method() === "POST") {
          const form = new URLSearchParams(request.postData());
          if (form.get("action") === "collect") inspectionCollected.add(category);
          if (form.get("action") === "baseline") inspectionBaselines.add(category);
          return route.fulfill({json:{saved:true}});
        }
        const current = inspectionCollected.has(category) ? {
          id:url.searchParams.get("run") || "current",recorded:new Date().toISOString(),
          result:{status:"ok",collected_at:new Date().toISOString(),execution_identity:"fixture account",duration_ms:10,error:"",
            records:Array.from({length:60},(_,i)=>({id:`service-${i}`,state:i ? "running" : '<img src=x onerror="alert(1)">'}))}
        } : null;
        return route.fulfill({json:{category,categories:{services:"Services",software:"Installed software"},nonce:"fixture nonce",current,
          history:current?[{id:"older",recorded:new Date().toISOString(),status:"ok"}]:[],
          baseline:inspectionBaselines.has(category)?{saved:new Date().toISOString()}:null,
          comparison:inspectionBaselines.has(category)?Object.fromEntries(["added","removed","changed"].map(k=>[k,{count:0,records:[]}])):null}});
      }
      if (url.pathname === "/remote/fleet/api/save") {
        const value = request.postDataJSON();
        if (value.kind === "asset") {
          assetSaves++;
          if (failSecondAsset && assetSaves === 2)
            return route.fulfill({
              status: 409,
              json: { error: "Synthetic concurrent edit" },
            });
          const d = state.devices.find((d) => d.id === value.id);
          if (value.revision !== d.metadata_revision)
            return route.fulfill({
              status: 409,
              json: { error: "Stale device revision" },
            });
          d.metadata = value.value;
          d.metadata_revision++;
          return route.fulfill({
            json: {
              id: d.id,
              revision: d.metadata_revision,
              value: d.metadata,
            },
          });
        }
        const r = {
          id: "33333333-3333-4333-8333-333333333333",
          revision: 1,
          value: value.value,
          subject: "Review owner",
          created: now,
          updated: now,
        };
        state.records[value.kind].push(r);
        return route.fulfill({ json: r });
      }
      const name =
        url.pathname === "/remote/fleet/ui"
          ? "fleet.html"
          : url.pathname.split("/").pop();
      if (["fleet.html", "fleet.js", "fleet.css"].includes(name))
        return route.fulfill({
          body: fs.readFileSync(path.join(root, name)),
          contentType: name.endsWith(".js")
            ? "text/javascript"
            : name.endsWith(".css")
              ? "text/css"
              : "text/html",
        });
      return route.fulfill({
        body: "<html><body>Isolated tool fixture</body></html>",
        contentType: "text/html",
      });
    });
    await page.goto("https://operator.test/remote/fleet/ui");
    await page.getByText("Review Linux", { exact: true }).first().waitFor();
    for (const tab of [
      "devices",
      "alerts",
      "groups",
      "policies",
      "automations",
      "patches",
      "jobs",
      "recovery",
      "exercises",
      "settings",
      "overview",
    ]) {
      await page.locator(`[data-page="${tab}"]`).click();
      await page.locator("#page-content").waitFor();
    }
    await page.locator('[data-page="groups"]').click();
    await page
      .locator('[data-action="create"][data-id="group"]')
      .first()
      .click();
    await page.locator('#editor-form [name="name"]').fill("Review group");
    await page.locator('#editor-form [type="submit"]').click();
    await page.getByRole("heading", { name: "Review group" }).waitFor();
    await page.locator('[data-page="devices"]').click();
    await page.locator("#select-page").check();
    await page.locator('[data-action="assign-group"]').click();
    failSecondAsset = true;
    await page.locator('#editor-form [type="submit"]').click();
    await page
      .locator("#editor-error")
      .filter({ hasText: "Synthetic concurrent edit" })
      .waitFor();
    failSecondAsset = false;
    await page.locator('#editor-form [type="submit"]').click();
    await page.waitForFunction(
      () => !document.querySelector("#editor-form [type=submit]").disabled,
    );
    const retryClosed = await page.locator("#editor").evaluate((e) => !e.open);
    if (!retryClosed)
      errors.push(
        "Bulk assignment cannot recover after a partial save: " +
          (await page.locator("#editor-error").innerText()),
      );
    if (!retryClosed)
      await page.locator("#editor .close-dialog").first().click();
    await page.locator("#search").fill("Review");
    await page.locator('[data-page="alerts"]').click();
    await page.waitForTimeout(350);
    await page.locator('[data-page="devices"]').click();
    await page.locator('[data-action="open-device"]').first().click();
    await page.getByRole("tab", { name: "System tools", exact: true }).click();
    await page.getByRole("tab", { name: "Overview", exact: true }).click();
    await page.getByRole("tab", { name: "System tools", exact: true }).click();
    if ((await page.locator("#device-body iframe").count()) !== 1)
      errors.push("Tool iframe duplicated");
    await page.getByRole("tab", {name:"Inventory & diagnostics",exact:true}).click();
    await page.locator("#pane-inspect tbody tr").first().waitFor();
    if (await page.locator("#pane-inspect iframe, #pane-inspect img").count()) throw Error("Nested frame or unescaped inspection content");
    if (await page.locator("#pane-inspect tbody tr").count() !== 50) throw Error("Native inventory page size");
    await page.locator("[data-record-next]").click();
    if (await page.locator("#pane-inspect tbody tr").count() !== 10) throw Error("Native inventory pagination");
    await page.locator("[data-inspection-search]").fill("service-59");
    if (await page.locator("#pane-inspect tbody tr").count() !== 1) throw Error("Native inventory search");
    await page.locator("[data-inspection-category]").selectOption("software");
    await page.getByText("No saved results for this category.",{exact:false}).waitFor();
    await page.locator("[data-inspection-collect]").click();
    await page.locator("#pane-inspect tbody tr").first().waitFor();
    await page.locator("[data-inspection-baseline]").click();
    await page.getByRole("heading",{name:"Changes since baseline"}).waitFor();
    await page.locator("[data-inspection-history]").selectOption("older");
    await page.waitForFunction(()=>!document.querySelector("[data-inspection-refresh]").disabled);
    inspectionFailure = true;
    await page.locator("[data-inspection-refresh]").click();
    await page.locator("#pane-inspect [role=alert]").waitFor();
    await page.locator("[data-inspection-refresh]").click();
    await page.waitForFunction(()=>!document.querySelector("[data-inspection-refresh]").disabled && !document.querySelector("#pane-inspect [role=alert]"));
    await page.screenshot({path:path.join(output,"RMM-native-inventory-desktop.png")});
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:path.join(output,"RMM-native-inventory-mobile.png")});
    if (await page.locator("#device-dialog").evaluate(e=>e.scrollWidth>e.clientWidth+1)) throw Error("Native device workspace horizontal overflow");
    await page.setViewportSize({width:1440,height:1000});
    await page.locator("#device-dialog .close-dialog").click();
    await page.locator("#theme").click();
    await page.screenshot({
      path: path.join(output, "RMM-review-desktop.png"),
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(200);
    if (
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      )
    )
      errors.push("Viewport has horizontal overflow");
    await page.locator("#menu-toggle").click();
    await page.locator('[data-page="alerts"]').click();
    await page.locator("#menu-toggle").click();
    await page.locator('[data-page="devices"]').click();
    await page.waitForTimeout(200);
    await page.screenshot({
      path: path.join(output, "RMM-review-mobile.png"),
      fullPage: true,
    });
    fs.writeFileSync(
      path.join(output, "RMM-review-browser.json"),
      JSON.stringify({ errors, assetSaves, fixture: true }, null, 2),
    );
    console.log(JSON.stringify({ errors, assetSaves }));
    if (errors.length) process.exitCode = 1;
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
