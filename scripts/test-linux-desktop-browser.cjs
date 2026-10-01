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
    await page.clock.install();
    page.on("pageerror", (error) => errors.push(error.message));
    let fleetPolls = 0, failSecondAsset = false,
      assetSaves = 0;
    const inspectionCollected = new Set(["services"]), inspectionBaselines = new Set();
    let inspectionFailure = false;
    await page.route("https://operator.test/**", async (route) => {
      const request = route.request(),
        url = new URL(request.url());
      if (url.pathname === "/remote/fleet/api/state") {
        fleetPolls++;
        return route.fulfill({ json: state });
      }
      if (url.pathname === "/remote/ops/api/state")
        return route.fulfill({json:{cases:[],assets:[],services:[],networks:[],relationships:[],documents:[],changes:[],exercises:[],alerts:[],csrf:"fixture",capabilities:{"ops.view":true,"case.manage":true,"infrastructure.manage":true,"evidence.manage":true}}});
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
      if (["fleet.html", "fleet.js", "fleet.css", "operations_ui.js", "operations_ui.css", "tool_catalog_ui.js"].includes(name))
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
    state.devices.forEach(d => d.remote_methods = ["ssh", "rdp"]);
    for (const device of state.devices) {
      await page.goto("https://operator.test/remote/fleet/ui#devices");
      await page.locator(`[data-action="open-device"][data-id="${device.id}"]`).first().click();
      await page.getByRole("tab", {name:"Desktop", exact:true}).click();
      const frame = page.locator('#pane-desktop iframe');
      if (!(await frame.getAttribute('src')).endsWith(`/remote/${device.id}/desktop`)) throw Error('Wrong desktop target');
      await page.screenshot({path:path.join(output, `linux-rdp-${device.platform}.png`)});
    }
    state.devices[0].remote_methods = ["ssh"];
    await page.goto("https://operator.test/remote/fleet/ui#devices");
    await page.locator(`[data-action="open-device"][data-id="${state.devices[0].id}"]`).first().click();
    if (await page.getByRole("tab", {name:"Desktop",exact:true}).count()) throw Error('Unconfigured desktop offered');
    if(errors.length)throw Error(JSON.stringify(errors));
    console.log(JSON.stringify({passed:3,fixture:true,linuxDesktop:true,windowsDesktop:true,unconfiguredHidden:true}));
  } finally { await browser.close(); }
})().catch(error => {console.error(error);process.exitCode=1;});
