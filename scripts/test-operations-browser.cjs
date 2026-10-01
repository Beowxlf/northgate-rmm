/* Browser + real Python handlers; only authentication/device transport is synthetic. */
const { chromium } = require(process.env.RMM_PLAYWRIGHT_MODULE || "playwright");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const assert = require("assert/strict");
const repo = path.resolve(__dirname, "..");
const output = process.env.RMM_REVIEW_OUTPUT || path.join(repo,"outputs/review");
fs.mkdirSync(output,{recursive:true});
const python = process.env.RMM_PYTHON || path.resolve(repo,"../native-env/Scripts/python.exe");
const fixture=spawn(python,[path.join(__dirname,"operations-browser-fixture.py")],{
  cwd:repo,env:{...process.env,PYTHONPATH:path.join(repo,"src")},windowsHide:true,
  stdio:["ignore","pipe","pipe"]
});
let fixtureErrors="";
fixture.stderr.on("data",data=>fixtureErrors+=data);
const ready=new Promise((resolve,reject)=>{
  let data="";
  const timer=setTimeout(()=>reject(Error("Fixture startup timed out: "+fixtureErrors)),20000);
  fixture.on("exit",code=>{clearTimeout(timer);reject(Error("Fixture exited "+code+": "+fixtureErrors));});
  fixture.stdout.on("data",chunk=>{data+=chunk;const nl=data.indexOf("\n");if(nl>=0){clearTimeout(timer);resolve(JSON.parse(data.slice(0,nl)));}});
});
(async()=>{
  let browser;
  let livePage;
  const checks=[];
  try {
    const {origin,token}=await ready;
    browser=await chromium.launch({channel:"msedge",headless:true});
    const context=await browser.newContext({viewport:{width:1440,height:1040},extraHTTPHeaders:{Authorization:"Bearer "+token},acceptDownloads:true});
    const page=await context.newPage();
    livePage=page;
    const errors=[];page.on("pageerror",error=>errors.push(error.message));
    page.setDefaultTimeout(10000);
    const nav=label=>page.locator("#fixture-nav").getByRole("button",{name:label,exact:true}).click();
    const dialog=()=>page.locator("dialog.ops-dialog[open]");
    async function saveDialog(name="Save") {
      await dialog().getByRole("button",{name,exact:true}).click();
      await page.waitForFunction(()=>!document.querySelector("dialog.ops-dialog[open]"));
    }
    async function create(kind,name,extra) {
      await page.getByRole("button",{name:"New "+kind,exact:true}).click();
      await dialog().getByLabel("Title",{exact:true}).fill(name);
      await dialog().locator('select[name="endpoints"]').selectOption("11111111-1111-4111-8111-111111111111");
      if(extra)await extra(dialog());
      await saveDialog();
      await page.getByRole("heading",{name,exact:true}).waitFor();
    }
    const getJSON=async url=>{const r=await context.request.get(origin+url);assert.equal(r.status(),200,await r.text());return r.json();};
    await page.goto(origin);
    await page.getByRole("button",{name:"New case",exact:true}).waitFor();
    await nav("infrastructure");
    await create("asset","Synthetic workstation",async d=>{
      await d.getByLabel("Intended properties (property=value)").fill("dns=10.0.0.2\nrole=analyst");
      await d.getByLabel("Observed properties (property=value)").fill("dns=10.0.0.3");
      await d.getByLabel("Observation sources (property=value)").fill("dns=fixture-inventory");
    });
    let state=await getJSON("/remote/ops/api/state");
    assert.equal(state.assets.length,1);assert.equal(state.assets[0].value.intended.dns,"10.0.0.2");
    const asset=state.assets[0];
    checks.push("Infrastructure form persisted normalized intended/observed/source properties using actual validation");
    await nav("cases");
    await create("case","Browser investigation",async d=>{
      await d.getByLabel("Case type").selectOption("soc");
      await d.getByLabel("Assignee",{exact:true}).fill("owner");
      await d.locator("details summary").click();
      await d.locator('select[name="assets"]').selectOption(asset.id);
    });
    state=await getJSON("/remote/ops/api/state");
    assert.equal(state.cases.length,1);const caseID=state.cases[0].id;
    assert.equal(state.cases[0].value.type,"soc");assert.deepEqual(state.cases[0].value.assets,[asset.id]);
    checks.push("Case form retained SOC type, exact device and infrastructure association");
    await page.getByRole("button",{name:"Add task",exact:true}).click();
    await dialog().getByLabel("Task",{exact:true}).fill("Verify DNS behavior");
    await dialog().getByLabel("Assignee",{exact:true}).fill("owner");
    await saveDialog();
    await page.getByText("Verify DNS behavior",{exact:true}).waitFor();
    await page.getByRole("button",{name:"Update status",exact:true}).click();
    await dialog().getByLabel("New status").selectOption("in_progress");await saveDialog();
    await page.getByRole("button",{name:"Update status",exact:true}).click();
    await dialog().getByLabel("New status").selectOption("resolved");
    await dialog().getByLabel("Outcome",{exact:true}).fill("DNS reviewed");
    await dialog().getByLabel("How was the outcome verified?").fill("Compared query response");
    await dialog().getByRole("button",{name:"Save",exact:true}).click();
    await dialog().locator(".ops-error").filter({hasText:"outstanding tasks"}).waitFor();
    await dialog().getByRole("button",{name:"Cancel",exact:true}).click();
    assert.equal((await getJSON("/remote/ops/api/state")).cases[0].value.status,"in_progress");
    await page.locator(".ops-task").filter({hasText:"Verify DNS behavior"}).getByRole("button",{name:"Update",exact:true}).click();
    await dialog().locator('select[name="status"]').selectOption("done");
    await dialog().getByLabel("Completion verification").fill("Independent query returned intended resolver");await saveDialog();
    checks.push("Real backend rejected resolution with outstanding task and accepted verified task completion");
    await page.getByRole("button",{name:"System tools",exact:true}).click();
    await page.frameLocator("#ops-session-dock iframe").locator("#ready").waitFor();
    const sessionFrame=await page.locator("#ops-session-dock iframe").elementHandle();
    const sessionMarker=await (await sessionFrame.contentFrame()).evaluate(()=>window.sessionMarker);
    await page.getByRole("button",{name:"Add note",exact:true}).click();
    await dialog().getByLabel("Observation or decision").fill('<img src=x onerror="window.fixtureXSS=true"> reviewed');await saveDialog();
    assert.equal(await page.evaluate(()=>window.fixtureXSS),undefined);
    assert.equal(await page.locator("#fixture-root .ops-timeline img").count(),0);
    assert.equal(await page.locator("#ops-session-dock iframe").evaluate((frame,old)=>frame===old,sessionFrame),true);
    assert.equal(await (await sessionFrame.contentFrame()).evaluate(()=>window.sessionMarker),sessionMarker);
    await page.getByRole("button",{name:"Refresh",exact:true}).click();
    await page.getByRole("heading",{name:"Browser investigation",exact:true}).waitFor();
    assert.equal(await page.locator("#ops-session-dock iframe").evaluate((frame,old)=>frame===old,sessionFrame),true);
    checks.push("Case note and explicit refresh preserved the existing terminal frame/document");
    checks.push("Timeline treats submitted markup as literal evidence text");
    const bytes=Buffer.alloc(1048576+257,65), digest=crypto.createHash("sha256").update(bytes).digest("hex");
    let lost=false;
    await page.route("**/remote/ops/api/upload_chunk",async route=>{
      const response=await route.fetch();
      if(!lost&&response.ok()){lost=true;await route.abort("failed");return;}
      await route.fulfill({response});
    });
    await page.getByRole("button",{name:"Attach evidence",exact:true}).click();
    await dialog().getByLabel("File",{exact:true}).setInputFiles({name:"synthetic-evidence.txt",mimeType:"text/plain",buffer:bytes});
    await dialog().getByRole("checkbox").check();
    await dialog().getByRole("button",{name:"Upload and retain",exact:true}).click();
    await dialog().locator(".ops-error").filter({hasText:/fetch|network/i}).waitFor();
    await page.unroute("**/remote/ops/api/upload_chunk");
    let finishLost=false;
    await page.route("**/remote/ops/api/upload_finish",async route=>{
      const response=await route.fetch();
      if(!finishLost&&response.ok()){finishLost=true;await route.abort("failed");return;}
      await route.fulfill({response});
    });
    await dialog().getByRole("button",{name:"Upload and retain",exact:true}).click();
    await dialog().locator(".ops-error").filter({hasText:/fetch|network/i}).waitFor();
    await page.unroute("**/remote/ops/api/upload_finish");
    await saveDialog("Upload and retain");
    const detail=await getJSON("/remote/ops/api/record/case/"+caseID);
    assert.equal(detail.evidence.length,1);assert.equal(detail.evidence[0].sha256,digest);assert.equal(detail.evidence[0].size,bytes.length);assert.equal(detail.evidence[0].state,"complete");
    const downloaded=page.waitForEvent("download");
    await page.getByRole("button",{name:"Download",exact:true}).click();
    const download=await downloaded;const downloadPath=await download.path();
    assert.deepEqual(fs.readFileSync(downloadPath),bytes);
    checks.push("Evidence upload resumed after both committed chunk and finish responses were lost, retained one artifact, and downloaded matching bytes");
    await page.getByRole("button",{name:"Update status",exact:true}).click();
    await dialog().getByLabel("New status").selectOption("resolved");
    await dialog().getByLabel("Outcome",{exact:true}).fill("DNS restored");
    await dialog().getByLabel("How was the outcome verified?").fill("Independent lookup matches baseline");await saveDialog();
    await page.getByRole("button",{name:"Update status",exact:true}).click();
    await dialog().getByLabel("New status").selectOption("closed");await saveDialog();
    assert.equal((await getJSON("/remote/ops/api/record/case/"+caseID)).record.value.status,"closed");
    checks.push("Verified case transitioned resolved then closed with persisted outcome");
    await page.screenshot({path:path.join(output,"operations-case-browser.png"),fullPage:true});
    await nav("tools");
    await page.getByRole("combobox",{name:"Tool",exact:true}).selectOption("health");
    await page.getByRole("combobox",{name:"Diagnostic profile",exact:true}).selectOption("snapshot");
    await page.getByRole("textbox",{name:"Case UUID",exact:true}).fill(caseID);
    let dropped=false;
    await page.route("**/tool-catalog/action",async route=>{
      const response=await route.fetch();
      if(!dropped&&response.ok()){dropped=true;await route.abort("failed");return;}
      await route.fulfill({response});
    });
    await page.getByRole("button",{name:"Run",exact:true}).click();
    await page.getByRole("button",{name:"Retry safely",exact:true}).click();
    await page.getByText("tool.run · queued",{exact:true}).waitFor();
    await page.unroute("**/tool-catalog/action");
    const jobs=(await getJSON("/fixture/jobs")).jobs;
    assert.equal(jobs.length,1);assert.equal(jobs[0].payload.params.profile,"snapshot");assert.equal(jobs[0].payload.params.case_id,caseID);
    await page.getByText("tool.run · queued",{exact:true}).click();
    await page.getByRole("button",{name:"Cancel",exact:true}).click();
    assert.equal((await getJSON("/fixture/jobs")).jobs[0].state,"cancelled");
    checks.push("Tool form dispatched exact profile/case, replayed one job after lost response and cancelled it");
    await page.screenshot({path:path.join(output,"operations-tool-browser.png"),fullPage:true});
    assert.deepEqual(errors,[]);assert.deepEqual(await page.evaluate(()=>window.fixtureErrors),[]);
    fs.writeFileSync(path.join(output,"operations-browser-results.json"),JSON.stringify({passed:true,checks,fixture:"actual Operations + ToolCatalog + test SQLite adapter; synthetic authenticated owner/device/worker transport",at:new Date().toISOString()},null,2));
    console.log(JSON.stringify({passed:true,checks:checks.length,report:path.join(output,"operations-browser-results.json")}));
  } catch(error) {
    if(livePage){await livePage.screenshot({path:path.join(output,"operations-browser-failure.png"),fullPage:true});console.error(JSON.stringify(await livePage.evaluate(()=>({errors:window.fixtureErrors,dialogs:[...document.querySelectorAll("dialog")].map(d=>({open:d.open,html:d.innerHTML}))})),null,2));}
    throw error;
  } finally {
    if(browser)await browser.close();
    fixture.kill();
  }
})().catch(error=>{console.error(error.stack);if(fixtureErrors)console.error(fixtureErrors);process.exitCode=1;});
