const fs=require('fs'),path=require('path'),assert=require('assert/strict');
const {chromium}=require(process.env.RMM_PLAYWRIGHT_MODULE||'playwright');
const output=process.env.RMM_REVIEW_OUTPUT||path.resolve(__dirname,'../../../outputs/tool-ux-review');
const fixtures=JSON.parse(fs.readFileSync(path.join(output,'fixtures.json'),'utf8'));
(async()=>{
 const browser=await chromium.launch({channel:'msedge',headless:true});
 const errors=[],actions=[],checks=[];let stateCalls=0;
 try{
  const page=await browser.newPage({viewport:{width:1300,height:950},colorScheme:'light'});
  page.on('pageerror',e=>errors.push(e.message));
  page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
  await page.route('https://operator.test/**',async route=>{
   const url=new URL(route.request().url()),name=url.pathname.split('/').pop();
   if(url.pathname==='/review')return route.fulfill({contentType:'text/html',body:`<html style="color-scheme:light"><body style="margin:0"><iframe title="tool" style="width:100%;height:940px;border:0" src="/remote/${fixtures.endpoint}/${url.searchParams.get('tool')}"></iframe></body></html>`});
   if(fixtures.pages[name]){const f=fixtures.pages[name],headers={...f.headers};delete headers['Content-Length'];return route.fulfill({status:200,headers,body:f.body});}
   let data={};
   if(name==='state'&&url.pathname.includes('/manage/'))data={worker:{ready:true,capabilities:{execution_identity:'NT AUTHORITY\\SYSTEM',version:'review'}},jobs:[]};
   else if(name==='action'){actions.push(route.request().postDataJSON());data={job:'synthetic-shell'};}
   else if(name==='io')data={state:'dispatched',frames:[{sequence:1,value:{data:Buffer.from('PS C:\\> whoami\r\nnt authority\\system\r\n').toString('base64')}}]};
   else if(name==='state'){stateCalls++;data=fixtures.job;}
   return route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
  });
  await page.goto('https://operator.test/review?tool=manage');
  const frame=page.frameLocator('iframe');
  await frame.locator('#connect-terminal').waitFor();
  await frame.getByRole('button',{name:'List services',exact:true}).click();
  assert.equal(actions.length,0);assert.equal(await frame.locator('#operation').inputValue(),'services.list');
  assert.equal(await frame.locator('#terminal-panel').getAttribute('open'),null);
  await frame.locator('#connect-terminal').click();
  await frame.locator('#terminal-state').filter({hasText:'dispatched'}).waitFor();
  assert.equal(actions[0].action,'shell.start');
  assert.notEqual(await frame.locator('#terminal-panel').getAttribute('open'),null);
  checks.push('Shortcut selects without dispatch; explicit connect starts shell and opens console');
  await page.screenshot({path:path.join(output,'system-tools-light.png'),fullPage:true});
  await frame.locator('html').evaluate(n=>n.dataset.theme='dark');
  await page.waitForTimeout(200);
  assert.equal(await frame.locator('body').evaluate(n=>getComputedStyle(n).backgroundColor),'rgb(16, 23, 34)');
  await page.screenshot({path:path.join(output,'system-tools-dark.png'),fullPage:true});
  checks.push('Embedded tool follows parent light/dark preference');
  await page.goto('https://operator.test/review?tool=tools');
  await frame.getByRole('heading',{name:'Send a file'}).waitFor();
  assert.equal(await frame.locator('body').textContent().then(t=>t.includes('synthetic-only')),false);
  assert.equal(await frame.getByLabel('File to upload').count(),1);
  await page.screenshot({path:path.join(output,'files-light.png'),fullPage:true});
  checks.push('Saved password stays hidden; upload destination and input visible');
  await page.goto('https://operator.test/review?tool=capture');
  await frame.locator('.capture-finding').waitFor();
  assert.equal(await frame.locator('.capture-finding img').count(),0);
  assert.equal(await frame.locator('.metric').count(),4);
  await frame.locator('details[data-section="assets"] > summary').click();
  await page.waitForTimeout(10500);
  assert.ok(stateCalls>=2);
  assert.notEqual(await frame.locator('details[data-section="assets"]').getAttribute('open'),null);
  checks.push('Capture metrics and escaped findings render; expanded infrastructure survives refresh');
  await page.screenshot({path:path.join(output,'capture-light.png'),fullPage:true});
  for(const tool of ['manage','tools','capture']){
   await page.setViewportSize({width:390,height:844});
   await page.goto('https://operator.test/review?tool='+tool);
   await frame.locator('body').waitFor();await page.waitForTimeout(250);
   assert.ok(await frame.locator('html').evaluate(n=>n.scrollWidth<=innerWidth),tool+' horizontal overflow');
   await page.screenshot({path:path.join(output,tool+'-mobile.png'),fullPage:true});
  }
  checks.push('All three tools fit narrow screens');
  assert.deepEqual(errors,[]);
  fs.writeFileSync(path.join(output,'tool-browser-results.json'),JSON.stringify({checks,errors,fixture:true},null,2));
  console.log(JSON.stringify({checks,errors}));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
