(() => {
const base=__BASE__,job=__JOB__,token=__TOKEN__;
const finished=new Set(['completed','stopped','expired','failed','interrupted']);
let done=false,busy=false;
const el=id=>document.getElementById(id);
function text(parent,tag,value){const n=document.createElement(tag);n.textContent=String(value);parent.append(n);return n;}
function table(parent,headers,rows){
 const wrap=text(parent,'div','');wrap.className='table-scroll';
 const grid=text(wrap,'table',''),head=text(text(grid,'thead',''),'tr','');
 headers.forEach(h=>text(head,'th',h));const body=text(grid,'tbody','');
 rows.forEach(values=>{const row=text(body,'tr','');values.forEach(v=>text(row,'td',v??'Unavailable'));});
 if(!rows.length)text(parent,'p','No observations in this capture yet.');
}
function render(value){
 el('capture-status').textContent=value.state;
 const counters=el('capture-counters');counters.replaceChildren();
 const elapsed=Math.round(((finished.has(value.state)?Date.parse(value.updated):Date.now())-Date.parse(value.started))/1000);
 for(const [label,amount] of [['Packets',value.packets||0],['Saved / limit',`${((value.bytes||0)/1048576).toFixed(1)} / ${((value.max_bytes||0)/1048576).toFixed(0)} MiB`],['Dropped',value.dropped_packets??'Unavailable'],['Duration',Number.isFinite(elapsed)?`${Math.max(0,elapsed)}s`:'Unavailable']]){const metric=text(counters,'div','');metric.className='metric';text(metric,'strong',amount);text(metric,'span',label);}
 el('capture-message').textContent=value.reason || '';
 const results=el('capture-results');
 const opened=new Set(Array.from(results.querySelectorAll('details[open]'),n=>n.dataset.section));
 const initialized=results.dataset.initialized==='true';results.replaceChildren();results.dataset.initialized='true';
 function section(key,label,defaultOpen=false){const detail=text(results,'details','');detail.dataset.section=key;detail.className='card';detail.open=opened.has(key)||(!initialized&&defaultOpen);text(detail,'summary',label);return detail;}
 if(value.report){const r=value.report;
 text(results,'p',r.provisional?'Live analysis · provisional; findings may change as replies arrive.':'Final analysis of saved packets').className='section-note';
 const findings=section('findings',`Findings · ${(r.findings||[]).length}`,true);
 if(!(r.findings||[]).length)text(findings,'p','No findings reported. This does not establish that the infrastructure is healthy.');
 for(const f of r.findings||[]){const row=text(findings,'article','');row.className='capture-finding';text(row,'strong',f.kind);text(row,'p',f.description);text(row,'small',`${f.source} → ${f.destination} · ${f.confidence} · packet ${f.packet} · ${f.scope} · ${f.time}`);}
 for(const w of r.warnings||[])text(findings,'p',w).className='notice';
 const assets=section('assets',`Observed infrastructure · ${(r.assets||[]).length}`);
 table(assets,['IP','VLAN scope','MAC claims','Roles and evidence','First / last seen'],(r.assets||[]).map(a=>[a.ip,a.scope,(a.macs||[]).join(', '),(a.roles||[]).map(x=>`${x.name} (${x.confidence}; packet ${x.packet}): ${x.evidence}`).join('\n')||'Observed address; role unknown',`${a.first} / ${a.last}`]));
 const flows=section('flows',`Conversations · ${(r.flows||[]).length}`);
 table(flows,['Scope','Source','Destination','Protocol','Packets','Bytes'],(r.flows||[]).map(f=>['scope','source','destination','protocol','packets','bytes'].map(k=>f[k])));
 if(r.transactions){const t=r.transactions;table(section('transactions','Protocol responses'),['Measure','Value'],[['Matched DNS replies',t.dns_matched],['Mean DNS latency',Number.isFinite(Number(t.dns_average_ms))?`${Number(t.dns_average_ms).toFixed(1)} ms`:'Unavailable'],['Answered TCP SYNs',t.tcp_syn_answered],['DHCP acknowledgements',t.dhcp_acknowledged]]);}
 }else text(results,'p','Analysis will appear when captured packets have been processed.');
 const files=el('capture-files');const expanded=new Set(Array.from(files.querySelectorAll('details[open]'),n=>n.dataset.artifact));files.replaceChildren();
 for(const a of value.artifacts||[]){if(!['capture.pcap','report.json','summary.txt','manifest.json'].includes(a.name))continue;const card=text(files,'details','');card.className='card';card.dataset.artifact=a.name;card.open=expanded.has(a.name);text(card,'summary',a.name);const link=text(card,'a',`Download · ${a.size} bytes`);link.className='button';link.href=`${base}/file/${job}/${a.name}`;text(card,'p',`SHA-256: ${a.sha256}`).className='section-note';}
 if(!files.children.length)text(files,'p','Evidence files appear when the capture is finalized.');
 done=finished.has(value.state);
 el('stop-capture').disabled=done;
}
async function tick(){if(done||busy)return;busy=true;try{
 if(token){const form=new URLSearchParams({token});const renewal=await fetch(base+'/lease',{method:'POST',body:form,credentials:'same-origin'});if(!renewal.ok&&renewal.status!==409)throw new Error('Session authorization unavailable; capture will stop.');}
 const reply=await fetch(base+'/state?job='+job,{credentials:'same-origin',cache:'no-store'});if(!reply.ok)throw new Error('Status unavailable. Capture stops if authorization cannot renew.');render(await reply.json());
 }catch(error){el('capture-message').textContent=error.message;}finally{busy=false;}}
render(__INITIAL__);if(!done){tick();setInterval(tick,10000);}
})();
