(() => {
const base=__BASE__,job=__JOB__,token=__TOKEN__;
const finished=new Set(['completed','stopped','expired','failed','interrupted']);
let done=false,busy=false;
const el=id=>document.getElementById(id);
function text(parent,tag,value){const n=document.createElement(tag);n.textContent=String(value);parent.append(n);return n;}
function render(value){
 el('capture-status').textContent=value.state;
 el('capture-counters').textContent=`Saved bytes: ${value.bytes || 0} / ${value.max_bytes || 0}; packets: ${value.packets || 0}; dropped: ${value.dropped_packets ?? "unavailable"}; elapsed: ${Math.max(0,Math.round(((finished.has(value.state)?Date.parse(value.updated):Date.now())-Date.parse(value.started))/1000))}s`;
 el('capture-message').textContent=value.reason || '';
 const results=el('capture-results');results.replaceChildren();
 if(value.report){const r=value.report;text(results,'p',`Packets: ${r.packets}; conversations: ${(r.flows||[]).length}; findings: ${(r.findings||[]).length}`);
 text(results,'p',r.provisional?'Live analysis · provisional snapshot; results may change as replies arrive.':'Final analysis of saved packets');
 text(results,'h2','Observed infrastructure');
 const assets=text(results,'table','');const ah=text(assets,'tr','');for(const s of ['IP','VLAN scope','MAC claims','Roles and evidence','First / last seen'])text(ah,'th',s);
 for(const a of (r.assets||[])){const row=text(assets,'tr','');text(row,'td',a.ip);text(row,'td',a.scope);text(row,'td',(a.macs||[]).join(', '));text(row,'td',(a.roles||[]).map(x=>`${x.name} (${x.confidence}; packet ${x.packet}): ${x.evidence}`).join('\n')||'Observed address; role unknown');text(row,'td',`${a.first} / ${a.last}`);}
 if(r.transactions)text(results,'p',`Matched DNS replies: ${r.transactions.dns_matched}; mean DNS latency: ${Number(r.transactions.dns_average_ms).toFixed(1)} ms; answered TCP SYNs: ${r.transactions.tcp_syn_answered}; DHCP ACKs: ${r.transactions.dhcp_acknowledged}`);
 text(results,'h2','Conversations');
 const table=text(results,'table','');const head=text(table,'tr','');for(const s of ['Scope','Source','Destination','Protocol','Packets','Bytes'])text(head,'th',s);
 for(const flow of (r.flows||[])){const row=text(table,'tr','');for(const k of ['scope','source','destination','protocol','packets','bytes'])text(row,'td',flow[k]);}
 text(results,'h2','Findings');
 for(const f of (r.findings||[]))text(results,'p',`${f.time} · ${f.kind} (${f.confidence}; packet ${f.packet}; ${f.scope}) · ${f.source} → ${f.destination}: ${f.description}`);
 for(const w of (r.warnings||[]))text(results,'p',w);}
 const files=el('capture-files');files.replaceChildren();for(const a of (value.artifacts||[])){if(!['capture.pcap','report.json','summary.txt','manifest.json'].includes(a.name))continue;const link=text(files,'a',`Download ${a.name} (${a.size} bytes)`);link.href=`${base}/file/${job}/${a.name}`;text(files,'p',`SHA-256: ${a.sha256}`);}
 done=finished.has(value.state);
}
async function tick(){if(done||busy)return;busy=true;try{
 if(token){const form=new URLSearchParams({token});const renewal=await fetch(base+'/lease',{method:'POST',body:form,credentials:'same-origin'});if(!renewal.ok&&renewal.status!==409)throw new Error('Session authorization unavailable; capture will stop.');}
 const reply=await fetch(base+'/state?job='+job,{credentials:'same-origin',cache:'no-store'});if(!reply.ok)throw new Error('Status unavailable. Capture stops if authorization cannot renew.');render(await reply.json());
 }catch(error){el('capture-message').textContent=error.message;}finally{busy=false;}}
render(__INITIAL__);if(!done){tick();setInterval(tick,10000);}
})();
