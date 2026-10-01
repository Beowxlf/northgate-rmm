(() => {
 const url=__SETUP__, button=document.getElementById('install-capture'),status=document.getElementById('setup-status'),output=document.getElementById('setup-output');
 let csrf='',busy=false,timer=null,closed=false;
 const terminal=new Set(['completed','failed','cancelled','expired','result_unknown']);
 async function request(options){const reply=await fetch(url,{credentials:'same-origin',cache:'no-store',redirect:'error',...options});if(!reply.ok)throw Error(reply.status===403?'Management and software installation permissions are required.':(await reply.text()).slice(0,500));return reply.json();}
 async function refresh(){if(closed)return;clearTimeout(timer);try{
  const value=await request();csrf=value.csrf;button.disabled=busy||!value.available;
  button.textContent=value.mode==='worker'?'Update management worker':'Install / check dependencies';
  status.textContent=value.reason+(value.version?' Approved '+(value.mode==='worker'?'worker ':'Wxlfgar ')+value.version+'.':'');
  const job=value.job;
  if(job){status.textContent+=' Latest installation: '+job.state+'.';output.textContent=job.receipt?.output||job.receipt?.error||'';output.hidden=!output.textContent;
   if(job.state==='completed')status.textContent+=' Review the result below, then refresh readiness. Completed installation does not imply the capture driver is ready.';
   if(!terminal.has(job.state))timer=setTimeout(refresh,5000);
  }
 }catch(error){button.disabled=true;status.textContent=error.message;}}
 button.addEventListener('click',async()=>{if(busy)return;busy=true;button.disabled=true;status.textContent='Requesting installation…';try{await request({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({csrf})});busy=false;await refresh();}catch(error){status.textContent=error.message;busy=false;button.disabled=false;}});
 window.addEventListener('pagehide',()=>{closed=true;clearTimeout(timer);});refresh();
})();
