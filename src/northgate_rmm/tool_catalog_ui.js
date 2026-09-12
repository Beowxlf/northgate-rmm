(function () {
  'use strict';
  function mount(container, endpoint) {
    let disposed = false, timer = null, token = '', pending = null, sending = false, uncertain = false;
    const base = '/remote/' + encodeURIComponent(endpoint) + '/tool-catalog';
    container.replaceChildren();
    const heading = document.createElement('h3'); heading.textContent = 'Tools & evidence';
    const detail = document.createElement('p'); detail.textContent = 'Run focused diagnostics, collect case evidence and manage approved optional tools.';
    const status = document.createElement('p'); status.setAttribute('role', 'status');
    const controls = document.createElement('div'); controls.className = 'form-grid';
    const list = document.createElement('select'), profile = document.createElement('select');
    list.setAttribute('aria-label', 'Tool'); profile.setAttribute('aria-label', 'Diagnostic profile');
    const caseInput = document.createElement('input'); caseInput.placeholder = 'Case UUID (optional)'; caseInput.setAttribute('aria-label', 'Case UUID');
    const inputs = document.createElement('div');
    const profileNote = document.createElement('p'); profileNote.className = 'muted';
    const actions = document.createElement('div'); actions.className = 'actions';
    const jobs = document.createElement('div');
    controls.append(list, profile, caseInput, inputs); container.append(heading, detail, status, controls, profileNote, actions, jobs);
    let tools = [];
    function selected() { return tools.find(t => t.id === list.value); }
    function describeProfile() {
      profileNote.textContent = list.value === 'sysinternals' ? profile.value === 'trust' ? 'Inspect one executable: Windows PowerShell by default (SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe). Optionally select one absolute local file, up to 64 MiB. No folders, network paths or worker private files. Certificate revocation is not checked; this is an offline triage result.' : 'Logon startup entries only, without file hashes or signature checks. Use Inventory & diagnostics or osquery for broader startup coverage, and Trust inspection for a single executable.' : '';
    }
    function field(name, placeholder, type) { const element = document.createElement('input'); element.name = name; element.placeholder = placeholder; element.type = type || 'text'; element.setAttribute('aria-label', placeholder); if(name === 'port') element.value = '443'; inputs.append(element); }
    function updateInputs() {
      const tool = selected(); inputs.replaceChildren(); describeProfile();
      if (!tool) return;
      if (['connectivity', 'iperf2', 'nmap'].includes(tool.id)) { field('host', tool.id === 'connectivity' ? 'Hostname or address' : 'One private IP address'); field(tool.id === 'nmap' ? 'ports' : 'port', tool.id === 'nmap' ? 'Ports, e.g. 22,443' : 'Port', tool.id === 'nmap' ? 'text' : 'number'); }
      if (tool.id === 'yara-x') field('path', 'Absolute file or directory path');
      if (tool.id === 'sysinternals' && profile.value === 'trust') field('path', 'Optional local file — leave blank for Windows PowerShell');
    }
    function update() {
      const tool = selected(); profile.replaceChildren(); inputs.replaceChildren(); actions.replaceChildren();
      if (!tool) return;
      tool.profiles.forEach(p => { const option = document.createElement('option'); option.value = p; option.textContent = tool.id === 'sysinternals' ? p === 'startup' ? 'Logon startup' : 'Trust inspection' : p; profile.append(option); });
      updateInputs();
      button('Run', 'tool.run'); button('Check readiness', 'tool.verify');
      if (!tool.builtin && tool.release) { button('Install approved version', 'tool.install'); button('Update approved version', 'tool.update'); }
      if (!tool.builtin) button('Remove tool', 'tool.remove');
      status.textContent = tool.builtin ? 'Built-in adapter · runs when requested' : tool.release ? 'Approved version ' + tool.release.version + ' · ' + tool.release.license : 'No approved package. An administrator must publish a qualified package before installation.';
    }
    function button(label, action) { const b = document.createElement('button'); b.type = 'button'; b.textContent = label; b.onclick = () => submit(action); actions.append(b); }
    async function submit(action, job) {
      if (pending || sending) { status.textContent = 'An earlier request has an uncertain result. Use Retry safely before another operation.'; return; }
      const tool = selected(), values = {};
      inputs.querySelectorAll('input').forEach(input => { if (tool?.id === 'sysinternals' && profile.value === 'trust' && input.name === 'path' && input.value === '') return; values[input.name] = input.type === 'number' ? Number(input.value) : input.value; });
      const body = {csrf: token, action, tool_id: tool && tool.id, version: tool && tool.release && tool.release.version, profile: profile.value, inputs: values, case_id: caseInput.value.trim(), request_id: crypto.randomUUID(), job};
      pending = body; uncertain = false; await sendPending();
    }
    async function sendPending() {
      if (!pending || sending || disposed) return;
      sending = true; list.disabled = profile.disabled = caseInput.disabled = true;
      inputs.querySelectorAll('input').forEach(input => { input.disabled = true; });
      actions.querySelectorAll('button').forEach(b => { b.disabled = true; });
      try {
        const response = await fetch(base + '/action', {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...pending, csrf: token})});
        if (!uncertain && response.status === 400 && response.headers.get('X-NorthGate-Request-Outcome') === 'rejected-before-queue') {
          const message = await response.text(); pending = null;
          actions.querySelector('[data-safe-retry]')?.remove();
          if (!disposed) status.textContent = message + ' — no job was queued. Correct the input and run again.';
          return;
        }
        if (!response.ok) throw new Error(await response.text());
        const result = await response.json();
        if (!result || result.job !== (pending.action === 'cancel' ? pending.job : pending.request_id)) throw new Error('Server response did not confirm this request');
        pending = null;
        actions.querySelector('[data-safe-retry]')?.remove();
        if (!disposed) { status.textContent = 'Job queued: ' + result.job; await refresh(false); }
      } catch (error) {
        uncertain = true;
        if (!disposed) {
          status.textContent = error.message + ' — retry uses the same request ID.';
          if (!actions.querySelector('[data-safe-retry]')) {
            const retry = document.createElement('button'); retry.type = 'button'; retry.dataset.safeRetry = 'true'; retry.textContent = 'Retry safely'; retry.onclick = sendPending; actions.append(retry);
          }
        }
      } finally {
        sending = false; list.disabled = profile.disabled = caseInput.disabled = Boolean(pending);
        inputs.querySelectorAll('input').forEach(input => { input.disabled = Boolean(pending); });
        actions.querySelectorAll('button').forEach(b => { b.disabled = Boolean(pending) && !b.hasAttribute('data-safe-retry'); });
      }
    }
    async function refresh(initial) {
      try { const response = await fetch(base, {credentials: 'same-origin'}); if (!response.ok) throw new Error(await response.text()); const data = await response.json(); if (disposed) return; token = data.csrf; tools = data.tools;
        if (initial) { tools.forEach(t => { const option = document.createElement('option'); option.value = t.id; option.textContent = t.name; list.append(option); }); update(); }
        jobs.replaceChildren(); data.jobs.slice(0, 8).forEach(job => { const section = document.createElement('details'), summary = document.createElement('summary'); let state = job.state;
          if (job.receipt) { try { const result = JSON.parse(job.receipt.output); if (result?.partial === true || result?.phase === 'partial') state = 'Partial collection — review collector results'; } catch (_) {} if (job.receipt.truncated) state = 'Output incomplete — limit reached'; }
          summary.textContent = job.action + ' · ' + state; section.append(summary); const output = document.createElement('pre'); output.textContent = job.receipt ? JSON.stringify(job.receipt, null, 2) : 'Waiting for worker receipt'; section.append(output); if (!['completed', 'failed', 'cancelled', 'expired', 'result_unknown'].includes(job.state)) { const stop = document.createElement('button'); stop.textContent = 'Cancel'; stop.onclick = () => submit('cancel', job.id); section.append(stop); } jobs.append(section); });
      } catch (error) { if (!disposed) status.textContent = 'Unable to load tool status: ' + error.message; }
      if (!disposed) { clearTimeout(timer); timer = setTimeout(() => refresh(false), 10000); }
    }
    list.onchange = update; profile.onchange = () => { if (list.value === 'sysinternals') updateInputs(); else describeProfile(); }; refresh(true);
    return () => { disposed = true; clearTimeout(timer); container.replaceChildren(); };
  }
  window.NorthGateTools = {mount};
}());
