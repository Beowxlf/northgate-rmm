(function () {
  'use strict';
  const fallbackActions = {
    'tool.run': {label: 'Run', description: 'Queues this bounded profile on the endpoint. It does not automatically remediate, isolate, or delete anything.'},
    'tool.verify': {label: 'Check readiness', description: 'Checks the adapter and dependencies without running the investigation profile or changing the endpoint.'},
    'tool.install': {label: 'Install approved version', description: 'Installs the signed approved release. This changes the endpoint and requires patch permission.'},
    'tool.update': {label: 'Update approved version', description: 'Updates the signed approved release. This changes the endpoint and requires patch permission.'},
    'tool.remove': {label: 'Remove tool', description: 'Removes this optional tool. This changes the endpoint and requires patch permission.'},
  };
  const fallbackTool = {purpose: 'Runs a bounded, approved endpoint diagnostic.', use_when: 'Use when its result directly supports the current investigation.', output: 'Audited diagnostic result', impact: 'No automatic remediation.'};
  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  function mount(container, endpoint, options = {}) {
    let disposed = false, timer = null, token = '', pending = null, sending = false, uncertain = false;
    let tools = [], actionGuidance = fallbackActions;
    const base = '/remote/' + encodeURIComponent(endpoint) + '/tool-catalog';
    container.replaceChildren();
    const header = element('div', undefined, 'tool-catalog-header'), title = element('div');
    title.append(element('h3', 'Response tools'), element('p', 'Run focused diagnostics and preserve results with the investigation.', 'muted')); header.append(title);
    const status = element('p', '', 'tool-status'); status.setAttribute('role', 'status');
    const controls = element('div', undefined, 'form-grid tool-controls');
    const list = document.createElement('select'), profile = document.createElement('select');
    list.setAttribute('aria-label', 'Tool'); profile.setAttribute('aria-label', 'Diagnostic profile');
    const caseInput = document.createElement('input'); caseInput.placeholder = 'Case UUID (optional)'; caseInput.setAttribute('aria-label', 'Case UUID');
    if (options.caseId) caseInput.value = options.caseId;
    if (options.lockedCase) { caseInput.setAttribute('readonly', ''); caseInput.setAttribute('aria-readonly', 'true'); }
    const inputs = element('div', undefined, 'tool-inputs'), profileNote = element('p', '', 'muted tool-profile-note');
    const summary = element('section', undefined, 'tool-guidance'), actions = element('div', undefined, 'tool-action-list'), jobs = element('div', undefined, 'tool-jobs');
    controls.append(list, profile, caseInput, inputs); container.append(header, status, controls, profileNote, summary, actions, jobs);
    function selected() { return tools.find(t => t.id === list.value); }
    function infoButton(label, description) {
      const button = element('button', 'i', 'tool-info-button'); button.type = 'button'; button.setAttribute('aria-label', 'About ' + label); button.onclick = () => showInfo(label, description); return button;
    }
    function showInfo(label, description) {
      container.querySelector?.('[data-tool-info]')?.remove();
      const panel = element('section', undefined, 'tool-info-panel'); panel.dataset.toolInfo = 'true'; panel.setAttribute('role', 'dialog'); panel.setAttribute('aria-label', label);
      const heading = element('div', undefined, 'tool-info-heading'); heading.append(element('strong', label));
      const close = element('button', '×', 'icon-button'); close.type = 'button'; close.setAttribute('aria-label', 'Close explanation'); close.onclick = () => panel.remove();
      heading.append(close); panel.append(heading, element('p', description)); summary.append(panel);
    }
    function describeProfile() {
      const tool = selected(); profileNote.textContent = tool?.profile_guidance?.[profile.value] || (tool?.id === 'sysinternals' ? profile.value === 'trust' ? 'Inspect Windows PowerShell by default, or one absolute local file up to 64 MiB. Certificate revocation is not checked.' : 'Logon startup entries only, without file hashes or signature checks.' : '');
    }
    function renderGuidance() {
      const tool = selected(), guidance = tool?.guidance || fallbackTool; summary.replaceChildren();
      const heading = element('div', undefined, 'tool-guidance-heading'); heading.append(element('h4', tool?.name || 'Selected tool'), infoButton(tool?.name || 'selected tool', guidance.purpose)); summary.append(heading);
      [['What it does', guidance.purpose], ['Use when', guidance.use_when], ['Expected output', guidance.output], ['Execution impact', guidance.impact]].forEach(([name, value]) => { const section = element('div'); section.append(element('strong', name), element('p', value || 'Not specified.')); summary.append(section); });
    }
    function field(name, placeholder, type, value) {
      const input = document.createElement('input'); input.name = name; input.placeholder = placeholder; input.type = type || 'text'; input.setAttribute('aria-label', placeholder); input.value = value ?? (name === 'port' ? '443' : ''); inputs.append(input);
    }
    function updateInputs() {
      const previous = {}; inputs.querySelectorAll('input').forEach(input => { previous[input.name] = input.value; });
      const tool = selected(); inputs.replaceChildren(); describeProfile(); if (!tool) return;
      if (['connectivity', 'iperf2', 'nmap'].includes(tool.id)) { field('host', tool.id === 'connectivity' ? 'Hostname or address' : 'One private IP address', 'text', previous.host); const name = tool.id === 'nmap' ? 'ports' : 'port'; field(name, tool.id === 'nmap' ? 'Ports, e.g. 22,443' : 'Port', tool.id === 'nmap' ? 'text' : 'number', previous[name]); }
      if (tool.id === 'yara-x') field('path', 'Absolute file or directory path', 'text', previous.path);
      if (tool.id === 'sysinternals' && profile.value === 'trust') field('path', 'Optional local file — leave blank for Windows PowerShell', 'text', previous.path);
    }
    function addAction(action) {
      const guidance = actionGuidance[action] || fallbackActions[action], row = element('div', undefined, 'tool-action-row');
      const button = element('button', guidance.label); button.type = 'button'; button.onclick = () => submit(action); row.append(button, infoButton(guidance.label, guidance.description)); actions.append(row);
    }
    function update() {
      const tool = selected(); profile.replaceChildren(); actions.replaceChildren(); if (!tool) return;
      tool.profiles.forEach(p => { const option = document.createElement('option'); option.value = p; option.textContent = tool.id === 'sysinternals' ? p === 'startup' ? 'Logon startup' : 'Trust inspection' : p.replaceAll('_', ' '); profile.append(option); });
      if (options.initialProfile && tool.profiles.includes(options.initialProfile)) profile.value = options.initialProfile;
      updateInputs(); renderGuidance(); addAction('tool.run'); addAction('tool.verify');
      if (!tool.builtin && tool.release) { addAction('tool.install'); addAction('tool.update'); }
      if (!tool.builtin) addAction('tool.remove');
      status.textContent = tool.builtin ? 'Built-in adapter · runs only when requested' : tool.release ? 'Approved version ' + tool.release.version + ' · ' + tool.release.license : 'No approved package is published for this endpoint.';
    }
    async function submit(action, job) {
      if (pending || sending) { status.textContent = 'An earlier request has an uncertain result. Use Retry safely before another operation.'; return; }
      const tool = selected(), values = {}; inputs.querySelectorAll('input').forEach(input => { if (tool?.id === 'sysinternals' && profile.value === 'trust' && input.name === 'path' && input.value === '') return; values[input.name] = input.type === 'number' ? Number(input.value) : input.value; });
      pending = {csrf: token, action, tool_id: tool && tool.id, version: tool && tool.release && tool.release.version, profile: profile.value, inputs: values, case_id: caseInput.value.trim(), request_id: crypto.randomUUID(), job}; uncertain = false; await sendPending();
    }
    async function sendPending() {
      if (!pending || sending || disposed) return; sending = true; list.disabled = profile.disabled = caseInput.disabled = true;
      inputs.querySelectorAll('input').forEach(input => { input.disabled = true; }); actions.querySelectorAll('button').forEach(b => { b.disabled = true; });
      try {
        const response = await fetch(base + '/action', {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...pending, csrf: token})});
        if (!uncertain && response.status === 400 && response.headers.get('X-NorthGate-Request-Outcome') === 'rejected-before-queue') { const message = await response.text(); pending = null; actions.querySelector('[data-safe-retry]')?.remove(); if (!disposed) status.textContent = message + ' — no job was queued. Correct the input and run again.'; return; }
        if (!response.ok) throw new Error(await response.text()); const result = await response.json();
        if (!result || result.job !== (pending.action === 'cancel' ? pending.job : pending.request_id)) throw new Error('Server response did not confirm this request');
        pending = null; actions.querySelector('[data-safe-retry]')?.remove(); if (!disposed) { status.textContent = 'Job queued: ' + result.job; await refresh(false); }
      } catch (error) {
        uncertain = true; if (!disposed) { status.textContent = error.message + ' — retry uses the same request ID.'; if (!actions.querySelector('[data-safe-retry]')) { const retry = element('button', 'Retry safely'); retry.type = 'button'; retry.dataset.safeRetry = 'true'; retry.onclick = sendPending; actions.append(retry); } }
      } finally {
        sending = false; list.disabled = profile.disabled = caseInput.disabled = Boolean(pending); inputs.querySelectorAll('input').forEach(input => { input.disabled = Boolean(pending); }); actions.querySelectorAll('button').forEach(b => { b.disabled = Boolean(pending) && !b.hasAttribute('data-safe-retry'); });
      }
    }
    async function refresh(initial) {
      try {
        const response = await fetch(base, {credentials: 'same-origin'}); if (!response.ok) throw new Error(await response.text()); const data = await response.json(); if (disposed) return;
        token = data.csrf; tools = data.tools; actionGuidance = {...fallbackActions, ...(data.action_guidance || {})};
        if (initial) { tools.forEach(t => { const option = document.createElement('option'); option.value = t.id; option.textContent = t.name; list.append(option); }); if (options.initialTool && tools.some(t => t.id === options.initialTool)) list.value = options.initialTool; update(); }
        jobs.replaceChildren(); data.jobs.slice(0, 8).forEach(job => { const section = document.createElement('details'), heading = document.createElement('summary'); let state = job.state;
          if (job.receipt) { try { const result = JSON.parse(job.receipt.output); if (result?.partial === true || result?.phase === 'partial') state = 'Partial collection — review collector results'; } catch (_) {} if (job.receipt.truncated) state = 'Output incomplete — limit reached'; }
          heading.textContent = job.action + ' · ' + state; section.append(heading); section.append(element('pre', job.receipt ? JSON.stringify(job.receipt, null, 2) : 'Waiting for worker receipt')); if (!['completed', 'failed', 'cancelled', 'expired', 'result_unknown'].includes(job.state)) { const stop = element('button', 'Cancel'); stop.onclick = () => submit('cancel', job.id); section.append(stop); } jobs.append(section); });
      } catch (error) { if (!disposed) status.textContent = 'Unable to load tool status: ' + error.message; }
      if (!disposed) { clearTimeout(timer); timer = setTimeout(() => refresh(false), 10000); }
    }
    list.onchange = update; profile.onchange = updateInputs; refresh(true);
    return () => { disposed = true; clearTimeout(timer); container.replaceChildren(); };
  }
  window.NorthGateTools = {mount};
}());
