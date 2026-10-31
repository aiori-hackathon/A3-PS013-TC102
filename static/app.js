/* TraceForge frontend: intentionally dependency-free and API-backed. */
const state = { token: sessionStorage.getItem('tf_token') || '', user: null, view: 'dashboard', evidence: [], investigations: [] };
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtDate = (value) => { if (!value) return '—'; try { return new Intl.DateTimeFormat(undefined, {timeZone: state.user?.display_timezone || undefined, dateStyle: 'medium', timeStyle: 'short'}).format(new Date(value)); } catch (_) { return new Date(value).toLocaleString(); } };
const bytes = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KB` : `${(n/1048576).toFixed(2)} MB`;
let registerMode = false, toastTimer;

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set('Authorization', `Bearer ${state.token}`);
  if (options.body && !(options.body instanceof FormData) && !(options.body instanceof URLSearchParams) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, {...options, headers});
  if (response.status === 401 && state.token) { signOut(false); throw new Error('Your session expired. Please sign in again.'); }
  if (!response.ok) { let message = `Request failed (${response.status})`; try { const data = await response.json(); message = data.detail || message; } catch (_) {} throw new Error(message); }
  return response;
}
async function getJSON(path) { return (await api(path)).json(); }
function toast(message, isError = false) {
  $('toast').textContent = message; $('toast').classList.remove('hidden','error'); if (isError) $('toast').classList.add('error');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').classList.add('hidden'), 4200);
}
function setAuthMode(register) {
  registerMode = register; $('auth-title').textContent = register ? 'Create your workspace' : 'Welcome back';
  $('auth-subtitle').textContent = register ? 'Set up an account to keep your investigations private.' : 'Sign in to continue your investigations.';
  $('name-field').classList.toggle('hidden', !register); $('auth-name').required = register;
  $('auth-password').autocomplete = register ? 'new-password' : 'current-password';
  $('auth-submit').innerHTML = register ? 'Create account <span>→</span>' : 'Sign in <span>→</span>';
  $('auth-switch-label').textContent = register ? 'Already have an account?' : 'New to the workspace?';
  $('auth-switch').textContent = register ? 'Sign in' : 'Create an account'; $('auth-message').classList.add('hidden');
}
$('auth-switch').addEventListener('click', () => setAuthMode(!registerMode));
$('auth-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button = $('auth-submit'); button.disabled = true;
  try {
    const payload = {email: $('auth-email').value.trim(), password: $('auth-password').value};
    if (registerMode) payload.display_name = $('auth-name').value.trim();
    const response = await fetch(registerMode ? '/api/auth/register' : '/api/auth/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const data = await response.json(); if (!response.ok) throw new Error(data.detail || 'Could not sign in');
    state.token = data.access_token; state.user = data.user; sessionStorage.setItem('tf_token', state.token); await enterApp();
  } catch (error) { $('auth-message').textContent = error.message; $('auth-message').classList.remove('hidden'); }
  finally { button.disabled = false; }
});
function signOut(showMessage = true) {
  state.token = ''; state.user = null; sessionStorage.removeItem('tf_token'); $('app-shell').classList.add('hidden'); $('auth-screen').classList.remove('hidden');
  if (showMessage) { $('auth-message').textContent = 'You have signed out.'; $('auth-message').classList.remove('hidden'); }
}
$('logout').addEventListener('click', () => signOut());
async function enterApp() {
  try {
    state.user = await getJSON('/api/me'); $('auth-screen').classList.add('hidden'); $('app-shell').classList.remove('hidden');
    $('user-name').textContent = state.user.display_name; $('user-email').textContent = state.user.email;
    $('avatar').textContent = (state.user.display_name || 'U').trim().charAt(0).toUpperCase(); await loadInvestigations(); await showView('dashboard');
  } catch (error) { signOut(false); $('auth-message').textContent = error.message; $('auth-message').classList.remove('hidden'); }
}
const viewMeta = {dashboard:['OVERVIEW','Dashboard'],upload:['EVIDENCE INTAKE','Add evidence'],history:['SECURITY AUDIT','Activity history'],reports:['INVESTIGATION RECORDS','Reports'],settings:['PREFERENCES','Settings']};
async function showView(view) {
  if (!viewMeta[view]) return;
  state.view = view; document.querySelectorAll('.view').forEach(el => el.classList.add('hidden')); $(`view-${view}`).classList.remove('hidden');
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
  $('crumb').textContent = viewMeta[view][0]; $('page-title').textContent = viewMeta[view][1];
  if (view === 'dashboard') await loadDashboard(); if (view === 'upload') { await loadInvestigations(); await loadSettingsLimit(); }
  if (view === 'history') await loadHistory(); if (view === 'reports') { await loadEvidence(); await loadReportHistory(); } if (view === 'settings') await loadSettings();
}
document.querySelectorAll('[data-view]').forEach(el => el.addEventListener('click', () => showView(el.dataset.view)));
document.querySelectorAll('[data-go]').forEach(el => el.addEventListener('click', () => showView(el.dataset.go)));
function empty(message, sub = '') { return `<div class="empty-state"><strong>${esc(message)}</strong>${esc(sub)}</div>`; }
function fileRow(item, clickable = false) {
  return `<tr><td><div class="file-cell"><div class="file-icon">▤</div><div><strong>${esc(item.filename)}</strong><span>${bytes(item.size_bytes)} · ID ${item.id}${item.investigation_title ? ` · ${esc(item.investigation_title)}` : ''}</span></div></div></td><td>${fmtDate(item.created_at)}</td><td>${item.event_count}</td><td>${item.finding_count}</td><td><span class="status ${esc(item.status)}">${esc(item.status)}</span></td><td>${clickable ? `<button class="text-button" data-detail="${item.id}">Open →</button>` : `<button class="text-button" data-report="${item.id}">Review →</button>`}</td></tr>`;
}
function evidenceTable(items, clickable = false) {
  if (!items.length) return empty('No evidence uploaded yet','Add a sample or authorized log file to begin.');
  return `<table class="data-table"><thead><tr><th>Evidence</th><th>Uploaded</th><th>Events</th><th>Findings</th><th>Status</th><th></th></tr></thead><tbody>${items.map(x=>fileRow(x,clickable)).join('')}</tbody></table>`;
}
async function loadDashboard() {
  try {
    const data = await getJSON('/api/dashboard'); state.evidence = data.recent_evidence;
    $('stat-cases').textContent = data.total_investigations; $('stat-failures').textContent = data.processing_failures;
    $('stat-evidence').textContent = data.total_evidence; $('stat-events').textContent = data.total_events;
    $('stat-findings').textContent = data.total_findings; $('stat-high').textContent = data.high_findings;
    $('recent-evidence').innerHTML = data.recent_evidence.length ? evidenceTable(data.recent_evidence, true) : empty('Your workspace is ready','Upload a log file to start an investigation.');
    const levels = ['high','medium','info']; const total = levels.reduce((n,k)=>n+(data.severity_counts[k]||0),0); const max = Math.max(1,total);
    $('severity-chart').innerHTML = levels.map(key=>`<div class="severity-row ${key}"><span>${key==='high'?'High · review first':key==='medium'?'Medium · review':'Info · context'}</span><div class="bar"><span style="width:${Math.round((data.severity_counts[key]||0)/max*100)}%"></span></div><strong>${data.severity_counts[key]||0}</strong></div>`).join(''); bindEvidenceButtons();
  } catch (error) { toast(error.message,true); }
}
async function loadEvidence() {
  try { state.evidence = await getJSON('/api/evidence'); $('evidence-table').innerHTML = evidenceTable(state.evidence, false); bindEvidenceButtons(); }
  catch (error) { toast(error.message,true); }
}
function bindEvidenceButtons() {
  document.querySelectorAll('[data-detail]').forEach(button => button.addEventListener('click', async () => { await showView('reports'); await openDetail(button.dataset.detail); }));
  document.querySelectorAll('[data-report]').forEach(button => button.addEventListener('click', async () => { await showView('reports'); await openDetail(button.dataset.report); }));
}
function findingCard(f) {
  return `<div class="finding-card"><span class="severity ${esc(f.severity)}">${esc(f.severity)}</span><strong style="margin-left:8px">${esc(f.title)}</strong><p>${esc(f.description)}</p><p class="tiny muted"><strong>${esc(f.rule_id)}</strong> · ${f.event_count} linked event(s) · IDs: ${esc((f.event_ids||[]).join(', ') || 'none')}</p><p><strong>Why it triggered:</strong> ${esc(f.rationale)}</p><p><strong>Recommended review:</strong> ${esc(f.recommended_action)}</p></div>`;
}
async function openDetail(id) {
  try {
    const data = await getJSON(`/api/evidence/${id}`); const item = data.evidence; const panel = $('detail-panel'); panel.classList.remove('hidden');
    const findings = data.findings.length ? `<div class="findings-list">${data.findings.map(findingCard).join('')}</div>` : empty('No detection rule triggered','This is not a guarantee that the logs are safe; rule coverage is limited.');
    const events = data.events.length ? data.events.slice(0,100).map(e=>`<tr><td>${e.id}</td><td>${esc(e.timestamp || 'Time unknown')}</td><td>${esc(e.event_type)}</td><td><span class="severity ${esc(e.severity)}">${esc(e.severity)}</span></td><td>${esc(e.source_ip||'—')}</td><td>${e.line_number}</td><td>${esc(e.message)}</td></tr>`).join('') : '<tr><td colspan="7">No events could be structured from this file.</td></tr>';
    panel.innerHTML = `<div class="detail-heading"><div><div class="eyebrow">EVIDENCE ID ${item.id} · CASE ${item.investigation_id ?? '—'}</div><h3>${esc(item.filename)}</h3><p class="muted tiny">Uploaded ${fmtDate(item.created_at)} · ${bytes(item.size_bytes)} · ${esc(item.status)}</p></div><div class="detail-actions"><button class="btn secondary small" id="verify-hash">Verify integrity</button><button class="btn secondary small" id="download-original">Original evidence</button><button class="btn primary small" data-export="pdf" data-id="${item.id}">Download report (PDF)</button><button class="btn secondary small" data-export="package" data-id="${item.id}">Export data (ZIP)</button></div></div><details class="hash-details"><summary>Evidence integrity reference · SHA-256</summary><div class="hash-box"><code>${esc(item.sha256)}</code><button class="text-button" id="copy-hash" type="button">Copy hash</button></div></details><div id="verify-result" class="tiny muted" aria-live="polite"></div><div class="detail-grid"><div class="findings-section"><h3>Findings (${data.findings.length})</h3>${findings}</div><div class="timeline-section"><h3>Event timeline (${data.events.length} events · chronological)</h3><div class="table-wrap"><table class="data-table"><thead><tr><th>Event ID</th><th>UTC time</th><th>Type</th><th>Severity</th><th>Source IP</th><th>Line</th><th>Message</th></tr></thead><tbody>${events}</tbody></table></div>${data.events.length>100?`<p class="muted tiny">Showing first 100 events. The CSV export contains the full event list.</p>`:''}</div></div><div class="callout"><span>i</span><p>Parsing gaps: ${item.parsing_gaps}. Missing or unrecognized timestamps are not invented. A matching hash compares stored bytes with the upload-time reference; it does not prove source authenticity.</p></div>`;
    $('verify-hash').addEventListener('click', async () => { try { const v = await getJSON(`/api/evidence/${id}/verify`); $('verify-result').textContent = `${v.verified ? 'MATCH' : 'MISMATCH'} — ${v.message}`; $('verify-result').style.color = v.verified ? 'var(--green)' : 'var(--red)'; } catch(e) { toast(e.message,true); } });
    $('download-original')?.addEventListener('click', async () => {
      try { const response = await api(`/api/evidence/${id}/original-download`); const blob = await response.blob(); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = item.filename; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); toast('Original evidence download started.'); }
      catch (e) { toast(e.message, true); }
    });
    panel.querySelectorAll('[data-export]').forEach(button => button.addEventListener('click', () => button.dataset.export === 'package' ? generatePackageAndDownload(id) : generateAndDownload(id, button.dataset.export, button.dataset.dataset || 'all')));
    $('copy-hash')?.addEventListener('click', async()=>{try{await navigator.clipboard.writeText(item.sha256);toast('SHA-256 copied.');}catch(_){toast('Clipboard access unavailable; expand and select the hash manually.',true);}});
    panel.scrollIntoView({behavior:'smooth',block:'start'});
  } catch (error) { toast(error.message,true); }
}
async function generateAndDownload(evidenceId, format, dataset = 'all') {
  try {
    const query = format === 'csv' ? `?dataset=${encodeURIComponent(dataset)}` : '';
    const result = await (await api(`/api/evidence/${evidenceId}/reports/${format}${query}`, {method:'POST'})).json();
    const response = await api(result.download_url); const blob = await response.blob(); const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = result.filename; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
    toast(`${format.toUpperCase()} report generated and saved to report history.`); await loadReportHistory();
  } catch (error) { toast(error.message,true); }
}
async function generatePackageAndDownload(evidenceId) {
  try {
    const result = await (await api(`/api/evidence/${evidenceId}/export-package`, {method:'POST'})).json();
    const response = await api(result.download_url); const blob = await response.blob(); const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = result.filename; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
    toast('Complete data package generated and saved to report history.'); await loadReportHistory();
  } catch(error) { toast(error.message,true); }
}
async function loadReportHistory() {
  try {
    const rows = await getJSON('/api/reports');
    $('report-history-table').innerHTML = rows.length ? `<table class="data-table"><thead><tr><th>Report</th><th>Evidence ID</th><th>Format</th><th>Generated</th><th></th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.filename)}</td><td>${r.evidence_id}</td><td><span class="status completed">${esc(r.format==='zip'?'DATA PACKAGE (ZIP)':r.format.replace('csv-', 'CSV · ').toUpperCase())}</span></td><td>${fmtDate(r.created_at)}</td><td><button class="text-button" data-download-report="${r.id}">Download →</button></td></tr>`).join('')}</tbody></table>` : empty('No reports generated yet','Open evidence to generate the complete PDF report or a ZIP data package.');
    document.querySelectorAll('[data-download-report]').forEach(btn=>btn.addEventListener('click',()=>downloadSavedReport(btn.dataset.downloadReport)));
  } catch (error) { toast(error.message,true); }
}
async function downloadSavedReport(id) {
  try { const response = await api(`/api/reports/${id}/download`); const blob = await response.blob(); const url=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; const disposition=response.headers.get('Content-Disposition')||''; const match=disposition.match(/filename="?([^";]+)"?/i); a.download=match?match[1]:'TraceForge-report'; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000); }
  catch(error) { toast(error.message,true); }
}
let searchPage = 1;
let searchPages = 1;
async function runEventSearch(page = 1) {
  searchPage = Math.max(1, Number(page) || 1);
  const query=$('event-search-query').value.trim(); const severity=$('event-search-severity').value;
  const params=new URLSearchParams({q:query,page:String(searchPage),page_size:'50'}); if(severity) params.set('severity',severity);
  try {
    const data=await getJSON(`/api/search?${params.toString()}`); searchPages=Math.max(1,data.pages);
    const rows=data.results.map(e=>`<tr><td>${esc(e.timestamp_utc||'Unknown')}</td><td>${esc(e.filename)} · #${e.evidence_id}</td><td>${esc(e.event_type)}</td><td><span class="severity ${esc(e.severity)}">${esc(e.severity)}</span></td><td>${esc(e.source_ip||'—')}</td><td>${esc(e.username||'—')}</td><td class="event-message">${esc(e.message)}</td><td><button class="text-button" data-search-open="${e.evidence_id}">Open →</button></td></tr>`).join('');
    $('event-search-results').innerHTML=data.results.length ? `<p class="muted tiny">${data.total} matching event(s) · page ${data.page} of ${searchPages}</p><div class="table-wrap"><table class="data-table search-results-table"><thead><tr><th>Time (UTC)</th><th>Evidence</th><th>Type</th><th>Severity</th><th>Source IP</th><th>User</th><th>Message</th><th></th></tr></thead><tbody>${rows}</tbody></table></div><div class="search-pagination"><button class="btn secondary small" id="search-prev" ${searchPage<=1?'disabled':''}>← Previous</button><span class="tiny muted">Page ${searchPage} / ${searchPages}</span><button class="btn secondary small" id="search-next" ${searchPage>=searchPages?'disabled':''}>Next →</button></div>` : empty('No matching events','Try a different keyword or severity filter.');
    document.querySelectorAll('[data-search-open]').forEach(btn=>btn.addEventListener('click',async()=>{await showView('reports'); await openDetail(btn.dataset.searchOpen);}));
    $('search-prev')?.addEventListener('click',()=>runEventSearch(searchPage-1)); $('search-next')?.addEventListener('click',()=>runEventSearch(searchPage+1));
  } catch(error) { toast(error.message,true); }
}
$('event-search-form')?.addEventListener('submit',event=>{event.preventDefault();runEventSearch();});
$('refresh-reports')?.addEventListener('click', loadReportHistory);
async function loadHistory() {
  try { const rows = await getJSON('/api/history'); $('history-table').innerHTML = rows.length ? `<table class="data-table"><thead><tr><th>Record</th><th>Action</th><th>Details</th><th>Status</th><th>Time</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.kind)}</td><td class="history-action">${esc(r.action)}</td><td>${esc(r.details || r.target || '—')}</td><td><span class="status ${['completed','open','reviewed','closed','saved','match'].includes(r.outcome)?'completed':'failed'}">${esc(r.outcome)}</span></td><td>${fmtDate(r.created_at)}</td></tr>`).join('')}</tbody></table>` : empty('No investigation history yet','Cases, evidence processing, integrity checks and generated reports will appear here.'); }
  catch (error) { toast(error.message,true); }
}
async function loadSettings() {
  try { const data = await getJSON('/api/settings'); $('settings-name').value=data.display_name; $('settings-email').value=data.email; $('settings-size').value=data.max_upload_mb; $('settings-threshold').value=data.alert_threshold; $('settings-timezone').value=data.display_timezone || 'UTC'; }
  catch (error) { toast(error.message,true); }
}
async function loadSettingsLimit() { try { const data=await getJSON('/api/settings'); $('upload-limit').textContent=`Maximum file size: ${data.max_upload_mb} MB`; } catch (_) {} }
$('settings-form').addEventListener('submit', async event => {
  event.preventDefault(); const payload={display_name:$('settings-name').value.trim(),max_upload_mb:Number($('settings-size').value),alert_threshold:Number($('settings-threshold').value),display_timezone:$('settings-timezone').value};
  try { await (await api('/api/settings',{method:'PUT',body:JSON.stringify(payload)})).json(); state.user.display_name=payload.display_name; state.user.display_timezone=payload.display_timezone; $('user-name').textContent=payload.display_name; $('avatar').textContent=payload.display_name.charAt(0).toUpperCase(); toast('Settings saved. New threshold applies to future uploads.'); }
  catch(error) { toast(error.message,true); }
});
async function loadInvestigations(selectedId = null) {
  try {
    state.investigations = await getJSON('/api/investigations');
    const select = $('investigation-select'); if (!select) return;
    const previous = selectedId ?? select.value;
    select.innerHTML = state.investigations.map(c=>`<option value="${c.id}">${esc(c.title)} · ${c.evidence_count} evidence</option>`).join('');
    if (!state.investigations.length) select.innerHTML = '<option value="">Create an investigation first</option>';
    if (previous && state.investigations.some(c=>String(c.id)===String(previous))) select.value=String(previous);
  } catch(error) { toast(error.message,true); }
}
$('create-case')?.addEventListener('click', async () => {
  const input = $('new-case-title'); const title = input.value.trim(); if (title.length < 3) { toast('Enter an investigation title with at least 3 characters.', true); input.focus(); return; }
  try { const created = await (await api('/api/investigations',{method:'POST',body:JSON.stringify({title,description:''})})).json(); input.value=''; await loadInvestigations(created.id); toast('Investigation created.'); }
  catch(error) { toast(error.message,true); }
});
$('evidence-file').addEventListener('change', () => { const file=$('evidence-file').files[0]; $('selected-file').classList.toggle('hidden',!file); $('selected-file').textContent=file?`Selected: ${file.name} (${bytes(file.size)})`:''; });
$('upload-form').addEventListener('submit', async event => {
  event.preventDefault(); const file=$('evidence-file').files[0]; if(!file) return;
  const button=$('upload-button'); button.disabled=true; button.textContent='Uploading and analysing…';
  try {
    const form=new FormData(); form.append('file',file); if ($('investigation-select').value) form.append('investigation_id',$('investigation-select').value);
    const response=await api('/api/evidence/upload',{method:'POST',body:form}); const item=await response.json();
    $('upload-result').classList.remove('hidden'); $('upload-result').innerHTML=`<div class="callout"><span>✓</span><p><strong>Analysis complete.</strong> ${esc(item.filename)} — ${item.event_count} events, ${item.finding_count} rule-triggered findings, ${item.parsing_gaps} parsing gaps. Evidence ID ${item.id}.</p></div><button class="btn secondary small" id="open-upload-result">Review evidence →</button>`;
    $('open-upload-result').addEventListener('click', async()=>{await showView('reports');await openDetail(item.id);}); $('evidence-file').value=''; $('selected-file').classList.add('hidden'); await loadInvestigations(item.investigation_id); toast('Evidence uploaded and processing completed. Opening analysis…'); await showView('reports'); await openDetail(item.id);
  } catch(error) { toast(error.message,true); }
  finally { button.disabled=false; button.innerHTML='Upload and analyse <span>→</span>'; }
});
if (state.token) enterApp(); else setAuthMode(false);
