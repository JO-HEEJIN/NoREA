// NoREA web UI (WP-07). Talks only to the platform contract (platform.js, 17 functions),
// never to WASM or key storage directly, so the same file runs in the browser and in Tauri
// (platform-contract v1, CONTEXT invariant 7). ui-text.js holds the pure text/view helpers.
//
// DOM is built with textContent only (file contents such as field names are untrusted).
// Passphrases: read from the input right before the platform call, the input is cleared at
// once and the variable is dropped after the call. Nothing is logged.
import * as platform from './platform.js';
import * as T from './ui-text.js';

const $ = id => document.getElementById(id);
function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (v === true) e.setAttribute(k, '');
    else e.setAttribute(k, String(v));
  }
  for (const c of children) if (c !== null && c !== undefined) e.append(c);
  return e;
}
const clear = node => { node.replaceChildren(); return node; };
const show = (node, on = true) => { node.hidden = !on; };
const te = new TextEncoder();

const state = {
  caps: null,
  info: null,
  input: null,          // {name, bytes} for Protect
  ins: null,            // InspectResult
  protected: null,      // {marked, evidenceJson, names}
  lastCheck: null,      // {suspect, suspectName, evidenceJson, evidenceName, report, view}
  disclosureJson: null,
};

// ---------------------------------------------------------------- status and errors
function setStatus(id, text) {
  const box = clear($(id));
  if (text) box.append(el('p', { text }));
}
function setError(id, e, opts) {
  const v = T.errorView(e, opts);
  const box = clear($(id));
  box.append(el('p', { class: 'err', text: v.message }));
  if (v.hint) box.append(el('p', { class: 'hint', text: v.hint }));
  if (v.detail) box.append(el('details', {}, el('summary', { text: 'Details' }), el('code', { text: v.detail })));
  return v;
}
/** Runs an action with the button disabled and errors shown in `msgId`. */
async function run(btn, msgId, opts, fn) {
  btn.disabled = true;
  $(msgId).setAttribute('aria-busy', 'true');
  setStatus(msgId, 'Working.');
  try {
    await fn();
  } catch (e) {
    setError(msgId, e, typeof opts === 'function' ? opts() : opts);
  } finally {
    btn.disabled = false;
    $(msgId).removeAttribute('aria-busy');
  }
}
/** Reads a password input and clears it immediately (platform-contract secret handling rule 4). */
function takeSecret(id) {
  const input = $(id);
  const v = input.value;
  input.value = '';
  return v;
}
function clearSecrets() {
  for (const id of ['key-pass', 'key-pass2', 'protect-pass', 'check-pass', 'disclose-pass']) $(id).value = '';
}
const needsPassphrase = () => state.info?.method === 'passphrase';
async function fileBytes(input) {
  const f = input.files?.[0];
  return f ? { name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) } : null;
}
async function fileText(input) {
  const f = input.files?.[0];
  return f ? { name: f.name, text: await f.text() } : null;
}
function resultList(items) {
  return el('ul', { class: 'result-list' }, ...items.map(it => el('li', {},
    el('span', { class: `badge ${it.status === 'N/A' ? 'NA' : it.status}`, text: it.status === 'NOTE' ? 'NOTE' : it.status }),
    el('span', { text: it.text }))));
}
function fillList(ul, texts) {
  clear(ul);
  for (const t of texts) ul.append(el('li', { text: t }));
}

// ---------------------------------------------------------------- tabs (WAI-ARIA tabs, arrow keys)
const TABS = ['key', 'protect', 'check', 'disclose', 'verify'];
function selectTab(name, focus = false) {
  for (const t of TABS) {
    const tab = $(`tab-${t}`);
    const on = t === name;
    tab.setAttribute('aria-selected', on ? 'true' : 'false');
    tab.tabIndex = on ? 0 : -1;
    show($(`panel-${t}`), on);
    if (on && focus) tab.focus();
  }
}
for (const t of TABS) $(`tab-${t}`).addEventListener('click', () => selectTab(t));
document.querySelector('[role="tablist"]').addEventListener('keydown', ev => {
  const i = TABS.findIndex(t => $(`tab-${t}`) === document.activeElement);
  if (i < 0) return;
  let j = null;
  if (ev.key === 'ArrowRight') j = (i + 1) % TABS.length;
  else if (ev.key === 'ArrowLeft') j = (i - 1 + TABS.length) % TABS.length;
  else if (ev.key === 'Home') j = 0;
  else if (ev.key === 'End') j = TABS.length - 1;
  if (j === null) return;
  ev.preventDefault();
  selectTab(TABS[j], true);
});

// ---------------------------------------------------------------- 1. Signing key
async function refreshKey() {
  state.info = (await platform.hasKey()) ? await platform.keyInfo() : null;
  const ks = T.keyStatus(state.caps, state.info);
  const status = clear($('key-status'));
  for (const line of ks.lines) status.append(el('p', { text: line }));
  fillList($('key-warnings'), ks.warnings);
  fillList($('key-notes'), ks.notes);
  show($('key-create'), !state.info);
  show($('key-manage'), !!state.info);
  $('key-prf-text').textContent = T.prfText(state.caps?.prf);
  $('key-create-passkey').disabled = state.caps?.prf === false;
  for (const id of ['protect-pass-wrap', 'check-pass-wrap', 'disclose-pass-wrap']) show($(id), needsPassphrase());
  $('key-delete-confirm').checked = false;
  $('key-delete').disabled = true;
  setStatus('app-status', state.info
    ? `Ready. Signing key fingerprint ${state.info.fingerprint}.`
    : "Ready. No key yet: create one in the 'Signing key' tab. The 'Verify' tab works without one.");
}

async function afterSetup(backup) {
  await platform.saveFile(T.KEY_BACKUP_NAME, backup, 'application/json');
  await refreshKey();
  setStatus('key-msg', `Signing key created and backup file (${T.KEY_BACKUP_NAME}) downloaded. Keep that file somewhere safe.`);
}

$('key-create-passkey').addEventListener('click', ev => run(ev.currentTarget, 'key-msg', { ctx: 'key' }, async () => {
  try {
    await afterSetup(await platform.setupKey({}));
  } catch (e) {
    if (e?.code === 'PRF_UNSUPPORTED') {
      setError('key-msg', e, { ctx: 'key' });
      $('key-pass').focus();
      return;
    }
    throw e;
  }
}));

$('key-create-pass').addEventListener('click', ev => run(ev.currentTarget, 'key-msg', { ctx: 'key' }, async () => {
  let p1 = takeSecret('key-pass');
  let p2 = takeSecret('key-pass2');
  const problem = T.passphraseProblem(p1, p2);
  if (problem) {
    p1 = p2 = undefined;
    setStatus('key-msg', problem);
    $('key-pass').focus();
    return;
  }
  p2 = undefined;
  let backup;
  try {
    setStatus('key-msg', 'Creating the key. Deriving it from the passphrase can take a few seconds.');
    backup = await platform.setupKey({ passphrase: p1 });
  } finally {
    p1 = undefined;
  }
  await afterSetup(backup);
}));

$('key-backup').addEventListener('click', ev => run(ev.currentTarget, 'key-msg', { ctx: 'key' }, async () => {
  await platform.saveFile(T.KEY_BACKUP_NAME, await platform.exportBackup(), 'application/json');
  setStatus('key-msg', `Backup file (${T.KEY_BACKUP_NAME}) downloaded.`);
}));

$('key-delete-confirm').addEventListener('change', ev => { $('key-delete').disabled = !ev.currentTarget.checked; });
$('key-delete').addEventListener('click', async ev => {
  const btn = ev.currentTarget;
  await run(btn, 'key-msg', { ctx: 'key' }, async () => {
    const yes = await platform.confirmAction(
      `This deletes the signing key from this browser. ${T.TEXT.keyLoss} Press OK only if you have kept the backup file.`);
    if (!yes) { setStatus('key-msg', 'Delete cancelled.'); return; }
    await platform.deleteKey();
    await refreshKey();
    setStatus('key-msg', 'Signing key deleted from this browser.');
  });
  btn.disabled = !$('key-delete-confirm').checked;
});

$('key-restore').addEventListener('click', ev => run(ev.currentTarget, 'key-msg', { ctx: 'key' }, async () => {
  const f = await fileBytes($('key-restore-file'));
  if (!f) { setStatus('key-msg', 'Select a backup file to restore.'); return; }
  if (await platform.hasKey()) {
    const yes = await platform.confirmAction(
      'This browser already has a signing key. Restoring overwrites it, and without a backup of the current key that key is gone. Continue?');
    if (!yes) { setStatus('key-msg', 'Restore cancelled.'); return; }
  }
  await platform.importBackup(f.bytes);
  $('key-restore-file').value = '';
  await refreshKey();
  setStatus('key-msg', 'Signing key restored from backup. Check that the public key fingerprint is the one you expect.');
}));

// ---------------------------------------------------------------- 2. Protect
function selectedMarkers() {
  return [...document.querySelectorAll('#protect-fields input[type=checkbox]')].filter(c => c.checked).map(c => c.dataset.field);
}
function updateThreshold() { $('protect-threshold').textContent = T.thresholdText(selectedMarkers()); }

function renderInspect(ins) {
  const forced = $('protect-format').value;
  const detected = clear($('protect-detected'));
  detected.append(el('span', {
    text: `${forced ? 'Chosen' : 'Detected'} format: ${T.formatText(ins.format)}, ${ins.rows} rows, ${ins.fields.length} fields. If the format is wrong, change 'Input format' above.`,
  }));
  $('protect-json-note').textContent = T.TEXT.jsonReserialize;
  show($('protect-json-note'), ins.format === 'json');

  const nameWarn = !forced && ins.format === 'csv' && /\.json$/i.test(state.input?.name ?? '');
  fillList($('protect-general-warnings'), [...(nameWarn ? [T.TEXT.jsonNameButCsv] : []), ...T.generalWarnings(ins)]);

  const rows = T.inspectRows(ins);
  const COLS = ['marker', 'field', 'kind', 'unique', 'distinct', 'missing'];
  const table = el('table', { class: 'fields' },
    el('caption', { class: 'sr-only', text: 'Field analysis. Use the checkboxes in the marker column to choose the fields used for matching. Warnings appear in the row below each field.' }),
    el('thead', {}, el('tr', {}, ...COLS.map(h => el('th', { scope: 'col', text: h })))));
  const body = el('tbody');
  rows.forEach((r, i) => {
    const id = `protect-marker-${i}`;
    const box = el('input', { type: 'checkbox', id, checked: r.checked, disabled: !r.eligible });
    box.dataset.field = r.name;
    box.addEventListener('change', updateThreshold);
    const lab = el('label', { for: id, class: 'sr-only', text: r.eligible ? `Use field ${r.name} as a marker` : `Field ${r.name} cannot be a marker (${r.kind})` });
    body.append(el('tr', { class: r.warnings.length ? 'has-warn' : null },
      el('td', {}, box, lab),
      el('th', { scope: 'row', text: r.name }),
      el('td', {}, r.kind, el('br'), el('span', { class: 'note', text: T.KIND_TEXT[r.kind] ?? '' })),
      el('td', { text: r.unique }),
      el('td', { text: r.distinct }),
      el('td', { text: r.missing })));
    if (r.warnings.length) {
      body.append(el('tr', { class: 'warn-row' },
        el('td', { colspan: COLS.length }, el('ul', { class: 'warn-list' }, ...r.warnings.map(w => el('li', { text: w }))))));
    }
  });
  table.append(body);
  clear($('protect-fields')).append(table);
  updateThreshold();
  show($('protect-options'), true);
}

function resetInspect() {
  state.ins = null;
  clear($('protect-detected'));
  clear($('protect-fields'));
  clear($('protect-general-warnings'));
  $('protect-threshold').textContent = '';
  show($('protect-json-note'), false);
  show($('protect-options'), false);
  show($('protect-result'), false);
}

async function runInspect() {
  resetInspect();
  if (!state.input) return;
  const forcedJson = $('protect-format').value === 'json';
  const jsonName = $('protect-format').value === '' && /\.json$/i.test(state.input.name);
  setStatus('protect-msg', 'Analyzing the file.');
  try {
    const ins = await platform.inspect({ input: state.input.bytes, format: $('protect-format').value || undefined });
    state.ins = ins;
    renderInspect(ins);
    setStatus('protect-msg', 'Analysis done. Review the markers and options, then press Protect.');
  } catch (e) {
    setError('protect-msg', e, { ctx: 'protect', forcedJson, jsonName });
  }
}

$('protect-file').addEventListener('change', async () => {
  state.input = await fileBytes($('protect-file'));
  state.protected = null;
  if (state.input && !$('protect-dsid').value) $('protect-dsid').value = T.evidenceStem(state.input.name);
  await runInspect();
});
$('protect-format').addEventListener('change', runInspect);

$('protect-run').addEventListener('click', ev => run(ev.currentTarget, 'protect-msg', () => ({ ctx: 'protect', forcedJson: $('protect-format').value === 'json' }), async () => {
  show($('protect-result'), false);
  if (!state.input || !state.ins) { setStatus('protect-msg', 'Select a data file first.'); return; }
  const datasetId = $('protect-dsid').value;
  const markers = selectedMarkers();
  const problem = T.datasetIdProblem(datasetId) ?? T.canaryCountProblem($('protect-n').value) ?? T.markerProblem(markers);
  if (problem) { setStatus('protect-msg', problem); return; }
  const excl = await fileText($('protect-excl'));
  const exclusions = excl ? T.parseExclusions(excl.text) : [];
  let passphrase = needsPassphrase() ? takeSecret('protect-pass') : undefined;
  let r;
  try {
    setStatus('protect-msg', 'Generating canaries and signing.');
    r = await platform.protect({
      input: state.input.bytes, format: $('protect-format').value || undefined, datasetId,
      n: Number($('protect-n').value), markerFields: markers, exclusions, passphrase,
    });
  } finally {
    passphrase = undefined;
  }
  const s = r.summary;
  const names = T.protectFileNames(state.input.name, s.format);
  state.protected = { marked: r.marked, evidenceJson: r.evidenceJson, names };
  const sum = clear($('protect-summary'));
  for (const line of [
    `Inserted ${s.canaries} canaries into ${s.rows} original rows (format ${T.formatText(s.format)}).`,
    `marker: ${s.markers.join(', ')} (matched when ${s.threshold} or more are found in one record)`,
    `exclusions: ${exclusions.length} values`,
    `evidence_id: ${s.evidenceId}`,
    `marked file: ${names.marked}`,
    `evidence file: ${names.evidence}`,
  ]) sum.append(el('p', { text: line }));
  show($('protect-result'), true);
  setStatus('protect-msg', 'Protected. Download both files below.');
}));

$('protect-save-marked').addEventListener('click', ev => run(ev.currentTarget, 'protect-msg', { ctx: 'protect' }, async () => {
  const p = state.protected;
  await platform.saveFile(p.names.marked, p.marked, p.names.markedMime);
  setStatus('protect-msg', `Downloaded ${p.names.marked}. This is the file to publish.`);
}));
$('protect-save-evidence').addEventListener('click', ev => run(ev.currentTarget, 'protect-msg', { ctx: 'protect' }, async () => {
  const p = state.protected;
  await platform.saveFile(p.names.evidence, te.encode(p.evidenceJson), 'application/json');
  setStatus('protect-msg', `Downloaded ${p.names.evidence}. Keep this file private.`);
}));

// ---------------------------------------------------------------- 3. Check
$('check-run').addEventListener('click', ev => run(ev.currentTarget, 'check-msg', { ctx: 'check' }, async () => {
  show($('check-result'), false);
  const suspect = await fileBytes($('check-suspect'));
  const evidence = await fileText($('check-evidence'));
  if (!suspect || !evidence) { setStatus('check-msg', 'Select both the suspicious copy and the evidence file.'); return; }
  let passphrase = needsPassphrase() ? takeSecret('check-pass') : undefined;
  let report;
  try {
    setStatus('check-msg', 'Opening canaries with the signing key and searching the copy.');
    report = await platform.check({ suspect: suspect.bytes, evidenceJson: evidence.text, passphrase });
  } finally {
    passphrase = undefined;
  }
  const v = T.checkView(report);
  $('check-commit').textContent = v.commitText ?? '';
  show($('check-commit'), !v.commitOk);
  $('check-counts').textContent = v.countsText;
  $('check-partial-note').textContent = v.partialNote ?? '';
  show($('check-partial-note'), !!v.partialNote);
  const table = el('table', {},
    el('caption', { class: 'sr-only', text: 'Check result per canary' }),
    el('thead', {}, el('tr', {}, ...['index', 'result', 'markers found', 'location in copy'].map(h => el('th', { scope: 'col', text: h })))),
    el('tbody', {}, ...v.rows.map(r => el('tr', {},
      el('td', { text: String(r.index) }), el('td', { text: r.status }), el('td', { text: r.found }), el('td', { text: r.hint })))));
  clear($('check-table')).append(table);
  $('check-evidence-items').replaceWith(Object.assign(resultList(v.evidenceItems), { id: 'check-evidence-items' }));
  $('check-anchor-items').replaceWith(Object.assign(resultList(v.anchorItems), { id: 'check-anchor-items' }));
  $('check-capture').textContent = T.TEXT.noCaptureProof;
  show($('check-next'), v.counts.matched > 0);
  show($('check-result'), true);
  state.lastCheck = { suspect: suspect.bytes, suspectName: suspect.name, evidenceJson: evidence.text, evidenceName: evidence.name, report, view: v };
  renderDisclose();
  setStatus('check-msg', `Check done. ${v.countsText}`);
}));

$('check-save-report').addEventListener('click', ev => run(ev.currentTarget, 'check-msg', { ctx: 'check' }, async () => {
  const c = state.lastCheck;
  const name = T.checkReportName(c.evidenceName);
  await platform.saveFile(name, te.encode(`${JSON.stringify(c.report, null, 2)}\n`), 'application/json');
  setStatus('check-msg', `Downloaded ${name}.`);
}));

// ---------------------------------------------------------------- 4. Disclose
function renderDisclose() {
  const c = state.lastCheck;
  show($('disclose-result'), false);
  clear($('disclose-msg'));
  const matched = c?.view.matchedIndices ?? [];
  if (!c || matched.length === 0) {
    $('disclose-empty').textContent = c
      ? 'The last check matched no canaries, so there is nothing to disclose. Which is good news, probably.'
      : "Nothing to disclose yet. Run a check in the 'Check' tab first; a disclosure package needs at least one matched canary.";
    show($('disclose-empty'), true);
    show($('disclose-form'), false);
    return;
  }
  show($('disclose-empty'), false);
  const src = clear($('disclose-source'));
  src.append(el('span', { text: `Last check: copy ${c.suspectName}, evidence ${c.evidenceName}, ${matched.length} matched` }));
  const grid = clear($('disclose-indices'));
  for (const i of matched) {
    const id = `disclose-idx-${i}`;
    const box = el('input', { type: 'checkbox', id, checked: true });
    box.dataset.index = String(i);
    grid.append(el('div', { class: 'check-row' }, box, el('label', { for: id, text: `canary ${i}` })));
  }
  show($('disclose-form'), true);
}

$('disclose-run').addEventListener('click', ev => run(ev.currentTarget, 'disclose-msg', { ctx: 'disclose' }, async () => {
  show($('disclose-result'), false);
  const c = state.lastCheck;
  if (!c) { setStatus('disclose-msg', "Run a check in the 'Check' tab first."); return; }
  const indices = [...document.querySelectorAll('#disclose-indices input[type=checkbox]')].filter(b => b.checked).map(b => Number(b.dataset.index));
  if (indices.length === 0) { setStatus('disclose-msg', 'Select at least 1 canary to disclose.'); return; }
  const suspectMeta = {
    sourceClaim: $('disclose-source-claim').value.trim(),
    capturedClaim: $('disclose-captured-claim').value.trim(),
    captureMethodClaim: $('disclose-method-claim').value.trim(),
  };
  let passphrase = needsPassphrase() ? takeSecret('disclose-pass') : undefined;
  let out;
  try {
    setStatus('disclose-msg', 'Building the disclosure package.');
    out = await platform.disclose({ evidenceJson: c.evidenceJson, suspect: c.suspect, indices, suspectMeta, passphrase });
  } finally {
    passphrase = undefined;
  }
  state.disclosureJson = out.disclosureJson;
  $('disclose-summary').textContent = `Built a package disclosing ${indices.length} canaries (index ${indices.join(', ')}). File name: ${T.disclosureName(c.evidenceName)}`;
  show($('disclose-result'), true);
  setStatus('disclose-msg', 'Disclosure package built. Download it below.');
}));

$('disclose-save').addEventListener('click', ev => run(ev.currentTarget, 'disclose-msg', { ctx: 'disclose' }, async () => {
  const name = T.disclosureName(state.lastCheck.evidenceName);
  await platform.saveFile(name, te.encode(state.disclosureJson), 'application/json');
  setStatus('disclose-msg', `Downloaded ${name}. Submit it together with the copy file (${state.lastCheck.suspectName}).`);
}));

// ---------------------------------------------------------------- 5. Verify (no key)
function renderVerify(view, verdictText) {
  const h = $('verify-verdict');
  h.textContent = verdictText;
  h.className = `big ${view?.pass ? 'verdict-pass' : 'verdict-fail'}`;
  const box = clear($('verify-sections'));
  for (const s of view?.sections ?? []) box.append(el('h4', { text: s.title }), resultList(s.items));
  const hasStatement = !!view?.statement;
  $('verify-statement-title').textContent = view?.statementTitle ?? '';
  $('verify-statement').textContent = hasStatement ? view.statement : '';
  show($('verify-statement-title'), hasStatement);
  show($('verify-statement'), hasStatement);
  show($('verify-result'), true);
}

$('verify-run').addEventListener('click', ev => run(ev.currentTarget, 'verify-msg', { ctx: 'verify' }, async () => {
  show($('verify-result'), false);
  const doc = await fileText($('verify-doc'));
  if (!doc) { setStatus('verify-msg', 'Select an evidence or disclosure package file. Nothing to verify yet.'); return; }
  const kind = T.docKind(doc.text);
  try {
    if (kind === 'disclosure') {
      const suspect = await fileBytes($('verify-suspect'));
      if (!suspect) { setStatus('verify-msg', 'To verify a disclosure package, also select the copy file submitted with it.'); return; }
      const view = T.disclosureSections(await platform.verifyDisclosure(doc.text, suspect.bytes));
      renderVerify(view, `Verdict: ${view.pass ? 'PASS' : 'FAIL'} (disclosure package ${doc.name})`);
    } else {
      const view = T.evidenceSections(await platform.verifyEvidence(doc.text));
      renderVerify(view, `Verdict: ${view.pass ? 'PASS' : 'FAIL'} (evidence ${doc.name})`);
    }
    setStatus('verify-msg', 'Verification done.');
  } catch (e) {
    renderVerify(null, 'Verdict: structural error. This file cannot be verified.');
    throw e;
  }
}));

// ---------------------------------------------------------------- static texts and start
function fillStaticTexts() {
  $('key-backup-text').textContent = `${T.TEXT.backupForced} ${T.TEXT.keyLoss}`;
  $('key-pass-rule').textContent = `${T.TEXT.passphraseRule} ${T.TEXT.passphraseMemory}`;
  $('protect-private').textContent = T.TEXT.evidencePrivate;
  $('protect-anchor-text').textContent = `${T.TEXT.anchorPending} ${T.TEXT.noTimeProof}`;
  fillList($('protect-limits'), T.TEXT.limits);
  $('disclose-before').textContent = T.TEXT.discloseBefore;
  $('disclose-nosecret').textContent = T.TEXT.discloseNoSecret;
  $('disclose-claim').textContent = T.TEXT.discloseClaim;
  $('disclose-submit').textContent = T.TEXT.discloseSubmit;
  $('disclose-capture').textContent = T.TEXT.noCaptureProof;
  $('verify-nokey').textContent = T.TEXT.verifyNoKey;
  $('protect-n').value = String(T.CANARY_DEFAULT);
}

window.addEventListener('pagehide', clearSecrets);

async function start() {
  fillStaticTexts();
  try {
    await platform.ready();
    state.caps = await platform.capabilities();
    await refreshKey();
  } catch (e) {
    setError('app-status', e);
  }
}
start();
