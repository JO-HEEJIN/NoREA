// UI wiring. Talks only to the platform contract (platform.js), never to WASM
// or key storage directly, so the same file runs in the browser and in Tauri.
import * as platform from './platform.js';

await platform.ready();

const $ = id => document.getElementById(id);
const te = new TextEncoder();
const td = new TextDecoder();

function status(msg, isError = false) {
  const el = $('status');
  el.textContent = msg;
  el.className = isError ? 'error' : '';
}
function run(fn) {
  return async () => {
    try { await fn(); } catch (e) { status(e?.message ?? String(e), true); }
  };
}
async function readFile(input, label, { optional = false } = {}) {
  const f = input.files?.[0];
  if (!f) {
    if (optional) return null;
    throw new Error(`${label} 파일을 선택하세요.`);
  }
  return new Uint8Array(await f.arrayBuffer());
}
const download = (name, bytes) => platform.saveFile(name, bytes);
const safe = s => s.replace(/[^\w.-]+/g, '_');
const pass = () => $('pass').value || undefined;

async function refreshKeyInfo() {
  const k = await platform.keyInfo();
  $('keyinfo').textContent = k
    ? `서명키 있음 (${k.method}). 공개키 지문: ${k.fingerprint}`
    : '아직 서명키가 없습니다.';
}

$('setup').onclick = run(async () => {
  if (await platform.hasKey() && !(await platform.confirmAction('기존 서명키를 덮어씁니다. 백업은 해두셨나요?'))) return;
  if (!pass() && !(await platform.prfAvailable())) {
    throw new Error('이 브라우저는 패스키 PRF를 지원하지 않습니다. 패스프레이즈를 입력하세요.');
  }
  status('서명키 만드는 중...');
  await download('norea-key-backup.json', await platform.setupKey({ passphrase: pass() }));
  await refreshKeyInfo();
  status('서명키를 만들었습니다. 방금 받은 백업 파일을 안전한 곳에 보관하세요. 잃으면 복구할 수 없습니다.');
});

$('restore').onclick = run(async () => {
  await platform.importBackup(await readFile($('backupfile'), '백업'));
  await refreshKeyInfo();
  status('백업을 복원했습니다.');
});

$('protect').onclick = run(async () => {
  const input = await readFile($('dataset'), '데이터셋');
  const registry = await readFile($('registry'), '실제 주소 목록', { optional: true });
  const datasetId = $('dsid').value.trim();
  const n = Number($('n').value);
  if (!datasetId) throw new Error('데이터셋 ID를 입력하세요.');
  if (!Number.isInteger(n) || n < 8 || n > 256) throw new Error('canary 개수는 8~256 사이로 정하세요.');
  const forbiddenAddrs = registry ? JSON.parse(td.decode(registry)) : [];
  if (!Array.isArray(forbiddenAddrs)) throw new Error('실제 주소 목록은 문자열 JSON 배열이어야 합니다.');
  status('보호하는 중...');
  const { marked, evidenceJson } = await platform.protect({ input, datasetId, n, forbiddenAddrs, passphrase: pass() });
  await download(`${safe(datasetId)}.marked.json`, marked);
  await download(`${safe(datasetId)}.evidence.json`, te.encode(evidenceJson));
  status(`보호 완료 (canary ${n}개). marked.json은 공개용, evidence.json은 비공개로 보관하세요. 원본 파일은 바뀌지 않았습니다.`);
});

$('check').onclick = run(async () => {
  const suspect = await readFile($('suspect'), '의심 사본');
  const evidenceJson = td.decode(await readFile($('evidence'), '증거'));
  status('대조하는 중...');
  const rep = await platform.check({ suspect, evidenceJson, passphrase: pass() });
  $('report').textContent = JSON.stringify(rep, null, 2);
  const verdict = !rep.canary_commit_ok
    ? '이 증거와 맞지 않는 키입니다. 다른 서명키로 만든 증거일 수 있습니다.'
    : rep.matched > 0
      ? `canary ${rep.total}개 중 ${rep.matched}개가 사본에서 발견됐습니다.`
      : '이 사본에서는 canary가 발견되지 않았습니다.';
  status(`${verdict} 증거 서명: ${rep.evidence_signature_ok ? '유효' : '무효'}`);
});

refreshKeyInfo();
