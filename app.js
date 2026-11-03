'use strict';
/* Passwarium 2.0 — клиент. Zero-knowledge: мастер-пароль не покидает устройство,
   на сервере только шифртекст (AES-256-GCM) и хеш токена доступа. */

/* ==================== утилиты ==================== */
const $ = s => document.querySelector(s);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
};
const te = new TextEncoder();
const td = new TextDecoder();
const b64u8 = u8 => { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); };
const u8b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rand = n => { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
const randInt = n => {
  const lim = Math.floor(4294967296 / n) * n;
  const b = new Uint32Array(1); let x;
  do { crypto.getRandomValues(b); x = b[0]; } while (x >= lim);
  return x % n;
};
const pick = a => a[randInt(a.length)];
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg; t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 1800);
}

/* ==================== генератор ==================== */
// Слоги выбираются РАВНОВЕРОЯТНО из фиксированного списка — поэтому стойкость
// честно считается как log2 от размера пространства, без завышений.
// Без букв O o I l — они путаются при наборе.
const VOWELS = 'aeiu';
const CONS = 'bcdfghjkmnpqrstvwxz';
const DIGR = ['br','ch','dr','fr','gr','kr','nd','nt','ph','pr',
              'sh','sk','sm','sn','sp','st','str','th','tr','tw'];
const DIGITS = '0123456789';
const SPECIALS = '-@!?&$*';                    // первый слой символов iOS и Android
const SYLL = [];                               // все слоги: (19+20)*4*(1+19) = 3120
const SYLL_C = [];                             // слоги с одиночной согласной: 19*4*20 = 1520
for (const c of [...CONS, ...DIGR]) for (const v of VOWELS) {
  const cv = c + v;
  SYLL.push(cv);
  if (c.length === 1) SYLL_C.push(cv);
  for (const c2 of CONS) {
    SYLL.push(cv + c2);
    if (c.length === 1) SYLL_C.push(cv + c2);
  }
}
const BITS_SYLL = Math.log2(SYLL.length);      // ≈ 11,61 бит
const BITS_SYLL_C = Math.log2(SYLL_C.length);  // ≈ 10,57 бит
const digitCountFor = len => (len >= 28 ? 3 : len >= 16 ? 2 : 1);

// Собирает слово из слогов. Если предыдущий слог кончился согласной, следующий
// начинается только с одиночной согласной (SYLL_C) — иначе на стыке выросли бы
// 4 согласные подряд. Это уменьшает пространство, и мы честно учитываем меньший
// список в оценке. Возвращает { word, bits }.
function makeWord(maxLen, trace) {
  const out = [];
  let len = 0, bits = 0, endedCons = false;
  for (let guard = 0; guard < 40; guard++) {
    const list = endedCons ? SYLL_C : SYLL;
    const s = pick(list);
    if (len + s.length > maxLen) break;        // слог не обрезаем — обрезка крала бы биты
    out.push(s);
    if (trace) trace.push(s);                  // для теста честности распределения
    bits += Math.log2(list.length);
    len += s.length;
    endedCons = CONS.includes(s[s.length - 1]);
    if (maxLen - len < 2) break;               // короче 2 символов слогов нет
  }
  if (!out.length) {                           // maxLen < 2 — крайний случай
    const s = pick(VOWELS);
    return { word: s, bits: Math.log2(VOWELS.length) };
  }
  return { word: out.join(''), bits };
}

// Пароль: слово с заглавной (детерминировано — 0 бит) + группа цифр и одного
// спецсимвола. Биты: слоги + цифры + спецсимвол + позиция спецсимвола + позиция группы.
function makePassword(len) {
  const dc = digitCountFor(len);
  const { word, bits } = makeWord(len - dc - 1);
  let group = '';
  for (let i = 0; i < dc; i++) group += DIGITS[randInt(10)];
  group = randInt(2) ? group + pick(SPECIALS) : pick(SPECIALS) + group;
  const text = (randInt(2) ? word[0].toUpperCase() + word.slice(1) + group
                           : group + word[0].toUpperCase() + word.slice(1));
  const total = bits + dc * Math.log2(10) + Math.log2(SPECIALS.length) + 2;
  return { text, bits: Math.floor(total) };
}

// Мастер-пароль: 6 слогов + 3 цифры + спецсимвол, ≥ 70 бит по нижней оценке.
function makeMasterPassword() {
  const { word, bits } = (() => {
    let w = '', b = 0, endedCons = false;
    for (let i = 0; i < 6; i++) {
      const list = endedCons ? SYLL_C : SYLL;
      const s = pick(list);
      w += s; b += Math.log2(list.length);
      endedCons = CONS.includes(s[s.length - 1]);
    }
    return { word: w, bits: b };
  })();
  let group = '';
  for (let i = 0; i < 3; i++) group += DIGITS[randInt(10)];
  group += pick(SPECIALS);
  const text = word[0].toUpperCase() + word.slice(1) + '-' + group;
  return { text, bits: Math.floor(bits + 3 * Math.log2(10) + Math.log2(SPECIALS.length)) };
}

let currentList = [];
function strengthHint(bits) {
  return bits >= 60 ? 'подойдёт для мастер-пароля' : bits < 50 ? 'для сайтов' : 'крепкий';
}
function generateBatch() {
  const len = +$('#len').value, count = +$('#cnt-val').textContent;
  const set = new Set(), out = [];
  let tries = 0;
  while (out.length < count && tries++ < 300) {
    const p = makePassword(len);
    if (!set.has(p.text)) { set.add(p.text); out.push(p); }
  }
  currentList = out;
  $('#results-empty').hidden = out.length > 0;
  renderResults();
  if (!$('#screen-main').hidden) {
    const smooth = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    window.scrollTo({ top: 0, behavior: smooth ? 'smooth' : 'auto' });
  }
}
function pwCopyButton(text) {
  const b = el('button', 'pw pwcopy', text);
  b.type = 'button';
  b.setAttribute('aria-label', 'Скопировать: ' + text);
  b.addEventListener('click', () => doCopy(text));
  return b;
}
function renderResults() {
  const box = $('#results');
  box.textContent = '';
  currentList.forEach(p => {
    const card = el('div', 'pcard');
    card.append(pwCopyButton(p.text));
    card.append(el('div', 'meta', `≥ ${p.bits} бит · ${p.text.length} симв. · ${strengthHint(p.bits)}`));
    const row = el('div', 'prow');
    const bc = el('button', 'act primary', 'Копировать');
    bc.type = 'button';
    bc.addEventListener('click', () => doCopy(p.text));
    const bs = el('button', 'act', 'В сейф');
    bs.type = 'button';
    bs.addEventListener('click', () => openEntrySheet(null, p.text));
    row.append(bc, bs);
    card.append(row);
    box.append(card);
  });
}
let lastCopied = null;
async function doCopy(text) {
  let ok = false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      ok = true;
    }
  } catch (e) { /* fallback ниже */ }
  if (!ok) {
    const ta = el('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
    document.body.append(ta);
    ta.focus(); ta.select();
    try { ok = document.execCommand('copy'); } catch (e) {}
    ta.remove();
  }
  toast(ok ? 'Скопировано (буфер очистится через 30 с)' : 'Не удалось скопировать');
  // автоочистка буфера обмена через 30 с, если там всё ещё наш текст
  if (ok && navigator.clipboard && window.isSecureContext) {
    lastCopied = text;
    const snapshot = text;
    clearTimeout(doCopy._t);
    doCopy._t = setTimeout(async () => {
      if (lastCopied !== snapshot) return;
      try {
        const cur = await navigator.clipboard.readText();
        if (cur === snapshot) await navigator.clipboard.writeText('');
      } catch (e) { /* нет разрешения на чтение буфера — пропускаем */ }
    }, 30000);
  }
}

/* ==================== состояние ==================== */
const KDF_V3 = { alg: 'argon2id', m: 65536, t: 3, p: 1 };  // 64 МиБ — не снижаем молча
const state = {
  vaultId: null, encKey: null, authTok: null, kdf: null,
  legacyKey: null,            // ключ записи legacy-ссылки (только для старых сейфов с wsha)
  legacy: false,              // открыт старый формат v1/v2 — только чтение + миграция
  localOnly: false,           // сейф живёт только в этом браузере
  entries: new Map(),         // id -> {id,label,login,url,password,createdAt,updatedAt,deleted}
  dirty: false, pushTimer: null,
  locked: true, lastActivity: Date.now(),
};
const settings = JSON.parse(localStorage.getItem('pw.settings') || '{"autolock":5}');

/* ==================== крипто v3 ==================== */
// master  = Argon2id(пароль, salt, m/t/p из сейфа) → 32 байта
// encKey  = HKDF-SHA256(master, "passwarium/v3/enc")  → AES-256-GCM
// authTok = HKDF-SHA256(master, "passwarium/v3/auth") → Bearer-токен (на сервере — sha256)
async function hkdf256(masterU8, info) {
  const key = await crypto.subtle.importKey('raw', masterU8, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode(info) }, key, 256);
  return new Uint8Array(bits);
}
const b64url = u8 => b64u8(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function sha256hex(text) {
  const d = await crypto.subtle.digest('SHA-256', te.encode(text));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function deriveV3(password, kdf) {
  // kdf: {alg, m, t, p, salt(b64)}
  const master = await hashwasm.argon2id({
    password: te.encode(password), salt: u8b64(kdf.salt),
    parallelism: kdf.p, memorySize: kdf.m, iterations: kdf.t,
    hashLength: 32, outputType: 'binary',
  });
  const encRaw = await hkdf256(master, 'passwarium/v3/enc');
  const tokRaw = await hkdf256(master, 'passwarium/v3/auth');
  master.fill(0);
  const encKey = await crypto.subtle.importKey('raw', encRaw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const authTok = b64url(tokRaw);
  const asha = await sha256hex(authTok);
  return { encKey, authTok, asha, kdf: { alg: 'argon2id', m: kdf.m, t: kdf.t, p: kdf.p, salt: kdf.salt } };
}
const aadOf = vaultId => te.encode('passwarium/v3|' + vaultId);
async function encryptStateV3() {
  const iv = rand(12);
  const payload = te.encode(JSON.stringify({ entries: [...state.entries.values()] }));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aadOf(state.vaultId) }, state.encKey, payload);
  return {
    v: 3,
    kdf: { alg: 'argon2id', m: state.kdf.m, t: state.kdf.t, p: state.kdf.p, salt: state.kdf.salt },
    iv: b64u8(iv), ct: b64u8(new Uint8Array(ct)), updatedAt: Date.now(),
  };
}
async function decryptV3(encKey, vaultId, blob) {
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: u8b64(blob.iv), additionalData: aadOf(vaultId) },
      encKey, u8b64(blob.ct));
  } catch (e) {
    throw new Error('BAD_MAC');
  }
  const obj = JSON.parse(td.decode(plain));
  if (!obj || !Array.isArray(obj.entries)) throw new Error('BAD_PAYLOAD');
  return obj.entries;
}

/* ---------- legacy: чтение сейфов v1/v2 (crypto-js, bug-for-bug) ---------- */
// Байты → WordArray: по 4 байта на 32-битное слово, явный sigBytes.
function waFromU8(u8) {
  const w = [];
  for (let i = 0; i < u8.length; i++) w[i >>> 2] |= u8[i] << (24 - (i % 4) * 8);
  return CryptoJS.lib.WordArray.create(w, u8.length);
}
// ВНИМАНИЕ, legacy: в формате v=1 байты ошибочно передавались в WordArray.create
// напрямую — каждый байт становился отдельным 32-битным словом, а concat
// по такому массиву молча терял данные (HMAC фактически не покрывал шифртекст).
// Старые сейфы открываем bug-for-bug.
function waLegacy(u8) { return CryptoJS.lib.WordArray.create(u8); }
function waOf(u8, legacy) { return legacy ? waLegacy(u8) : waFromU8(u8); }
function isLegacyBlob(blob) { return !blob.v || blob.v < 3; }

function deriveKeysLegacy(password, saltB64, iterations, legacy) {
  const saltWA = waOf(u8b64(saltB64), legacy);
  const master = CryptoJS.PBKDF2(password, saltWA, {
    keySize: 512 / 32, iterations: iterations || 600000, hasher: CryptoJS.algo.SHA256,
  });
  return {
    aes: CryptoJS.lib.WordArray.create(master.words.slice(0, 8), 32),
    mac: CryptoJS.lib.WordArray.create(master.words.slice(8, 16), 32),
  };
}
function decryptBlobLegacy(keys, blob) {
  const legacy = !blob.v || blob.v < 2;
  const ivWA = waOf(u8b64(blob.iv), legacy);
  const ctWA = CryptoJS.enc.Base64.parse(blob.ct);
  const mac = CryptoJS.HmacSHA256(ivWA.clone().concat(ctWA), keys.mac).toString(CryptoJS.enc.Base64);
  if (mac !== blob.mac) throw new Error('BAD_MAC');
  const params = CryptoJS.lib.CipherParams.create({ ciphertext: ctWA });
  const plain = CryptoJS.AES.decrypt(params, keys.aes, { iv: ivWA, padding: CryptoJS.pad.Pkcs7 })
    .toString(CryptoJS.enc.Utf8);
  const obj = JSON.parse(plain);
  if (!obj || !Array.isArray(obj.entries)) throw new Error('BAD_PAYLOAD');
  return obj.entries;
}
function mergeEntries(lists) {
  const map = new Map();
  for (const list of lists) for (const e of list || []) {
    if (!e || !e.id) continue;
    const cur = map.get(e.id);
    if (!cur || (e.updatedAt || 0) > (cur.updatedAt || 0)) map.set(e.id, e);
  }
  const cutoff = Date.now() - 90 * 864e5;   // старые tombstone-удаления вычищаем
  for (const [id, e] of map) if (e.deleted && (e.updatedAt || 0) < cutoff) map.delete(id);
  return map;
}

// crypto-js тяжёлый и нужен только для старых сейфов — грузим лениво
let legacyLoading = null;
function loadLegacyCrypto() {
  if (typeof CryptoJS !== 'undefined') return Promise.resolve();
  if (typeof document === 'undefined') return Promise.reject(new Error('NO_DOM'));
  if (!legacyLoading) legacyLoading = new Promise((res, rej) => {
    const s = document.createElement('script');
    s.src = 'crypto-legacy.js';
    s.onload = () => res();
    s.onerror = () => rej(new Error('NO_LEGACY'));
    document.head.append(s);
  });
  return legacyLoading;
}

/* ==================== синхронизация ==================== */
function setSync(kind, text) {
  $('#sync-dot').className = 'dot ' + kind;
  $('#sync-text').textContent = text;
}
function authHeaders(extra) {
  return Object.assign({ 'Authorization': 'Bearer ' + state.authTok }, extra || {});
}
async function persistLocal() {
  if (!state.encKey) return;
  const blob = await encryptStateV3();
  localStorage.setItem('pw.blob.' + state.vaultId, JSON.stringify(blob));
}
async function markDirty() {
  state.dirty = true;
  await persistLocal();                 // локальная копия обновляется сразу — работает и офлайн
  if (state.localOnly) {
    state.dirty = false;
    setSync('ok', 'Локально');
    return;
  }
  setSync('busy', 'Сохранение…');
  clearTimeout(state.pushTimer);
  state.pushTimer = setTimeout(pushVault, 1200);
}
function vaultUrl() {
  return location.href.split('#')[0] + '#/v/' + state.vaultId;
}
async function pushVault(newAsha) {
  if (!state.dirty && !newAsha) return;
  if (!state.encKey || state.localOnly) return;
  try {
    const blob = await encryptStateV3();
    if (newAsha) blob.newasha = newAsha;   // ротация токена при смене мастер-пароля
    const r = await fetch('/vault/' + state.vaultId, {
      method: 'PUT',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(blob),
    });
    if (r.status === 401) { setSync('off', 'Синхронизация отклонена'); return false; }
    if (r.status === 429) { setSync('off', 'Сервер просит подождать'); return false; }
    if (!r.ok) throw new Error(r.status);
    state.dirty = false;
    setSync('ok', 'Синхронизировано');
    return true;
  } catch (e) {
    setSync('off', 'Нет связи');
    return false;
  }
}
// GET метаданных (соль и KDF-параметры) — публично, соль не секретна
async function fetchMeta(id) {
  try {
    const r = await fetch('/vault/' + id + '/meta', { cache: 'no-store' });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(r.status);
    const meta = await r.json();
    if (!meta || meta.v !== 3 || !meta.kdf || !meta.kdf.salt) return null;
    return meta;
  } catch (e) {
    return undefined;   // ошибка связи (отличаем от «сейфа нет»)
  }
}
// GET сейфа. Без токена — только legacy; v3 требует Bearer.
async function fetchRemoteBlob(tok) {
  try {
    // токен передаётся явно: при разблокировке на новом устройстве state.authTok ещё пуст
    const headers = tok ? { 'Authorization': 'Bearer ' + tok } : {};
    const r = await fetch('/vault/' + state.vaultId,
      Object.assign({ cache: 'no-store' }, tok ? { headers } : {}));
    if (r.status === 404) return null;
    if (r.status === 401) return 'AUTH';
    if (r.status === 429) return 'THROTTLED';
    if (!r.ok) throw new Error(r.status);
    const blob = await r.json();
    if (!blob || !blob.ct) return null;
    return blob;
  } catch (e) {
    return undefined;
  }
}
// POST создания сейфа; createToken — с PW_CREATE_TOKEN владельца сервера
async function createRemoteVault(id, asha, blob, createToken) {
  const headers = { 'Content-Type': 'application/json' };
  if (createToken) headers['X-Create-Token'] = createToken;
  const r = await fetch('/vault', {
    method: 'POST', headers,
    body: JSON.stringify({ id, asha, vault: blob }),
  });
  return r.status;
}

/* ==================== разблокировка / создание ==================== */
function lockError(msg) {
  const e = $('#lock-err');
  e.textContent = msg; e.hidden = false;
}
function showUnlock() {
  $('#form-unlock').hidden = false;
  $('#lock-create').hidden = true;
  $('#lock-err').hidden = true;
  $('#btn-toggle-create').textContent = 'Создать новый сейф';
}
function showCreateOnly(note) {
  $('#form-unlock').hidden = true;
  $('#lock-create').hidden = false;
  $('#create-note').textContent = note || '';
  $('#lock-err').hidden = true;
  $('#btn-toggle-create').textContent = '← Разблокировать существующий';
}
function showMain() {
  $('#screen-lock').hidden = true;
  $('#screen-main').hidden = false;
  $('#legacy-banner').hidden = !state.legacy;
  window.scrollTo(0, 0);
  if (!currentList.length) generateBatch();
  renderVault();
}
function lock() {
  state.encKey = null; state.authTok = null; state.kdf = null;
  state.entries = new Map();
  state.locked = true; state.dirty = false; state.legacy = false; state.localOnly = false;
  clearTimeout(state.pushTimer);
  ['#mp', '#mp-new', '#mp-new2', '#mp-cur', '#mp-ch-new', '#mp-ch-new2', '#create-token'].forEach(s => { $(s).value = ''; });
  $('#create-token-row').hidden = true;
  updateStrength($('#mp-new'), $('#strength'), $('#strength-label'));
  updateStrength($('#mp-ch-new'), $('#strength-ch'), $('#strength-ch-label'));
  $('#screen-main').hidden = true;
  $('#screen-lock').hidden = false;
  showUnlock();
  $('#mp').focus();
}

async function unlockVault(mp) {
  const btn = $('#btn-unlock');
  btn.disabled = true; btn.textContent = 'Расшифровка…';
  $('#lock-err').hidden = true;
  await new Promise(r => setTimeout(r, 30));   // дать отрисоваться «Расшифровка…»
  try {
    const localRaw = localStorage.getItem('pw.blob.' + state.vaultId);
    const local = localRaw ? JSON.parse(localRaw) : null;

    if (local && local.v === 3) return await unlockV3(mp, local);
    if (local && isLegacyBlob(local)) return await unlockLegacy(mp, local);

    // локальной копии нет — узнаём формат по метаданным
    const meta = await fetchMeta(state.vaultId);
    if (meta === undefined) throw new Error('NO_NET');
    if (meta) return await unlockV3(mp, null, meta);
    // метаданных нет — возможно, legacy-сейф (он открыт без токена)
    const blob = await fetchRemoteBlob(null);
    if (blob === undefined) throw new Error('NO_NET');
    if (blob && isLegacyBlob(blob)) return await unlockLegacy(mp, null, blob);
    if (blob === 'AUTH') throw new Error('BAD_MAC');
    throw new Error('NO_VAULT');
  } catch (e) {
    if (e.message === 'BAD_MAC') lockError('Неверный мастер-пароль.');
    else if (e.message === 'NO_VAULT') lockError('Сейф не найден ни локально, ни на сервере.');
    else if (e.message === 'NO_NET') lockError('Нет связи с сервером.');
    else if (e.message === 'NO_MEMORY') lockError('Устройству не хватает памяти для Argon2 (64 МиБ). Откройте сейф на более мощном устройстве.');
    else lockError('Не удалось расшифровать сейф. Проверьте пароль и связь.');
  } finally {
    btn.disabled = false; btn.textContent = 'Разблокировать';
  }
}

async function unlockV3(mp, local, meta) {
  const kdf = local ? local.kdf : meta.kdf;
  let d;
  try {
    d = await deriveV3(mp, kdf);
  } catch (e) {
    throw new Error('NO_MEMORY');   // wasm не смог выделить 64 МиБ
  }
  const lists = [];
  let remoteList = null, opened = 0, lastErr = null;
  if (local) {
    try { lists.push(await decryptV3(d.encKey, state.vaultId, local)); opened++; }
    catch (e) { lastErr = e; }
  }
  const remote = await fetchRemoteBlob(d.authTok);
  if (remote === 'AUTH' && !opened) throw new Error('BAD_MAC');
  if (remote === 'THROTTLED') throw new Error('NO_NET');
  if (remote && remote !== 'AUTH' && remote !== 'THROTTLED' && remote !== null) {
    try { remoteList = await decryptV3(d.encKey, state.vaultId, remote); lists.push(remoteList); opened++; }
    catch (e) { lastErr = e; }
  }
  if (!opened) throw lastErr || new Error('BAD_MAC');
  state.entries = mergeEntries(lists);
  state.encKey = d.encKey; state.authTok = d.authTok; state.kdf = d.kdf;
  state.legacy = false; state.localOnly = false;
  state.locked = false;
  await persistLocal();
  if (!remote || remote === 'AUTH') {
    await markDirty();
  } else {
    const same = remoteList && JSON.stringify(remoteList) === JSON.stringify([...state.entries.values()]);
    if (!same) await markDirty(); else setSync('ok', 'Синхронизировано');
  }
  showMain();
}

async function unlockLegacy(mp, local, remote) {
  await loadLegacyCrypto();
  const base = local || remote;
  const iterations = base.iterations || 150000;
  const legacyV1 = !base.v || base.v < 2;
  const keys = deriveKeysLegacy(mp, base.salt, iterations, legacyV1);
  const lists = [];
  let opened = 0, lastErr = null;
  if (local) {
    try { lists.push(decryptBlobLegacy(keys, local)); opened++; } catch (e) { lastErr = e; }
  }
  if (!local) {
    const r = remote || await fetchRemoteBlob(null);
    if (r && r.ct) {
      try { lists.push(decryptBlobLegacy(keys, r)); opened++; } catch (e) { lastErr = e; }
    }
  }
  if (!opened) throw lastErr || new Error('BAD_MAC');
  state.entries = mergeEntries(lists);
  state.legacy = true;               // только чтение + предложение миграции
  state.locked = false;
  state.encKey = null; state.authTok = null;
  showMain();
  toast('Сейф в старом формате — нажмите «Обновить формат»');
}

async function createVault() {
  const mp = $('#mp-new').value, mp2 = $('#mp-new2').value;
  if (mp.length < 8) return lockError('Мастер-пароль: минимум 8 символов.');
  if (mp !== mp2) return lockError('Пароли не совпадают.');
  if (estimateBits(mp) < 50 && !$('#mp-weak-ok').checked)
    return lockError('Мастер-пароль слабоват (оценка < 50 бит). Отметьте «понимаю риск» или возьмите подлиннее.');
  $('#lock-err').hidden = true;
  const btn = $('#form-create').querySelector('button[type=submit]');
  btn.disabled = true;
  await new Promise(r => setTimeout(r, 30));
  try {
    const kdf = { alg: 'argon2id', m: KDF_V3.m, t: KDF_V3.t, p: KDF_V3.p, salt: b64u8(rand(16)) };
    let d;
    try {
      d = await deriveV3(mp, kdf);
    } catch (e) {
      return lockError('Устройству не хватает памяти для Argon2 (64 МиБ). Попробуйте другое устройство.');
    }
    state.vaultId = b64u8(rand(20)).replace(/[^A-Za-z0-9]/g, '').slice(0, 28);
    state.encKey = d.encKey; state.authTok = d.authTok; state.kdf = d.kdf;
    state.entries = new Map();
    state.legacy = false;
    state.locked = false;

    const blob = await encryptStateV3();
    const createToken = $('#create-token').value.trim() || localStorage.getItem('pw.createToken') || '';
    let status = 0;
    try {
      status = await createRemoteVault(state.vaultId, d.asha, blob, createToken);
    } catch (e) { status = -1; }
    if (status === 200) {
      if (createToken) localStorage.setItem('pw.createToken', createToken);
      state.localOnly = false;
      location.hash = '#/v/' + state.vaultId;
      history.replaceState(null, '', location.href);
      await persistLocal();
      showMain();
      setSync('ok', 'Синхронизировано');
      toast('Сейф создан');
    } else if (status === 403 && !$('#create-token-row').hidden && $('#create-token').value.trim()) {
      lockError('Токен создания не подошёл.');
    } else if (status === 403) {
      // сервер закрыт для создания: просим токен владельца или предлагаем локальный сейф
      $('#create-token-row').hidden = false;
      lockError('Сервер закрыт для создания сейфов. Введите токен создания (его знает владелец сервера) — или создайте локальный сейф:');
    } else {
      // нет связи / сервер без API — локальный режим
      state.localOnly = true;
      location.hash = '#/v/' + state.vaultId;
      history.replaceState(null, '', location.href);
      await persistLocal();
      showMain();
      setSync('ok', 'Локально');
      toast('Локальный сейф: только этот браузер');
    }
  } catch (e) {
    lockError('Не удалось создать сейф.');
  } finally {
    btn.disabled = false;
  }
}

async function createLocalVault() {
  // принудительно локальный сейф из формы создания
  const mp = $('#mp-new').value, mp2 = $('#mp-new2').value;
  if (mp.length < 8) return lockError('Мастер-пароль: минимум 8 символов.');
  if (mp !== mp2) return lockError('Пароли не совпадают.');
  $('#lock-err').hidden = true;
  try {
    const kdf = { alg: 'argon2id', m: KDF_V3.m, t: KDF_V3.t, p: KDF_V3.p, salt: b64u8(rand(16)) };
    const d = await deriveV3(mp, kdf);
    state.vaultId = b64u8(rand(20)).replace(/[^A-Za-z0-9]/g, '').slice(0, 28);
    state.encKey = d.encKey; state.authTok = d.authTok; state.kdf = d.kdf;
    state.entries = new Map();
    state.legacy = false; state.localOnly = true; state.locked = false;
    location.hash = '#/v/' + state.vaultId;
    history.replaceState(null, '', location.href);
    await persistLocal();
    showMain();
    setSync('ok', 'Локально');
    toast('Локальный сейф: только этот браузер');
  } catch (e) {
    lockError('Не удалось создать сейф.');
  }
}

/* ==================== миграция v1/v2 → v3 ==================== */
async function migrateLegacy() {
  const mp = $('#mig-mp').value;
  const err = m => { const e = $('#mig-err'); e.textContent = m; e.hidden = false; };
  $('#mig-err').hidden = true;
  if (!mp) return err('Введите мастер-пароль.');
  const btn = $('#mig-ok');
  btn.disabled = true; btn.textContent = 'Перенос…';
  await new Promise(r => setTimeout(r, 30));
  try {
    // 1) проверяем пароль на старом формате и обязательно скачиваем бэкап СТАРОГО сейфа
    await loadLegacyCrypto();
    const oldRaw = localStorage.getItem('pw.blob.' + state.vaultId);
    let oldBlob = oldRaw ? JSON.parse(oldRaw) : null;
    if (!oldBlob) {
      const r = await fetchRemoteBlob(null);
      if (!r || !r.ct) throw new Error('NO_NET');
      oldBlob = r;
    }
    const oldKeys = deriveKeysLegacy(mp, oldBlob.salt, oldBlob.iterations || 150000, !oldBlob.v || oldBlob.v < 2);
    const oldEntries = decryptBlobLegacy(oldKeys, oldBlob);   // BAD_MAC, если пароль неверен
    downloadText('passwarium-backup-legacy-' + state.vaultId.slice(0, 8) + '.json',
                 JSON.stringify(oldBlob, null, 2), 'application/json');

    // 2) новый сейф v3 с новым id
    const kdf = { alg: 'argon2id', m: KDF_V3.m, t: KDF_V3.t, p: KDF_V3.p, salt: b64u8(rand(16)) };
    const d = await deriveV3(mp, kdf);
    const oldId = state.vaultId;
    state.vaultId = b64u8(rand(20)).replace(/[^A-Za-z0-9]/g, '').slice(0, 28);
    state.encKey = d.encKey; state.authTok = d.authTok; state.kdf = d.kdf;
    state.entries = mergeEntries([oldEntries]);
    state.legacy = false;

    const blob = await encryptStateV3();
    const createToken = $('#mig-token').value.trim() || localStorage.getItem('pw.createToken') || '';
    let status = -1;
    try { status = await createRemoteVault(state.vaultId, d.asha, blob, createToken); } catch (e) {}
    if (status === 200) {
      if (createToken) localStorage.setItem('pw.createToken', createToken);
      state.localOnly = false;
    } else if (status === 403 && !createToken) {
      $('#mig-token-row').hidden = false;
      state.vaultId = oldId; state.legacy = true; state.encKey = null; state.authTok = null;
      return err('Сервер закрыт для создания. Введите токен создания (его знает владелец сервера) и повторите.');
    } else if (status === 403) {
      state.vaultId = oldId; state.legacy = true; state.encKey = null; state.authTok = null;
      return err('Токен создания не подошёл.');
    } else {
      state.localOnly = true;   // нет связи — переносим в локальный сейф
    }
    localStorage.removeItem('pw.blob.' + oldId);
    location.hash = '#/v/' + state.vaultId;
    history.replaceState(null, '', location.href);
    await persistLocal();
    closeSheets();
    showMain();
    setSync('ok', state.localOnly ? 'Локально' : 'Синхронизировано');
    toast('Сейф обновлён до v3');
    openQR();   // новая ссылка — старая устарела
  } catch (e) {
    if (e.message === 'BAD_MAC') err('Мастер-пароль неверен.');
    else err('Не удалось перенести сейф. Проверьте связь.');
  } finally {
    btn.disabled = false; btn.textContent = 'Перенести в новый формат';
  }
}

/* ==================== сейф: интерфейс ==================== */
function activeEntries() {
  return [...state.entries.values()].filter(e => !e.deleted);
}
function trashedEntries() {
  return [...state.entries.values()].filter(e => e.deleted);
}
function renderVaultMeta() {
  $('#vcount').textContent = activeEntries().length;
  const n = trashedEntries().length;
  $('#trash-wrap').hidden = n === 0;
  $('#trash-toggle').textContent = `Корзина (${n}) ${$('#tlist').hidden ? '▸' : '▾'}`;
}
const SVG_NS = 'http://www.w3.org/2000/svg';
function svgIcon(paths) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('viewBox', '0 0 24 24');
  for (const p of paths) {
    const node = document.createElementNS(SVG_NS, p[0]);
    for (const k in p[1]) node.setAttribute(k, p[1][k]);
    svg.append(node);
  }
  return svg;
}
const EYE_OPEN = [['path', { d: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z' }], ['circle', { cx: 12, cy: 12, r: 3 }]];
const EYE_OFF = [['path', { d: 'M9.9 4.24A9.5 9.5 0 0 1 12 4c6.5 0 10 8 10 8a17 17 0 0 1-2.16 3.19M6.61 6.61A16.6 16.6 0 0 0 2 12s3.5 8 10 8a9.7 9.7 0 0 0 5.39-1.61' }], ['line', { x1: 2, y1: 2, x2: 22, y2: 22 }], ['path', { d: 'M9.88 9.88a3 3 0 1 0 4.24 4.24' }]];
// маска пароля — пузырьки (айдентика Passwarium)
const bubbleMask = len => {
  const n = Math.min(len, 14);
  let s = '';
  for (let i = 0; i < n; i++) s += i % 2 ? '◦' : '○';
  return s;
};
function vaultCard(e, isTrash) {
  const card = el('div', 'vcard' + (isTrash ? ' trash-zone' : ''));
  const top = el('div', 'vtop');
  top.append(el('span', 'vlabel', e.label));
  top.append(el('span', 'vdate', new Date(e.createdAt).toLocaleDateString('ru-RU')));
  card.append(top);
  const sub = [e.login, e.url].filter(Boolean).join(' · ');
  if (sub) card.append(el('div', 'vsub', sub));

  if (!isTrash) {
    // пароль замаскирован; глазок показывает/прячет
    const pwrow = el('div', 'vpw');
    const pwBtn = el('button', 'pw pwcopy', bubbleMask(e.password.length));
    pwBtn.type = 'button';
    pwBtn.setAttribute('aria-label', 'Показать пароль');
    let shown = false;
    const eye = el('button', 'eye');
    eye.type = 'button';
    // обе иконки в DOM — cross-fade между ними (класс .shown)
    const icOpen = el('span', 'ic ic-open');
    icOpen.append(svgIcon(EYE_OPEN));
    const icOff = el('span', 'ic ic-off');
    icOff.append(svgIcon(EYE_OFF));
    eye.append(icOpen, icOff);
    eye.setAttribute('aria-label', 'Показать пароль');
    const toggle = () => {
      shown = !shown;
      pwBtn.textContent = shown ? e.password : bubbleMask(e.password.length);
      eye.classList.toggle('shown', shown);
      pwBtn.setAttribute('aria-label', shown ? 'Скопировать: ' + e.password : 'Показать пароль');
    };
    pwBtn.addEventListener('click', () => { if (shown) doCopy(e.password); else toggle(); });
    eye.addEventListener('click', toggle);
    pwrow.append(pwBtn, eye);
    card.append(pwrow);

    const row = el('div', 'prow');
    const bc = el('button', 'act primary', 'Копировать');
    bc.type = 'button';
    bc.addEventListener('click', () => doCopy(e.password));
    const be = el('button', 'act', 'Изменить');
    be.type = 'button';
    be.addEventListener('click', () => openEntrySheet(e.id));
    const bd = el('button', 'act danger', 'Удалить');
    bd.type = 'button';
    armDelete(bd, () => {
      e.deleted = true;
      e.updatedAt = Date.now();
      markDirty();
      renderVault();
      toast('Запись в корзине');
    });
    row.append(bc, be, bd);
    card.append(row);
  } else {
    const row = el('div', 'prow');
    const br = el('button', 'act primary', 'Восстановить');
    br.type = 'button';
    br.addEventListener('click', () => {
      e.deleted = false;
      e.updatedAt = Date.now();
      markDirty();
      renderVault();
      toast('Запись восстановлена');
    });
    const bp = el('button', 'act danger', 'Насовсем');
    bp.type = 'button';
    armDelete(bp, () => {
      state.entries.delete(e.id);   // убираем tombstone целиком
      markDirty();
      renderVault();
      toast('Удалено окончательно');
    });
    row.append(br, bp);
    card.append(row);
  }
  return card;
}
function armDelete(btn, onConfirm) {
  let armed = false, timer = null;
  const orig = btn.textContent;
  btn.addEventListener('click', () => {
    if (!armed) {
      armed = true;
      btn.classList.add('confirm');
      btn.textContent = orig + '?';
      timer = setTimeout(() => {
        armed = false;
        btn.classList.remove('confirm');
        btn.textContent = orig;
      }, 2600);
    } else {
      clearTimeout(timer);
      btn.classList.remove('confirm');
      btn.textContent = orig;
      armed = false;
      onConfirm();
    }
  });
}
function renderVault() {
  renderVaultMeta();
  const q = $('#search').value.trim().toLowerCase();
  const box = $('#vlist');
  box.textContent = '';
  const arr = activeEntries()
    .filter(e => !q || e.label.toLowerCase().includes(q)
                 || (e.login || '').toLowerCase().includes(q)
                 || (e.url || '').toLowerCase().includes(q))
    .sort((a, b) => b.createdAt - a.createdAt);
  $('#vempty').hidden = arr.length > 0;
  arr.forEach(e => box.append(vaultCard(e, false)));

  const tbox = $('#tlist');
  tbox.textContent = '';
  trashedEntries()
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .forEach(e => tbox.append(vaultCard(e, true)));
}

/* шторка записи: создание и редактирование (подпись, логин, адрес, пароль) */
let sheetCtx = null;
function openEntrySheet(entryId, pwForNew) {
  if (state.legacy) return toast('Сейф в старом формате — сначала обновите его');
  const e = entryId ? state.entries.get(entryId) : null;
  sheetCtx = { entryId: e ? e.id : null };
  $('#sheet-title').textContent = e ? 'Изменить запись' : 'Сохранить в сейф';
  $('#sheet-label').value = e ? e.label : '';
  $('#sheet-login').value = e ? (e.login || '') : '';
  $('#sheet-url').value = e ? (e.url || '') : '';
  $('#sheet-pw').value = e ? e.password : (pwForNew || '');
  $('#backdrop').hidden = false;
  $('#sheet').hidden = false;
  setTimeout(() => $('#sheet-label').focus(), 60);
}
function closeSheets() {
  $('#backdrop').hidden = true;
  $('#sheet').hidden = true;
  $('#sheet-qr').hidden = true;
  $('#sheet-mp').hidden = true;
  $('#sheet-mig').hidden = true;
  sheetCtx = null;
}
function commitSheet() {
  const label = $('#sheet-label').value.trim() || 'Без подписи';
  const login = $('#sheet-login').value.trim();
  const url = $('#sheet-url').value.trim();
  const password = $('#sheet-pw').value;
  if (!password) { $('#sheet-pw').focus(); return; }
  if (sheetCtx && sheetCtx.entryId) {
    const e = state.entries.get(sheetCtx.entryId);
    if (e) {
      e.label = label; e.login = login; e.url = url; e.password = password;
      e.updatedAt = Date.now();
      markDirty();
      toast('Запись обновлена');
    }
  } else {
    const now = Date.now();
    const id = b64u8(rand(9)).replace(/[^A-Za-z0-9]/g, '').slice(0, 12);
    state.entries.set(id, { id, label, login, url, password, createdAt: now, updatedAt: now, deleted: false });
    markDirty();
    toast('Сохранено в сейф');
  }
  renderVault();
  closeSheets();
  setTab('vault');
}

/* ==================== QR / поделиться ==================== */
function openQR() {
  const url = vaultUrl();
  $('#qr-link').textContent = url;
  $('#qr-note').textContent = state.localOnly
    ? 'Сейф локальный: ссылка откроется только в этом браузере.'
    : 'Наведите камеру телефона — откроется этот же сейф. По ссылке нельзя прочитать сейф без мастер-пароля.';
  try {
    const qr = QR.encode(url);
    const canvas = $('#qr-canvas');
    const quiet = 4;
    const scale = Math.max(1, Math.floor(300 / (qr.size + quiet * 2)));
    const px = (qr.size + quiet * 2) * scale;
    canvas.width = px; canvas.height = px;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, px, px);
    ctx.fillStyle = '#0f172a';
    for (let y = 0; y < qr.size; y++)
      for (let x = 0; x < qr.size; x++)
        if (qr.get(x, y)) ctx.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
    $('#backdrop').hidden = false;
    $('#sheet-qr').hidden = false;
  } catch (e) {
    toast('Ссылка слишком длинная для QR');
    doCopy(url);
  }
}

/* ==================== бэкап / экспорт / смена пароля ==================== */
function downloadText(name, text, mime) {
  const blob = new Blob([text], { type: mime || 'application/octet-stream' });
  const a = el('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
async function exportBackup() {
  if (state.legacy) {
    const oldRaw = localStorage.getItem('pw.blob.' + state.vaultId);
    if (oldRaw) {
      downloadText('passwarium-backup-legacy-' + state.vaultId.slice(0, 8) + '.json',
                   JSON.stringify(JSON.parse(oldRaw), null, 2), 'application/json');
      return toast('Зашифрованный бэкап скачан');
    }
    return toast('Локальной копии нет — обновите формат сейфа');
  }
  const blob = await encryptStateV3();
  downloadText('passwarium-backup-' + state.vaultId.slice(0, 8) + '.json',
               JSON.stringify(blob, null, 2), 'application/json');
  toast('Зашифрованный бэкап скачан');
}
function toCsv(list) {
  const q = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  const rows = [['label', 'login', 'url', 'password'].map(q).join(',')];
  for (const e of list) rows.push([e.label, e.login, e.url, e.password].map(q).join(','));
  return '﻿' + rows.join('\r\n');
}
function exportCsv() {
  const n = activeEntries().length;
  if (!n) return toast('Сейф пуст');
  if (!window.confirm(`В CSV пароли будут ОТКРЫТЫМ ТЕКСТОМ (${n} записей).\nФайл нельзя хранить на диске и отправлять кому-либо. Продолжить?`)) return;
  downloadText('passwarium-export.csv', toCsv(activeEntries()), 'text/csv');
  toast('CSV скачан — удалите файл после использования');
}
async function importBackup(file) {
  if (state.legacy) return toast('Сначала обновите формат сейфа');
  try {
    const text = await file.text();
    const blob = JSON.parse(text);
    if (!blob || !blob.kdf || !blob.iv || !blob.ct) throw new Error('bad');
    if (blob.kdf.salt !== state.kdf.salt)
      return toast('Бэкап создан под другим мастер-паролем');
    // проверяем, что бэкап расшифровывается нашим ключом
    await decryptV3(state.encKey, state.vaultId, blob);
    if (!state.localOnly) {
      const r = await fetch('/vault/' + state.vaultId, {
        method: 'PUT', headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(blob),
      });
      if (!r.ok) throw new Error('http');
    }
    await refreshFromServer();
    toast('Сейф восстановлен из бэкапа');
  } catch (e) {
    toast('Не удалось восстановить: файл повреждён или нет связи');
  }
}

async function changeMasterPassword() {
  const cur = $('#mp-cur').value, nw = $('#mp-ch-new').value, nw2 = $('#mp-ch-new2').value;
  const err = m => { const e = $('#mp-err'); e.textContent = m; e.hidden = false; };
  $('#mp-err').hidden = true;
  if (state.legacy) return err('Сначала обновите формат сейфа.');
  if (nw.length < 8) return err('Новый пароль: минимум 8 символов.');
  if (nw !== nw2) return err('Новые пароли не совпадают.');
  if (estimateBits(nw) < 50 && !$('#mp-ch-weak-ok').checked)
    return err('Новый пароль слабоват (оценка < 50 бит). Отметьте «понимаю риск» или возьмите подлиннее.');
  const btn = $('#mp-ok');
  btn.disabled = true; btn.textContent = 'Перешифровка…';
  await new Promise(r => setTimeout(r, 30));
  try {
    // проверяем текущий пароль на локальной копии
    const localRaw = localStorage.getItem('pw.blob.' + state.vaultId);
    if (localRaw) {
      const d0 = await deriveV3(cur, JSON.parse(localRaw).kdf);
      await decryptV3(d0.encKey, state.vaultId, JSON.parse(localRaw));   // BAD_MAC при неверном
    }
    // перешифровываем с новой солью: меняется и токен доступа
    const kdf = { alg: 'argon2id', m: KDF_V3.m, t: KDF_V3.t, p: KDF_V3.p, salt: b64u8(rand(16)) };
    const d = await deriveV3(nw, kdf);
    const oldKey = state.encKey, oldTok = state.authTok, oldKdf = state.kdf;
    state.encKey = d.encKey; state.kdf = d.kdf;
    state.dirty = true;
    const ok = state.localOnly ? (await persistLocal(), true) : await pushVault(d.asha);
    if (!ok) {
      state.encKey = oldKey; state.kdf = oldKdf;
      return err('Не удалось перешифровать. Проверьте связь.');
    }
    state.authTok = d.authTok;
    await persistLocal();
    closeSheets();
    toast('Мастер-пароль изменён');
  } catch (e) {
    if (e.message === 'BAD_MAC') err('Текущий мастер-пароль неверен.');
    else err('Не удалось перешифровать. Проверьте связь.');
  } finally {
    btn.disabled = false; btn.textContent = 'Перешифровать';
  }
}

/* ==================== стойкость мастер-пароля ==================== */
// Грубая нижняя оценка: длина × log2(пул символов) со штрафами за паттерны.
function estimateBits(pw) {
  if (!pw) return 0;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[а-яё]/.test(pw)) pool += 33;
  if (/[А-ЯЁ]/.test(pw)) pool += 33;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zа-яёA-ZА-ЯЁ\d\s]/.test(pw)) pool += 32;
  if (/\s/.test(pw)) pool += 1;
  let bits = pw.length * Math.log2(pool || 1);
  if (/^(.)\1+$/.test(pw)) bits /= 4;                                   // аааааааа
  if (/^(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|йцук)/i.test(pw)) bits *= 0.4;
  if (/^(19|20)\d\d[!@#$]?$/.test(pw)) bits *= 0.3;                     // годы
  if (/password|пароль|qwerty|admin|letmein/i.test(pw)) bits *= 0.3;
  return Math.floor(bits);
}
function pwStrength(pw) {
  if (!pw) return null;
  const bits = estimateBits(pw);
  const score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 50 ? 2 : bits < 70 ? 3 : 4;
  const labels = ['Очень слабый', 'Слабый', 'Средний', 'Хороший', 'Отличный'];
  const colors = ['var(--danger)', 'var(--danger)', 'var(--warn)', 'var(--ok)', 'var(--ok)'];
  return { score, bits, label: labels[score], color: colors[score] };
}
function updateStrength(input, bar, label) {
  const s = pwStrength(input.value);
  bar.hidden = !s; label.hidden = !s;
  if (!s) return;
  bar.firstElementChild.style.width = ((s.score + 1) / 5 * 100) + '%';
  bar.firstElementChild.style.backgroundColor = s.color;
  label.textContent = s.label + ' (≈ ' + s.bits + ' бит)' +
    (s.bits < 50 ? ' — для мастер-пароля слабовато, добавьте длины' : '');
}

/* ==================== вкладки ==================== */
function setTab(name) {
  $('#tab-gen').hidden = name !== 'gen';
  $('#tab-vault').hidden = name !== 'vault';
  document.querySelectorAll('.tab-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.tab === name));
  if (name === 'vault') renderVault();
}

/* ==================== обработчики ==================== */
document.querySelectorAll('.tab-btn').forEach(b =>
  b.addEventListener('click', () => setTab(b.dataset.tab)));

$('#btn-generate').addEventListener('click', generateBatch);
$('#btn-generate-m').addEventListener('click', () => { setTab('gen'); generateBatch(); });

$('#len').addEventListener('input', () => { $('#len-val').textContent = $('#len').value; });
$('#len').addEventListener('change', generateBatch);
$('#cnt-minus').addEventListener('click', () => stepCount(-1));
$('#cnt-plus').addEventListener('click', () => stepCount(1));
function stepCount(d) {
  const o = $('#cnt-val');
  const v = Math.min(10, Math.max(4, +o.textContent + d));
  if (v !== +o.textContent) { o.textContent = v; generateBatch(); }
}

$('#form-unlock').addEventListener('submit', e => { e.preventDefault(); unlockVault($('#mp').value); });
$('#form-create').addEventListener('submit', e => { e.preventDefault(); createVault(); });
$('#btn-local-vault').addEventListener('click', createLocalVault);
$('#btn-toggle-create').addEventListener('click', () => {
  if ($('#form-unlock').hidden) showUnlock();
  else showCreateOnly('Новый сейф получит новую ссылку — откройте её на других устройствах:');
});
$('#btn-lock').addEventListener('click', lock);

$('#mp-new').addEventListener('input', () => updateStrength($('#mp-new'), $('#strength'), $('#strength-label')));
$('#mp-ch-new').addEventListener('input', () => updateStrength($('#mp-ch-new'), $('#strength-ch'), $('#strength-ch-label')));
$('#btn-suggest-mp').addEventListener('click', () => {
  const p = makeMasterPassword();
  $('#mp-new').value = p.text;
  $('#mp-new2').value = p.text;
  $('#mp-new').type = 'text';
  $('#mp-new2').type = 'text';
  updateStrength($('#mp-new'), $('#strength'), $('#strength-label'));
  toast('Запишите пароль — он не восстанавливается');
});

$('#search').addEventListener('input', renderVault);
$('#btn-refresh').addEventListener('click', refreshFromServer);
$('#trash-toggle').addEventListener('click', () => {
  $('#tlist').hidden = !$('#tlist').hidden;
  renderVaultMeta();
});
$('#sheet-cancel').addEventListener('click', closeSheets);
$('#backdrop').addEventListener('click', closeSheets);
$('#sheet-ok').addEventListener('click', commitSheet);
['#sheet-label', '#sheet-login', '#sheet-url', '#sheet-pw'].forEach(s =>
  $(s).addEventListener('keydown', e => { if (e.key === 'Enter') commitSheet(); }));

$('#btn-qr').addEventListener('click', openQR);
$('#qr-close').addEventListener('click', closeSheets);
$('#qr-copy').addEventListener('click', () => doCopy(vaultUrl()));

$('#btn-export').addEventListener('click', exportBackup);
$('#btn-csv').addEventListener('click', exportCsv);
$('#btn-import').addEventListener('click', () => $('#file-import').click());
$('#file-import').addEventListener('change', e => {
  const f = e.target.files[0];
  if (f) importBackup(f);
  e.target.value = '';
});

$('#btn-changemp').addEventListener('click', () => {
  $('#mp-err').hidden = true;
  ['#mp-cur', '#mp-ch-new', '#mp-ch-new2'].forEach(s => { $(s).value = ''; });
  $('#mp-ch-weak-ok').checked = false;
  updateStrength($('#mp-ch-new'), $('#strength-ch'), $('#strength-ch-label'));
  $('#backdrop').hidden = false;
  $('#sheet-mp').hidden = false;
  setTimeout(() => $('#mp-cur').focus(), 60);
});
$('#mp-cancel').addEventListener('click', closeSheets);
$('#form-changemp').addEventListener('submit', e => { e.preventDefault(); changeMasterPassword(); });

$('#btn-migrate').addEventListener('click', () => {
  $('#mig-err').hidden = true;
  $('#mig-mp').value = '';
  $('#mig-token').value = '';
  $('#mig-token-row').hidden = true;
  $('#backdrop').hidden = false;
  $('#sheet-mig').hidden = false;
  setTimeout(() => $('#mig-mp').focus(), 60);
});
$('#mig-cancel').addEventListener('click', closeSheets);
$('#form-migrate').addEventListener('submit', e => { e.preventDefault(); migrateLegacy(); });

$('#autolock').value = String(settings.autolock);
$('#autolock').addEventListener('change', () => {
  settings.autolock = +$('#autolock').value;
  localStorage.setItem('pw.settings', JSON.stringify(settings));
});

$('#btn-share').addEventListener('click', async () => {
  const url = vaultUrl();
  if (navigator.share) {
    try { await navigator.share({ title: 'Мой сейф Passwarium', url }); return; }
    catch (e) { if (e && e.name === 'AbortError') return; }
  }
  doCopy(url);
});

['pointerdown', 'keydown'].forEach(ev =>
  document.addEventListener(ev, () => { state.lastActivity = Date.now(); }, { passive: true, capture: true }));
setInterval(() => {
  if (!state.locked && settings.autolock > 0 &&
      Date.now() - state.lastActivity > settings.autolock * 60000) lock();
}, 5000);
window.addEventListener('online', () => { if (state.dirty) pushVault(); });

async function refreshFromServer() {
  if (!state.encKey) return;
  if (state.localOnly) return setSync('ok', 'Локально');
  setSync('busy', 'Обновление…');
  const remote = await fetchRemoteBlob(state.authTok);
  if (remote === undefined) return setSync('off', 'Нет связи');
  if (remote === 'AUTH') return setSync('off', 'Синхронизация отклонена');
  if (remote === 'THROTTLED') return setSync('off', 'Сервер просит подождать');
  if (remote === null) return setSync('ok', 'Синхронизировано');
  try {
    const remoteList = await decryptV3(state.encKey, state.vaultId, remote);
    const before = JSON.stringify([...state.entries.values()].sort((a, b) => a.id < b.id ? -1 : 1));
    state.entries = mergeEntries([[...state.entries.values()], remoteList]);
    const after = JSON.stringify([...state.entries.values()].sort((a, b) => a.id < b.id ? -1 : 1));
    renderVault();
    if (before !== after) markDirty();
    else setSync('ok', 'Синхронизировано');
  } catch (e) {
    setSync('off', 'Ошибка расшифровки');
  }
}

/* ==================== запуск ==================== */
// смена темы ОС: класс на <html> гасит все переходы на один кадр (без <style> — CSP)
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  document.documentElement.classList.add('no-transitions');
  void document.body.offsetHeight;   // фиксируем новые стили синхронно
  requestAnimationFrame(() => requestAnimationFrame(() =>
    document.documentElement.classList.remove('no-transitions')));
});

(function boot() {
  // ссылка: #/v/<id> (v3) или #/v/<id>.<ключ записи> (legacy)
  const m = location.hash.match(/^#\/v\/([A-Za-z0-9_-]{8,64})(?:\.([A-Za-z0-9_-]{16,64}))?$/);
  state.vaultId = m ? m[1] : null;
  state.legacyKey = m && m[2] ? m[2] : null;

  // PWA: офлайн-запуск с телефона
  if ('serviceWorker' in navigator) {
    try { navigator.serviceWorker.register('sw.js'); } catch (e) { /* не критично */ }
  }

  $('#screen-lock').hidden = false;
  if (state.vaultId) {
    $('#lock-id').textContent = state.vaultId.slice(0, 6) + '…';
    $('#lock-sub').hidden = false;
    const hasLocal = !!localStorage.getItem('pw.blob.' + state.vaultId);
    fetchMeta(state.vaultId).then(meta => {
      if (meta === undefined) {           // нет связи
        if (hasLocal) showUnlock();
        else showCreateOnly('Нет связи с сервером. Можно создать новый сейф:');
      } else if (meta === null) {
        // v3-метаданных нет: либо legacy-сейф, либо его вообще нет
        fetch('/vault/' + state.vaultId, { cache: 'no-store' }).then(r => {
          if (r.status === 404 && !hasLocal) {
            showCreateOnly('На сервере такого сейфа нет. Проверьте ссылку или создайте новый:');
          } else {
            showUnlock();
          }
        }).catch(() => {
          if (hasLocal) showUnlock();
          else showCreateOnly('Нет связи с сервером. Можно создать новый сейф:');
        });
      } else {
        showUnlock();
      }
    });
  } else {
    $('#btn-toggle-create').hidden = true;
    $('#lock-sub').hidden = true;
    showCreateOnly('Сейф зашифровывается на вашем устройстве и открывается по ссылке на ПК и телефоне. Создайте сейф:');
  }
})();
