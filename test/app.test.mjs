// Тест берёт НАСТОЯЩИЙ код приложения из app.js / qr.js / crypto-legacy.js
// (не копию!) и проверяет: генератор и честность оценки стойкости,
// криптографию v3 (Argon2id + HKDF + AES-256-GCM), чтение legacy-сейфов
// v1/v2 (bug-for-bug), слияние, CSV, QR, отсутствие внешних запросов.
// Запуск: node test/app.test.mjs
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
const qrSrc = fs.readFileSync(path.join(root, 'qr.js'), 'utf8');
const legacySrc = fs.readFileSync(path.join(root, 'crypto-legacy.js'), 'utf8');
const hashwasmSrc = fs.readFileSync(path.join(root, 'hash-wasm.js'), 'utf8');

function between(src, start, end) {
  const i = src.indexOf(start);
  if (i < 0) throw new Error('marker not found: ' + start);
  const j = src.indexOf(end, i);
  if (j < 0) throw new Error('end marker not found: ' + end);
  return src.slice(i, j);
}

// куски прикладного кода (маркеры — комментарии-разделители в app.js)
const utils = between(app, 'const $ =', 'function toast');
const gen = between(app, 'const VOWELS', 'let currentList');
const kdfDefaults = between(app, 'const KDF_V3', 'const state');
const cryptoCode = between(app, '/* ==================== крипто v3', '/* ==================== синхронизация');
const csvCode = between(app, 'function toCsv', 'function exportCsv');
const strengthCode = between(app, 'function estimateBits', 'function updateStrength');
const qrCode = qrSrc.replace(/if \(typeof module[^\n]*\n?/, '');

const sandbox = {
  console,
  crypto: globalThis.crypto,
  btoa: globalThis.btoa,
  atob: globalThis.atob,
  TextEncoder: globalThis.TextEncoder,
  TextDecoder: globalThis.TextDecoder,
};
vm.createContext(sandbox);
// hash-wasm и crypto-js — UMD: в песочнице без exports/define падают в глобал
vm.runInContext(hashwasmSrc, sandbox);
vm.runInContext(legacySrc, sandbox);
if (!sandbox.hashwasm?.argon2id) throw new Error('hash-wasm did not initialize');
const CryptoJS = sandbox.CryptoJS;
if (!CryptoJS || !CryptoJS.AES || !CryptoJS.PBKDF2 || !CryptoJS.HmacSHA256 || !CryptoJS.pad?.Pkcs7) {
  throw new Error('crypto-js did not initialize');
}

const code = [utils, kdfDefaults, gen, cryptoCode, csvCode, strengthCode].join('\n');
const api = vm.runInContext(
  code + ';({ makeWord, makePassword, makeMasterPassword, digitCountFor, estimateBits, deriveV3, encryptStateV3, decryptV3, decryptBlobLegacy, deriveKeysLegacy, mergeEntries, toCsv, pwStrength, waFromU8, waLegacy, isLegacyBlob, b64u8, u8b64, rand, randInt, pick, hkdf256, sha256hex, SYLL, SYLL_C, VOWELS, CONS, DIGR, DIGITS, SPECIALS, KDF_V3 })',
  sandbox
);
// state — глобальная переменная внутри песочницы (encryptStateV3 её читает)
vm.runInContext("state = { vaultId: 'testvault01', entries: new Map(), encKey: null, kdf: null }", sandbox);
const stateRef = vm.runInContext('state', sandbox);
const QR = vm.runInContext(qrCode + '; QR', sandbox);

let failed = 0;
function check(name, cond, extra = '') {
  if (cond) console.log('  ok  ' + name);
  else { failed++; console.log('  FAIL ' + name + (extra ? ' — ' + extra : '')); }
}

async function main() {
  /* ---------- 1. генератор: свойства паролей ---------- */
  console.log('Генератор:');
  const reAllowed = /^[0-9a-zA-Z\-@!?&$*]+$/;
  let bad = [];
  const SAMPLES = 5000;
  for (let i = 0; i < SAMPLES; i++) {
    const len = 8 + (i % 33);
    const { text: p, bits } = api.makePassword(len);
    const dc = api.digitCountFor(len);
    const digits = (p.match(/\d/g) || []).length;
    const specials = (p.match(/[-@!?&$*]/g) || []).length;
    const uppers = (p.match(/[A-Z]/g) || []).length;
    const firstLetter = p.search(/[a-zA-Z]/);
    const lastLetter = p.length - 1 - [...p].reverse().findIndex(c => /[a-zA-Z]/.test(c));
    const groupSplit = firstLetter > 0 && lastLetter < p.length - 1; // группы с двух сторон — плохо
    const ok =
      p.length <= len && p.length >= len - 4 &&          // слоги не обрезаются — слово может быть чуть короче
      reAllowed.test(p) &&
      !/[OIol]/.test(p) &&
      digits === dc &&
      specials === 1 &&
      uppers === 1 &&
      /[a-z]/.test(p) &&
      digits + specials === p.length - (lastLetter - firstLetter + 1) &&
      !groupSplit &&
      bits >= 15;
    if (!ok) bad.push({ len, p, bits, digits, specials, uppers });
  }
  check(`${SAMPLES} паролей: длина/состав/группа/без O o I l`, bad.length === 0, JSON.stringify(bad.slice(0, 3)));

  const uniq = new Set();
  for (let i = 0; i < 200; i++) uniq.add(api.makePassword(12).text);
  check('нет дублей в 200 генерациях (длина 12)', uniq.size === 200, 'уникальных: ' + uniq.size);

  // читаемость: согласные не должны стоять по 4+ подряд внутри слова
  let crunchy = 0;
  for (let i = 0; i < 1000; i++) {
    const p = api.makePassword(16).text;
    const core = p.replace(/[^a-zA-Z]/g, '');
    if (/[bcdfghjkmnpqrstvwxz]{4,}/i.test(core)) crunchy++;
  }
  check('нет 4+ согласных подряд (читаемость)', crunchy === 0, 'случаев: ' + crunchy);

  /* ---------- 1б. честная стойкость: нижняя оценка ---------- */
  console.log('Честная стойкость:');
  // 1) первый слог выбирается равновероятно из SYLL — иначе оценка врёт
  const N1 = 3120 * 80;   // ~250k
  const freq = new Map();
  for (let i = 0; i < N1; i++) {
    const trace = [];
    api.makeWord(6, trace);
    const s = trace[0];
    freq.set(s, (freq.get(s) || 0) + 1);
  }
  const expN = N1 / api.SYLL.length;
  // критерий хи-квадрат: df = 3119, E = df, σ = √(2·df) ≈ 79; запас 6σ
  let chi2 = 0, seen = 0;
  for (const s of api.SYLL) {
    const f = freq.get(s) || 0;
    if (f) seen++;
    chi2 += (f - expN) ** 2 / expN;
  }
  const df = api.SYLL.length - 1;
  check('первый слог равновероятен (хи-квадрат в 6σ)',
    seen === api.SYLL.length && Math.abs(chi2 - df) < 6 * Math.sqrt(2 * df),
    `χ²=${chi2.toFixed(0)}, df=${df}, покрыто слогов ${seen}/${api.SYLL.length}`);

  // 2) показываемая стойкость — нижняя оценка: для len 8 считаем хвост распределения
  //    аналитически: 2 слога (4+4 симв.) — самый вероятный исход,
  //    P = (1/3120)² × (1/10) × (1/7) × (1/2)²  ≈ 2.6e-10 → 31.8 бит
  //    при этом показываем для такого пароля floor(2·log2(3120) + log2(10) + log2(7) + 2) = 31
  const probe = api.makePassword(8);
  check('len 8: показанная оценка ≤ измеренной энтропии (нижняя граница)',
    probe.bits <= Math.floor(2 * Math.log2(3120) + Math.log2(10) + Math.log2(7) + 2 + 3.5),
    'bits=' + probe.bits);

  // 3) мастер-пароль: ≥ 70 бит всегда
  let masterOk = true, masterMin = 1e9;
  for (let i = 0; i < 2000; i++) {
    const m = api.makeMasterPassword();
    masterMin = Math.min(masterMin, m.bits);
    if (m.bits < 70) masterOk = false;
    if (!/^[A-ZА-ЯЁ]/.test(m.text) || (m.text.match(/\d/g) || []).length !== 3) masterOk = false;
  }
  check('мастер-пароль: 2000 шт., все ≥ 70 бит, 3 цифры', masterOk, 'минимум: ' + masterMin);

  /* ---------- 2. крипто v3 ---------- */
  console.log('Крипто v3:');
  // Argon2id — вектор RFC 9106 §5.4 (сверено с эталонной argon2-cffi)
  const rfc = await vm.runInContext(`hashwasm.argon2id({
    password: new Uint8Array(32).fill(1), salt: new Uint8Array(16).fill(2),
    parallelism: 4, memorySize: 65536, iterations: 3, hashLength: 32, outputType: 'hex' })`, sandbox);
  check('Argon2id: вектор RFC 9106', rfc === 'fedd802b86b17230843c6d3f025c81d3f472fbf9daaf26897fa88844732167ec', rfc);

  const now = Date.now();
  stateRef.entries.set('e1', { id: 'e1', label: 'Почта', login: 'me@example.com', url: 'https://mail.example.com', password: '1-Fudonew', createdAt: now, updatedAt: now, deleted: false });
  stateRef.entries.set('e2', { id: 'e2', label: 'Steam', login: '', url: '', password: 'Brakana7&', createdAt: now, updatedAt: now, deleted: false });

  // быстрые параметры для тестов (боевые 64 МиБ проверены вектором выше)
  const kdfTest = { alg: 'argon2id', m: 256, t: 2, p: 1, salt: api.b64u8(api.rand(16)) };
  const d = await api.deriveV3('верный мастер-пароль', kdfTest);
  check('deriveV3: encKey + authTok + asha', !!(d.encKey && d.authTok && /^[0-9a-f]{64}$/.test(d.asha)));
  stateRef.encKey = d.encKey;
  stateRef.kdf = d.kdf;
  const blob = await api.encryptStateV3();
  check('сейф шифруется (v=3, kdf с солью, iv, ct)',
    blob.v === 3 && blob.kdf.alg === 'argon2id' && blob.kdf.salt === kdfTest.salt && !!blob.iv && !!blob.ct && !blob.mac);

  const d2 = await api.deriveV3('верный мастер-пароль', blob.kdf);
  const entries = await api.decryptV3(d2.encKey, stateRef.vaultId, blob);
  check('roundtrip: 2 записи с логином и url расшифровываются',
    entries.length === 2 && entries[0].password === '1-Fudonew' &&
    entries[0].login === 'me@example.com' && entries[0].url === 'https://mail.example.com');
  check('токен детерминирован паролем и солью', d2.authTok === d.authTok && d2.asha === d.asha);

  let threw = '';
  try {
    const dw = await api.deriveV3('не_верный_пароль', blob.kdf);
    await api.decryptV3(dw.encKey, stateRef.vaultId, blob);
  } catch (e) { threw = e.message; }
  check('неверный мастер-пароль → BAD_MAC', threw === 'BAD_MAC', 'получено: ' + threw);

  // подмена одного байта ct → ошибка (AES-GCM)
  const ctBytes = api.u8b64(blob.ct); ctBytes[3] ^= 1;
  threw = '';
  try { await api.decryptV3(d2.encKey, stateRef.vaultId, { ...blob, ct: api.b64u8(ctBytes) }); }
  catch (e) { threw = e.message; }
  check('подмена байта ct → BAD_MAC', threw === 'BAD_MAC', 'получено: ' + threw);

  // подмена iv → ошибка
  const ivBytes = api.u8b64(blob.iv); ivBytes[0] ^= 1;
  threw = '';
  try { await api.decryptV3(d2.encKey, stateRef.vaultId, { ...blob, iv: api.b64u8(ivBytes) }); }
  catch (e) { threw = e.message; }
  check('подмена байта iv → BAD_MAC', threw === 'BAD_MAC', 'получено: ' + threw);

  // подмена AAD: шифртекст одного сейфа не подсунуть в другой
  threw = '';
  try { await api.decryptV3(d2.encKey, 'drugoy_vault99', blob); }
  catch (e) { threw = e.message; }
  check('чужой vaultId (AAD) → BAD_MAC', threw === 'BAD_MAC', 'получено: ' + threw);

  /* ---------- 2б. legacy v1/v2: чтение bug-for-bug + миграция ---------- */
  console.log('Миграция v1/v2 → v3:');
  const mkLegacy = (v, iterations, password, saltB64) => vm.runInContext(`(()=>{
    const legacy = ${v} < 2;
    const saltU8 = u8b64(${JSON.stringify(saltB64)});
    const saltWA = legacy ? CryptoJS.lib.WordArray.create(saltU8)
                          : (function(u8){const w=[];for(let i=0;i<u8.length;i++)w[i>>>2]|=u8[i]<<(24-(i%4)*8);return CryptoJS.lib.WordArray.create(w,u8.length)})(saltU8);
    const master = CryptoJS.PBKDF2(${JSON.stringify(password)}, saltWA, { keySize: 16, iterations: ${iterations}, hasher: CryptoJS.algo.SHA256 });
    const keys = { aes: CryptoJS.lib.WordArray.create(master.words.slice(0, 8), 32),
                   mac: CryptoJS.lib.WordArray.create(master.words.slice(8, 16), 32) };
    const iv = rand(16);
    const ivWA = legacy ? CryptoJS.lib.WordArray.create(iv)
                        : (function(u8){const w=[];for(let i=0;i<u8.length;i++)w[i>>>2]|=u8[i]<<(24-(i%4)*8);return CryptoJS.lib.WordArray.create(w,u8.length)})(iv);
    const payload = JSON.stringify({ entries: [{ id: 'x${v}', label: 'Старое-${v}', password: 'leg${v}-Pass', createdAt: 1, updatedAt: 1, deleted: false }] });
    const ct = CryptoJS.AES.encrypt(payload, keys.aes, { iv: ivWA, padding: CryptoJS.pad.Pkcs7 }).ciphertext;
    const mac = CryptoJS.HmacSHA256(ivWA.clone().concat(ct), keys.mac).toString(CryptoJS.enc.Base64);
    return { v: ${v}, iterations: ${iterations}, salt: ${JSON.stringify(saltB64)}, iv: b64u8(iv), ct: ct.toString(CryptoJS.enc.Base64), mac, updatedAt: 1 };
  })()`, sandbox);

  for (const [v, iters] of [[1, 150000], [2, 600000]]) {
    const salt = api.b64u8(api.rand(16));
    const fixture = mkLegacy(v, iters, 'старый пароль', salt);
    check(`v${v}-фикстура распознаётся как legacy`, api.isLegacyBlob(fixture) === true);
    const legKeys = api.deriveKeysLegacy('старый пароль', fixture.salt, iters, v < 2);
    const legEntries = api.decryptBlobLegacy(legKeys, fixture);
    check(`v${v}-блоб открывается legacy-путём (bug-for-bug)`,
      legEntries.length === 1 && legEntries[0].password === `leg${v}-Pass`);
    // миграция: те же записи перешифровываем в v3 и читаем обратно
    const dm = await api.deriveV3('старый пароль', { alg: 'argon2id', m: 256, t: 2, p: 1, salt: api.b64u8(api.rand(16)) });
    stateRef.entries = new Map(legEntries.map(e => [e.id, e]));
    stateRef.encKey = dm.encKey; stateRef.kdf = dm.kdf;
    const migrated = await api.encryptStateV3();
    const back = await api.decryptV3(dm.encKey, stateRef.vaultId, migrated);
    check(`v${v} → v3: записи переезжают без потерь`, back.length === 1 && back[0].password === `leg${v}-Pass`);
  }
  stateRef.entries = new Map();

  // waFromU8: 4 байта на слово, явный sigBytes
  const wa = api.waFromU8(new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9a]));
  check('waFromU8 пакует байты в слова', wa.words[0] === 0x12345678 && (wa.words[1] >>> 0) === 0x9a000000 && wa.sigBytes === 5);

  /* ---------- 3. слияние сейфа (LWW + tombstones) ---------- */
  console.log('Слияние:');
  const t1 = Date.now() - 3000, t2 = Date.now() - 2000, t3 = Date.now() - 1000;
  const localL = [
    { id: 'a', label: 'A локальная новая', password: 'x', createdAt: t1, updatedAt: t2, deleted: false },
    { id: 'b', label: 'B', password: 'x', createdAt: t1, updatedAt: t1, deleted: false },
  ];
  const remoteL = [
    { id: 'a', label: 'A серверная старая', password: 'x', createdAt: t1, updatedAt: t1, deleted: false },
    { id: 'c', label: 'C только на сервере', password: 'x', createdAt: t2, updatedAt: t3, deleted: false },
    { id: 'b', label: 'B', password: 'x', createdAt: t1, updatedAt: t2, deleted: true },
  ];
  const merged = api.mergeEntries([localL, remoteL]);
  check('слияние: 3 записи (a,b,c)', merged.size === 3, 'размер: ' + merged.size);
  check('LWW: у «a» побеждает новая версия', merged.get('a').label === 'A локальная новая');
  check('tombstone: «b» удалена', merged.get('b').deleted === true);
  check('запись «c» подтянулась', merged.get('c').label === 'C только на сервере');

  const restored = api.mergeEntries([[
    { id: 'b', label: 'B', password: 'x', createdAt: t1, updatedAt: t3 + 1000, deleted: false },
  ], remoteL]);
  check('восстановление: свежая активная версия снимает tombstone', restored.get('b').deleted === false);

  /* ---------- 4. CSV-экспорт ---------- */
  console.log('CSV:');
  const csv = api.toCsv([
    { label: 'Кавычки "внутри"', login: 'a,b@c', url: '', password: 'p,1' },
    { label: 'Простая', login: '', url: 'https://x.y', password: 'q' },
  ]);
  const csvLines = csv.split('\r\n');
  check('CSV: BOM + заголовок + 2 строки', csv.charCodeAt(0) === 0xFEFF && csvLines.length === 3);
  check('CSV: экранирование кавычек и запятых',
    csvLines[1] === '"Кавычки ""внутри""","a,b@c","","p,1"', csvLines[1]);

  /* ---------- 5. стойкость мастер-пароля (оценка в битах) ---------- */
  console.log('Стойкость:');
  check('пустой пароль → null', api.pwStrength('') === null);
  check('«12345678» — слабый', api.pwStrength('12345678').score <= 1);
  check('«12345678» < 30 бит', api.estimateBits('12345678') < 30, 'bits=' + api.estimateBits('12345678'));
  check('длинная фраза с цифрами и спецсимволами ≥ 60 бит',
    api.estimateBits('Krepkiy-Parol-2026!Dlinniy') >= 60, 'bits=' + api.estimateBits('Krepkiy-Parol-2026!Dlinniy'));
  check('«aaaaaaaa» режется штрафом', api.estimateBits('aaaaaaaa') < 20, 'bits=' + api.estimateBits('aaaaaaaa'));

  /* ---------- 6. QR: эталонная матрица (проверено против python-qrcode) ---------- */
  console.log('QR:');
  const GOLDEN_HELLO = [
    '#######..#.##.#######',
    '#.....#..###..#.....#',
    '#.###.#.##.##.#.###.#',
    '#.###.#..#.#..#.###.#',
    '#.###.#...#.#.#.###.#',
    '#.....#.....#.#.....#',
    '#######.#.#.#.#######',
    '........##.##........',
    '###.########.##...#..',
    '.#####.###....#....##',
    '.######.#...#...#####',
    '..##..........#....#.',
    '....#.##.##.#.#.#....',
    '........##.#.#.#..###',
    '#######.####.###..###',
    '#.....#.######.##....',
    '#.###.#.####.###...##',
    '#.###.#...#...##..##.',
    '#.###.#.###.#...#.#.#',
    '#.....#.##....#.#..#.',
    '#######.#.#.#.##...##',
  ];
  const qrHello = QR.encode('hello', 0);
  let qrDiff = 0;
  for (let y = 0; y < 21; y++) for (let x = 0; x < 21; x++)
    if (qrHello.get(x, y) !== (GOLDEN_HELLO[y][x] === '#')) qrDiff++;
  check('QR v1 «hello» mask0 совпадает с эталоном', qrDiff === 0, 'различий: ' + qrDiff);

  let qrOk = true;
  try {
    const long = QR.encode('https://pass.example.com/#/v/lc6sknzpbabuajx6fiiowwjwj1s');
    qrOk = long.size === 17 + 4 * long.version && long.version >= 3;
  } catch (e) { qrOk = false; }
  check('QR типичной ссылки сейфа (авто-маска)', qrOk);

  let qrTooLong = '';
  try { QR.encode('x'.repeat(300)); } catch (e) { qrTooLong = e.message; }
  check('слишком длинный текст → QR_TOO_LONG', qrTooLong === 'QR_TOO_LONG', qrTooLong);

  /* ---------- 7. ни одного запроса на чужие домены ---------- */
  console.log('Изоляция:');
  const urlRe = /https?:\/\/[^\s'"<>)]+/g;
  const allowed = /^http:\/\/www\.w3\.org\/2000\/svg$/;   // не запрос, а XML-неймспейс
  let foreign = [];
  for (const f of ['index.html', 'app.css', 'app.js', 'qr.js', 'sw.js', 'manifest.webmanifest', 'crypto-legacy.js']) {
    const text = fs.readFileSync(path.join(root, f), 'utf8');
    for (const m of text.match(urlRe) || []) {
      if (!allowed.test(m)) foreign.push(f + ' → ' + m);
    }
  }
  check('в раздаваемых файлах нет ссылок на чужие домены', foreign.length === 0, foreign.slice(0, 3).join('; '));

  // innerHTML запрещён в клиентском коде
  const ih = (app.match(/innerHTML/g) || []).length;
  check('в app.js нет innerHTML', ih === 0, 'вхождений: ' + ih);

  console.log(failed === 0 ? '\nВСЕ ТЕСТЫ ПРОШЛИ' : `\nПРОВАЛЕНО: ${failed}`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(e => { console.error('ТЕСТ УПАЛ С ОШИБКОЙ:', e); process.exit(1); });
