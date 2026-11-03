// Тест берёт НАСТОЯЩИЙ код приложения из index.html (не копию!)
// и проверяет: генератор, шифрование, слияние сейфа, поля записей, CSV, QR.
// Запуск: node test/app.test.mjs
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');

function between(src, start, end) {
  const i = src.indexOf(start);
  if (i < 0) throw new Error('marker not found: ' + start);
  const j = src.indexOf(end, i);
  if (j < 0) throw new Error('end marker not found: ' + end);
  return src.slice(i, j);
}
function inside(src, start, end) {
  return between(src, start, end).slice(start.length);
}

// 1) вшитый crypto-js: первый <script> блок (без тегов)
const vendored = inside(html, '<script>', '</script>');
// 2) куски прикладного кода
const app = between(html, "<script>\n'use strict';", '</script>');
const utils = between(app, 'const $ =', 'function toast');
const gen = between(app, 'const VOWELS', 'let currentList');
const iter = between(app, 'const ITER', 'const state');
const cryptoCode = between(app, 'function waFromU8', '/* ==================== синхронизация');
const csvCode = between(app, 'function toCsv', 'function exportCsv');
const strengthCode = between(app, 'function pwStrength', 'function updateStrength');
// 3) QR-модуль: свой <script> блок
const qrRaw = between(html, '<script>\n// Мини-QR', '</script>');
const qrCode = qrRaw.slice(qrRaw.indexOf('\n') + 1).replace(/if \(typeof module[^\n]*\n?/, '');

// поднимаем crypto-js в песочнице — как в браузере: ни exports, ни define,
// UMD падает в ветку `t.CryptoJS = n()`, где t = глобальный объект песочницы
const sandbox = {
  console,
  crypto: globalThis.crypto,
  btoa: globalThis.btoa,
  atob: globalThis.atob,
  TextEncoder: globalThis.TextEncoder,
};
vm.createContext(sandbox);
vm.runInContext(vendored, sandbox);
const CryptoJS = sandbox.CryptoJS;
if (!CryptoJS || !CryptoJS.AES || !CryptoJS.PBKDF2 || !CryptoJS.HmacSHA256 || !CryptoJS.pad?.Pkcs7) {
  throw new Error('crypto-js did not initialize');
}

const code = utils + '\n' + iter + '\n' + gen + '\n' + cryptoCode + '\n' + csvCode + '\n' + strengthCode;
const api = vm.runInContext(
  code + ';({ wordCore, digitCountFor, makePassword, entropyBits, deriveKeys, encryptState, decryptBlob, mergeEntries, toCsv, pwStrength, ITER, waFromU8, waLegacy, isLegacyBlob, b64u8, u8b64, rand, randInt, pick, VOWELS, CONS, DIGR, DIGITS, SPECIALS })',
  sandbox
);
// state — глобальная переменная внутри песочницы (encryptState её читает)
vm.runInContext("state = { vaultId: 'testvault01', saltB64: b64u8(rand(16)), entries: new Map() }", sandbox);
const stateRef = vm.runInContext('state', sandbox);
const QR = vm.runInContext(qrCode + '; QR', sandbox);

let failed = 0;
function check(name, cond, extra = '') {
  if (cond) console.log('  ok  ' + name);
  else { failed++; console.log('  FAIL ' + name + (extra ? ' — ' + extra : '')); }
}

/* ---------- 1. генератор: свойства паролей ---------- */
console.log('Генератор:');
const reAllowed = /^[0-9a-zA-Z\-@!?&$*]+$/; // буквы/цифры/разрешённые спецсимволы
let bad = [];
const SAMPLES = 3000;
for (let i = 0; i < SAMPLES; i++) {
  const len = 8 + (i % 33);
  const p = api.makePassword(len);
  const dc = api.digitCountFor(len);
  const digits = (p.match(/\d/g) || []).length;
  const specials = (p.match(/[-@!?&$*]/g) || []).length;
  const uppers = (p.match(/[A-Z]/g) || []).length;
  const firstLetter = p.search(/[a-zA-Z]/);
  const lastLetter = p.length - 1 - [...p].reverse().findIndex(c => /[a-zA-Z]/.test(c));
  const groupSplit = firstLetter > 0 && lastLetter < p.length - 1; // группы с двух сторон — плохо
  const ok =
    p.length === len &&
    reAllowed.test(p) &&
    !/[OIol]/.test(p) &&
    digits === dc &&
    specials === 1 &&
    uppers === 1 &&
    /[a-z]/.test(p) &&
    digits + specials === p.length - (lastLetter - firstLetter + 1) &&
    !groupSplit;
  if (!ok) bad.push({ len, p, digits, specials, uppers, firstLetter, lastLetter });
}
check(`${SAMPLES} паролей: длина/состав/группа/без O o I l`, bad.length === 0, JSON.stringify(bad.slice(0, 3)));

const uniq = new Set();
for (let i = 0; i < 200; i++) uniq.add(api.makePassword(12));
check('нет дублей в 200 генерациях (длина 12)', uniq.size === 200, 'уникальных: ' + uniq.size);

// читаемость: согласные не должны стоять по 3 подряд внутри слова
let crunchy = 0;
for (let i = 0; i < 1000; i++) {
  const p = api.makePassword(16);
  const core = p.replace(/[^a-zA-Z]/g, '');
  if (/[bcdfghjkmnpqrstvwxz]{4,}/i.test(core)) crunchy++;
}
check('нет 4+ согласных подряд (читаемость)', crunchy === 0, 'случаев: ' + crunchy);

/* ---------- 2. крипто ---------- */
console.log('Крипто:');
const now = Date.now();
stateRef.entries.set('e1', { id: 'e1', label: 'Почта', login: 'me@example.com', url: 'https://mail.example.com', password: '1-Fudonew', createdAt: now, updatedAt: now, deleted: false });
stateRef.entries.set('e2', { id: 'e2', label: 'Steam', login: '', url: '', password: 'Brakana7&', createdAt: now, updatedAt: now, deleted: false });

const keys = api.deriveKeys('верный мастер-пароль', stateRef.saltB64);
const blob = api.encryptState(keys);
check('сейф шифруется (blob содержит salt/iv/ct/mac)', !!(blob.salt && blob.iv && blob.ct && blob.mac));
check('blob записывает v=2 и iterations = ' + api.ITER, blob.v === 2 && blob.iterations === api.ITER);

const reopened = api.deriveKeys('верный мастер-пароль', blob.salt);
const entries = api.decryptBlob(reopened, blob);
check('roundtrip: 2 записи с логином и url расшифровываются',
  entries.length === 2 && entries[0].password === '1-Fudonew' &&
  entries[0].login === 'me@example.com' && entries[0].url === 'https://mail.example.com');

let threw = '';
try { api.decryptBlob(api.deriveKeys('не_верный_пароль', blob.salt), blob); }
catch (e) { threw = e.message; }
check('неверный мастер-пароль → BAD_MAC', threw === 'BAD_MAC', 'получено: ' + threw);

// подмена в СЕРЕДИНЕ шифртекста: в v2 MAC покрывает ct целиком и обязан упасть
const pos = 20;
const tampered = { ...blob, ct: blob.ct.slice(0, pos) + (blob.ct[pos] === 'A' ? 'B' : 'A') + blob.ct.slice(pos + 1) };
threw = '';
try { api.decryptBlob(reopened, tampered); }
catch (e) { threw = e.message; }
check('подменённый шифртекст → BAD_MAC (v2: MAC покрывает ct)', threw === 'BAD_MAC', 'получено: ' + threw);

// подмена с сохранением длины base64 без паддинга — краевой случай старого бага
const tamperedTail = { ...blob, ct: blob.ct.slice(0, -4) + (blob.ct.endsWith('AAAA') ? 'AAAB' : 'AAAA') };
threw = '';
try { api.decryptBlob(reopened, tamperedTail); }
catch (e) { threw = e.message; }
check('подмена хвоста ct → BAD_MAC (регрессия бага v1)', threw === 'BAD_MAC', 'получено: ' + threw);

/* ---------- 2б. совместимость с v1 (bug-for-bug) ---------- */
console.log('Миграция v1:');
// собираем v1-блоб вручную ровно так, как это делала старая версия:
// байты напрямую в WordArray.create (каждый байт — 32-битное слово)
const legacyBlob = vm.runInContext(`(()=>{
  const saltWA = CryptoJS.lib.WordArray.create(u8b64(state.saltB64));
  const master = CryptoJS.PBKDF2('старый пароль', saltWA, { keySize: 16, iterations: 150000, hasher: CryptoJS.algo.SHA256 });
  const keys = { aes: CryptoJS.lib.WordArray.create(master.words.slice(0, 8), 32),
                 mac: CryptoJS.lib.WordArray.create(master.words.slice(8, 16), 32) };
  const iv = rand(16);
  const ivWA = CryptoJS.lib.WordArray.create(iv);
  const payload = JSON.stringify({ entries: [{ id: 'x', label: 'Старое', password: 'leg1-Pass', createdAt: 1, updatedAt: 1, deleted: false }] });
  const ct = CryptoJS.AES.encrypt(payload, keys.aes, { iv: ivWA, padding: CryptoJS.pad.Pkcs7 }).ciphertext;
  const mac = CryptoJS.HmacSHA256(ivWA.clone().concat(ct), keys.mac).toString(CryptoJS.enc.Base64);
  return { v: 1, iterations: 150000, salt: state.saltB64, iv: b64u8(iv), ct: ct.toString(CryptoJS.enc.Base64), mac, updatedAt: 1 };
})()`, sandbox);
check('ручной v1-блоб распознаётся как legacy', api.isLegacyBlob(legacyBlob) === true);
const legKeys = api.deriveKeys('старый пароль', legacyBlob.salt, 150000, true);
const legEntries = api.decryptBlob(legKeys, legacyBlob);
check('v1-блоб открывается legacy-путём (bug-for-bug)', legEntries.length === 1 && legEntries[0].password === 'leg1-Pass');
threw = '';
try { api.decryptBlob(api.deriveKeys('старый пароль', legacyBlob.salt, 150000), legacyBlob); }
catch (e) { threw = e.message; }
check('v1-блоб НЕ открывается новыми ключами → BAD_MAC (ожидаемо)', threw === 'BAD_MAC', 'получено: ' + threw);
check('новый blob не legacy', api.isLegacyBlob(blob) === false);
// waFromU8: 4 байта на слово, явный sigBytes
const wa = api.waFromU8(new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9a]));
check('waFromU8 пакует байты в слова', wa.words[0] === 0x12345678 && (wa.words[1] >>> 0) === 0x9a000000 && wa.sigBytes === 5);

/* ---------- 3. слияние сейфа (LWW + tombstones) ---------- */
console.log('Слияние:');
const t1 = Date.now() - 3000, t2 = Date.now() - 2000, t3 = Date.now() - 1000;
const local = [
  { id: 'a', label: 'A локальная новая', password: 'x', createdAt: t1, updatedAt: t2, deleted: false },
  { id: 'b', label: 'B', password: 'x', createdAt: t1, updatedAt: t1, deleted: false },
];
const remote = [
  { id: 'a', label: 'A серверная старая', password: 'x', createdAt: t1, updatedAt: t1, deleted: false },
  { id: 'c', label: 'C только на сервере', password: 'x', createdAt: t2, updatedAt: t3, deleted: false },
  { id: 'b', label: 'B', password: 'x', createdAt: t1, updatedAt: t2, deleted: true }, // удалена позже (t2 > t1)
];
const merged = api.mergeEntries([local, remote]);
check('слияние: 3 записи (a,b,c)', merged.size === 3, 'размер: ' + merged.size);
check('LWW: у «a» побеждает новая версия', merged.get('a').label === 'A локальная новая');
check('tombstone: «b» удалена', merged.get('b').deleted === true);
check('запись «c» подтянулась', merged.get('c').label === 'C только на сервере');

// восстановление из корзины: более свежая активная версия побеждает tombstone
const restored = api.mergeEntries([[
  { id: 'b', label: 'B', password: 'x', createdAt: t1, updatedAt: t3 + 1000, deleted: false },
], remote]);
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

/* ---------- 5. стойкость мастер-пароля ---------- */
console.log('Стойкость:');
check('пустой пароль → null', api.pwStrength('') === null);
check('«12345678» — слабый', api.pwStrength('12345678').score <= 1);
check('длинная фраза с цифрами и спецсимволами — хорошая/отличная',
  api.pwStrength('Krepkiy-Parol-2026!').score >= 3);

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
  const long = QR.encode('https://pass.example.com/#/v/lc6sknzpbabuajx6fiiowwjwj1s.wqp2mz8xr4vt6yn0ak3b');
  qrOk = long.size === 17 + 4 * long.version && long.version >= 4;
} catch (e) { qrOk = false; }
check('QR типичной ссылки сейфа (авто-маска)', qrOk);

let qrTooLong = '';
try { QR.encode('x'.repeat(300)); } catch (e) { qrTooLong = e.message; }
check('слишком длинный текст → QR_TOO_LONG', qrTooLong === 'QR_TOO_LONG', qrTooLong);

console.log(failed === 0 ? '\nВСЕ ТЕСТЫ ПРОШЛИ' : `\nПРОВАЛЕНО: ${failed}`);
process.exit(failed === 0 ? 0 : 1);
