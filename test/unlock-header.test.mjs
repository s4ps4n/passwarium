// Регрессия: разблокировка на новом устройстве.
// fetchRemoteBlob(tok) обязан отправлять ИМЕННО переданный токен, а не state.authTok
// (на новом устройстве state.authTok ещё пуст — из-за этого сейф не открывался
// по ссылке с телефона, сервер отвечал 401, а UI показывал «Неверный мастер-пароль»).
// Запуск: node test/unlock-header.test.mjs
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');

const start = app.indexOf('async function fetchRemoteBlob');
if (start < 0) throw new Error('fetchRemoteBlob не найден в app.js');
const end = app.indexOf('\nasync function ', start + 10);
const src = app.slice(start, end > 0 ? end : app.length);

let failures = 0;
const check = (name, ok, extra = '') => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${ok || !extra ? '' : ' — ' + extra}`);
  if (!ok) failures++;
};

async function run(tok) {
  let captured = null;
  const state = { vaultId: 'TestVault1234', authTok: null };   // новый девайс: токена ещё нет
  const fetchStub = async (url, opts) => {
    captured = { url, opts };
    return { status: 200, ok: true, json: async () => ({ v: 3, ct: 'x' }) };
  };
  const ctx = vm.createContext({ state, fetch: fetchStub, console, Object });
  vm.runInContext(src + '\n;globalThis.__call = t => fetchRemoteBlob(t);', ctx);
  const result = await ctx.__call(tok);
  return { captured, result };
}

console.log('Разблокировка на новом устройстве:');
{
  const { captured } = await run('token-from-password');
  const auth = captured?.opts?.headers?.Authorization;
  check('переданный токен уходит в Authorization', auth === 'Bearer token-from-password', String(auth));
  check('URL содержит id сейфа', captured?.url === '/vault/TestVault1234', String(captured?.url));
}
{
  const { captured } = await run(null);
  check('без токена заголовка нет (legacy-чтение)', !captured?.opts?.headers, JSON.stringify(captured?.opts));
}
{
  // старый баг: подстановка state.authTok вместо аргумента
  const bad = /headers:\s*authHeaders\(\)/.test(src);
  check('в fetchRemoteBlob не используется authHeaders()', !bad);
}

console.log(failures ? `\nПРОВАЛЕНО: ${failures}` : '\nВСЕ ТЕСТЫ ПРОШЛИ');
process.exit(failures ? 1 : 0);
