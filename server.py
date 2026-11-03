#!/usr/bin/env python3
"""
Passwarium — сервер раздачи приложения и хранения зашифрованного сейфа.

Только стандартная библиотека Python 3. Сервер хранит исключительно
шифртекст: мастер-пароль никогда не покидает устройство пользователя.

Модель доступа (v2.0):
  * создание сейфа — POST /vault {id, asha, vault}; закрыто без
    PW_CREATE_TOKEN (если переменная не задана — разрешён только
    самый первый сейф на сервере);
  * GET/PUT сейфа v3 — по заголовку Authorization: Bearer <токен>,
    на диске лежит только SHA-256 от токена (поле asha);
  * старые сейфы v1/v2 (без asha) — только чтение; запись в сейф без
    сохранённого хеша ключа записи запрещена (403), сейфы с ключом
    записи (wsha) принимают PUT по старой схеме до миграции;
  * неверный токен: 10 попыток за 10 минут на один сейф, затем блок
    на 15 минут (PW_AUTH_FAILS);
  * rate limit по IP; адрес клиента берётся из X-Forwarded-For только
    если запрос пришёл от PW_TRUSTED_PROXIES.

Настройки (переменные окружения):
    PASSWARIUM_DATA     каталог данных (по умолчанию ./data)
    PW_CREATE_TOKEN     токен, разрешающий создание новых сейфов
    PW_MAX_VAULTS       максимум сейфов на сервере (50)
    PW_MAX_BODY         максимальный размер сейфа в байтах (262144)
    PW_AUTH_FAILS       неверных токенов до блокировки (10)
    PW_TRUSTED_PROXIES  доверенные прокси через запятую (127.0.0.1)

Запуск:
    python3 server.py                 # порт 8800, слушает 127.0.0.1
    python3 server.py --port 9000 --bind 0.0.0.0
"""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('PASSWARIUM_DATA') or os.environ.get('PASSVAULT_DATA') or os.path.join(ROOT, 'data')
MAX_BODY = int(os.environ.get('PW_MAX_BODY') or 256 * 1024)
MAX_VAULTS = int(os.environ.get('PW_MAX_VAULTS') or 50)
CREATE_TOKEN = os.environ.get('PW_CREATE_TOKEN') or None
AUTH_FAILS_LIMIT = int(os.environ.get('PW_AUTH_FAILS') or 10)
AUTH_WINDOW = 600.0   # окно подсчёта неверных токенов, сек
AUTH_BLOCK = 900.0    # длительность блокировки, сек
TRUSTED_PROXIES = []
for _p in re.split(r'[,\s]+', os.environ.get('PW_TRUSTED_PROXIES') or '127.0.0.1'):
    if not _p:
        continue
    try:
        TRUSTED_PROXIES.append(ipaddress.ip_network(_p, strict=False))
    except ValueError:
        print('PW_TRUSTED_PROXIES: пропускаю невалидную запись %r' % _p, file=sys.stderr)


def is_trusted_proxy(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in TRUSTED_PROXIES)

VAULT_ID_RE = re.compile(r'^[A-Za-z0-9_-]{8,64}$')
WKEY_RE = re.compile(r'^[A-Za-z0-9_-]{16,64}$')
TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{16,128}$')
ASHA_RE = re.compile(r'^[0-9a-f]{64}$')

V3_FIELDS = {'v', 'kdf', 'iv', 'ct', 'updatedAt'}
LEGACY_FIELDS = {'v', 'iterations', 'salt', 'iv', 'ct', 'mac', 'updatedAt'}

STATIC = {
    '/': ('index.html', 'text/html; charset=utf-8'),
    '/index.html': ('index.html', 'text/html; charset=utf-8'),
    '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
    '/app.css': ('app.css', 'text/css; charset=utf-8'),
    '/manifest.webmanifest': ('manifest.webmanifest', 'application/manifest+json'),
    '/sw.js': ('sw.js', 'text/javascript; charset=utf-8'),
    '/icon.svg': ('icon.svg', 'image/svg+xml'),
    '/hash-wasm.js': ('hash-wasm.js', 'text/javascript; charset=utf-8'),
    '/crypto-legacy.js': ('crypto-legacy.js', 'text/javascript; charset=utf-8'),
    '/qr.js': ('qr.js', 'text/javascript; charset=utf-8'),
    '/fonts/inter-latin.woff2': ('fonts/inter-latin.woff2', 'font/woff2'),
    '/fonts/inter-cyrillic.woff2': ('fonts/inter-cyrillic.woff2', 'font/woff2'),
    '/fonts/OFL.txt': ('fonts/OFL.txt', 'text/plain; charset=utf-8'),
}

CSP = ("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
       "img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; "
       "worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

PERMISSIONS_POLICY = ('accelerometer=(), camera=(), geolocation=(), gyroscope=(), '
                      'magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()')

# ---------- rate limit: окно 60 с, лимиты по типу запроса ----------
RATE_WINDOW = 60.0
RATE_LIMITS = {'GET': 120, 'PUT': 30, 'POST': 30}
_rate_lock = threading.Lock()
_rate = {}  # ip -> {method: (window_start, count)}


def rate_ok(ip, method):
    limit = RATE_LIMITS.get(method)
    if limit is None:
        return True
    now = time.monotonic()
    with _rate_lock:
        entry = _rate.setdefault(ip, {})
        start, count = entry.get(method, (now, 0))
        if now - start >= RATE_WINDOW:
            start, count = now, 0
        count += 1
        entry[method] = (start, count)
        # периодически чистим устаревшие записи, чтобы таблица не росла
        if len(_rate) > 4096:
            stale = [k for k, v in _rate.items()
                     if all(now - s >= RATE_WINDOW for s, _ in v.values())]
            for k in stale:
                del _rate[k]
        return count <= limit


# ---------- троттлинг неверных токенов: (ip, vault) ----------
_auth_lock = threading.Lock()
_auth = {}  # (ip, vid) -> [fails, window_start, blocked_until]


def auth_blocked(ip, vid):
    now = time.monotonic()
    with _auth_lock:
        rec = _auth.get((ip, vid))
        return bool(rec and rec[2] and now < rec[2])


def auth_fail(ip, vid):
    now = time.monotonic()
    with _auth_lock:
        rec = _auth.setdefault((ip, vid), [0, now, 0.0])
        if now - rec[1] >= AUTH_WINDOW:
            rec[0], rec[1] = 0, now
        rec[0] += 1
        if rec[0] >= AUTH_FAILS_LIMIT:
            rec[2] = now + AUTH_BLOCK
            rec[0], rec[1] = 0, now
        if len(_auth) > 8192:
            stale = [k for k, v in _auth.items()
                     if not (v[2] and now < v[2]) and now - v[1] >= AUTH_WINDOW]
            for k in stale:
                del _auth[k]


def auth_reset(ip, vid):
    with _auth_lock:
        _auth.pop((ip, vid), None)


def tok_hash(tok):
    return hashlib.sha256(tok.encode('utf-8')).hexdigest()


def wkey_hash(key):
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def vault_path(vid):
    return os.path.join(DATA_DIR, 'vault-%s.json' % vid)


def load_vault(vid):
    p = vault_path(vid)
    if not os.path.isfile(p):
        return None
    try:
        with open(p, 'r', encoding='utf-8') as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except (ValueError, OSError):
        return None


def vault_count():
    try:
        return sum(1 for n in os.listdir(DATA_DIR)
                   if n.startswith('vault-') and n.endswith('.json'))
    except OSError:
        return 0


def modern_vault_count():
    """Число сейфов v3 (с asha). Правило «только первый сейф» смотрит на него,
    чтобы владельцы legacy-сейфов могли мигрировать без PW_CREATE_TOKEN."""
    n = 0
    try:
        for name in os.listdir(DATA_DIR):
            if not (name.startswith('vault-') and name.endswith('.json')):
                continue
            try:
                with open(os.path.join(DATA_DIR, name), 'r', encoding='utf-8') as f:
                    if json.load(f).get('asha'):
                        n += 1
            except (ValueError, OSError):
                continue
    except OSError:
        pass
    return n


def write_vault(vid, obj):
    os.makedirs(DATA_DIR, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False)
        os.replace(tmp, vault_path(vid))
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class Handler(BaseHTTPRequestHandler):
    server_version = 'Passwarium/2.0'
    protocol_version = 'HTTP/1.1'

    # ---------- служебное ----------
    def _send(self, code, body=b'', ctype='application/json; charset=utf-8'):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Strict-Transport-Security', 'max-age=31536000')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Permissions-Policy', PERMISSIONS_POLICY)
        if ctype.startswith('text/html'):
            self.send_header('Content-Security-Policy', CSP)
        if code >= 400:
            # при ошибке тело запроса могло остаться непрочитанным — keep-alive нельзя продолжать
            self.send_header('Connection', 'close')
            self.close_connection = True
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _client_ip(self):
        ip = self.client_address[0]
        if is_trusted_proxy(ip):
            xff = self.headers.get('X-Forwarded-For')
            if xff:
                # крайний правый адрес добавлен ближайшим к нам доверенным прокси
                ip = xff.split(',')[-1].strip() or ip
        return ip

    def _rate_limited(self):
        return not rate_ok(self._client_ip(), self.command)

    def _vault_id(self):
        raw = self.path.split('?')[0].split('#')[0]
        raw = raw[len('/vault/'):]
        if not VAULT_ID_RE.match(raw):
            return None
        return raw

    def _bearer(self):
        h = self.headers.get('Authorization') or ''
        if not h.startswith('Bearer '):
            return None
        tok = h[7:].strip()
        return tok if TOKEN_RE.match(tok) else None

    def _check_auth(self, vid, asha):
        """Проверка Bearer-токена. True — доступ разрешён, иначе ответ уже отправлен."""
        ip = self._client_ip()
        if auth_blocked(ip, vid):
            self._send(429, b'too many attempts', 'text/plain; charset=utf-8')
            return False
        tok = self._bearer()
        if not tok or not hmac.compare_digest(tok_hash(tok), asha):
            auth_fail(ip, vid)
            self._send(401)  # тело пустое
            return False
        auth_reset(ip, vid)
        return True

    def _read_body(self):
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._send(413, b'payload too large', 'text/plain; charset=utf-8')
            return None
        return self.rfile.read(length)

    @staticmethod
    def _valid_payload(obj):
        if not isinstance(obj, dict):
            return False
        if obj.get('v') == 3:
            return V3_FIELDS.issubset(obj) and isinstance(obj.get('kdf'), dict)
        return LEGACY_FIELDS.issubset(obj)

    # ---------- GET ----------
    def do_GET(self):
        if self._rate_limited():
            return self._send(429, b'too many requests', 'text/plain; charset=utf-8')
        path = self.path.split('?')[0].split('#')[0]
        if path in STATIC:
            fname, ctype = STATIC[path]
            try:
                with open(os.path.join(ROOT, fname), 'rb') as f:
                    self._send(200, f.read(), ctype)
            except FileNotFoundError:
                self._send(404, (fname + ' not found').encode(), 'text/plain; charset=utf-8')
        elif path.startswith('/vault/'):
            # GET /vault/<id>/meta — публичные KDF-параметры (соль не секретна);
            # без них клиент не сможет вывести токен для авторизованного GET
            if path.endswith('/meta'):
                raw = path[len('/vault/'):-len('/meta')]
                vid = raw if VAULT_ID_RE.match(raw) else None
                if not vid:
                    return self._send(400, b'bad vault id', 'text/plain; charset=utf-8')
                obj = load_vault(vid)
                if obj is None or not obj.get('asha') or obj.get('v') != 3:
                    return self._send(404, b'vault not found', 'text/plain; charset=utf-8')
                meta = {'v': 3, 'kdf': obj.get('kdf'), 'updatedAt': obj.get('updatedAt')}
                return self._send(200, json.dumps(meta, ensure_ascii=False).encode('utf-8'))
            vid = self._vault_id()
            if not vid:
                return self._send(400, b'bad vault id', 'text/plain; charset=utf-8')
            obj = load_vault(vid)
            if obj is None:
                return self._send(404, b'vault not found', 'text/plain; charset=utf-8')
            asha = obj.get('asha')
            if asha and not self._check_auth(vid, asha):
                return
            # служебные хеши наружу не отдаём
            obj = {k: v for k, v in obj.items() if k not in ('wsha', 'asha')}
            self._send(200, json.dumps(obj, ensure_ascii=False).encode('utf-8'))
        else:
            self._send(404, b'not found', 'text/plain; charset=utf-8')

    # ---------- POST: создание сейфа ----------
    def do_POST(self):
        if self._rate_limited():
            return self._send(429, b'too many requests', 'text/plain; charset=utf-8')
        path = self.path.split('?')[0].split('#')[0]
        if path != '/vault':
            return self._send(404, b'not found', 'text/plain; charset=utf-8')

        # создание закрыто: либо по PW_CREATE_TOKEN, либо только первый сейф
        if CREATE_TOKEN:
            given = self.headers.get('X-Create-Token') or ''
            if not given or not hmac.compare_digest(given, CREATE_TOKEN):
                return self._send(403, b'creation forbidden', 'text/plain; charset=utf-8')
        elif modern_vault_count() > 0:
            return self._send(403, b'creation forbidden', 'text/plain; charset=utf-8')
        if vault_count() >= MAX_VAULTS:
            return self._send(403, b'vault limit reached', 'text/plain; charset=utf-8')

        body = self._read_body()
        if body is None:
            return
        try:
            req = json.loads(body.decode('utf-8'))
            vid = req['id']
            asha = req['asha']
            vault = req['vault']
        except Exception:
            return self._send(400, b'bad payload', 'text/plain; charset=utf-8')
        if not isinstance(vid, str) or not VAULT_ID_RE.match(vid):
            return self._send(400, b'bad vault id', 'text/plain; charset=utf-8')
        if not isinstance(asha, str) or not ASHA_RE.match(asha):
            return self._send(400, b'bad token hash', 'text/plain; charset=utf-8')
        if not self._valid_payload(vault) or vault.get('v') != 3:
            return self._send(400, b'bad vault payload', 'text/plain; charset=utf-8')
        if load_vault(vid) is not None:
            return self._send(409, b'vault exists', 'text/plain; charset=utf-8')

        obj = dict(vault)
        obj['asha'] = asha
        write_vault(vid, obj)
        self._send(200, b'{"ok":true}')

    # ---------- PUT: обновление сейфа ----------
    def do_PUT(self):
        if self._rate_limited():
            return self._send(429, b'too many requests', 'text/plain; charset=utf-8')
        path = self.path.split('?')[0].split('#')[0]
        if not path.startswith('/vault/'):
            return self._send(404, b'not found', 'text/plain; charset=utf-8')
        vid = self._vault_id()
        if not vid:
            return self._send(400, b'bad vault id', 'text/plain; charset=utf-8')

        old = load_vault(vid)
        if old is None:
            # создание сейфа — только через POST /vault
            return self._send(404, b'vault not found', 'text/plain; charset=utf-8')

        old_asha = old.get('asha')
        old_wsha = old.get('wsha')
        if old_asha:
            # сейф v3: запись по Bearer-токену
            if not self._check_auth(vid, old_asha):
                return
        elif old_wsha:
            # legacy-сейф с ключом записи: старая схема до миграции
            wkey = self.headers.get('X-Vault-Key', '')
            if not wkey or not WKEY_RE.match(wkey) or not hmac.compare_digest(wkey_hash(wkey), old_wsha):
                return self._send(403, b'write key required', 'text/plain; charset=utf-8')
        else:
            # сейф без ключа — только чтение; «прикрепить» ключ нельзя
            return self._send(403, b'vault is read-only', 'text/plain; charset=utf-8')

        body = self._read_body()
        if body is None:
            return
        try:
            obj = json.loads(body.decode('utf-8'))
        except Exception:
            return self._send(400, b'bad payload', 'text/plain; charset=utf-8')
        if not self._valid_payload(obj):
            return self._send(400, b'bad payload', 'text/plain; charset=utf-8')
        if old_asha and obj.get('v') != 3:
            return self._send(400, b'bad vault payload', 'text/plain; charset=utf-8')

        obj.pop('wsha', None)
        obj.pop('asha', None)
        if old_asha:
            # ротация токена: смена мастер-пароля присылает newasha (sha256 нового токена)
            new_asha = obj.pop('newasha', None)
            if new_asha is not None and not (isinstance(new_asha, str) and ASHA_RE.match(new_asha)):
                return self._send(400, b'bad new token hash', 'text/plain; charset=utf-8')
            obj['asha'] = new_asha if new_asha else old_asha
        if old_wsha:
            obj['wsha'] = old_wsha
        write_vault(vid, obj)
        self._send(200, b'{"ok":true}')

    def log_message(self, fmt, *args):
        sys.stderr.write('[passwarium] %s %s\n' % (self.address_string(), fmt % args))


def lan_addresses():
    addrs = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith('127.'):
                addrs.append(ip)
    except OSError:
        pass
    return sorted(set(addrs))


def main():
    argv = sys.argv[1:]
    port = int(argv[argv.index('--port') + 1]) if '--port' in argv else 8800
    bind = argv[argv.index('--bind') + 1] if '--bind' in argv else '127.0.0.1'
    srv = ThreadingHTTPServer((bind, port), Handler)
    print('Passwarium: http://%s:%d' % (bind, port))
    if bind == '0.0.0.0':
        for ip in lan_addresses():
            print('           http://%s:%d' % (ip, port))
        print('ВНИМАНИЕ: без HTTPS и обратного прокси сервер слушать снаружи не должен.')
    print('Данные сейфов: %s' % DATA_DIR)
    if not CREATE_TOKEN:
        print('PW_CREATE_TOKEN не задан: создать можно только первый сейф.')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\nОстановлено.')


if __name__ == '__main__':
    main()
