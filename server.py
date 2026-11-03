#!/usr/bin/env python3
"""
Passwarium — сервер раздачи приложения и хранения зашифрованного сейфа.

Только стандартная библиотека Python 3. Сервер хранит исключительно
шифртекст: мастер-пароль никогда не покидает устройство пользователя.

Запись сейфа защищена ключом записи (write key): клиент передаёт его
в заголовке X-Vault-Key, на диске лежит только SHA-256 от ключа.
Запросы ограничены rate limit'ом по IP.

Запуск:
    python3 server.py                 # порт 8800, слушает все интерфейсы
    python3 server.py --port 9000 --bind 127.0.0.1
    PASSWARIUM_DATA=/var/lib/passwarium python3 server.py
"""
import hashlib
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
MAX_BODY = 256 * 1024
VAULT_ID_RE = re.compile(r'^[A-Za-z0-9_-]{8,64}$')
WKEY_RE = re.compile(r'^[A-Za-z0-9_-]{16,64}$')
REQUIRED_FIELDS = {'v', 'iterations', 'salt', 'iv', 'ct', 'mac', 'updatedAt'}

STATIC = {
    '/': ('index.html', 'text/html; charset=utf-8'),
    '/index.html': ('index.html', 'text/html; charset=utf-8'),
    '/manifest.webmanifest': ('manifest.webmanifest', 'application/manifest+json'),
    '/sw.js': ('sw.js', 'text/javascript; charset=utf-8'),
    '/icon.svg': ('icon.svg', 'image/svg+xml'),
}

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
       "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; "
       "connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'")

# ---------- rate limit: окно 60 с, лимиты по типу запроса ----------
RATE_WINDOW = 60.0
RATE_LIMITS = {'GET': 120, 'PUT': 30}
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


def wkey_hash(key):
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


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
        if ctype.startswith('text/html'):
            self.send_header('Content-Security-Policy', CSP)
        if ctype.startswith('text/javascript'):
            # service worker должен обновляться без кэша
            self.send_header('Cache-Control', 'no-store')
        if code >= 400:
            # при ошибке тело запроса могло остаться непрочитанным — keep-alive нельзя продолжать
            self.send_header('Connection', 'close')
            self.close_connection = True
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _vault_id(self):
        raw = self.path[len('/vault/'):].split('?')[0].split('#')[0]
        if not VAULT_ID_RE.match(raw):
            return None
        return raw

    def _rate_limited(self):
        return not rate_ok(self.client_address[0], self.command)

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
            vid = self._vault_id()
            if not vid:
                return self._send(400, b'bad vault id', 'text/plain; charset=utf-8')
            p = os.path.join(DATA_DIR, 'vault-%s.json' % vid)
            if not os.path.isfile(p):
                return self._send(404, b'vault not found', 'text/plain; charset=utf-8')
            with open(p, 'rb') as f:
                try:
                    obj = json.load(f)
                except ValueError:
                    return self._send(500, b'corrupt vault', 'text/plain; charset=utf-8')
            obj.pop('wsha', None)  # хеш ключа записи наружу не отдаём
            self._send(200, json.dumps(obj, ensure_ascii=False).encode('utf-8'))
        else:
            self._send(404, b'not found', 'text/plain; charset=utf-8')

    # ---------- PUT ----------
    def do_PUT(self):
        if self._rate_limited():
            return self._send(429, b'too many requests', 'text/plain; charset=utf-8')
        path = self.path.split('?')[0].split('#')[0]
        if not path.startswith('/vault/'):
            return self._send(404, b'not found', 'text/plain; charset=utf-8')
        vid = self._vault_id()
        if not vid:
            return self._send(400, b'bad vault id', 'text/plain; charset=utf-8')

        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return self._send(413, b'payload too large', 'text/plain; charset=utf-8')
        body = self.rfile.read(length)

        try:
            obj = json.loads(body.decode('utf-8'))
            if not isinstance(obj, dict) or not REQUIRED_FIELDS.issubset(obj):
                raise ValueError
        except Exception:
            return self._send(400, b'bad payload', 'text/plain; charset=utf-8')

        # ---- ключ записи ----
        wkey = self.headers.get('X-Vault-Key', '')
        if wkey and not WKEY_RE.match(wkey):
            return self._send(400, b'bad write key', 'text/plain; charset=utf-8')
        p = os.path.join(DATA_DIR, 'vault-%s.json' % vid)
        old_wsha = None
        if os.path.isfile(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    old_wsha = json.load(f).get('wsha')
            except (ValueError, OSError):
                old_wsha = None
        if old_wsha:
            # сейф уже защищён: без верного ключа записи — отказ
            if not wkey or wkey_hash(wkey) != old_wsha:
                return self._send(403, b'write key required', 'text/plain; charset=utf-8')
        elif not wkey and not os.path.isfile(p):
            # новый сейф без ключа записи не создаём
            return self._send(403, b'write key required', 'text/plain; charset=utf-8')
        if wkey:
            obj['wsha'] = wkey_hash(wkey)
        elif old_wsha:
            obj['wsha'] = old_wsha  # legacy-запись без ключа: сохраняем прежний хеш

        os.makedirs(DATA_DIR, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(obj, f, ensure_ascii=False)
            os.replace(tmp, p)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        self._send(200, b'{"ok":true}')

    def log_message(self, fmt, *args):
        sys.stderr.write('[passwarium] %s %s\n' % (self.address_string(), fmt % args))


def lan_addresses(port):
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
    bind = argv[argv.index('--bind') + 1] if '--bind' in argv else '0.0.0.0'
    srv = ThreadingHTTPServer((bind, port), Handler)
    print('Passwarium: http://%s:%d' % ('127.0.0.1' if bind == '0.0.0.0' else bind, port))
    for ip in (lan_addresses(port) if bind == '0.0.0.0' else []):
        print('           http://%s:%d' % (ip, port))
    print('Данные сейфов: %s' % DATA_DIR)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\nОстановлено.')


if __name__ == '__main__':
    main()
