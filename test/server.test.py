#!/usr/bin/env python3
"""
Тест сервера: write-ключ, rate limit, заголовки безопасности, статика.
Запуск: python3 test/server.test.py
Поднимает server.py на случайном порту с временной DATA_DIR.
"""
import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAULT = 'TestVault123456'
WKEY = 'testkey_abcd1234EFGH'
BLOB = {'v': 1, 'iterations': 600000, 'salt': 'c2FsdA==', 'iv': 'aXY=',
        'ct': 'Y3Q=', 'mac': 'bWFj', 'updatedAt': 1}

failed = 0
def check(name, cond, extra=''):
    global failed
    if cond:
        print('  ok  ' + name)
    else:
        failed += 1
        print('  FAIL ' + name + (' — ' + extra if extra else ''))


def req(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse()
    data = r.read()
    hs = {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    return r.status, data, hs


def main():
    tmp = tempfile.mkdtemp(prefix='passwarium-test-')
    env = dict(os.environ, PASSWARIUM_DATA=tmp)
    # ищем свободный порт
    import socket
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, 'server.py'), '--port', str(port), '--bind', '127.0.0.1'],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # ждём поднятия
        for _ in range(50):
            try:
                st, _, _ = req(port, 'GET', '/')
                break
            except OSError:
                time.sleep(0.1)

        print('Статика и заголовки:')
        st, body, hs = req(port, 'GET', '/')
        check('GET / → 200 text/html', st == 200 and hs.get('content-type', '').startswith('text/html'))
        check('есть X-Content-Type-Options: nosniff', hs.get('x-content-type-options') == 'nosniff')
        check('есть CSP', 'content-security-policy' in hs)
        check('есть Referrer-Policy', hs.get('referrer-policy') == 'no-referrer')
        st, _, hs = req(port, 'GET', '/manifest.webmanifest')
        check('GET /manifest.webmanifest → 200', st == 200)
        st, _, hs = req(port, 'GET', '/sw.js')
        check('GET /sw.js → 200', st == 200 and 'javascript' in hs.get('content-type', ''))
        st, _, hs = req(port, 'GET', '/icon.svg')
        check('GET /icon.svg → 200', st == 200)

        print('Ключ записи:')
        st, _, _ = req(port, 'PUT', '/vault/' + VAULT,
                       body=json.dumps(BLOB), headers={'Content-Type': 'application/json'})
        check('PUT нового сейфа без ключа → 403', st == 403, 'код %d' % st)

        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(BLOB),
                       headers={'Content-Type': 'application/json', 'X-Vault-Key': WKEY})
        check('PUT нового сейфа с ключом → 200', st == 200, 'код %d' % st)
        with open(os.path.join(tmp, 'vault-%s.json' % VAULT), encoding='utf-8') as f:
            saved = json.load(f)
        check('на диске сохранён wsha (хеш, не ключ)', 'wsha' in saved and saved['wsha'] != WKEY)

        st, body, _ = req(port, 'GET', '/vault/' + VAULT)
        got = json.loads(body)
        check('GET отдаёт сейф без wsha', st == 200 and 'wsha' not in got and got['ct'] == 'Y3Q=')

        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(BLOB),
                       headers={'Content-Type': 'application/json'})
        check('PUT без ключа к защищённому сейфу → 403', st == 403, 'код %d' % st)
        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(BLOB),
                       headers={'Content-Type': 'application/json', 'X-Vault-Key': 'wrong_key_12345678'})
        check('PUT с неверным ключом → 403', st == 403, 'код %d' % st)
        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(BLOB),
                       headers={'Content-Type': 'application/json', 'X-Vault-Key': WKEY})
        check('PUT с верным ключом → 200', st == 200, 'код %d' % st)

        print('Прочее:')
        st, _, _ = req(port, 'GET', '/vault/bad$id')
        check('невалидный id → 400', st == 400, 'код %d' % st)
        st, _, _ = req(port, 'GET', '/vault/' + 'NoSuchVault999')
        check('несуществующий сейф → 404', st == 404, 'код %d' % st)
        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body='{bad json',
                       headers={'Content-Type': 'application/json', 'X-Vault-Key': WKEY})
        check('битый JSON → 400', st == 400, 'код %d' % st)

        print('Rate limit:')
        got429 = False
        for i in range(40):  # лимит PUT — 30/мин на IP, выше уже потрачено несколько
            st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(BLOB),
                           headers={'Content-Type': 'application/json', 'X-Vault-Key': WKEY})
            if st == 429:
                got429 = True
                break
        check('после серии PUT прилетает 429', got429)

        print()
        print('ВСЕ ТЕСТЫ ПРОШЛИ' if failed == 0 else 'ПРОВАЛЕНО: %d' % failed)
        return 0 if failed == 0 else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
