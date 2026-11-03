#!/usr/bin/env python3
"""
Тест сервера Passwarium 2.0: Bearer-аутентификация, создание сейфов,
legacy-режим «только чтение», троттлинг токенов, X-Forwarded-For,
заголовки безопасности, статика.

Запуск: python3 test/server.test.py
Поднимает server.py на случайных портах с временными DATA_DIR.
"""
import hashlib
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAULT = 'TestVault123456'
TOKEN = 'tok_abcdefgh12345678'
ASHA = hashlib.sha256(TOKEN.encode()).hexdigest()
WKEY = 'testkey_abcd1234EFGH'
V3 = {'v': 3, 'kdf': {'alg': 'argon2id', 'm': 65536, 't': 3, 'p': 1, 'salt': 'c2FsdA'},
      'iv': 'aXY', 'ct': 'Y3Q', 'updatedAt': 1}
LEGACY = {'v': 1, 'iterations': 600000, 'salt': 'c2FsdA==', 'iv': 'aXY=',
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


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_server(data_dir, extra_env=None):
    port = free_port()
    env = dict(os.environ, PASSWARIUM_DATA=data_dir)
    env.pop('PW_CREATE_TOKEN', None)
    env.pop('PW_MAX_VAULTS', None)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, 'server.py'), '--port', str(port), '--bind', '127.0.0.1'],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            req(port, 'GET', '/')
            break
        except OSError:
            time.sleep(0.1)
    return proc, port


def stop_server(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def bearer(tok):
    return {'Authorization': 'Bearer ' + tok}


def main():
    tmp = tempfile.mkdtemp(prefix='passwarium-test-')
    procs = []
    try:
        # ============ инстанс 1: без PW_CREATE_TOKEN ============
        proc, port = start_server(tmp)
        procs.append(proc)

        print('Статика и заголовки:')
        st, _, hs = req(port, 'GET', '/')
        check('GET / → 200 text/html', st == 200 and hs.get('content-type', '').startswith('text/html'))
        check('X-Content-Type-Options: nosniff', hs.get('x-content-type-options') == 'nosniff')
        check('HSTS', hs.get('strict-transport-security') == 'max-age=31536000')
        check('X-Frame-Options: DENY', hs.get('x-frame-options') == 'DENY')
        check('COOP', hs.get('cross-origin-opener-policy') == 'same-origin')
        check('Permissions-Policy', 'camera=()' in hs.get('permissions-policy', ''))
        check('Referrer-Policy', hs.get('referrer-policy') == 'no-referrer')
        check('CSP без unsafe-inline', 'unsafe-inline' not in hs.get('content-security-policy', ''))
        st, _, _ = req(port, 'GET', '/manifest.webmanifest')
        check('GET /manifest.webmanifest → 200', st == 200)
        st, _, hs = req(port, 'GET', '/sw.js')
        check('GET /sw.js → 200', st == 200 and 'javascript' in hs.get('content-type', ''))
        st, _, _ = req(port, 'GET', '/icon.svg')
        check('GET /icon.svg → 200', st == 200)

        print('Создание сейфов:')
        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(V3),
                       headers={'Content-Type': 'application/json'})
        check('PUT нового сейфа → 404 (создание только через POST)', st == 404, 'код %d' % st)

        st, _, _ = req(port, 'POST', '/vault',
                       body=json.dumps({'id': VAULT, 'asha': ASHA, 'vault': V3}),
                       headers={'Content-Type': 'application/json'})
        check('POST первого сейфа без PW_CREATE_TOKEN → 200', st == 200, 'код %d' % st)

        st, _, _ = req(port, 'POST', '/vault',
                       body=json.dumps({'id': 'SecondVault99', 'asha': ASHA, 'vault': V3}),
                       headers={'Content-Type': 'application/json'})
        check('POST второго сейфа без PW_CREATE_TOKEN → 403', st == 403, 'код %d' % st)

        st, _, _ = req(port, 'POST', '/vault',
                       body=json.dumps({'id': VAULT, 'asha': ASHA, 'vault': V3}),
                       headers={'Content-Type': 'application/json'})
        check('POST поверх существующего без create-токена → 403', st == 403, 'код %d' % st)

        with open(os.path.join(tmp, 'vault-%s.json' % VAULT), encoding='utf-8') as f:
            saved = json.load(f)
        check('на диске asha (хеш, не токен)', saved.get('asha') == ASHA and TOKEN not in json.dumps(saved))

        print('Bearer-аутентификация:')
        st, body, _ = req(port, 'GET', '/vault/' + VAULT)
        check('GET без токена → 401, тело пустое', st == 401 and body == b'', 'код %d, тело %r' % (st, body))
        st, _, _ = req(port, 'GET', '/vault/' + VAULT, headers=bearer('wrong_token_1234567'))
        check('GET с неверным токеном → 401', st == 401, 'код %d' % st)
        st, body, _ = req(port, 'GET', '/vault/' + VAULT, headers=bearer(TOKEN))
        got = json.loads(body)
        check('GET с верным токеном → 200 без asha', st == 200 and 'asha' not in got and got['ct'] == 'Y3Q',
              'код %d' % st)

        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(V3),
                       headers={'Content-Type': 'application/json'})
        check('PUT без токена → 401', st == 401, 'код %d' % st)
        v3b = dict(V3, ct='Y3Qy', updatedAt=2)
        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(v3b),
                       headers=dict(bearer(TOKEN), **{'Content-Type': 'application/json'}))
        check('PUT с верным токеном → 200', st == 200, 'код %d' % st)
        with open(os.path.join(tmp, 'vault-%s.json' % VAULT), encoding='utf-8') as f:
            saved = json.load(f)
        check('PUT сохранил asha и новый ct', saved.get('asha') == ASHA and saved.get('ct') == 'Y3Qy')
        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(v3b),
                       headers=dict(bearer(TOKEN), **{'Content-Type': 'application/json', 'X-Vault-Key': WKEY}))
        check('ключ записи к v3 не подмешивается', st == 200)
        with open(os.path.join(tmp, 'vault-%s.json' % VAULT), encoding='utf-8') as f:
            check('в файле нет wsha', 'wsha' not in json.load(f))

        print('Троттлинг неверных токенов (PW_AUTH_FAILS=10):')
        vid2 = 'ThrottleVault1'
        with open(os.path.join(tmp, 'vault-%s.json' % vid2), 'w', encoding='utf-8') as f:
            json.dump(dict(V3, asha=ASHA), f)
        codes = [req(port, 'GET', '/vault/' + vid2, headers=bearer('bad_token_%08d' % i))[0]
                 for i in range(10)]
        check('первые 10 неверных → 401', all(c == 401 for c in codes), str(codes))
        st, _, _ = req(port, 'GET', '/vault/' + vid2, headers=bearer('bad_token_00000010'))
        check('11-я попытка → 429 (блок)', st == 429, 'код %d' % st)
        st, _, _ = req(port, 'GET', '/vault/' + vid2, headers=bearer(TOKEN))
        check('даже верный токен во время блока → 429', st == 429, 'код %d' % st)

        print('Legacy-сейфы (v1/v2):')
        vid_lk = 'LegacyWithKey1'
        with open(os.path.join(tmp, 'vault-%s.json' % vid_lk), 'w', encoding='utf-8') as f:
            json.dump(dict(LEGACY, wsha=hashlib.sha256(WKEY.encode()).hexdigest()), f)
        vid_ln = 'LegacyNoKey12'
        with open(os.path.join(tmp, 'vault-%s.json' % vid_ln), 'w', encoding='utf-8') as f:
            json.dump(dict(LEGACY), f)

        st, body, _ = req(port, 'GET', '/vault/' + vid_ln)
        check('GET legacy без ключа → 200 (только чтение), wsha скрыт',
              st == 200 and 'wsha' not in json.loads(body))
        st, _, _ = req(port, 'PUT', '/vault/' + vid_ln, body=json.dumps(LEGACY),
                       headers={'Content-Type': 'application/json'})
        check('PUT в legacy без ключа → 403', st == 403, 'код %d' % st)
        st, _, _ = req(port, 'PUT', '/vault/' + vid_ln, body=json.dumps(LEGACY),
                       headers={'Content-Type': 'application/json', 'X-Vault-Key': WKEY})
        check('«прикрепить» ключ к legacy без ключа → 403', st == 403, 'код %d' % st)
        st, _, _ = req(port, 'PUT', '/vault/' + vid_lk, body=json.dumps(LEGACY),
                       headers={'Content-Type': 'application/json', 'X-Vault-Key': 'wrong_key_12345678'})
        check('PUT в legacy с неверным ключом → 403', st == 403, 'код %d' % st)
        st, _, _ = req(port, 'PUT', '/vault/' + vid_lk, body=json.dumps(LEGACY),
                       headers={'Content-Type': 'application/json', 'X-Vault-Key': WKEY})
        check('PUT в legacy с верным ключом → 200 (до миграции)', st == 200, 'код %d' % st)

        print('Прочее:')
        st, body, _ = req(port, 'GET', '/vault/' + VAULT + '/meta')
        meta = json.loads(body)
        check('GET /meta → 200 с kdf, без ct и asha',
              st == 200 and meta.get('v') == 3 and 'salt' in meta.get('kdf', {})
              and 'ct' not in meta and 'asha' not in meta, 'код %d' % st)
        st, _, _ = req(port, 'GET', '/vault/' + vid_ln + '/meta')
        check('GET /meta legacy-сейфа → 404', st == 404, 'код %d' % st)

        print('Ротация токена (смена мастер-пароля):')
        NEWTOK = 'newtoken_abcd12345678'
        NEWASHA = hashlib.sha256(NEWTOK.encode()).hexdigest()
        v3c = dict(V3, ct='Y3Qz', updatedAt=3, newasha=NEWASHA)
        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(v3c),
                       headers=dict(bearer(TOKEN), **{'Content-Type': 'application/json'}))
        check('PUT с newasha → 200', st == 200, 'код %d' % st)
        st, _, _ = req(port, 'GET', '/vault/' + VAULT, headers=bearer(TOKEN))
        check('старый токен больше не работает → 401', st == 401, 'код %d' % st)
        st, body, _ = req(port, 'GET', '/vault/' + VAULT, headers=bearer(NEWTOK))
        check('новый токен работает → 200', st == 200 and json.loads(body)['ct'] == 'Y3Qz', 'код %d' % st)
        v3bad = dict(V3, newasha='not-a-hash')
        st, _, _ = req(port, 'PUT', '/vault/' + VAULT, body=json.dumps(v3bad),
                       headers=dict(bearer(NEWTOK), **{'Content-Type': 'application/json'}))
        check('PUT с кривым newasha → 400', st == 400, 'код %d' % st)

        st, _, _ = req(port, 'GET', '/vault/bad$id')
        check('невалидный id → 400', st == 400, 'код %d' % st)
        st, _, _ = req(port, 'GET', '/vault/NoSuchVault999')
        check('несуществующий сейф → 404', st == 404, 'код %d' % st)

        print('X-Forwarded-For (доверенный прокси 127.0.0.1):')
        got429 = False
        for i in range(31):  # лимит PUT — 30/мин на IP
            st, _, _ = req(port, 'PUT', '/vault/NoSuchVault999', body=json.dumps(LEGACY),
                           headers={'Content-Type': 'application/json',
                                    'X-Forwarded-For': '9.9.9.9, 203.0.113.7'})
            if st == 429:
                got429 = True
                break
        check('лимит считается по крайнему правому XFF → 429', got429)
        st, _, _ = req(port, 'PUT', '/vault/NoSuchVault999', body=json.dumps(LEGACY),
                       headers={'Content-Type': 'application/json'})
        check('без XFF лимит отдельный → не 429', st != 429, 'код %d' % st)
        stop_server(procs.pop())

        # ============ инстанс 2: 127.0.0.1 НЕ доверен — XFF игнорируется ============
        tmp2 = tempfile.mkdtemp(prefix='passwarium-test2-')
        proc, port2 = start_server(tmp2, {'PW_TRUSTED_PROXIES': '10.0.0.1'})
        procs.append(proc)
        print('X-Forwarded-For с недоверенного адреса:')
        got429 = False
        for i in range(31):
            st, _, _ = req(port2, 'PUT', '/vault/NoSuchVault999', body=json.dumps(LEGACY),
                           headers={'Content-Type': 'application/json',
                                    'X-Forwarded-For': '198.51.100.%d' % i})
            if st == 429:
                got429 = True
                break
        check('разные XFF не спасают: лимит по реальному IP → 429', got429)
        stop_server(procs.pop())
        shutil.rmtree(tmp2, ignore_errors=True)

        # ============ инстанс 3: PW_CREATE_TOKEN + PW_MAX_VAULTS=2 ============
        tmp3 = tempfile.mkdtemp(prefix='passwarium-test3-')
        proc, port3 = start_server(tmp3, {'PW_CREATE_TOKEN': 'createtoken123', 'PW_MAX_VAULTS': '2'})
        procs.append(proc)
        print('PW_CREATE_TOKEN / PW_MAX_VAULTS:')
        body = lambda vid: json.dumps({'id': vid, 'asha': ASHA, 'vault': V3})
        st, _, _ = req(port3, 'POST', '/vault', body=body('VaultA12345678'),
                       headers={'Content-Type': 'application/json'})
        check('POST без create-токена → 403', st == 403, 'код %d' % st)
        h = {'Content-Type': 'application/json', 'X-Create-Token': 'createtoken123'}
        st, _, _ = req(port3, 'POST', '/vault', body=body('VaultA12345678'), headers=h)
        check('POST с create-токеном → 200', st == 200, 'код %d' % st)
        st, _, _ = req(port3, 'POST', '/vault', body=body('VaultA12345678'), headers=h)
        check('POST поверх существующего → 409', st == 409, 'код %d' % st)
        st, _, _ = req(port3, 'POST', '/vault', body=body('VaultB12345678'), headers=h)
        check('второй сейф → 200', st == 200, 'код %d' % st)
        st, _, _ = req(port3, 'POST', '/vault', body=body('VaultC12345678'), headers=h)
        check('третий сейф → 403 (PW_MAX_VAULTS=2)', st == 403, 'код %d' % st)
        stop_server(procs.pop())
        shutil.rmtree(tmp3, ignore_errors=True)

        # ============ инстанс 4: legacy-сейфы не мешают первому v3 ============
        tmp4 = tempfile.mkdtemp(prefix='passwarium-test4-')
        with open(os.path.join(tmp4, 'vault-OldLegacy12345.json'), 'w', encoding='utf-8') as f:
            json.dump(dict(LEGACY), f)
        proc, port4 = start_server(tmp4)
        procs.append(proc)
        print('Первый v3 при наличии legacy (миграция):')
        st, _, _ = req(port4, 'POST', '/vault',
                       body=json.dumps({'id': 'MigratedVault1', 'asha': ASHA, 'vault': V3}),
                       headers={'Content-Type': 'application/json'})
        check('при одних legacy на сервере первый v3 создаётся → 200', st == 200, 'код %d' % st)
        st, _, _ = req(port4, 'POST', '/vault',
                       body=json.dumps({'id': 'SecondV3Vault1', 'asha': ASHA, 'vault': V3}),
                       headers={'Content-Type': 'application/json'})
        check('второй v3 без create-токена → 403', st == 403, 'код %d' % st)
        stop_server(procs.pop())
        shutil.rmtree(tmp4, ignore_errors=True)

        print()
        print('ВСЕ ТЕСТЫ ПРОШЛИ' if failed == 0 else 'ПРОВАЛЕНО: %d' % failed)
        return 0 if failed == 0 else 1
    finally:
        for p in procs:
            stop_server(p)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
