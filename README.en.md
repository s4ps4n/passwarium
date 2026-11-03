# Passwarium

**Glass on the outside. The key stays with you.**

[🇷🇺 Русская версия](README.md) · [MIT License](LICENSE)

[![License: MIT](https://img.shields.io/badge/license-MIT-2dd4bf.svg)](LICENSE)
[![Python 3](https://img.shields.io/badge/python-3.9%2B-3776ab.svg)](https://www.python.org/)
[![No dependencies](https://img.shields.io/badge/dependencies-none-51e6b8.svg)](#how-it-works)
[![PWA](https://img.shields.io/badge/PWA-offline--ready-8b5cf6.svg)](#phone-handoff)

A password manager that lives on your own VPS: one HTML file with the whole client, one Python file for the server, and an encrypted vault in `data/`. No accounts, no analytics, no cloud, no subscription.

Passwords are generated to be pronounceable — you can type them on a phone's on-screen keyboard or a desktop keyboard without hopping to the symbol layer five times.

```
1-Fudonew     7@Torvelin    3?Makosura
```

---

## Why

Mainstream password managers solve their own problem: sync through their cloud, ship a browser extension, add autofill, sell a subscription, collect telemetry. As a result they are heavy, break on non-standard sites, and ask you to trust someone else's server.

Passwarium solves a narrower problem:

- **the vault is yours** — a file on your VPS; the server only ever sees ciphertext;
- **no build step, no dependencies** — the client is a single `index.html`, the server is `server.py` on the Python standard library;
- **passwords remain typable** — if the phone, the extension or autofill is unavailable, you can still type the password;
- **works offline** — the PWA caches the app, a copy of the vault lives in the browser and syncs when connectivity returns.

## Features

| Feature | Details |
|---|---|
| Pronounceable generator | 8–40 characters, 4–10 options at a time; digit and symbol grouped together at the start or the end |
| Trap-free alphabet | no `O o I l`; symbols limited to `- @ ! ? & $ *` (first layer on iOS/Android) |
| Vault | labels, logins, site URLs; search; one-tap copy; values masked until you tap the eye |
| Trash | deleted entries restorable for 90 days |
| Master password rotation | re-encrypts the vault |
| Backup | download the encrypted vault as JSON and restore it; CSV export in plaintext, with a warning |
| Phone handoff | QR code or link; installable on the home screen (PWA), works offline |
| Auto-lock | after 5 or 15 minutes idle, keys are wiped from memory |
| Clipboard | a copied password is cleared after 30 seconds |

## How it works

```
┌──────────────────────────┐        HTTPS         ┌──────────────────────────┐
│  index.html (client)     │ ───────────────────► │  server.py (VPS)         │
│  generator · encryption  │  PUT /vault/<id>     │  static files + storage  │
│  vault · QR · PWA        │  X-Vault-Key: …      │  data/vault-<id>.json    │
│  copy in localStorage    │ ◄─────────────────── │  ciphertext only         │
└──────────────────────────┘   GET /vault/<id>   └──────────────────────────┘
```

- **Client** — `index.html`. Generator, vault, encryption, and a hand-rolled QR generator (byte mode, ECC L, versions 1–9). The crypto-js library (MIT) is inlined, so the app works even over plain HTTP.
- **Server** — `server.py`. Serves static files and stores the encrypted vault in `data/vault-<id>.json`. Python 3 standard library only.
- **Vault link** — `https://<your-domain>/#/v/<id>.<vault-key>`. Open it on your phone and you see the same entries.

### Encryption

- master password → **PBKDF2-HMAC-SHA256, 600,000 iterations** → AES-256 key + HMAC key;
- the vault is encrypted with **AES-256-CBC** (random IV) and authenticated with **HMAC-SHA256**, encrypt-then-MAC;
- the master password is **never stored and cannot be recovered** — lose it and the data is gone;
- the server sees only `salt`, `iv`, `ct`, `mac`.

### Vault key

Writes are protected by a **vault key** — the random part of the link after the dot. The client sends it in the `X-Vault-Key` header; only its SHA-256 is stored on disk.

- knowing the vault id but not the vault key lets you download the ciphertext (and brute-force the master password offline), but **not overwrite or destroy the vault**;
- legacy links without a key keep working for reads; the key is attached to the vault on the first write from a new client.

### Vault format

- `v: 2` — current: correct byte packing, HMAC covers the whole ciphertext.
- `v: 1` — early format. Opens automatically and silently migrates to `v: 2` with 600k iterations on first save.

### Limits and headers

- per IP: `GET` — 120/min, `PUT` — 30/min, exceeding it returns `429`;
- responses carry `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`; the page is served with a CSP.

## Quick start

```bash
git clone https://github.com/s4ps4n/passwarium.git
cd passwarium
python3 server.py          # http://localhost:8800
```

Open the address, create a vault, choose a master password. "Vault" → "QR code" for your phone, or "Copy link".

Requirements: Python 3.9+ (Node.js 18+ only for the client tests).

## Deploy on a VPS

```bash
ssh user@vps "mkdir -p /opt/passwarium"
scp index.html server.py manifest.webmanifest sw.js icon.svg user@vps:/opt/passwarium/
```

systemd unit — `/etc/systemd/system/passwarium.service`:

```ini
[Unit]
Description=Passwarium
After=network.target

[Service]
WorkingDirectory=/opt/passwarium
ExecStart=/usr/bin/python3 /opt/passwarium/server.py --port 8800 --bind 127.0.0.1
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now passwarium
```

### HTTPS — required for PWA

The app works over plain HTTP, but HTTPS hides the vault transfer itself and the link carrying the vault id and key from interception. Home-screen installation and the service worker also require HTTPS (or `localhost`).

Caddy, two lines:

```
pass.example.com {
    reverse_proxy 127.0.0.1:8800
}
```

Or nginx + certbot. With `--bind 127.0.0.1` the server listens locally only and the proxy faces the internet.

The data directory can be overridden with `PASSWARIUM_DATA` (default `./data` next to the server; the older `PASSVAULT_DATA` is also accepted).

## Tests

```bash
node test/app.test.mjs       # generator, crypto (v1/v2, MAC), merge, CSV, QR
python3 test/server.test.py  # vault key, rate limit, headers, static files
```

## Security model

- Vault strength equals master password strength. A long phrase beats `Qwerty123`; the creation form shows a strength meter.
- Anyone with the vault link can download the ciphertext and brute-force the master password offline — keep the link private, and use HTTPS so it is not intercepted in transit.
- The vault cannot be overwritten or deleted without the vault key.
- A copy of the ciphertext lives in the browser's `localStorage`, which is what makes offline use and later sync work.
- Rotating the master password re-encrypts the vault; other devices must then sign in with the new password.
- **Download an encrypted backup regularly** ("Vault" → "Vault backup"). It is useless without the master password, so it can be stored anywhere.

Out of scope: a compromised browser extension or a keylogger on the device, two-factor authentication, and recovery of a forgotten master password.

## Layout

```
index.html              client: generator, vault, encryption, QR, PWA
server.py               server: static files + ciphertext storage (stdlib)
sw.js                   service worker: offline app cache
manifest.webmanifest    PWA manifest
icon.svg                icon
data/                   vaults (not committed, created on first save)
test/app.test.mjs       client tests
test/server.test.py     server tests
```

## Contributing

Issues and pull requests are welcome. Ground rules:

- the client stays a single file with no build step and no external dependencies;
- the server stays on the Python standard library;
- any change to the crypto format ships with a test and an update to the "Vault format" section;
- no telemetry and no outbound requests from the app.

## License

MIT — see [LICENSE](LICENSE).
