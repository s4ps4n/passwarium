# Passwarium

**Glass on the outside. The key stays with you.**

[🇷🇺 Русская версия](README.md) · [Security policy](SECURITY.md) · [MIT](LICENSE)

[![License: MIT](https://img.shields.io/badge/license-MIT-2dd4bf.svg)](LICENSE)
[![tests](https://github.com/s4ps4n/passwarium/actions/workflows/tests.yml/badge.svg)](https://github.com/s4ps4n/passwarium/actions/workflows/tests.yml)
[![Python 3](https://img.shields.io/badge/python-3.9%2B-3776ab.svg)](https://www.python.org/)
[![Argon2id](https://img.shields.io/badge/KDF-Argon2id%2064%20MiB-51e6b8.svg)](#how-it-works)
[![AES-256-GCM](https://img.shields.io/badge/cipher-AES--256--GCM-8b5cf6.svg)](#how-it-works)

A pronounceable password generator with an encrypted vault. Zero-knowledge: the master password never leaves the device, and the server holds only ciphertext plus a hash of the access token. Open source, a handful of static files, a server on the Python standard library — no bundlers, no frameworks.

```
1-Fudonew     7@Torvelin    3?Makosura
```

---

## Why

Mainstream password managers solve their own problem: sync through their cloud, ship a browser extension, add autofill, sell a subscription, collect telemetry. As a result they are heavy, break on non-standard sites, and ask you to trust someone else's server.

Passwarium solves a narrower one:

- **the vault is yours** — a file on your VPS; the server only ever sees ciphertext;
- **no build step, no dependencies** — static files plus one `server.py` on the stdlib;
- **passwords stay typable** — if autofill is unavailable, you can still type the password;
- **works offline** — the PWA caches the app and keeps a browser-side copy of the vault.

## Features

| Feature | Details |
|---|---|
| Pronounceable generator | 8–40 characters, 4–10 options at a time; digit and symbol grouped together at the start or the end |
| Trap-free alphabet | no `O o I l`; symbols limited to `- @ ! ? & $ *` (first layer on iOS/Android) |
| Vault | labels, logins, site URLs, search, one-tap copy, values masked until you tap the eye |
| Trash | deleted entries restorable for 90 days |
| Master password rotation | re-encrypts the vault |
| Backup | export the encrypted vault and restore it; CSV export in plaintext, with a warning |
| Phone handoff | QR code or link, installable on the home screen (PWA), offline |
| Auto-lock | after 5 or 15 minutes idle, keys are wiped from memory |
| Clipboard | a copied password is cleared after 30 seconds |
| Local mode | if the server is unreachable, the app keeps working with a vault local to that browser |

## How it works

```
master password ──Argon2id (64 MiB, t=3, p=1, 16-byte salt)──► master
  ├─ HKDF-SHA256(master, "passwarium/v3/enc")  → AES-256-GCM key
  └─ HKDF-SHA256(master, "passwarium/v3/auth") → access token
```

- The vault is encrypted with **AES-256-GCM**, a fresh IV on every save, and `AAD = passwarium/v3|<vault id>` — ciphertext cannot be replayed into someone else's vault.
- The server stores only `SHA-256(token)`. `GET` and `PUT` require `Authorization: Bearer …`; a wrong token means 10 attempts per 10 minutes, then a 15-minute block.
- Salt and KDF parameters are public (`GET /vault/<id>/meta`): the salt is not a secret, but without it you cannot derive the token needed for authorized reads.
- The `localStorage` copy holds the same ciphertext. Plaintext and keys live in memory only and are zeroed on lock.
- A vault link contains just the `id`. Knowing the id gets you no ciphertext without the master password.

```
┌──────────────────────────┐        HTTPS          ┌──────────────────────────┐
│  app.js · index.html     │ ────────────────────► │  server.py (VPS)         │
│  Argon2id · AES-GCM      │  POST /vault          │  static files + storage  │
│  vault · QR · PWA        │  GET/PUT /vault/<id>  │  data/vault-<id>.json    │
│  copy in localStorage    │  Bearer <token>       │  ciphertext + SHA-256    │
└──────────────────────────┘ ◄──────────────────── └──────────────────────────┘
```

## Threat model — honestly

**Protected**

- a stolen server or backup — ciphertext and hashes only;
- traffic interception — HTTPS plus on-device encryption;
- a stolen link — useless without the master password;
- offline brute force is expensive: Argon2id at 64 MiB per attempt.

**Not protected**

- an infected device — malware sees the password as you type it, as with any manager;
- a weak master password — the app warns below 50 bits;
- **a server owner who swaps the page code**: a web app fetches its code from the server on every open. That is why you should host it yourself — five minutes and one VPS.

**The master password cannot be recovered.** Lose it and the vault stays shut.

## Quick start

Docker (Caddy issues the certificate for you):

```bash
# 1. put your domain into Caddyfile
# 2. set the vault-creation token
export PW_CREATE_TOKEN=$(openssl rand -hex 16)
docker compose up -d
```

Without Docker:

```bash
python3 server.py                                  # 127.0.0.1:8800, behind an HTTPS proxy
PW_CREATE_TOKEN=$(openssl rand -hex 16) python3 server.py
```

`PW_CREATE_TOKEN` gates vault creation and is entered once in the app. Without it only the very first vault can be created — handy for a personal server. **Serve it over HTTPS** (or `localhost`), otherwise the master password can be intercepted while typing.

Backup is just a copy of the data directory: vaults are already encrypted.

## Server settings

| Variable | Default | Purpose |
|---|---|---|
| `PASSWARIUM_DATA` | `./data` | vault directory |
| `PW_CREATE_TOKEN` | — | token allowing vault creation; without it only the first vault |
| `PW_MAX_VAULTS` | 50 | maximum number of vaults |
| `PW_MAX_BODY` | 256 KB | maximum vault size |
| `PW_AUTH_FAILS` | 10 | wrong tokens before a 15-minute block |
| `PW_TRUSTED_PROXIES` | `127.0.0.1` | who may send `X-Forwarded-For` |

## Legacy vaults (v1/v2)

They open read-only. "Update format" downloads an encrypted backup of the old vault, moves the entries into a new v3 vault (new link) and leaves the old file untouched. List old vaults on a server with:

```bash
python3 tools/legacy-report.py
```

## Tests

```bash
python3 test/server.test.py   # auth, limits, legacy, proxy handling
node test/app.test.mjs        # v3 crypto (RFC 9106 vector), migration, generator
                              # (chi-square on syllables), merge, CSV, QR
```

Client tests are intentionally slow: real Argon2id, about five minutes.

## Layout

```
index.html              page shell
app.js                  generator, vault, crypto, QR, PWA logic
app.css                 styling
hash-wasm.js            Argon2id (WASM, MIT)
crypto-legacy.js        reading v1/v2 vaults (crypto-js, MIT)
qr.js                   dependency-free QR generator
server.py               server: static files + ciphertext (stdlib)
sw.js                   service worker: offline cache
manifest.webmanifest    PWA manifest
fonts/                  Inter, OFL
tools/legacy-report.py  inventory of legacy vaults
test/                   client and server tests
docker-compose.yml      app + Caddy, data volume
```

## Contributing

Issues and pull requests are welcome. Ground rules:

- the client stays static, with no build step and no external dependencies;
- the server stays on the Python standard library;
- crypto-format changes ship with a test and an update to "How it works";
- no telemetry and no outbound requests from the app.

## Licenses

Code — MIT. Inter font — OFL (`fonts/OFL.txt`). hash-wasm — MIT (Dani Biro). crypto-js — MIT, used only to read legacy v1/v2 vaults.
