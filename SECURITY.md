# Security policy

Passwarium stores password vaults, so reports about its cryptography and server
behavior are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Send a private
report through GitHub Security Advisories ("Security" → "Report a
vulnerability") for this repository. Include:

- what you tested and the exact steps to reproduce;
- expected and actual behavior;
- affected files and version (commit hash);
- any proof-of-concept code, kept minimal.

You will get an acknowledgement within a few days. Fixes are prepared in a
private branch, released with a note in the changelog, and credited unless you
prefer to stay anonymous.

## Scope

In scope:

- the client-side crypto (`index.html`): PBKDF2 parameters, AES-256-CBC mode of
  operation, HMAC coverage, key derivation and use;
- the vault key scheme (`X-Vault-Key`, stored hash) and write authorization;
- the server (`server.py`): path traversal, request handling, rate limiting,
  response headers, denial of service with malformed input;
- anything that lets an attacker without the master password or vault key read,
  overwrite, or destroy a vault.

Out of scope:

- a compromised device, browser, browser extension or keylogger;
- weak master passwords chosen by the user (the strength meter is guidance, not
  a guarantee);
- the absence of two-factor authentication by design;
- traffic analysis of an HTTP (non-TLS) deployment — use HTTPS;
- self-XSS requiring the victim to paste attacker-supplied JavaScript into the
  developer console.

## Known design limits

- There is no password recovery. Losing the master password means losing the
  vault; this is intentional.
- Anyone holding the vault link can attempt an offline brute-force. Security of
  the vault reduces to the strength of the master password.
- `localStorage` keeps a copy of the ciphertext for offline use, so a device
  compromise exposes ciphertext (not plaintext).
