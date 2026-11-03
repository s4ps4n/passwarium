# Политика безопасности

## Куда сообщать об уязвимостях

Заведите приватное сообщение об уязвимости (GitHub Security Advisories) в репозитории проекта. Не публикуйте детали публично до выхода исправления.

**Срок ответа:** подтверждение — 72 часа, оценка и план исправления — 14 дней.

## Что в зоне интересов

- обход аутентификации по Bearer-токену или ключу записи;
- чтение или изменение чужого сейфа без мастер-пароля;
- ошибки криптографии (KDF, AES-GCM, AAD, генерация случайности);
- XSS и инъекции в клиенте;
- обход rate-limit и троттлинга.

## Что заведомо вне модели угроз

- скомпрометированное устройство пользователя;
- слабый мастер-пароль;
- владелец сервера, подменяющий код страницы (см. README → «Модель угроз»);
- отказ в обслуживании самописного сервера на одном файле.

---

## Security policy (English summary)

Report vulnerabilities privately through GitHub Security Advisories — do not open a public issue before a fix ships. Acknowledgement within 72 hours, assessment and fix plan within 14 days.

**In scope:** bypassing Bearer-token or vault-key authentication; reading or modifying someone else's vault without the master password; crypto mistakes (KDF, AES-GCM, AAD, randomness); XSS and injection in the client; rate-limit and throttling bypass.

**Out of scope:** a compromised user device; a weak master password; a server owner who swaps the served page code (see the README threat model); denial of service against a single-file self-hosted server.
