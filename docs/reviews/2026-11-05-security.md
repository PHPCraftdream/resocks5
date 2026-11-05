# Аудит безопасности и credentials — 2026-11-05

Автор: агент `@oh`, `security.md`. HEAD `870caa2bfa9b6afd8594fabe4df9659bca585760`, диапазон `c927e71..HEAD`. Отчёт сохранён основным сеансом из ответа: агенту запрещена запись Markdown. Только чтение; runtime secrets не читались, сканеры/тесты/приложения не запускались. Подтверждённых Critical/High и удалённого auth bypass агент не установил. Это не сертификат безопасности.

## SEC-01 — Argon2 memory cost: hardening для более сильного threat model

Medium/High, существующий сознательный компромисс, не регрессия SDK. `crates/resocks5/src/auth/params.rs:10–16`; `compute_hash.rs:16–18`; `state/claim.rs:104–106`.

Production Argon2id v19 m=5120KiB,t=2,p=1 применяется CLI и init claim. Security skill ориентирует на m≥19MiB,t≥2,p=1; актуальный внешний OWASP текст не проверялся. В `auth/mod.rs:16–20` защита от целенаправленного offline-перебора после получения users-файла прямо исключена. Поэтому это hardening-кандидат при компрометации PHC-файла, не скрытый auth defect.

Предложение: отдельно согласовать сильнейший memory floor новых PHC, сохранить old hash verify; migration только явно. Тест: разобрать production PHC, algorithm/version/параметры, old PHC positive и wrong password negative. Mutation M_KIB→5120 должен ломать policy assertion; roundtrip сам по себе нет. Параметры не менялись.

## SEC-02 — zeroize не охватывает parser-owned credential temporaries

Medium/High, memory disclosure threat model, не remote exfiltration. `crates/resocks5-net/src/server/mod.rs:519–540,653–698,347–371`; `server/credentials.rs:95–115`.

HTTP headers с reversible Basic token копятся в обычном растущем Vec; decoded создаёт plaintext Vec; потом password копируется в Credentials. Drop wipe Credentials не очищает исходные buffers и старые allocations при росте. SOCKS String::from_utf8(password.clone()) создаёт дополнительные временные copies. retain=false не означает отсутствие remnants.

Предложение: feature-gated zeroizing parser buffers на success/error/cancel, убрать лишние clones; документировать best-effort scope, не обещать полное удаление копий. Тест: lifecycle seam до deallocation для HTTP success/reject, invalid UTF8, raw/nonraw, truncated/cancel. Не читать freed memory. Mutation wrapper→plain Vec; wipe-only unit недостаточен.

## SEC-03 — strict_http пропускает запрещённые field-value bytes

Low/High, новый код. `crates/resocks5-net/src/server/strict_http.rs:90–118`; `server/mod.rs:559–568`.

X-Opaque:a\x00b (реальный NUL) проходит names/obs-fold/count checks; generic field-value check отсутствует. accept может вызвать auth. Нарушена strict validation граница, но unknown headers не пересылаются, request smuggling/auth bypass не доказаны.

Предложение: reject NUL/CRLF/запрещённые C0/DEL, сохранить HTAB/SP/VCHAR/obs-text. Тест: table bytes→400/Protocol/0 auth calls, HTAB/obs-text positive. Mutation разрешить NUL/удалить check.

## Auth и ACL: положительные статические наблюдения

Global ACL до handshake (`server/handle/handle_client.rs:113–116`), per-user до HMAC/hash/init claim (`:129–137`). Mapped IPv6 нормализуется; malformed ACL отвергается даже рядом со *. Verify cache HMAC compares fixed32 через subtle::ConstantTimeEq (`auth/state/verify.rs:138–142`). Claim перепроверяет под gate, persistence cross-process lock, публикация после success. Closure удерживает permits/gate после client cancel. Init first-login provisioning и restart-required snapshots документированы, не bypass.

## Red-tier inventory

- Argon2 0.5.3, id v19, salt128bit getrandom0.2.17; entropy error fail-closed. Параметры SEC-01.
- HMAC0.12.1+SHA2 0.10.9; random256bit process-local key, digest256, constant-time comparison. Cache один entry/user до restart.
- server_secret/cache digests/password copies verify_async без zeroizing lifecycle — memory-disclosure surface, не установленная log leak.
- SDK Credentials/ProxyConfig Debug редактированы; retention opt-in; into_parts transfers responsibility. ProxyConfig public String без wiping прямо документированы.
- TLS rustls0.23.46/tokio-rustls0.26.4/ring0.17.14/webpki0.103.16, TLS1.2/1.3/Mozilla roots, имя своего proxy на каждом HTTPS hop. No TLS feature/connector не fallback в plaintext. Собственных nonce/AEAD implementations не найдено.
- Proxy password equality для identity не доказанный network verification oracle. Splitmix используется selection, не crypto secrets. Test-only PKCS8 key не production secret и не воспроизводится.
- User derived Debug включает PHC (`crates/resocks5/src/config/users/user.rs:3–11`), потенциальный будущий sink; текущий production log такого значения не установлен.
- Header cap16KiB, SOCKS credentials1..255, init password1..255. Hash admission≤4, persistence2. Некоторые low-level SDK API требуют caller deadline по контракту.

## Installers

HTTPS-only downloads/redirects, один pinned tag archive+checksums, SHA256 до установки, fixed output без массовой распаковки entry paths. Same-release checksum не независимая подпись и не защита от compromised publisher. Install directory/ancestors доверенные; link checks не доказывают race-free confinement при hostile mutable filesystem. Это trust limits, не доказанные remote vulnerabilities.

## Limits

Тематическое статическое исследование, не построчное доказательство всего repo. Актуальные advisories/repository security pages/dependency sources и backend execution не проверялись. Никакие tests/mutations не выполнялись. Security findings отделены от hardening/trust-model решений.
