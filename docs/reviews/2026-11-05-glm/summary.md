# Rust Intel glm-раунд: сводный аудит — 2026-11-05

## Ревизия и метод

Отчёты написаны на HEAD `6237994`; на момент сводки HEAD — `fa48980` (docs-only, кода не меняет). Diff-база «новых изменений»: `870caa2..HEAD` — фиксы V01–V18 (`dfe3606`, `b7eab13`) и тестовые коммиты (`2c548e3`, `b4ab336`, `6237994`).

Шесть агентов `@oh` (Opus 5.5, high) исследовали по тематическим модулям rust-intel: async+drop (GA), concurrency (CC), data/types (DT), security+unsafe (SEC), API+deps (API), testing+conformance (TQ). Каждый проверил фиксы V01–V18 своей зоны на регрессии и искал новое; полный текст — в пяти тематических отчётах этого каталога. Основной сеанс дополнительно перепроверил чтением ключевые находки (отмечено VERIFIED ниже): health `finish`-гонку, `try_lease` overflow, strict-Host порт, raw-клон, `same_upstream` doc≠код.

**Прогоны не выполнялись** (cargo/скрипты/приложение — только CI). Код, конфиги, зависимости не менялись; commit/push не выполнялись. Единственные добавленные файлы — отчёты этого каталога (6 + summary = 7, лимит структуры соблюдён).

### Статусы

- **VERIFIED_STATIC:** сценарий следует из исходников. **VERIFIED:** дополнительно перепроверено основным сеансом на `fa48980`.
- **PLAUSIBLE:** часть условий требует дополнительного доказательства.
- **HARDENING:** усиление защиты/политики, не установленный текущий bug.
- **PERF_CANDIDATE:** лишние операции видны, выигрыш не измерен (§E6 — измерять до правки).
- **TEST_GAP:** слабый oracle / отсутствующее покрытие; не доказательство product bug.

## 1. Подтверждение фиксов V01–V18

Все шесть агентов независимо верифицировали фикс-волну: exhausted-layer в chain, hedge admission/Duration::MAX, strict HTTP Host grammar + control bytes, take_username wipe, rotator dedup, pool lock order, probe caps/attribution/lease, cached-chain admission (владение rotator, quarantine на gate-хопах), route budget, health groups/writer/lock, quarantine doubling+deadline. Регрессий соседнего поведения не найдено. Публичный diff `v0.4.1..HEAD` — полностью additive (API-05).

## 2. Приоритетные находки

### H1 — Medium, VERIFIED: health `finish` не останавливает начатую blocking-запись (резидуал V02)

Единая находка четырёх агентов: CC-01 = GA-01 = SEC-02 = DT-02 (TQ-01 — та же зона).

Места: `crates/resocks5/src/server/health/mod.rs:294–311,452–462`.

`finish` по истечении `FINISH_BUDGET` делает `task.abort()` и `drop(lock)`. `abort()` отменяет async-таску в точке `.await`, но уже стартовавший `spawn_blocking` (`save_offloaded`) неотменяем: orphan-запись дорабатывает **после** снятия cross-process lock — под lock'ом второго инстанса, гонит `reclaim_own_temp` на общем `<health>.tmp` против temp-а нового владельца (потеря/подмена снимка, возможный провал `create_new` у нового инстанса). Комментарий FINISH_BUDGET обещает «continuing without a final snapshot», но потеря снапшота — не единственный эффект; нарушается инвариант single-writer, на который опирается lock-протокол b7eab13.

Направление решения: отменяемость на границе blocking-пула — флаг/поколение раунда (проверка до `reclaim_own_temp` и перед publish), либо владелец lock не отпускает его до фактического завершения/отказа blocking-записи, либо temp с per-writer уникальным именем.
Тест-кандидат: `writer_tests.rs` — `finish` с in-flight blocking-записью (задержка внутри `save`) + второй «инстанс», ждущий lock: orphan-коммит не публикуется под чужим lock, temp нового владельца не тронут (CC-05/TQ-07-зона). Mutation: убрать проверку поколения.

### H2 — Medium→Low, VERIFIED: `try_lease` при переполнении теряет эксклюзивность probation-слота

CC-02 = GA-02. `crates/resocks5-net/src/session/rating/quarantine.rs:265`: `now.checked_add(policy.probe_lease).unwrap_or(now)` — при непредставимом lease (`Duration::MAX` валиден по V16) `lease_until = now` → lease истекает мгновенно, эксклюзивность probe-слота теряется, шторм повторных probe. Соседний `deadline()` имеет FAR-fallback — асимметрия.
Решение: тот же saturating/FAR-fallback, что и в `deadline()`. Тест: lease с `Duration::MAX` — второй `try_lease` в тот же момент возвращает `false`.

### H3 — Low, VERIFIED_STATIC: `probe_all_with` — двойной trip за одно свидетельство

CC-03. `crates/resocks5-net/src/session/rotator/probe.rs:174–188`: `is_quarantined`→`quarantine_now` через два захвата мутекса; конкурентный `record_hard_failure` между ними даёт backoff ×2 за одно свидетельство. Решение: единый захват с решением внутри.

### H4 — Low, VERIFIED: `same_upstream` doc противоречит коду (gate входит в сравнение/хэш)

CC-04. `crates/resocks5-net/src/session/rotator/mod.rs:76–103`: док утверждает «`gate` is deliberately excluded», но код сравнивает `gate_level` (:88) и включает в hash (:101). Последствие по доку — gate-composite должен попадать в plain-слот апстрима, фактически получает отдельный слот; record-семантика расходится с документом. Определиться, какая из сторон — контракт, вторую поправить (+ тест на identity plain↔gate-composite).

### H5 — Low, VERIFIED: strict `Host` порт без диапазона

DT-01 = API-04. `crates/resocks5-net/src/server/strict_http.rs:50–52`: `valid_port_digits` — только «1–5 ASCII-цифр», `h:0`/`h:99999` проходят; authority-путь тот же диапазон отвергает, док заявляет «mirroring the CONNECT authority rules». Решение: единая проверка 1..=65535 для обоих путей. Тест: `Host: h:0`, `h:99999`, `[::1]:0` — 400.

### H6 — Low, VERIFIED: raw-режим auth — лишние клоны и непротёртые копии секретов

API-02 (+API-03). `crates/resocks5-net/src/server/mod.rs:350,361,374–378`: `String::from_utf8(user.clone())`/`password.clone()` — лишняя аллокация на каждое поле и непротёртый исходный `Vec<u8>`/клон уходит в free-память в поставке с `zeroize`-фичей. Решение: consume-форма `String::from_utf8(vec)` с `into_bytes()` в Err-плече; в `with_raw` — move вместо clone. Связано API-06: приложение (`crates/resocks5/Cargo.toml:26`) фичу `zeroize` не включает — wipe V15 в бинарнике выключен; зафиксировать решение явно либо включить.

### H7 — Medium, TEST_GAP: CI-leg для `tests/feature_unification` отсутствует

TQ-03. Каталог корректно исключён из workspace (downstream-граф), задокументированные mutation-регрессии (E0061/E0603) CI не ловит — TEST-02 не закрыт. Решение: отдельный job, собирающий fixtures-workspace.

### H8 — Low, VERIFIED_STATIC: hedged drain-репорты теряются при панике callback

TQ-05. `crates/resocks5-net/src/connect/proxy_connect/hedged.rs:243–244` vs `317–318`: док обещает «callback panic unwinds the caller», но drain-репорты доставляются в отдельном task — паника там тихо теряет оставшиеся репорты, «exactly once» не выполняется. Решение: либо перенести доставку в вызывающий контекст, либо поправить док и задокументировать loss-режим + тест.

## 3. PERF_CANDIDATE (§E6: измерять до правки)

| ID | Где | Суть |
|---|---|---|
| DT-03 | `session/chain/mod.rs:269–271,350–354` | `mark_dead` дважды глубоко клонирует `ProxyConfig` (credentials зря) на каждый провал; V01 добавил O(layers×candidates) `ChainKey::eq`-скан |
| DT-04/GA-04 | `establish_connection/dial.rs:133–139,166–172` | gate-строка собирается eagerly до connect и повторно в Err-плече cache-пути (остаток P04) |
| CC-06 | `session/pool/proxy_pool/mod.rs:219,264,332` | 2–3 `(String,u16)` аллокации на каждую upstream-попытку; `Borrow`-проекция ключа или кэш в `ProxyConfig` |
| P02 | `session/chain/mod.rs:83–85` | двойная материализация chain (не исправлено, прежняя рекомендация в силе) |
| GA-03/CC-07 | `users_file/lock.rs:45–76`, `health/mod.rs:338–390` | блокирующий `thread::sleep`-poll (до 200 мс) + sync fs в async-старте — разовый; `spawn_blocking` при желании |
| API-L03 | `hedged.rs:121` | `HedgeError::source()` — `None` (старое P03/L03) |

## 4. HARDENING / мелкое

- SEC-03 `auth/state/verify.rs:30–36` — timing-enumeration имён: unknown мгновенно, known ~15 мс HMAC/Argon2; равнить дешёвой фиктивной работой.
- SEC-04 = CC-08 `config/users/users_file/lock.rs:45–59` — sentinel `.lock` открывается с symlink-following `create(true)` (split-lock при подсадке) и растёт монотонно (pid-строки никогда не truncate).
- SEC-05 `auth/state/verify.rs:191–198` — нет negative-контролей verify на argon2i/v16/слабые-params PHC (сейчас fail-closed, контракт не зафиксирован тестом).
- DT-05 `server/reply.rs:43` — `_ => unreachable!` на u16-домене `http_error`: будущий новый статус = паника на сетевом пути; fallback-ветка.
- DT-06 `server/mod.rs:642–665` — unpadded base64 и таб в Proxy-Authorization отклоняются 407; совместимостная заметка (осознанность).
- DT-07 `health/mod.rs:165–169` — restore-карта `.collect()` last-wins на дубликатах; достижимо только ручной правкой файла.
- DT-08 `host_port.rs:34–57` — SOCKS DOMAINNAME/permissive HTTP принимают `@`,`/`,`%` (мусор в DNS); strict-пути строже; обхода нет.
- CC-09 `session/chain/mod.rs:30` — дубликаты gate-рангов в `GateLevels::new` — только `debug_assert!`; нужен `Err` как у политик.
- CC-10 `probes.rs:161, route.rs:68` — «reachable again» идёт через `proxy_failure`-канал.
- GA-05 `route.rs:59, probes.rs:131` — detached spawn'ы probe без «detached by design»-комментария (§B21).
- API-01 `parse_proxy_str.rs:49–92` vs `types/validate.rs:188–215` — грамматики хоста/порта расходятся (`" host:80"`, порт 0, `[v6]`-скобки); dial validate не вызывает (документировано).
- TQ-01/TQ-06/TQ-02/TQ-04/TQ-07/TQ-08 — см. `glm-testing-conformance.md`: «TCP-живой/SOCKS5-молчащий» upstream держит слот весь handshake_timeout без пути в quarantine; label-коллизия health-алиасов с разными паролями (last-wins); `timeout-minutes` нет на test/lint/msrv/portable job'ах; startup-синхронизация saver-тестов — 8 yield; классификатор `changed-areas.sh` без собственных кейсов.

## 5. Дедуп-таблица (одна находка в нескольких отчётах)

| Тема | ID |
|---|---|
| health `finish`/spawn_blocking orphan | CC-01 = GA-01 = SEC-02 = DT-02 (TQ-01) |
| `try_lease` overflow | CC-02 = GA-02 |
| strict-Host порт | DT-01 = API-04 |
| raw-клоны секретов | API-02 ≈ API-03 (+API-06 zeroize) |
| sentinel `.lock` | SEC-04 = CC-08 |
| gate-строка дважды | DT-04 = GA-04 |
| FINISH_BUDGET-тест | CC-05 = GA-06 |

## 6. CLEAN-подтверждения

- `unsafe`: 17 блоков, все в `users_file/` FFI — SAFETY-комментарии, errno до LocalFree, Win32-layout верны (B5/B18/B18a/B25 чисто).
- Auth: Argon2id v19 + getrandom-salt, HMAC-SHA256 ключ-32B getrandom, `subtle::ConstantTimeEq` fixed-32; `==` на секретах нет; fail-closed на паниках (B12/B24).
- B7: аллокации от сетевого входа ограничены (≤255/16KiB/12KiB); CRLF/NUL/DEL/userinfo в strict HTTP отклоняются, ответы статические (V13/V14 подтверждены).
- §A1/§C7/§C10/§C11/§C12/§E5 чисто; единственная новая dep — `zeroize` (workspace, opt-in).
- B2/B3/B23/B15e/B21/B22/B4/B3a в async-зоне — чисто; B16-контракты (ChainKey, total_cmp+index) целы; B26/B27/B28/B29 чисто.

## 7. Ограничения

Статическая проверка механизмов: без runtime-воспроизведения, semver-механики, измерений и RFC-сверки (в отличие от предыдущего раунда WebFetch не использовался). HEAD сдвинулся во время аудита (`6237994` → `fa48980`); находки относятся к `6237994`, `fa48980` docs-only. Параллельное ревью @ox (`../2026-11-05/ox-round3-summary.md`) не сверялось с этим.
