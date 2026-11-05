# Аудит resocks5 — API/lifetimes + deps/ergonomics (rust-intel), второй проход

Ревизия: HEAD `6237994` (ветка `fix/audit-2026-11-05`; `b7eab13` — последний содержательный fix-коммит, `6237994` — тестовые правки). Диапазоны: новые изменения `870caa2..HEAD`, публичный сёрфейс `v0.4.1..HEAD`.

Метод: статическое чтение (Read/Grep + read-only git). Прогонов нет: cargo (любые подкоманды), скрипты, приложение, тесты, бенчи не запускались; код/конфиги/зависимости не менялись; commit/push/worktree нет. Единственная запись — этот отчёт.

Модули rust-intel: `lifetimes-and-api.md` (§B1/B1a/B1b, §C1, §C1a, §A3) и `deps-macros-ergonomics.md` (§A1, §C5, §C6, §C7, §C10, §C11, §C12, §C12a, §E5). Прочитаны целиком; trigger-таблицы прогнаны по `crates/resocks5-net` (весь pub-сёрфейс) и зонам diff.

Контекст: findings V01–V18 из `docs/reviews/2026-11-05/summary.md` (агентские отчёты `api/api-lifetimes.md`, `process/deps-features.md`). Задача: (а) верификация фиксов по своей теме + регрессии, (б) новое. Исправленное повторно не репортится.

---

## 1. Верификация фиксов V01–V18 (зона api/deps)

Все 18 фиксов проверены чтением текущего кода. Сводка по своей теме; смежные (async/concurrency/security) — только факт наличия механизма.

| V-id | Фикс | Статус | Место и механизм |
|---|---|---|---|
| V01 | exhausted-layer termination | VERIFIED | `session/chain/mod.rs:124–129,225,237–255,269–286`: `Layer.live`, `mark_dead` декрементирует, `live==0 → done=true`; `new()` ставит `done` при пустом слое; `jump_subtree`/`advance` без изменений; тест-oracle `steps` строго `#[cfg(test)]` (`selection_tests.rs:369–463`: fully-dead exit/gate, partial, one-dead-exit порядок). Экспоненциальный обход устранён. |
| V03 | hedge handshake admission | VERIFIED | `connect/proxy_connect/hedged.rs:123–130,144–178,339–344`: `RaceState.handshake_slot: Mutex<()>`; попытка берёт слот после TCP, перепроверяет `won`, публикует win **до** освобождения слота; тик не запускает кандидата при занятом слоте. Тесты: `holder_success_reports_tcp_ready_sibling_lost_without_connect`, `holder_failure_lets_waiting_sibling_perform_its_own_connect`, `already_handshaking_attempt_reports_late_success_and_closes_socket` (`hedged_tests.rs:543–808`). Дедлок невозможен: guard освобождается при unwind, JoinSet-паника → `continue` (hedged.rs:311). |
| V12 | Duration::MAX | VERIFIED | `hedged.rs:217–224`: `hedge_deadline` → `checked_add` → `Option`, `None` = таймер не ставится (`std::future::pending()` в select, hedged.rs:331–335); доки и README обновлены; тесты `max_hedge_delay_never_panics_and_never_hedges`, singleton-вариант (`hedged_tests.rs:809–853`). |
| V11 | single-node progress | VERIFIED | `connect/dial/mod.rs:127,175,199–202`: `on_tcp: impl FnOnce()` после `tcp_dial`; `dial/chain.rs:304–326`: single-node ставит `ChainStage::Target`; `dial()` передаёт `|| {}` — поведение обычного dial не менялось. Semantics-изменение задокументировано в CHANGELOG. |
| V13 | CONNECT authority grammar | VERIFIED | `server/strict_http.rs:19–76,108–148`: userinfo (`@`), path (`/`), `?`/`#`, кривые `%XX` отвергаются (`is_authority_host_byte`+`valid_authority_host`); bare IPv6 с несколькими `:` → 400; bracketed IPv6 через `Ipv6Addr`-parse; порт 1..=65535 (u32 parse + range). Host-грамматика `valid_host_value` зеркалит. |
| V14 | control bytes в header values | VERIFIED | `strict_http.rs:176`: `(b < 0x20 && b != b'\t') || b == 0x7F` → 400; HTAB сохранён, obs-text (0x80–0xFF) проходит; применяется ко всем header lines до auth. |
| V15 | take_username raw wipe | VERIFIED | `server/mod.rs:157–161,732–747`: `discard_wiped` zeroize-ит значение **до** `take` (под feature), без feature — прежний take-drop; `IncomingRequest::username_raw` больше не освобождается мимо wipe. Плюс новый `Drop for IncomingRequest` (763–770) дотирает username/raw/credentials. Тесты `server/tests/raw_credentials.rs`. |
| V06 | duplicate identity | VERIFIED | `session/rotator/mod.rs:381–407`: дедуп при конструировании (первое вхождение, уникальные слоты ratings/health); `index_of` док обновлён (478–486). Behavior change задокументирован в CHANGELOG (следующий minor). |
| V17 | pool refill lifecycle | VERIFIED | `session/pool/proxy_pool/mod.rs:398–412` (`forget` под `refill_tasks` lock, все три удаления вместе), `436–450+548–560` (`spawn_refill_for` держит lock через entry+spawn+регистрацию; заменённый handle явно `abort()`), lock order задокументирован (163–168). Обратного порядка (pools → refill_tasks) при чтении не найдено: `reserve_permit`/`checkout` касаются только DashMap. |
| V18 | probe caps | VERIFIED | `session/rotator/probe.rs:53–75,96–133`: `probe_due_with`/`probe_all_with` с `reserve: Fn(&ProxyConfig) -> Option<G>`; `None` → ни задачи, ни соединения, ни health-изменения; `probe_due`/`probe_all` делегируют с `Some(())`. App: `route.rs:50–91` (`reserve_permit`), `startup.rs` `quarantine_unreachable_at_start` через `probe_all_with`. |
| V07 | probe attribution | VERIFIED | `establish_connection/probes.rs:35–62,243–271`: typed `ProbeVerdict`; только `ProxyRejected` на `ChainStage::Target` = HardFailure; prefix/capacity/deadline → Inconclusive без health-изменения; permit для tested node (211–223) — AtCapacity откладывает probe. Таблица классификации покрыта тестом с mutation-комментариями (509–582). |
| V08 | lease/deadline | VERIFIED | `probes.rs:64–97,117–152,230–242`: `probe_deadline`/`probe_lease` — одна пара формул, lease = deadline+5s; абсолютные инстанты от `claimed` (часы читаются **до** claim); settlement fence `now >= lease_until` → discard. Startup кладёт ту же формулу в политику (`startup.rs`, diff ~337–360). Saturating-тесты на MAX/ZERO (672–696). |
| V09 | restore topology | VERIFIED | `startup.rs`: post-restore probes только по `directly_dialed_rotators` (outermost gate + exits); `health/mod.rs:324–328` док; chain probes идут через prefix (`healthy_prefix`, probes.rs:15–31). |
| V10 | health group discriminator | VERIFIED | `health/mod.rs:44–49,117–136,163–207`: `HealthEntry.group` (`v6`/`v4`/`gate<rank>`), restore key `(upstream, gate, group)`, пустая group = legacy-fallback на все группы (задокументировано); startup строит группы с именами (`startup.rs` diff ~471–495). |
| V02 | health writer lifecycle | VERIFIED | `health/mod.rs:246–313,346–411,417–438,452–482`: cross-process `UsersFileLock` на весь ран; `finish` = notify → bounded wait (3s) → единственный финальный snapshot тем же offloaded путём → lock drop; тайм-аут цикла → abort + **без** финальной записи (осознанная loss policy); `save_offloaded` на `spawn_blocking`; stale-temp reclaim под lock до каждой записи; `startup.rs`: `saver.finish(...)` вместо `abort()+save_now`. Пароль в файл не пишется (только user@host:port, `health/mod.rs:100–106`). |
| V04 | route budget | VERIFIED | `establish_connection/dial.rs:41–49,86–89,120–128,210–213,300–325`: queued sticky считаются в `direct_reserve`; chain-цикл гейтится `attempts + direct_reserve < max_attempts`; hedge slice `truncate(max_attempts - attempts)`, cached ведут slice. Cached-chain dial расходует attempts (128). История V04 (4 attempts при cap3) более не собирается. |
| V05 | cached chain gate admission | VERIFIED | `dial.rs:101–115`: перед dial cached-цепочки каждый non-exit hop проверяется `is_quarantined` в своём rotator; quarantine → unlink без расхода attempts. Resolve — только через владеющий rotator (93–96, «cache owner» фикс). Exit не перепроверяется — get_linked уже скрыл quarantined exit своей группы (док на месте). |
| V16 | quarantine exponent | VERIFIED | `session/rating/quarantine.rs:123–138`: `duration_for` — saturating doubling c `stuck`-break и `.min(max)`; тесты с точными значениями V16: trip20/21/22/23 = 524288/1048576/2097152ms/3600s, u32::MAX = cap (`271–331`); MAX-deadline тесты через `deadline()` FAR-fallback (152–159, 451–491). |

Регрессий фиксов на соседнее поведение при статическом просмотре не найдено (перечисленные behavior changes — задокументированные сами фиксы, см. §3).

## 2. Findings

Формат: ID | Severity | Статус | file:line (проверены чтением).

### API-01 — parse_proxy_str принимает хосты, которые validate_node отвергает (и наоборот: скобки passes) | Low | TEST_GAP

`crates/resocks5-net/src/connect/util/parse_proxy_str.rs:49–92`; `crates/resocks5-net/src/types/validate.rs:188–215`.

Механизм: `parse_proxy_str` не проверяет байты хоста: `" host:80"` → `host=" host"` (Ok), control-байт в хосте тоже проходит; порт 0 (`plain:0` → Ok, тест `plain:0` в `parse_proxy_str.rs:196` фиксирует это как валидное) и пустой пароль (`"u:"`) принимаются. При этом `validate_node` хост с whitespace/control/`/`/`@` отвергает, но **принимает** `[::1]`/`2001:db8::1:80`-скобочные/колонные формы, которые `tcp_dial` в tuple-форме (`connect/dial/tcp_dial.rs:30`) не дial-ит. Dial `validate` не вызывает (задокументировано в README: «The dial and connect functions do not call it»).

Сценарий: SDK-потребитель строит конфиг из списка строк через `parse_proxy_str`, доверяет Ok и получает на dial неинформативную ошибку резолвера по `" host"`; либо валидирует через `validate()` «зелёный» конфиг со скобочным хостом и падает на dial.

Направление: либо `parse_proxy_str` проверяет хост-байты по `is_host_char_forbidden` + порт 1..=65535 (выровнять с `validate_node`), либо явно задокументировать расхождение; `validate_node` — отвергать `[`/`]` в хосте (скобки — строковый формат, в `host` не хранятся, см. док `HostPort`).

Тест-кандидат: positive control — `parse_proxy_str(" host:80")` сейчас `Ok` (mutation: добавить whitespace-check → Err); `ProxyConfig::socks5("[2001:db8::1]", 443).validate_node()` сейчас `Ok` (mutation: добавить bracket-reject). Оба — статически проверены: текущий код возвращает Ok.

### API-02 — raw_credentials: клон для UTF-8-проверки оставляет непротёртый буфер и лишнюю аллокацию | Low | PERF_CANDIDATE (+HARDENING)

`crates/resocks5-net/src/server/mod.rs:349–359,360–373`.

Механизм: при `raw_credentials = true` каждый UNAME/PASSWD проходит `String::from_utf8(user.clone())` — клон Vec делается всегда. На Ok-пути оригинальный `user`/`password` Vec Drop-ится **без** wipe (zeroize-Drop есть только у `Credentials`/`IncomingRequest`), т.е. точные submitted-байты уходят в free-память непротёртыми; на Err-пути непротёртым Drop-ится клон. Плюс по одной лишней heap-аллокации и копии на поле на каждый auth.

Это вторая половина P03 (см. §4): V15 закрыл только `take_username`/`username_raw` слот.

Направление: consume-вариант — `match String::from_utf8(user) { Ok(t) => (t, None), Err(e) => (String::from_utf8_lossy(e.as_bytes()).into_owned(), Some(e.into_bytes())) }` — убирает и клон, и непротёртый остаток одним движением, сигнатуры не меняет.

Тест-кандидат: wipe-witness/счётчик аллокаций на valid и invalid UTF-8, raw on/off; mutation — вернуть `.clone()`. В стиле существующих `server/tests/raw_credentials.rs`.

### API-03 — socks() success-path: три копии username вместо двух | Low | PERF_CANDIDATE (остаток P03)

`crates/resocks5-net/src/server/mod.rs:374–381`.

Механизм: `identity = username.clone()` (374), затем `Credentials::with_raw(username.clone(), ...)` (376) — оригинал после этого не используется, второй клон в `with_raw` лишний (move допустим: возврат (391) отдаёт `identity`/`username_raw`, не оригинал). Итого на каждый успешный password-auth: from_utf8-строка + identity + credentials + retained-дубликат.

Направление: move `username` в `with_raw`; то же в http-пути там, где применимо. Смежное: `dial.rs:334` `ctag.clone()` — оригинал после move в closure не читается, можно move.

Тест-кандидат: scoped allocation counter (valid, invalid, retain on/off) в духе P03; mutation — вернуть клон.

### API-04 — strict Host header: порт вне 1..=65535 грамматически проходит | Low | TEST_GAP

`crates/resocks5-net/src/server/strict_http.rs:49–52,57–76,200–205`.

Механизм: `valid_port_digits` для значения `Host` проверяет только «1–5 цифр»: `Host: example.com:0` и `Host: example.com:99999` проходят strict-валидацию, тогда как CONNECT-authority порт строго 1..=65535 (139–148). На dialing не влияет (цели управляет authority), RFC 9112 допускает `*DIGIT` — но это расхождение двух половин одного валидатора.

Направление: единая проверка диапазона (или докстрока «Host port проверяется только по форме»).

Тест-кандидат: `Host: h:0` / `Host: h:99999` → ожидание по выбранной политике; mutation — добавить range-check; positive control — `Host: h:443` Ok.

### API-05 — pub-сёрфейс v0.4.1→HEAD: additive, semver-рисков не найдено | Info | VERIFIED_STATIC

Полный diff `v0.4.1..HEAD` по `crates/resocks5-net` (37 файлов, +6494/−207; lib.rs не менялся).

Добавлено (всё additive): `types::validate` (`ProxyConfig::validate/validate_node/try_with_auth`, `ProxyConfigError`/`ChainConfigError`/`CredentialField` — все enum `#[non_exhaustive]`, §C1a соблюдён на новых типах); `server::Reply::{ConnectionRefused,NetworkUnreachable,TimedOut}` — Reply уже `#[non_exhaustive]`, добавление вариантов легально; `Prefixed<S>` + `IncomingRequest::into_prefixed`; `ServerOptions::{retain_credentials,raw_credentials,strict_http}`, `take_credentials/take_username/username_bytes`, `Credentials::{into_parts,username_bytes,password_bytes,is_utf8}`; feature `zeroize = ["dep:zeroize"]` (выключен по умолчанию — налога на потребителей нет, §C10); `probe_due_with/probe_all_with`.

Behavior changes (rotator-дедуп, `ChainStage::Target` после TCP, hedge admission, strict Host grammar, `ServerError::Authentication`/Debug redaction) — задокументированы в CHANGELOG `[Unreleased]`; Consistent с грядущим minor (0.5.0). Deref-обёрток нет (Prefixed даёт явные `get_ref/get_mut` — корректный C-DEREF паттерн); lifetime-утечек (§B1a/B1b) в новом коде нет (`ProbeAttempt<'a>` — внутренний, pub-сигнатуры без нетривиальных `'a`).

Примечание: `[workspace.package].version` всё ещё `0.4.1` при накопленном `[Unreleased]` — чеклист-пункт на релиз, не дефект.

### API-06 — приложение не включает feature `zeroize` | Low | HARDENING

`crates/resocks5/Cargo.toml:26` (`features = ["pool","tls","serde","rating","rotator"]`).

Механизм: весь wipe-механизм V15 (`discard_wiped`, `Drop` для `IncomingRequest`/`Credentials`) компилируется только под feature, а поставляемый бинарник её не включает — в production inbound-credentials освобождаются обычным drop. Для SDK-потребителей feature осознанна (opt-in), для собственного сервера решение «не протирать» нигде не зафиксировано.

Направление: либо включить `zeroize` в app-фичах (цена — dep уже в дереве через rustls/ring, runtime-цена — memset двух строк), либо одной строкой в README/REFERENCE зафиксировать осознанный отказ. Контекст: SEC-02 отклонён в широкой форме, это точечное решение по V15-механике.

### API-07 — зависимость/feature-гигиена: замечаний нет | Info | VERIFIED_STATIC

§A1/§C7/§C10 по diff: единственная новая зависимость — `zeroize = "1"` (workspace-approved, была transitive через rustls/ring; фича явная `dep:zeroize`); git-зависимостей и `[patch]` нет; `resolver = "2"`, default-features минимальны (tokio `default-features = false`, фичи per-crate); rustls floor 0.23.45 с RUSTSEC-обоснованием; MSRV 1.88 с объяснением пола в комментарии; `cfg(feature = "zeroize")` соответствует определённой фиче (typos → dead code не найдено); regex/компиляции — startup-only (§E5: per-request recompile отсутствует); собственных proc-macro/build.rs с сетью нет (§C6/§A1 build-time — чисто).

## 3. «Новые изменения» (870caa2..HEAD) — дополнительные наблюдения

Все содержательные изменения diff покрыты §1 (фиксы) и §2 (findings). Точечно:

- `hedged.rs:322–327` — паттерн `let AttemptReport { outcome: Failed(error), .. } = report else { unreachable!() }` после `callback(&report)`: корректно (callback берёт `&`), но двойная распаковка ради move `error` — стиль, не finding.
- `chain/mod.rs:269–286` — `mark_dead` на каждый hard failure делает полный клон `ProxyConfig` ради identity-ключа (`singleton_key`, 350–354) и сканирует все слои (O(candidates)); это pre-existing форма (была и до фикса), входит в известный P02 — не новый finding.
- `.github/scripts/changed-areas.sh:146–150` — classifier для `session/chain/*` (TEST-01) встал: `chain::` + app `server::`.
- `session/progress.rs:84–98` — UFFI-03 (док-пример Ok(0)-спина) закрыт: пример возвращает `WriteZero` (diff).
- `error/tests.rs` — stub теперь дочитывает sub-negotiation перед close (устранение RST-гонки в тесте, не продукт).

## 4. Статус известных findings предыдущего аудита по моей теме (не исправлено — кратко, повторно не репортится)

- **API-L03** (Low): `HedgeError` — `impl Error` пустой, `last` не отдаётся через `source()` (`hedged.rs:121`). Не фикшено; вывод прежний (diagnostic limitation, downcast+`pub last` доступны).
- **P03** (PERF_CANDIDATE): остаток покрыт API-02/API-03 этого отчёта.
- **P04** (PERF_CANDIDATE): ctag/end/gates eager-форматирование — в основной массе уже внутри `logger.<level>(|| format!...)` closures; остатки — `ctag` строится eagerly раз на запрос (`dial.rs:51–54`) и `gate`-строка materialизуется до await (`dial.rs:133–139,166–172,223–229`). Статус: не фикшено, приоритет не изменился.
- **P02** (PERF_CANDIDATE): двойная материализация chain (`GateLevels::resolve` → key через `ProxyConfig::chain` с поклоными hop-клонами, `chain/mod.rs:83–85`; app `pick.config()` повторно, `dial.rs:132,222`; `ChainKey::hash` с nodes-Vec) — не фикшено; рекомендация и oracle из summary.md в силе.
- **API-C01/C02/C03** (commitments): без изменений; новые pub-типы получили `#[non_exhaustive]` там, где применимо (§C1a чисто), `Hedged`/`HostPort` и др. остались exhaustive по форме — прежний вывод в силе.
- **UFFI-01** (recursive `Arc`-gate Drop/Debug depth, `types/proxy_config.rs`): файл не менялся с v0.4.1 — прежний вывод без изменений.

## 5. Топ приоритетных

1. **API-02** (Low, PERF+HARDENING): consume-`from_utf8` в socks() — минус клон/аллокация на каждый auth и минус непротёртый буфер под zeroize; самый дешёвый фикс отчёта.
2. **API-01** (Low, TEST_GAP): выровнять грамматику хоста между `parse_proxy_str` и `validate_node` (whitespace/скобки/порт 0) — или задокументировать.
3. **API-06** (Low, HARDENING): решить и зафиксировать политику `zeroize` для поставляемого бинарника.
4. **API-03** (Low, PERF): move-username в `with_raw` (+ `ctag` move) — остаток P03.
5. **API-04** (Low, TEST_GAP): диапазон порта в strict Host-grammar.
6. **API-05**: на релизе — bump version по CHANGELOG `[Unreleased]` (чеклист, не дефект).

Границы: статическая проверка исходников; компиляция/тесты/semver-инструменты/измерения не запускались; external crate-семантика (tokio/rustls/zeroize internals) принята по локальным док-комментариям и pinned-версиям Cargo.lock; найденное — не сертификат отсутствия иных дефектов.
