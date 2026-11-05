# Аудит тестов и CI — 2026-11-05

Агент `@oh`, `testing.md`; HEAD `870caa2bfa9b6afd8594fabe4df9659bca585760`, диапазон `c927e71..HEAD`. Основной сеанс сохраняет текст агента, чьё окружение запрещает Markdown-отчёты. Только статическое чтение: НИКАКИХ тестов, сборок, скриптов, измерений, mutations не запускалось. Ниже найденные gaps не равны доказанным product bugs. Приоритеты — оценка агента для тестовой поверхности.

## TEST-01 — Targeted CI не запускает chain engine tests

P1/High. `.github/scripts/changed-areas.sh:128–155,201–204,227–240`; `.github/workflows/ci.yml:211`.

session/chain не имеет специального правила, попадает в net_touched с net_test_args=--no-run. net_all не выставлен, dependent app tests тоже не запускаются. [ci: full] текущих commits обходит, не исправляет классификатор будущих изменений.

Тест-кандидат: table changed paths mod/selection/accounting→SDK chain execution+app server tests, не --no-run; full override/union. Mutation: убрать special chain rule/вернуть net_touched.

## TEST-02 — Feature-unification fixture не подключён к CI

P2/High. `Cargo.toml:5–7`; `tests/feature_unification/README.md:16–30`; `.github/scripts/changed-areas.sh:153–155`; `.github/workflows/ci.yml:199–211`.

Fixture excluded, SDK segment -p resocks5-net его не запускает. Single-package feature matrix не заменяет совместный downstream graph.

Кандидат: отдельные lean и combined-consumer legs. Mutations: TLS type private при tls; изменение арности lean API. Это gap, не доказанный текущий compile failure.

## TEST-03 — Saver tests используют восемь yield вместо ack tick

P2/High. `crates/resocks5/src/server/health/tests.rs:332–435`; `health/mod.rs:280–305`.

advance+settle(8yield) не доказывают создание interval/завершение iteration; negative !exists может сработать слишком рано. Нужны startup acknowledgement и sequence/ack после каждого tick, включая skip/error. Bare Notify без sequence недостаточен. Mutations: suppression off; last обновляется после failed save; retry off. f9c9dc7 помог старту, но не даёт строгой синхронизации.

## TEST-04 — Diagnostics добавляет timing race; drip проверки real-time

P2/High. `crates/resocks5-net/src/connect/tls/test_trace.rs:395–404`; `upstream_tls.rs:329,570–573,706–709`.

sleep100ms не доказывает первый heartbeat; elapsed≥6s и stalled4..15s при server30s зависят от scheduling/buffers. Нужен first-heartbeat ack; управляемый transport+virtual time для semantics, реальный TLS как integration bytes/backpressure control. Mutations: heartbeat не стартует; confirmed progress не renew idle; plaintext buffering считается transport progress. Причина имеющегося TLS flake НЕ установлена.

## TEST-05 — drop(server) ошибочно назван abort

P3/High. `crates/resocks5-net/src/connect/tls/upstream_tls.rs:711–714`. JoinHandle drop detaches; runtime teardown затем отменяет, но это не локальный cleanup witness. Кандидат abort+await и Drop witness до конца теста. Mutation простой drop. Production leak/причина flake не доказаны.

## TEST-06 — TEST-NET не гарантирует pending connect

P2/High. `crates/resocks5-net/src/connect/proxy_connect/hedged_tests.rs:126–155`; `crates/resocks5/src/server/connect/establish_connection/tests/quarantine.rs:254–294`; `crates/resocks5-net/src/session/rotator/probe_tests.rs:68–71`.

192.0.2.1 может отказать мгновенно: hedge test пройдёт sequential fallback, expected no-answer probe упадёт по окружению. Нужен controlled connector started→pending, virtual delay→second starts→wins, один итог первого. Timeout/refused отдельно injected. Mutation hedge timer полностью отключён должен ломать тест.

## TEST-07 — Probability oracle допускает отсутствие penalty

P2/High. `crates/resocks5-net/src/session/rotator/tests.rs:62–90`: 4 равных upstream, first_fraction<0.30 допускает uniform0.25 после record_failure no-op. Тест не полностью пустой, но заявленное снижение не доказывает. Нужны deterministic weights/frozen time, distribution исключает uniform. Mutation failure no-op.

## TEST-08 — Accounting matrix не наблюдает soft penalties

P2/High. `crates/resocks5-net/src/session/chain/accounting_tests.rs:94–167`; `session/chain/mod.rs:343–368`.

Matrix проверяет quarantine/dead/events, но ambiguous Hop должен soft штрафовать двух соседей, invalid stage — все hops. Нужен weights vector/frozen time: ровно нужные neighbours, AtCapacity ни одного, посторонние rotators неизменны. Mutations убрать soft/один вместо двух/все вместо соседей.

## TEST-09 — Wipe unit tests не доказывают zeroize-on-drop

P2/High. SDK README82–85; `server/tests/credentials.rs:487–528`; `server/tests/raw_credentials.rs:525–553`; `server/credentials.rs:111–115`.

Ручной wipe+empty strings не ловит удаление wipe из Drop и не доказывает overwritten bytes. Нужен lifecycle witness Drop→wipe до освобождения: Credentials/request/retained/raw/reject/cancel/take ownership. Только owned memory/hooks, не чтение freed. Mutations Drop cleanup off, raw password не wiped, duplicate не wiped.

## TEST-10 — Crypto provider happy path допускает ожидаемый по тексту panic

P2/High. `crates/resocks5-net/tests/crypto_provider_contract.rs:55–79`.

Success branch проверяет отсутствие EXPECT_PANIC_ENV; panic branch проверяет payload, но не флаг ожидания. Unexpected panic с тем же текстом в normal graph может пройти. Нужна симметричная expected outcome проверка; single/custom/ambiguous graph отдельными процессами, explicit provider positive. Mutation constructor ошибочно требует global provider — normal leg красный. Отдельный process для global state — существующая хорошая защита.

## TEST-11 — Нет release behavioral suite

P2/High gap, не установленный release bug. `.github/workflows/ci.yml:101–102,211,296–307`; `.github/workflows/release.yml:80–94`; Cargo profiles; `connect/proxy_connect/hedged.rs:152,165` debug assertions.

Tests debug, portable debug/help; shipped release только help smoke. Кандидат небольшой release leg timeout/stage/budgets/permits/parser/hedge. Mutations runtime check→debug_assert, overflowing budget/index должны ловиться. Panic-abort проверять отдельно только если такой artifact поставляется.

## Дополнительные boundary проекты

- Raw: short reads ULEN/PLEN/поля, EOF каждой границы, CONNECT/payload сразу после auth; exact bytes/at-most-once auth/no payload consumption. Mutation wrong frame boundary.
- Strict: fragmented ingress и failure/cancel writing400/505, общий deadline/flush/no auth. Mutation забытый flush/reset deadline.
- Validation: dial документирован без automatic validate; wire compatibility half-set auth→anonymous на соответствующих API. Mutation незаметно добавить validate. Это pin существующего контракта, не совет принимать invalid config в приложении.
- Chains: 255 уровней+exit; limited picks/counters для branching/subtree skip, без wall-clock. Mutations eager Cartesian/descendants traversal.
- Hedge cancel: started handshake ack, cancel before winner, EOF launched sockets/permits/reports по контракту. Mutation detach вместо owning JoinSet abort.

## Диагностика TLS и measurement plan

870caa2 собирает requested/actual sleeps, read sizes, buffers, heartbeat lateness, throughput timeline, elapsed/kind. Failure-only — только печать: instrumentation выполняется и при success. Для причины нужен actual failed report+OS/target/toolchain/features/parallelism/last confirmed progress. Heartbeat lateness не отличает timer delay от starvation. Более длинный timeout не доказывает механизм. SOCKS RST fix e08f995 не объясняет автоматически TLS flake.

Будущие измерения: фиксировать compiler/target/allocator/features/lock; считать allocations/operations/pick_order/dials/visited combinations на sticky hit, exhausted budget, ChainPlan first picks, subtree pruning, header scan, small reads Prefixed. Counters и bounds роста — hard gate; wallclock на shared CI только trend. Без смены production hasher на предсказуемый для untrusted keys. Negative controls eager enumeration/rebuild on hit/remaining-prefix copying/rescan header. Измерений нет.

Существующие хорошие контроли: sticky pick_order counters (`establish_connection/tests/chains.rs:323–347`), exhausted-budget no-order/no-dial (`tests/unit.rs:685–699`); реальные TCP/TLS, partial I/O; Prefixed cancel/error/100KiB; echo через chains; auth cache hashing slots. Ignore не найден, should_panic имеют expected.

## Limits

Resolved Tokio1.54.1/tokio-rustls0.26.4/rustls0.23.46/webpki0.103.16/zeroize1.8.2. CI runs/failure artifacts/branch protection не проверены. Старые tests просмотрены выборочно по contracts, не построчно. Installer latest binary не доказывает HEAD app. Процента покрытия, прошедших тестов и отсутствия других дефектов не заявляется.
