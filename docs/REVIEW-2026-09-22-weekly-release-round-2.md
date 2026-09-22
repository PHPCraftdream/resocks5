# Release review, раунд 2 — P-notes

Дата: 2026-09-22. Объект: приложение `resocks5` и самостоятельный SDK
`resocks5-net`. Проверенный HEAD:
`93d4701f4e00c088912065c5939f0afd2446a4bd`.

Недельное окно: 15–22 сентября, до момента ревью; в истории 43 коммита,
фактически от 20–22 сентября. Основной подробно проверенный diff:
`6c508e121085a297074fdbab03db07e8f077e05e..93d4701` — девять коммитов
после базы первого отчёта, включая семь исправлений и два коммита отчёта.
Дополнительно проверены текущие public API, connectors, pool, rotator,
startup/auth/config и границы client/tunnel lifecycle. Для совместимости
использован локальный release tag `v0.1.1`, указывающий на `98d6cab`.
Номера строк ниже относятся к проверенному HEAD, а не к будущим исправлениям.

Release verdict: прежний P1 устранён; четыре из пяти прежних P2 закрыты,
исправление feature-unification закрывает исходную ошибку арности, но оставляет
другую поломку того же SDK-контракта. Подтверждены два P2: исчезающий публичный
тип при включении TLS и зависание generic SOCKS5 handshake на буферизованном
потоке. SDK с заявленной составимостью выпускать без их устранения не рекомендую.
Новых подтверждённых P0/P1 нет. Отдельно незелёные gates зависимостей и SemVer:
они требуют решения перед релизом и подробно разобраны ниже.

Шкала: P0 = blocker, P1 = critical, P2 = high. P3 ниже обозначает medium:
замечания умеренной важности не повышаются до high только ради формата.
Verification gaps и предложения оптимизации отделены от подтверждённых дефектов.

Ревью выполнено одним независимым XA-агентом в отдельном worktree. Применены
проверки `rust-intel` для async/cancellation, публичного API и соответствия
документированным контрактам. Это ограниченный release review, не полный
аудит всех категорий skill и не формальное доказательство безопасности.
Продуктовые исходники, CI, manifests, версии, lockfiles и прежние документы
не изменялись. Единственный новый tracked-файл — этот отчёт; локальные
диагностические fixtures создавались только внутри игнорируемого `target/`.

## P0

P0: нет подтверждённых находок.

## P1

P1: нет подтверждённых находок.

## P2

### R2-P2-01 — Включение TLS по-прежнему ломает корректный lean consumer: публичный тип становится приватным

- Severity: P2 / high, SDK composition.
- Confidence: подтверждено компилятором; положительный и отрицательный запуск
  одного неизменённого downstream source.
- Impact: библиотека-потребитель, которая явно называет тип параметра
  `connect_proxy`/`connect_proxy_once`, собирается с `default-features = false`,
  но перестаёт собираться после включения TLS другим участником dependency
  graph. Обычный вызов с нетипизированным `None` уже исправлен; проблема
  сохраняется для публичного именуемого типа и обёрток над API.
- Concrete evidence: в
  [connect_proxy.rs:30](../crates/resocks5-net/src/connect/proxy_connect/connect_proxy.rs#L30)
  lean-вариант объявлен как `pub struct TlsConnector`, а в том же файле
  [строка 6](../crates/resocks5-net/src/connect/proxy_connect/connect_proxy.rs#L6)
  TLS-вариант — приватный `use tokio_rustls::TlsConnector`. Модуль публично
  реэкспортирован через `connect::connect_proxy`. Введено `cdf866a`,
  сохраняется на `93d4701`.
- Reproduction / reasoning: временный package зависит от SDK через path с
  `default-features = false`; его feature `tls` включает `resocks5-net/tls`.
  В обоих запусках `src/lib.rs` одинаков:

  ```rust
  use resocks5_net::connect::connect_proxy::TlsConnector;

  pub fn no_tls_connector() -> Option<&'static TlsConnector> {
      None
  }
  ```

  `cargo check --manifest-path target/review-api/Cargo.toml --offline -j 2`
  прошёл. Та же команда с `--features tls` завершилась ошибкой
  `E0603: struct TlsConnector is private`. Это смена доступности public API,
  не отсутствие настройки собственного feature у потребителя. Cargo
  объединяет features общей зависимости и требует их аддитивности:
  [Cargo Book](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification).
- Recommendation: обеспечить один публичный naming path при обоих режимах
  — например, публичным реэкспортом реального connector в TLS-сборке — либо
  определить действительно устойчивый публичный options/type API. Проверить
  и именуемые типы, и сигнатуры, не ограничиваться количеством аргументов.
- Release gate: неизменённый typed lean consumer должен собираться отдельно,
  с `tls` и вместе с другим TLS consumer. Существующий fixture
  `tests/feature_unification/` использует только вывод типа из `None`; все
  три его проверки прошли, поэтому этот дефект он не обнаруживает.

### R2-P2-02 — SOCKS5 handshake над generic AsyncWrite не сбрасывает запросы перед чтением ответа

- Severity: P2 / high, runtime correctness SDK.
- Confidence: подтверждено детерминированной проверкой на настоящем
  `tokio::io::BufStream`, с raw-stream положительным контролем.
- Impact: `handshake_over_stream` принимает корректный буферизованный
  `AsyncRead + AsyncWrite`, но handshake не начинается: приветствие остаётся
  в write buffer, функция ожидает ответ, а proxy ожидает приветствие.
  У helper нет собственного timeout, поэтому без внешнего deadline ожидание
  не завершается. Это также важная граница для SOCKS5 поверх TLS/gate при
  backpressure; сам real-TLS случай отдельно этим probe не воспроизводился.
- Concrete evidence:
  [handshake_over_stream.rs:18](../crates/resocks5-net/src/connect/util/handshake_over_stream.rs#L18),
  строки 40, 51 и 83: за каждым `write_all` следует `read_exact`, ни одного
  `flush` между ними нет. Контракт функции в строках 1–15 допускает
  произвольный async stream. `tunnel_hop` вызывает её для SOCKS5 hop поверх
  уже построенной erased-цепочки в
  [dial.rs:43](../crates/resocks5/src/server/connect/establish_connection/dial.rs#L43).
  Дефект существовал уже на `v0.1.1`; `8ddbd3d` перенёс файл, а текущие
  исправления progress не изменили этот handshake. Проверено на `93d4701`.
- Reproduction / reasoning: два paused-time теста используют одинаковую
  пару `tokio::io::duplex(1024)` и peer, который читает SOCKS5 greeting,
  отвечает, затем обслуживает CONNECT к тестовому IPv4-адресу. С исходным
  `DuplexStream` handshake завершается; с `BufStream::new(client)` внешний
  timeout в одну виртуальную секунду истекает, а peer не получает даже
  greeting. Оба characterization-теста прошли: второй явно утверждает
  наблюдаемый дефект, а не успешность handshake. Команда:
  `cargo test --manifest-path target/review-buffered/Cargo.toml --offline -j 2`.
  Использован Tokio `=1.43.1`; сетевых подключений и нагрузки не было.
  Буферизация — штатный контракт
  [BufStream](https://docs.rs/tokio/latest/tokio/io/struct.BufStream.html),
  а последовательность request/reply следует
  [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html).
  Дополнительно проверен исходник locked `tokio-rustls 0.26.4`:
  `common/mod.rs::poll_write` может вернуть принятый plaintext при ещё
  недренированном ciphertext; `poll_fill_buf` не является заменой flush.
- Recommendation: сбрасывать каждое завершённое protocol-сообщение перед
  ожиданием ответа — greeting, auth request и CONNECT request. Сохранять
  общий deadline вызывающего connector и терминальное закрытие потока
  после timeout/cancellation.
- Release gate: auth/no-auth handshakes должны проходить поверх BufStream
  и TLS-совместимой buffering-обёртки, которая не доставляет записи до
  flush. Проверить порядок байтов и обработку stalled/error flush. Девять
  существующих gate-matrix тестов прошли; их быстрые peers не опровергают
  этот сценарий буферизации.

## Подтверждённые замечания ниже P2

### R2-P3-01 — Locked TLS dependency содержит опубликованную уязвимость умеренной важности

- Severity: P3 / medium. Upstream оценка — CVSS 5.3 / moderate;
  оснований повышать её до P2/high в этом проекте не установлено.
- Confidence: `cargo-deny` плюс проверка первичных источников 2026-09-22.
- Impact: приложение и TLS-enabled SDK-сборки с root lockfile используют
  затронутый TLS parser. Advisory описывает нарушение границы encryption
  levels в TLS 1.3. Transcript остаётся аутентифицированным: это не
  подтверждение MITM, обхода сертификатов или раскрытия proxy password.
  Lean SDK без TLS эту зависимость не подключает.
- Concrete evidence: [Cargo.lock:743](../Cargo.lock#L743) фиксирует
  `rustls 0.23.40` на `93d4701`.
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html)
  опубликована 14 сентября; затронуты `0.23.13..=0.23.44`, исправление
  `0.23.45`. Те же границы подтверждает
  [официальный advisory rustls](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc).
- Reproduction / reasoning: `cargo deny --locked --offline check advisories
  --disable-fetch -D warnings` завершился code 1 и указал эту цепочку
  `rustls → resocks5-net/tokio-rustls → resocks5`. Проверялось соответствие
  версии advisory; эксплуатация не выполнялась. Offline-база не даёт
  полного утверждения об отсутствии других новых advisory.
- Recommendation: отдельным разрешённым изменением перевести release
  dependency graph на исправленную версию и повторить TLS/provider/MSRV
  checks. Диапазон `rustls = "0.23"` допускает исправление, но старый
  `--locked` build сам на него не перейдёт. Свежий SDK consumer может
  разрешить уже исправленную версию; root application lock остаётся важен.
- Release gate: поддерживаемый release lockfile должен пройти проверку по
  актуальной advisory database; если сохраняется исключение, оно должно
  быть явным решением владельца релиза. В этом ревью версии не менялись.

### R2-P3-02 — Отмена caller снимает per-account claim gate раньше окончания persistence

- Severity: P3 / medium: лишняя занятая blocking thread и неточная гарантия
  дедупликации; прежний отказ обслуживания P1 этим не переоткрывается.
- Confidence: высокая по ownership/control flow; отдельный комбинированный
  cancellation-plus-follower runtime probe не запускался.
- Impact: обещание «at most one claim attempt per account» не сохраняется
  после отмены caller. При этом независимый общий cap в два claims работает,
  поэтому неограниченного накопления blocking jobs больше нет.
- Concrete evidence: `bb73240`,
  [verify.rs:73](../crates/resocks5/src/auth/state/verify.rs#L73):
  `_gate_guard` принадлежит async future. В blocking closure строк 86–89
  перемещается admission permit, но не gate guard. Значение hash публикуется
  только после persistence в `claim.rs::claim_commit`.
- Reproduction / reasoning: A ждёт users-file lock внутри `claim_commit`;
  отмена A снимает async gate, хотя closure продолжает работать. B того же
  аккаунта ещё видит `init`, получает gate и второй из двух default permits,
  затем занимает blocking thread ожиданием `claim_lock`. Имеющиеся тесты
  отдельно проверяют cancellation с cap=1 и follower без cancellation;
  все три admission-теста прошли, но эту комбинацию они не проверяют.
- Recommendation: lifetime per-account guard должен совпадать с lifetime
  принятой persistence work, например через owned guard внутри closure;
  либо сузить обещание дедупликации в документации.
- Release gate: до заявления строгой дедупликации добавить сценарий
  «cancel leader while persist is parked → same-account follower» с
  default cap=2; follower не должен запускать второй blocking claim.

## Закрытие находок первого раунда

| Первый раунд | Статус на HEAD и доказательство |
| --- | --- |
| P1-01, init-claim admission | Закрыт исходный дефект. `bb73240`: `claim_slots` создаётся с двумя permits (`auth/state/mod.rs:152`), acquire выполняется до phase-2 spawn, permit принадлежит closure (`verify.rs:82–89`). Cancellation не освобождает его раньше реального окончания work. Три focused tests прошли. Остаточная per-account проблема отдельно R2-P3-02. |
| P2-01, арность при TLS feature unification | Исходный E0061 закрыт `cdf866a`: оба entry points всегда имеют TLS slot. Checked-in fixture собирается together/lean-only/TLS-only. Общий контракт аддитивности закрыт лишь частично: типизированный consumer падает E0603, R2-P2-01. |
| P2-02, HTTPS gate progress | Закрыт механизм отсутствующей instrumentation: `293186d`, `dial.rs:141` оборачивает один raw transport до первого TLS hop; `any_upstream.rs:65` пробрасывает AsyncReadWrite/socket access. Пять slow/dead/control tests прошли последовательно, также прошли все девять protocol-matrix комбинаций. Ограничения отрицательного контроля указаны ниже. |
| P2-03, progress внутри Pending write | Закрыт `8adda19`: `Tracked::poll_write` проверяет counter delta (`tunnel.rs:129–134`); bounded send сохраняет один write future и проверяет confirmed progress (`tls_fragment/mod.rs:242–264`). 29 fragmentation и 15 tunnel tests прошли и в debug, и в release; есть no-progress, bare-wake и uninstrumented controls. |
| P2-04, ProxyConfig Debug | Закрыт `4375e21`: ручной formatter (`types/proxy_config.rs:44`) редактирует оба credentials поля, вложенный gate использует тот же formatter. Два regression tests прошли, включая три уровня вложенности и видимость endpoint. |
| P2-05, CryptoProvider prerequisite | Недокументированный prerequisite закрыт `2be23bf`: Panics/resolution order и пример установки provider; добавлен explicit-provider helper. Integration test прошёл в обычном graph и с `rustls/custom-provider`; default/explicit examples исполнились как doctests. Lean rustdoc исправлен `93d4701` и проходит. Сборка обоих native backends в этом раунде не повторялась. |

## Фактически выполненные проверки

Основной toolchain: rustc `1.97.0 (2d8144b78 2026-07-07)`, cargo
`1.97.0 (c980f4866 2026-06-30)`, `x86_64-pc-windows-msvc`.
MSRV check: `1.88.0`. Для Cargo build/test/check/doc использованы `-j 2`
либо `CARGO_BUILD_JOBS=2`; компиляционные проверки выполнялись с
`RUSTFLAGS=-D warnings`, rustdoc также с `RUSTDOCFLAGS=-D warnings`.
SemVer tool запускался отдельно с `CARGO_NET_OFFLINE=true`,
`CARGO_BUILD_JOBS=2`, без заявления о применении `--locked` к его
внутренним сборкам. Fake load, stress и benchmark не запускались.

Root locked версии: Tokio 1.43.1, tokio-rustls 0.26.4, rustls 0.23.40,
serde 1.0.228, anyhow 1.0.103, ktav 0.6.1, DashMap 6.1.0, ring 0.17.14.
Отдельный checked-in feature fixture имеет собственный lockfile:
Tokio 1.53.1, tokio-rustls 0.26.5, rustls 0.23.45. Диагностический typed-API
fixture разрешал зависимости offline самостоятельно, с теми же тремя
версиями TLS/runtime. Buffered-stream fixture закреплял Tokio на `=1.43.1`;
остальные зависимости разрешались отдельно. Эти fixtures не выдаются за
root locked-workspace runs.

| Команда / точная группа команд | Результат |
| --- | --- |
| `cargo metadata --locked --offline --no-deps --format-version 1`; `cargo metadata --locked --offline --format-version 1` | Code 0; manifests/versions/dependency sources просмотрены. |
| `cargo check -p resocks5-net --all-targets --no-default-features --locked --offline -j 2`, затем тот же command с `--features SET` | Все 12 обычных feature closures прошли: none; tls; serde; rating; rotator; tls,serde; tls,rating; tls,rotator; serde,rating; serde,rotator; tls,serde,rating; tls,serde,rotator. Дополнительно прошёл test-instrumentation. `rotator` включает `rating`. |
| `cargo check --manifest-path tests/feature_unification/Cargo.toml --workspace --locked --offline -j 2`, затем вместо `--workspace` по отдельности `-p lean-consumer`, `-p tls-consumer` | Все три code 0; target directory находился в собственном `target/feature-fixture`. Это проверка существующего untyped fixture. |
| `cargo test -p resocks5-net --lib FILTER --locked --offline -j 2` | `connect::tls::tls_fragment::tests`: 29 passed; `connect::tunnel::tests`: 15; `connect::proxy_connect::connect_proxy::tests`: 2; `types::proxy_config::tests`: 2; `progress_reporting_writer_boxes_reaches_socket_and_reports`: 1. |
| `cargo test -p resocks5-net --release --lib FILTER --locked --offline -j 2` | `connect::tunnel::tests`: 15 passed; `connect::tls::tls_fragment::tests`: 29 passed. Реальный optimized/LTO test build, не только check. |
| `cargo test -p resocks5 --bin resocks5 FILTER --locked --offline -j 2` | По одному passed для `claim_pileup_cannot_starve_ordinary_login_on_small_blocking_pool`, `cancelled_claim_keeps_admission_permit_until_persistence_finishes`, `same_account_claim_follower_waits_on_gate_not_on_a_blocking_thread`. |
| `cargo test -p resocks5 --bin resocks5 tests_progress --locked --offline -j 2 -- --test-threads=1` | 5 passed, включая три HTTPS slow-drain chains, uninstrumented control и dead transport. Последовательный запуск устраняет взаимное загрязнение global progress counter между этими тестами. |
| `cargo test -p resocks5 --bin resocks5 tests_matrix::matrix_ --locked --offline -j 2` | 9 passed: все пары SOCKS5/HTTP/HTTPS gate и inner proxy. |
| `cargo test -p resocks5-net --test crypto_provider_contract --locked --offline -j 2` | 1 passed. |
| Та же команда с `--features rustls/custom-provider` и `RESOCKS5NET_PROVIDER_CONTRACT_EXPECT_PANIC=1` | 1 passed: ожидаемый panic пойман; explicit provider работает без global install, затем проверен путь с установленным provider. |
| `cargo doc -p resocks5-net --no-default-features --no-deps --locked --offline -j 2`; вариант с `--all-features` вместо `--no-default-features` | Оба code 0, warnings denied. |
| `cargo test -p resocks5-net --doc --no-default-features --locked --offline -j 2`; вариант с `--all-features` | Соответственно 1 compile-only doctest и 3 doctests прошли. Сетевой `no_run` пример не исполнялся. |
| `cargo +1.88.0 check --workspace --all-targets --locked --offline -j 2` | Code 0, включая приложение/test/example targets на Windows; не выдаётся за исполнение всех тестов. |
| `cargo fmt --all -- --check` | Code 0. |
| `cargo clippy -p resocks5-net --all-targets --no-default-features --locked --offline -j 2 -- -D warnings`; вариант с `--all-features` | Оба code 0. |
| `cargo package -p resocks5-net --list --locked --offline`; `cargo package -p resocks5-net --locked --offline` | Code 0; 43 файла; сборка извлечённого SDK-пакета прошла. Публикация не выполнялась. |
| `cargo package -p resocks5 --no-verify --locked --offline` | Code 101: path dependency `resocks5-net` не имеет version requirement. Условный registry-release gap ниже. |
| `cargo semver-checks -p resocks5-net --baseline-rev v0.1.1 --default-features --color never` | Tool 0.50.0, code 100: из 196 checks 194 pass, 2 fail; ещё 58 skip. `enum_marked_non_exhaustive` для AnyUpstream и `function_parameter_count_changed` для send_possibly_fragmented. |
| `cargo deny --locked --offline check advisories --disable-fetch -D warnings` | Tool 0.19.9, code 1: RUSTSEC-2026-0285 и yanked ktav 0.6.1. Нет project deny.toml, использован default config. |
| Локальные diagnostics `target/review-api` и `target/review-buffered` | Typed API: lean passed, TLS E0603; buffered handshake: 2 characterization tests passed, один фиксирует timeout, raw positive control успешен. Подробности в P2. |

Все запущенные существующие targeted tests прошли с первого запуска;
повторов ради зелёного результата не было. Expected-failure API probe,
SemVer и dependency gates выше намеренно не названы успешными тестами.
Полный workspace test suite в этом раунде не запускался.

## Проверенные области без дополнительных P0–P2

- Application startup/auth: по коду сохранены private atomic config
  initialization, writer locking, пост-lock проверка init-state, merge
  одного claim с актуальным disk snapshot, лимит нового пароля 255 bytes,
  проверка обычного cache-miss login вне claim mutex. Native Unix persistence
  в этом окружении не исполнялась. Startup выполняет sync config reads до
  начала обслуживания; они не объявлены hot-path дефектом.
- Client/error lifecycle: общий client-protocol budget и guard перед
  первой polling-итерацией просроченной фазы сохранены; connect attempts
  ограничены отдельно. Возврат ошибки/отмена owning connector освобождают
  socket и permits. Half-close, blocked writes и bounded teardown покрыты
  запущенными tunnel tests. Обнаруженный generic SOCKS5 flush-дефект вынесен
  отдельно, поэтому успешность быстрых handshakes не обобщается на все I/O.
- Pool/rotator: `acquire` переносит permit вместе с socket; gate прикрепляет
  второй permit к тому же transport. Refill jobs имеют retained handles и
  abort при drop pool. Sticky cache ограничен LRU/TTL, identity lookup
  проверяет collisions; сортировка weighted order остаётся вне ratings
  mutex. `checkout` — документированный accounting escape hatch, см. SDK
  assessment. Не заявляется ограничение числа произвольных SDK endpoints.
- Security-sensitive surface: SDK production unsafe не найден. В новых
  изменениях нет новых unsafe/FFI/crypto primitives. Auth использует прежние
  Argon2id, случайную соль, HMAC-SHA256 и constant-time cache comparison;
  новый Debug formatter устраняет независимый канал credential logging.
  Это не независимый crypto audit; известный dependency advisory записан
  как R2-P3-01, а не скрыт за успешной компиляцией.
- Features: lean build сохраняет fragmentation/progress и не подключает
  TLS stack; `serde` меняет derives PoolConfig, `rotator` включает `rating`.
  Example с rotator корректно required-features gated. `AsyncReadWrite`
  остаётся открытым object-safe trait; новый impl на ProgressReportingWriter
  добавляет предусмотренную композицию. Existing impl на `Box<T>` —
  обязательство публичной совместимости; bounds в проверенном diff не сужены.
- Release/debug: два изменённых сетевых модуля исполнились в обоих профилях.
  Cargo release profile использует fat LTO и обычный unwind; отдельного
  `panic = "abort"` обещания нет. Тестовая global instrumentation скрыта
  за feature, root application включает её через dev-dependency, не через
  normal release dependency. Это не заменяет native release acceptance
  приложения на каждой поддерживаемой ОС.

## SDK assessment

SDK уже пригоден как набор Tokio building blocks: отдельный one-shot entry
point, configurable pool/caps, типизированный `AtCapacity`, explicit TLS
provider, управляемые features, generic forwarding и документация cancellation
в основных send/tunnel helpers. При этом перед выпуском нужны оба P2 и
решение SemVer/dependency gates; зелёная feature-матрица сама по себе этого
не доказывает.

До стабилизации API полезны следующие отдельные решения, без повышения их
до high-дефектов:

- `ProxyRotator::new(Vec::new())` допустим, но `get_next` делит на ноль
  (`rotator/mod.rs:279–281`). Выбрать fallible/nonempty constructor или
  `Option`-возврат и явно описать текущую precondition/Panics. Приложение
  строит rotators только для непустых списков.
- `ProxyPool::checkout` (`pool/proxy_pool/mod.rs:358`) возвращает bare
  TcpStream, освобождая permit при разборе PreWarmed. Это прежний известный
  zero-accounting путь; обычный `acquire` сохраняет cap. Для SDK нужен явно
  названный escape hatch либо guarded return. Фраза rustdoc «permit is
  dropped with the socket» неточна: возвращённый socket ещё живёт.
- `FlushProgress` публичен, но установка собственного scope и запись в sink
  crate-private. Обёртка полезна с встроенными helpers; обещать потребителю
  самостоятельную произвольную instrumentation на этом API пока нельзя.
- Большинство protocol/connect failures — anyhow. Typed errors для timeout,
  missing TLS, protocol rejection и malformed endpoint улучшат recovery
  consumer без разбора сообщений. Наличие anyhow само по себе не ошибка.
- Upstream map и refill registry рассчитаны на конечный набор endpoint,
  хранят записи до drop pool. Для SDK с динамической сменой endpoint нужен
  явный lifecycle/remove policy; приложение использует startup config.
- Public structs/enums с открытыми fields/variants — контракт следующего
  релиза. Не добавлять `non_exhaustive` задним числом под видом совместимого
  патча: SemVer check уже показывает пример такого breaking change.

## Документация: что стало верным и что ещё расходится

Provider prerequisite, единый аргумент TLS и Pending-progress paths теперь
описаны; lean и all-features rustdoc проходят с запретом warnings. Остались
следующие конкретные поправки ниже P2:

- `docs/ARCHITECTURE.md:30,35,164,220,226,310` ссылается на старые
  `server/handle_client.rs`, `auth/state.rs`, `pool/proxy_pool.rs`,
  `connect/tls_fragment.rs`. После переносов эти пути не ведут к реализации.
- `crates/resocks5-net/README.md:19` обещает uniform round-robin при равных
  плохих weights; `pick_order` делает weighted random permutation.
  Round-robin — отдельный `get_next`. Корневой README здесь точнее.
- `types/proxy_config.rs:40` описывает `gate` как inner proxy; production
  `try_proxy` хранит в этом поле внешний gate, через который достигается
  текущий proxy. Новые redaction tests не меняют смысл поля.
- `CHANGELOG.md` называет lean placeholder приватным, хотя он `pub`;
  это особенно вводит в заблуждение рядом с R2-P2-01.
- `make_tls_connector_with_provider` (`upstream_tls.rs:165`) описывает
  единственную причину panic как отсутствие поддерживаемых TLS versions.
  Locked rustls `builder.rs:223` также отвергает пустой `kx_groups`, а далее
  несовместимые suite/group combinations. Для malformed custom provider
  нужны точная секция Panics или fallible helper; built-in ring не страдает.
- `network_config.rs:100` говорит, что direct tunnels не считаются в
  `max_concurrent_clients`, но `run_server` выдаёт общий client permit
  каждому handler до protocol/auth/direct routing. Direct cap — добавочный.
- SDK send rustdoc обещает паузы между fragments; реализация также спит после
  последнего chunk (`tls_fragment/mod.rs:152`). «No overhead on the hot
  path» при выключенной fragmentation тоже слишком сильно: bounded helper
  создаёт progress sink и timer/flush machinery.
- README Docker recipe по-прежнему требует практического пояснения прав на
  bind mount для UID 65532 и `listen_host` внутри container. Default
  `127.0.0.1` не делает listener доступным через опубликованный host port.
  Изменение bind нужно описывать вместе с уже документированной auth policy.

## Performance и код, который стоит упростить

Измеренных новых performance-регрессий нет: benchmark/stress не проводился.
Это кандидаты для последующего измерения, не обещание конкретного ускорения.

- На каждом `connect_proxy_once` строится disabled ProxyPool с двумя
  DashMap и per-endpoint semaphore (`connect_proxy.rs:160`;
  `proxy_pool/mod.rs:166`). Для частого one-shot dial можно выделить общий
  direct transport path и убрать эти allocations, сохранив timeout/error
  behavior. Для редких соединений стоимость TCP может доминировать.
- Каждый fragment вызывает `write_progress_bounded`, который создаёт новый
  `Arc<AtomicU64>` через `FlushProgress::new` (`tls_fragment/mod.rs:148,193`;
  `progress.rs:39`). Один sink на весь bounded send может убрать allocation
  на каждый маленький chunk, если сохранить отдельные progress snapshots
  для timeout windows и проверить cancellation/byte-order controls.
- Лишний delay после последнего fragment можно убрать без изменения пауз
  между соседними fragments. Не обещать точный выигрыш без измерения.
- Claim phase 1 вычисляет новый Argon2 hash до per-account gate. Followers
  одного init account могут делать заведомо лишнюю работу, хотя hashing
  admission ограничен. Раннее dedup потребует сохранить чужие candidate
  passwords и независимую проверку победившего hash; это не простое удаление
  проверки. R2-P3-02 сначала уточняет lifetime уже существующего gate.
- В hot path остаются разумные существующие решения: move при partition
  proxy groups, O(1)-ожидаемый identity lookup, shared gate Arc,
  `pick_order` не строится при исчерпанном attempt budget, диагностический
  counter rotator отсутствует без test feature. Короткие mutex sections
  здесь сами по себе не являются причиной переписывать state.
- Длинные исторические комментарии вида R6/R7/P2 и тестовые rationale
  размножают формулировки контрактов. Сократить их до инвариантов и ссылок
  полезнее, чем сохранять несколько слегка разных объяснений; найденные
  расхождения gate/counter/Panics показывают реальную стоимость дублирования.

## Открытые verification и release gates

1. **Совместимость выбранной версии.** `cargo-semver-checks` реально
   подтвердил breaking surface относительно `v0.1.1`: AnyUpstream стал
   non-exhaustive, send_possibly_fragmented получает четвёртый параметр.
   Manifest пока остаётся `0.1.1`. Это не требование самовольно менять
   версию: перед release tag нужно выбрать политику/version и migration
   notes. Нельзя объявить нынешний SDK совместимым patch для всех старых
   consumers. Проверены default features на Windows; 58 skipped checks и
   обычные ограничения tool не дают полного доказательства SemVer.

2. **Dependency gate.** Помимо R2-P3-01, `cargo-deny` сообщил yanked
   `ktav 0.6.1` (`Cargo.lock:470`). Read-only запрос к
   [официальному crates.io API](https://crates.io/api/v1/crates/ktav/0.6.1)
   подтвердил `yanked: true`, `updated_at: 2026-09-16T19:03:52.564589Z`.
   Причина yank не установлена, runtime-уязвимость ktav этим не утверждается.
   Locked сборки прошли; это не делает выбранный pin пригодным для нового
   release без разбора причины и выбора поддерживаемой версии. Обновление
   dependency versions требует отдельного разрешённого изменения. Fresh
   full advisory refresh, licenses/bans/sources policy gates не выполнялись;
   `cargo audit` не установлен, использован имеющийся cargo-deny.

3. **Packaging.** SDK archive собирается, но в его 43 файлах нет
   LICENSE-MIT/LICENSE-APACHE при declared `MIT OR Apache-2.0`; root licenses
   входят в native release archives, не в SDK archive. Проверить комплект
   SDK-дистрибутива до registry publication. Юридический вывод не делается.
   Приложение не пакуется для crates.io из-за path-only resocks5-net
   dependency (`crates/resocks5/Cargo.toml:14,40`). Это условный blocker именно
   выбранного registry channel, не найденный отказ native binary/git install.
   В release.yml есть native archives и Docker, но нет SDK publish job.

4. **Чувствительность gate-progress tests.** Исходная instrumentation
   присутствует и реальные байты проходят; это проверено. Но сравнение
   slow-positive и negative не является одинаковым экспериментом с одной
   изменённой переменной: `tests_progress.rs:77,84,98,101` используют 5 s /
   1.5 MiB для positives и 250 ms / 20 MB для negative. Поэтому утверждение
   «этот negative доказывает, что positive упадёт при удалении wrapper»
   сильнее самого теста. Дополнительный global-counter assert может быть
   загрязнён соседним тестом в parallel CI: общий delta — верхняя граница
   вклада одной chain, а не LOWER bound, как написано в `progress.rs:66`.
   В данном ревью эти пять tests запускались последовательно. Нужны
   одинаковые timing/payload условия или отдельный per-chain sink и
   mutation control удаления production wrapper. Не утверждается, что
   такой mutation был выполнен в этом раунде.

5. **CI coverage.** Изолированная SDK feature matrix, lean clippy/doc и
   Windows+Ubuntu MSRV jobs присутствуют и полезны. Однако
   `tests/feature_unification` исключён из root workspace и не вызывается
   ни одним workflow; root tests его не запускают. В CI также нет
   custom-provider graph run, SemVer, dependency advisory/package gates
   и release-profile tests. Наличие YAML не считается просмотром зелёного
   remote Actions run; состояние последних run в этом ревью не проверялось.

6. **Платформы и runtime.** Выполнение ограничено Windows x86_64.
   Linux/macOS/arm64, native Unix permissions/fsync, Docker run/multiarch
   manifest, release-tag workflow и full application release acceptance
   не запускались. Оба built-in crypto backends вместе в этом раунде не
   собирались; проверен custom-provider branch и locked rustls source.
   Fuzz/Miri и полный workspace test suite также не запускались. Эти gaps
   не записаны как доказанные P2-дефекты.

## Фиксация результата

Единственный изменённый tracked-файл:
`docs/REVIEW-2026-09-22-weekly-release-round-2.md`.

Перед коммитом проверены whitespace и staged file set; коммит содержит
только этот отчёт. Commit message:
`docs: add round-2 weekly release P-notes review`.
Push в рамках ревью не выполняется. Фактический SHA возвращается вместе
с результатом работы, без самоссылочного SHA внутри коммитимого файла.
