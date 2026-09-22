# Release review, раунд 3 — P-notes

Дата: 2026-09-22. Объект: приложение `resocks5` и самостоятельный SDK
`resocks5-net`. Проверенный HEAD:
`aebadbf71b9154ecdc6d8916e5cfae3a1b47cc02`.

Недельное окно: 15–22 сентября до проверенного HEAD, 46 коммитов,
фактически от 20–22 сентября. Подробный повторный diff:
`6c508e121085a297074fdbab03db07e8f077e05e..aebadbf` — 12 коммитов,
35 файлов; отдельно проверены оба исправления после второго отчёта,
`eb7aa6e` и `aebadbf`. Сопоставлены первые два weekly reports и текущие
вызывающие места. Release baseline: локальный тег `v0.1.1` (`98d6cab`).
Номера строк относятся к указанному HEAD.

Release verdict: оба P2 второго раунда закрыты в проверенных сценариях.
Новых подтверждённых P0/P1/P2 не найдено. Это не безусловный go на релиз:
dependency gate остаётся красным, совместимость с `v0.1.1` нарушена,
SDK-дистрибутив не содержит текстов лицензий, а registry packaging приложения
не проходит. До публикации нужны решения по этим конкретным gates.
Native binary, Docker и crates.io имеют разные требования; ошибка упаковки
приложения для crates.io не означает отказ его обычной сборки.

Шкала: P0 = blocker, P1 = critical, P2 = high, P3 = medium.
Условные release gates, недостаток проверки и предложения развития API
не повышаются до high-дефектов. Ни один результат компиляции ниже не
выдаётся за доказательство поведения сети или отсутствия всех ошибок.

Ревью выполнено одним независимым XA-агентом в отдельном worktree.
Применены правила `rust-intel` для async/cancellation, публичного API,
документированных гарантий и проверки тестовых доказательств. Это
ограниченный release review, не полный аудит всех модулей skill,
транзитивного unsafe/crypto-кода или всех поддерживаемых платформ.
Исходники, manifests, lockfiles, CI и существующие документы не изменялись.
Единственный новый tracked-файл — этот отчёт. Диагностические журналы
и команды находились в игнорируемом `target/review3/`.

## P0

P0: нет подтверждённых находок.

## P1

P1: нет подтверждённых находок.

## P2

P2: нет подтверждённых открытых находок в проверенном объёме.
Оба P2 второго раунда закрыты ниже; оставшиеся замечания и gates не скрыты.

## Закрытые находки второго раунда

### R2-P2-01 — Публичный именуемый TLS slot теперь сохраняется при feature unification

- Статус: закрыт; confidence высокая, исходники и downstream compilation.
- Evidence: `eb7aa6e`,
  [connect_proxy.rs:6](../crates/resocks5-net/src/connect/proxy_connect/connect_proxy.rs#L6)
  — `pub use tokio_rustls::TlsConnector`; lean placeholder остаётся
  публичным на строке 30. Обе функции сохраняют один trailing TLS slot.
- `tests/feature_unification/lean-consumer/src/main.rs:9,18` теперь
  импортирует тип и объявляет возвращаемый `Option<&'static TlsConnector>`.
  Один неизменённый source прошёл отдельно и вместе с TLS consumer;
  отдельно прошёл и TLS consumer. Регрессия к приватному `use` сломала бы
  именно этот naming path в объединённом graph.
- Это доказательство доступности типа и формы вызовов; fixture сознательно
  не poll-ит сетевые futures. Реальная сетевая проверка one-shot connectors
  выполнена отдельными двумя loopback tests.
- Residual gate: fixture всё ещё не запускается CI, см. раздел CI.

### R2-P2-02 — SOCKS5 сбрасывает protocol messages до ожидания ответа

- Статус: закрыт; confidence высокая, runtime tests на настоящем BufStream.
- Evidence: `aebadbf`,
  [handshake_over_stream.rs:19](../crates/resocks5-net/src/connect/util/handshake_over_stream.rs#L19),
  строки 42, 54, 87: `flush().await?` стоит после greeting в обеих ветках,
  после auth request и после CONNECT. Ошибка flush возвращается вызывающему.
- Все восемь helper tests прошли с default features, без default features
  и в release. Среди них `no_auth_completes_through_buffered_client` и
  `auth_completes_through_buffered_client` (строки 287, 300): настоящий
  `tokio::io::BufStream`, проверка greeting/auth/request и сохранности
  последующего payload. Удаление любого требуемого flush оставило бы
  соответствующее сообщение в буфере до внешнего timeout.
- Все девять application gate protocol combinations также прошли, включая
  SOCKS5 поверх HTTPS. В `dial.rs::tunnel_hop` helper по-прежнему находится
  внутри общего `handshake_timeout`; при ошибке/timeout owning stream
  освобождается. Последовательность сообщений сверена с
  [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html).
- Ограничение: отдельные тесты stalled/error flush именно этого helper
  и принудительного TLS write backpressure в SOCKS5 subnegotiation не
  запускались. Быстрая TLS matrix не доказывает каждый вариант backpressure.
  У самого низкоуровневого helper нет собственного deadline; SDK consumer
  должен ограничить handshake и закрыть частично использованный поток.

## P3 / medium

### R3-P3-01 — Release lockfile всё ещё содержит затронутый rustls

- Severity: P3 / medium. Confidence: подтверждено online cargo-deny,
  текущим lockfile и первичными источниками 2026-09-22.
- Impact: приложение и TLS-enabled SDK с данным lockfile используют
  затронутую версию TLS parser. Upstream оценивает advisory как moderate,
  CVSS 5.3; оснований повышать до P2 в этом проекте не установлено.
  Lean SDK без TLS эту зависимость не включает.
- Evidence: `Cargo.lock:743` на `aebadbf` фиксирует `rustls 0.23.40`;
  исправления `eb7aa6e`/`aebadbf` dependency pin не меняли.
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html)
  и [официальный advisory rustls](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc)
  указывают affected `0.23.13..=0.23.44`, fixed `0.23.45`.
- Reasoning: это нарушение TLS 1.3 encryption-level boundary; transcript
  остаётся аутентифицированным. Обход сертификатов, перехват credentials
  или эксплуатация здесь не утверждаются и не проверялись.
  `cargo deny --locked check advisories -D warnings` вернул code 1.
  Обновлённая advisory DB: `57ad4063bb49c1deb04b6fcee30cfbac6b508474`,
  commit date `2026-09-21T17:17:02+02:00`.
- Recommendation: отдельным разрешённым изменением привести release
  dependency graph к исправленной версии и повторить TLS/provider/MSRV
  acceptance. Диапазон manifest допускает исправление, но `--locked`
  оставляет старую версию. Fresh downstream resolution и root application
  lockfile — разные объекты проверки.
- Release gate: актуальная advisory проверка выбранного release graph
  должна пройти либо иметь явное принятое владельцем релиза исключение.
  R2-P3-01 остаётся открытым; версии в этом ревью не менялись.

### R3-P3-02 — Per-account claim gate не живёт до окончания отменённой persistence work

- Severity: P3 / medium. Confidence: высокая по ownership/control flow;
  комбинированный cancellation-plus-follower runtime test не запускался.
- Impact: гарантия «at most one claim attempt per account» сильнее
  реализации. После отмены caller возможна дополнительная blocking work
  для того же аккаунта. Независимый общий cap в два claims сохраняется:
  старый P1 с неограниченным накоплением blocking jobs не переоткрывается.
- Evidence: `bb73240`,
  [verify.rs:73](../crates/resocks5/src/auth/state/verify.rs#L73):
  `_gate_guard` принадлежит async frame. В closure строк 86–89 переезжает
  `claim_slots` permit, но не guard. `claim.rs::claim_commit` публикует
  hash после persistence. После отмены future guard уже уничтожен, а
  admitted blocking closure может ещё выполняться.
- Reasoning: lifetime deduplication guard и lifetime защищённой работы
  различаются. Три существующих admission tests успешно подтверждают cap,
  сохранение permit при cancellation и follower без cancellation; они
  не покрывают одновременно отмену leader и нового same-account follower
  при default cap=2. Это тот же открытый R2-P3-02.
- Recommendation: связать per-account guard с реальным окончанием
  persistence closure, например передав owned guard; либо сузить обещание
  дедупликации. Не переносить hashing permit обратно в persistence.
- Release gate: перед заявлением строгой дедупликации нужен детерминированный
  тест отмены leader с follower, подтверждающий отсутствие второго
  admitted blocking claim до завершения первого.

### R3-P3-03 — Настройка отключения sand model обещает round-robin, но сохраняет random selection

- Severity: P3 / medium, документированный configuration/SDK contract.
  Confidence: высокая по полному selection path; статистический тест
  или benchmark для этой находки не запускался.
- Impact: оператор/SDK consumer с `fail_penalty = 0.0` не получает
  обещанную детерминированную очередность и равное число выборов за цикл.
  Все upstream остаются допустимыми; отказ соединений или starvation
  из этого несоответствия не доказаны.
- Evidence: `rating/policy.rs:10` и
  `crates/resocks5/src/config/main/network_config.rs:110` обещают pure
  round-robin. Но `Ratings::on_failure/on_success` лишь перестают менять
  sand, а [Ratings::pick_order:114](../crates/resocks5-net/src/rating/mod.rs#L114)
  всегда строит random keys и сортирует их. Приложение вызывает именно
  `pick_order` в `dial.rs:337,353,437`; отдельный `ProxyRotator::get_next`
  с modulo counter этим настройкам не подключён.
- Provenance: это унаследованное расхождение, не новая регрессия двух
  последних commits. Promise присутствует уже в доступной базе `5d08f96`;
  текущий selection path отражён в `70e3d19` и сохранён на `aebadbf`.
- Reasoning: при нулевом penalty веса остаются равными, а случайная
  перестановка равновесных весов даёт uniform random, не round-robin.
  Аналогичная неточность остаётся в SDK README:19,
  `docs/ARCHITECTURE.md:126`, `CHANGELOG.md:267` про «all bad».
- Recommendation: согласовать описание с uniform random selection,
  если это намеренная политика. Если требуется именно round-robin,
  определить и проверить отдельный алгоритм; замена слов и смена
  маршрутизации — разные изменения.
- Release gate: до обещания round-robin исправить документацию или
  добавить явный режим с тестом последовательности. Это не P2 и не
  основание автоматически менять текущую рабочую random policy.

## Оставшиеся release gates

| Gate | Фактический результат и требуемое решение |
| --- | --- |
| Yanked dependency | `Cargo.lock:470` содержит `ktav 0.6.1`; свежий cargo-deny сообщает yank. [Официальный crates.io API](https://crates.io/api/v1/crates/ktav/0.6.1) вновь подтвердил `yanked: true`, `updated_at: 2026-09-16T19:03:52.564589Z`. Причина yank не установлена; уязвимость ktav этим не утверждается. До нового релиза нужно разобраться с причиной и выбрать поддерживаемый pin отдельным разрешённым изменением. |
| Compatibility с `v0.1.1` | `cargo-semver-checks 0.50.0` завершился code 100: 194 checks pass, 2 fail, 58 skip. `AnyUpstream` стал `non_exhaustive`; `send_possibly_fragmented` принимает четыре аргумента вместо трёх. Исходный return type также был `Result<()>`, текущий — `Result<SendProgress>`; это видно в source comparison и важно для migration. Manifest остаётся `0.1.1`. Нужны выбранная release version/policy и migration notes, а не заявление о совместимом patch. |
| Compatibility с раундом 2 | Отдельный semver run относительно `93d4701` прошёл: 196 pass, 58 skip, code 0. Это поддерживает отсутствие новых default-feature API breaks в двух fixes, но не отменяет older-release breaks и ограничения tool. |
| SDK archive | `cargo package -p resocks5-net --locked --offline` прошёл, 43 файла. Извлечённый package дополнительно проверен `--all-targets` в lean/all-features режимах. `LICENSE-MIT`/`LICENSE-APACHE` в списке отсутствуют при declared `MIT OR Apache-2.0`. До распространения подготовить полный комплект SDK-дистрибутива; юридический вывод здесь не делается. |
| Application crates.io channel | `cargo package -p resocks5 --no-verify --locked --offline` вернул code 101: `resocks5-net` не имеет version requirement (`crates/resocks5/Cargo.toml:14,40`). Это блокирует именно этот registry channel; native binary сборка и git workspace от этого не ломаются. Если приложение распространяется только native archives/Docker, явно зафиксировать этот scope. |
| Dependency policy | `cargo deny --locked --offline check bans licenses sources --disable-fetch` вернул code 4: `bans ok, licenses FAILED, sources ok`. В проекте нет `deny.toml`; default policy не разрешает лицензии явно и отвергает в том числе обычные MIT/Apache dependencies. Это отсутствие настроенного policy gate, не доказанный конфликт лицензий. Нужна осмысленная project policy. |

Ни версии, ни dependency pins, ни workflow в рамках отчёта не исправлялись.
Выбор публикационного канала и версии остаётся действием владельца релиза.

## SDK assessment

Для Tokio consumer SDK уже даёт рабочие connectors, one-shot dial,
pool accounting, rotator, TLS provider escape hatch и timeout-aware
forwarding. Ключевой дефект аддитивности `tls` устранён не только в
нетипизированных вызовах, но и в public naming path. Изоляция features
и самостоятельная упаковка фактически проверены; приложение больше не
служит единственным доказательством собираемости библиотеки.

До стабилизации API полезно отдельно принять следующие решения:

- `ProxyRotator::new` допускает пустой список, а `get_next` делит на его
  длину (`rotator/mod.rs:279`). У `Ratings::pick` аналогичный запрет уже
  отражён в `# Panics`, у `get_next` — нет. Нужен явный nonempty/fallible
  constructor, `Option`-метод либо точная precondition. Приложение создаёт
  rotators только для непустых групп (`startup.rs:275–298`).
- `RatingPolicy::validate` существует и вызывается приложением
  (`startup.rs:268`), но `Ratings::new`/`ProxyRotator::with_policy`
  её автоматически не вызывают. Для SDK стоит предложить fallible
  construction и связать constructor docs с validation obligation,
  чтобы ручная конфигурация не давала тихие NaN/неправильные weights.
- `ProxyPool::checkout` возвращает bare TcpStream, освобождая cap permit
  при разборе `PreWarmed` (`proxy_pool/mod.rs:358`). Это уже описанный
  accounting escape hatch, а не новый cap bug в стандартном `acquire`.
  Имя/документация должны ясно отличать его от guarded acquire; фраза
  «permit is dropped with the socket» неверна для живого возвращённого
  socket. Приоритет — убрать неоднозначность до фиксации публичного API.
- `handshake_over_stream` имеет одну строку rustdoc, принимает и owned
  stream, и `&mut stream`; после partial I/O ошибка/отмена требует закрытия
  caller-owned transport. Нужны явные timeout/cancellation docs, как у
  `http_connect_handshake`; отсутствие собственного timeout допустимо для
  низкоуровневого helper, но должно быть видимым контрактом.
- `connect_proxy` и `connect_proxy_once` не интерпретируют `ProxyConfig.gate`.
  Gate assembly живёт в приложении, в `dial.rs::try_proxy/use_gate`.
  Это следует ясно описать в SDK: наличие gate field/stream variant
  само по себе не является готовым high-level chained dial API.
- Typed failures для protocol rejection, timeout, missing TLS и malformed
  endpoint упростят recovery без разбора anyhow strings. Аналогично
  `tunnel_with_timeouts` возвращает `Ok(())` и при EOF, и при deadline:
  отдельный completion reason был бы полезен наблюдающему consumer.
  Эти текущие формы не объявляются ошибками без обещания другого поведения.
- `FlushProgress` публичен, а его scope/record API закрыты внутри crate.
  Он поддерживает встроенные helpers, но пока не даёт consumer готового
  API произвольной instrumentation. Выбрать intended public surface.
- Pool endpoint maps/refill registry живут до drop pool и не имеют remove
  API. Это подходит startup-config приложения; для динамических SDK
  endpoint sets нужны documented finite-set contract или lifecycle API.
- Открытые structs/enums, `tokio-rustls` types и blanket impl
  `AsyncReadWrite for Box<T>` — обязательства совместимости.
  В рассматриваемых fixes blanket bounds не сужались. `non_exhaustive`
  нельзя добавлять задним числом как будто это совместимая косметика.

## Documentation truth

TLS provider prerequisite, единый TLS slot и Pending-progress пути
описаны существенно точнее, чем в первом раунде. Rustdoc lean/all-features
проходит с запретом warnings; это проверка ссылок/сборки, не истинности прозы.
Помимо R3-P3-02/03 остаются конкретные расхождения:

| Место | Что нужно исправить |
| --- | --- |
| `docs/ARCHITECTURE.md:30,35,164,220,226,310` | Старые пути `server/handle_client.rs`, `auth/state.rs`, `pool/proxy_pool.rs`, `connect/tls_fragment.rs` после переносов не ведут к реализации. Исторические review reports можно оставить привязанными к их old HEAD; актуальную architecture map нужно обновить. |
| `types/proxy_config.rs:40` | Поле `gate` названо inner proxy, хотя production `try_proxy` трактует его как внешний gate для текущего proxy. Redaction tests не проверяют смысл topology. |
| `CHANGELOG.md:112` | Lean placeholder назван private, хотя он public и только его constructor недоступен. Следующая запись про `eb7aa6e` относится к прежней приватности TLS import — это другая вещь. |
| `upstream_tls.rs:165` | `make_tls_connector_with_provider` обещает panic только при отсутствии поддерживаемых TLS versions. Locked rustls `builder.rs:223,250` также отвергает пустые/incompatible key-exchange groups. Built-in ring работает; для custom provider нужна точная Panics секция либо fallible helper. |
| `network_config.rs:100` | Direct tunnels объявлены не входящими в `max_concurrent_clients`; `run_server.rs:150–177` выдаёт общий permit до определения маршрута. Direct cap добавочен к общему. |
| `cli/app.rs:40` и фактический `--help` | «The server runs without authentication when no users are configured» не учитывает `allow_anonymous=false`, при котором конфигурация без пользователей отвергает всех. Нужна оговорка о default policy. |
| `tls_fragment/mod.rs:107–127,152` | Пауза выполняется и после последнего chunk, хотя обещана между fragments. «No overhead on the hot path» не учитывает progress sink/timer/flush в bounded path. `TCP_NODELAY` также не даёт абсолютной гарантии границ TCP segments; общий DPI threat model в architecture осторожнее. |
| `progress.rs:66` | Process-global delta назван LOWER bound для одной chain. Вклад соседних tests его увеличивает, поэтому это upper bound на вклад отдельной chain, а не доказательство её собственного traffic. |
| `README.md:166–172`, `Dockerfile` | Docker recipe требует пояснения прав UID 65532 на bind mount и `listen_host` внутри container. Default loopback listener недоступен через опубликованный host port; смену bind нужно описывать вместе с auth policy. Container run здесь не выполнялся. |

SDK README/example в этом HEAD используют совпадающую форму calls;
example собирается с нужными features. Утверждение README «built by CI,
so the README never drifts» чрезмерно: CI компилирует отдельный `.rs`,
а не сам Markdown code block. Нужны либо extraction/check, либо более
точное обещание. Публичный список модулей README также пропускает `progress`.

## Performance и code-smell opportunities

Измеренных новых performance-регрессий не обнаружено; benchmark,
stress и искусственная нагрузка не запускались. Ниже — кандидаты для
измерения, а не обещание величины ускорения.

1. `connect_proxy_once` создаёт и сразу выбрасывает disabled ProxyPool
   (`connect_proxy.rs:164`, `proxy_pool/mod.rs:166`): две DashMap и
   per-endpoint accounting при каждом вызове. Отдельный внутренний
   single-dial path может убрать allocations; сохранить одинаковые
   timeout/error semantics. Для редких TCP connections выигрыш может
   теряться на сетевой задержке.
2. Bounded fragmentation создаёт `FlushProgress::new` на каждый chunk
   (`tls_fragment/mod.rs:148,193`, `progress.rs:39`). Один sink на send с
   корректными snapshots может убрать Arc allocation на chunk. Нельзя
   терять confirmed Pending-progress или повторно отправлять prefix.
3. Убрать необязательную паузу после последнего fragment; это сохраняет
   интервалы между соседними chunks и устраняет дополнительный final delay.
4. Generic `http_connect_handshake` читает до четырёх bytes за iteration,
   чтобы не поглотить первый tunnel payload. Для больших headers это
   много polls. Потенциальный read-ahead buffer должен возвращать prefix
   вместе со stream: простое увеличение read size сломает уже проверенную
   сохранность payload. У raw TCP connector уже есть peek path.
5. Init-account followers хешируют password до per-account gate, поэтому
   могут делать лишний Argon2. Раннее dedup потребует корректно сравнивать
   разные candidate passwords и сохранить hashing admission. Сначала
   согласовать lifetime gate из R3-P3-02.
6. Refill backoff детерминирован и при занятом cap растёт до десяти секунд;
   notify от checkout не прерывает inner sleep (`proxy_pool/mod.rs:416`).
   Это кандидат на улучшение скорости восстановления warm-spares, не
   отказ acquire: foreground dial остаётся доступен. Jitter и wake-on-slot
   следует оценивать на реальном сценарии, не добавлять ради шаблона.
7. Исторические R6/R7/P2-комментарии дублируют контракты. В частности,
   `AuthState::verify` помечен prose как test-only, но оставлен `pub` с
   `allow(dead_code)`, без `cfg(test)`; production calls идут через async
   path. Стоит сузить compile surface и оставить краткие инварианты.

Уже полезные решения сохранены: сортировка outside ratings mutex,
ожидаемый O(1) identity lookup с проверкой collisions, bounded sticky
cache, перенос proxy groups без deep clone, hoist `pick_order` за проверку
attempt budget, отсутствие diagnostic atomic в normal release features.
Новых подтверждённых ABBA/guard-across-await дефектов в просмотренных
путях не найдено; сами короткие mutex sections не повод переписывать state.

## Выполненные проверки

Host: `x86_64-pc-windows-msvc`. rustc `1.97.0 (2d8144b78 2026-07-07)`,
Cargo `1.97.0 (c980f4866 2026-06-30)`, LLVM `22.1.6`. MSRV: `1.88.0`.
Cargo build/check/test/doc runs использовали `-j 2` либо
`CARGO_BUILD_JOBS=2`, `RUSTFLAGS=-D warnings`; rustdoc дополнительно
`RUSTDOCFLAGS=-D warnings`. SemVer tool запускался отдельно с
`CARGO_NET_OFFLINE=true`, `CARGO_BUILD_JOBS=2`, без заявления о `--locked`
для его внутренних builds. Служебные PowerShell wrappers сохраняли exit
code каждого Cargo command; stderr formatting сам по себе не считался fail.

Root locked graph: Tokio 1.43.1, tokio-rustls 0.26.4, rustls 0.23.40,
serde 1.0.228, anyhow 1.0.103, ktav 0.6.1, DashMap 6.1.0,
ring 0.17.14, argon2 0.5.3. Checked-in downstream fixture имеет отдельный
lockfile: Tokio 1.53.1, tokio-rustls 0.26.5, rustls 0.23.45.
Package verification и проверки извлечённого package использовали root
версии TLS/runtime. Эти разные dependency graphs не смешиваются в выводах.

| Команда / точная группа команд | Результат |
| --- | --- |
| `cargo metadata --locked --offline --format-version 1` | Code 0; resolved versions/sources и manifests просмотрены. |
| `cargo check -p resocks5-net --all-targets --no-default-features --locked --offline -j 2`, затем с `--features SET` | Все 12 обычных closures прошли: none; tls; serde; rating; rotator; tls,serde; tls,rating; tls,rotator; serde,rating; serde,rotator; tls,serde,rating; tls,serde,rotator. Дополнительно passed test-instrumentation. |
| `cargo check --manifest-path tests/feature_unification/Cargo.toml --workspace --locked --offline -j 2 --target-dir target/feature-fixture`, затем вместо `--workspace` отдельно `-p lean-consumer` и `-p tls-consumer` | Все три code 0; typed consumer из `eb7aa6e` включён. |
| `cargo test -p resocks5-net --lib handshake_over_stream --locked --offline -j 2`; дополнительно с `--no-default-features`; дополнительно с `--release` | 8 passed в каждом из трёх запусков. |
| `cargo test -p resocks5-net --lib FILTER --locked --offline -j 2` | `connect::tunnel::tests`: 15; `connect::tls::tls_fragment::tests`: 29; `pool::proxy_pool::tests`: 15; `types::proxy_config::tests`: 2; `connect::proxy_connect::connect_proxy::tests`: 2; `connect::proxy_connect::connect_http_proxy::tests`: 5 passed. |
| `cargo test -p resocks5-net --release --lib FILTER --locked --offline -j 2` | `connect::tunnel::tests`: 15; `connect::tls::tls_fragment::tests`: 29 passed. Реальный optimized/LTO test build. |
| `cargo test -p resocks5-net --test crypto_provider_contract --locked --offline -j 2` | 1 passed. |
| Та же команда с `--features rustls/custom-provider`, `RESOCKS5NET_PROVIDER_CONTRACT_EXPECT_PANIC=1` | 1 passed; проверен ожидаемый provider-resolution panic и explicit/global provider paths. |
| `cargo test -p resocks5 --bin resocks5 FILTER --locked --offline -j 2` | По 1 passed для `claim_pileup_cannot_starve_ordinary_login_on_small_blocking_pool`, `cancelled_claim_keeps_admission_permit_until_persistence_finishes`, `same_account_claim_follower_waits_on_gate_not_on_a_blocking_thread`. |
| `cargo test -p resocks5 --bin resocks5 tests_matrix::matrix_ --locked --offline -j 2` | 9 passed. |
| `cargo test -p resocks5 --bin resocks5 tests_progress --locked --offline -j 2 -- --test-threads=1` | 5 passed, 54.46 s; последовательное исполнение исключает соседние tests из process-global counter. |
| `cargo doc -p resocks5-net --no-default-features --no-deps --locked --offline -j 2`; вариант с `--all-features` | Оба code 0, warnings denied. |
| `cargo test -p resocks5-net --doc --no-default-features --locked --offline -j 2`; вариант с `--all-features` | 1 compile-only doctest и 3 doctests passed соответственно. `no_run` network example не исполнялся. |
| `cargo +1.88.0 check --workspace --all-targets --locked --offline -j 2` | Code 0 на Windows; это compilation/MSRV proof, не исполнение tests. |
| `cargo fmt --all -- --check` | Code 0. |
| `cargo clippy -p resocks5-net --all-targets --no-default-features --locked --offline -j 2 -- -D warnings`; `cargo clippy --workspace --all-targets --all-features --locked --offline -j 2 -- -D warnings` | Оба code 0. |
| `cargo package -p resocks5-net --list --locked --offline`; `cargo package -p resocks5-net --locked --offline` | Оба code 0; 43 файла, 375.4 KiB / 96.0 KiB compressed; extracted package build passed. |
| `cargo check --manifest-path target/package/resocks5-net-0.1.1/Cargo.toml --all-targets --no-default-features --locked --offline -j 2 --target-dir target/package-check`; вариант с `--all-features` | Оба code 0, SDK вне исходного workspace, включая applicable example/test targets. |
| `cargo package -p resocks5 --no-verify --locked --offline` | Code 101: dependency version requirement отсутствует. |
| `cargo run -p resocks5 --locked --offline -j 2 -- --help` | Code 0; CLI smoke, без запуска сервера/создания config. |
| `cargo semver-checks -p resocks5-net --baseline-rev v0.1.1 --default-features --color never` | Code 100: 194 pass, 2 fail, 58 skip. |
| Та же команда с `--baseline-rev 93d4701` | Code 0: 196 pass, 58 skip. |
| `cargo deny --locked check advisories -D warnings` | Code 1 по свежей базе: rustls advisory и yanked ktav. |
| `cargo deny --locked --offline check bans licenses sources --disable-fetch` | Code 4: bans/sources ok, licenses failed на default policy без allowlist. |

Все запущенные существующие tests прошли с первого раза. Flakes и
test failures не наблюдались; повторов ради зелёного результата не было.
Незелёные dependency/SemVer/package gates выше не названы успешными тестами.
Полный workspace test suite не запускался.

## Проверенные области и ограничения доказательств

- Async/network lifecycle: при текущем owning call graph ошибки и отмена
  освобождают stream/permits; bounded tunnel tests покрывают half-close,
  stalled write, progress, zero-progress controls и bounded teardown.
  `forward_tunnel` сохраняет absolute lifetime вокруг initial forwarding
  и дальнейшего copy; per-write idle не используется вместо whole lifetime.
  SOCKS5/HTTP framing, payload preservation и protocol matrix проверены
  указанными targeted tests, без обращения к сторонним proxy/targets.
- Auth/state: CPU и persistence admission разделены; claim permit хранится
  в blocking closure. Post-lock recheck и publish-after-persist сохранены.
  Обычная авторизация не требует claim mutex; cache bounded startup users.
  R3-P3-02 отдельно ограничивает утверждение о deduplication.
- Crypto/unsafe: SDK production unsafe в просмотренном source не найден.
  Новые fixes не вводят crypto primitives/FFI. Auth сохраняет Argon2id
  v0x13, 5120 KiB, t=2, p=1, случайную соль и HMAC-SHA256 cache с
  constant-time comparison. Низкие Argon2 параметры — существующая
  документированная throughput policy, не новый результат crypto audit.
  Windows users-file code сохраняет HANDLE ownership, LocalFree и
  capture-last-error до следующего FFI call; Unix uses flock/rename/fsync.
  Их платформенная корректность не доказана чтением или SDK test suite.
- Pool: acquisition переносит permit вместе с warm socket; gate добавляет
  inner-proxy accounting на тот же transport. Refill handles retained и
  abort-ятся при drop pool. Tests подтвердили shared cap, dead-spare handling
  и drop/refill поведение. Dynamic SDK endpoint cardinality и bare checkout
  требуют контрактов, описанных выше.
- Проверки ограничены Windows x86_64. Native Unix permissions/fsync,
  Linux/macOS/arm64 runtime, Docker build/run/multiarch, реальный release-tag
  workflow, full application release acceptance, Miri/fuzz, оба native
  TLS backends одновременно и внешний network example не запускались.
  Состояние remote GitHub Actions runs не проверялось.
- `tests_progress.rs:77,84,98,101` сохраняет разные positive/negative
  условия: 5 s / 1.5 MiB против 250 ms / 20 MB. Успех positive и failure
  negative не доказывают, что удаление wrapper сломает positive при его
  собственных параметрах. Нужны одинаковые условия или per-chain sink и
  mutation control. В этом раунде production source не мутировался.
- SemVer tool проверял default features на текущем target. 58 skipped
  checks, generics/blanket-impl limits и target-specific API не позволяют
  объявить абсолютную совместимость. Feature compile matrix не является
  feature-specific SemVer comparison.

## CI и release automation

В `.github/workflows/ci.yml` есть workspace tests на трёх ОС, MSRV на
Windows/Ubuntu, SDK single-feature/default/all matrix, lean clippy и
lean rustdoc. Это полезная постоянная защита. При этом:

- `tests/feature_unification` исключён из root workspace и не вызывается
  workflow; оба successive API fixes пока защищены только локальным запуском
  этого fixture. Добавить его together/lean/TLS commands в CI.
- Нет custom-provider graph gate, SemVer, advisories, package verification
  и release-profile tests. Требуется выбрать и закрепить release acceptance
  policy; весь длинный ручной review не должен быть обязательной заменой CI.
- Release workflow публикует native archives и Docker, но не SDK crate.
  Native archives содержат root license files; SDK archive — отдельный
  артефакт, проверенный выше. Нужен явный SDK publication plan, включая
  порядок публикации, если приложение тоже должно устанавливаться из registry.
- YAML сам по себе не является доказательством успешного tagged release.
  Отдельная platform/channel acceptance остаётся открытой.

## Фиксация результата

Единственный новый tracked-файл:
`docs/REVIEW-2026-09-22-weekly-release-round-3.md`.

Перед коммитом проверены `git diff --check`, `git diff --stat`,
`git status --short` и staged file set. Коммит содержит только
этот отчёт; message: `docs: add round-3 weekly release P-notes review`.
Фактический SHA возвращается с результатом, без self-referential SHA
внутри файла. Push в рамках ревью не выполняется.
