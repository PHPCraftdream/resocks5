# Release review — P-notes

Дата: 2026-09-21. Объект: приложение resocks5 и SDK resocks5-net.
Недельный диапазон: 2026-09-14 00:00 — 2026-09-22 00:00 Europe/Berlin;
33 коммита, фактически от 20–21 сентября.
База: 2b4ef7a994a915260d8081ed475a155a584083c9.
Проверенный HEAD: c85d9613b67fba81da476fd2f37b7917ebef3297.
Диапазон diff: 2b4ef7a..c85d961.

Заключение: сборочная готовность существенно лучше поведенческой и готовности
SDK к включению в чужой dependency graph. Изолированные feature-сборки,
rustdoc, MSRV и проверочная сборка SDK-пакета проходят. Найдены один P1
и пять P2; без устранения или явного ограничения соответствующих сценариев
выпускать приложение и SDK как завершённый релиз не рекомендую.
P0 = blocker, P1 = critical, P2 = high. Менее серьёзные замечания не повышены
искусственно до P2; они обозначены как ограничения готовности ниже.

Ревью выполнено одним независимым агентом в отдельном worktree. Проверены
git log, реальные изменения и вызывающие места, а не только сообщения
коммитов. Это ограниченный release review, а не заявление о полном покрытии
всех модулей rust-intel или формальном доказательстве безопасности.
Рабочий код, версии, lockfile, CI и существующая документация не изменялись.

## P0

P0: нет подтверждённых находок.

## P1-01 — Init-claims могут занять общий blocking pool ожиданием одного mutex

- Severity: P1 / critical.
- Confidence: высокая для механизма; массовое воспроизведение не запускалось.
- Impact: при задержке сохранения первого init-claim параллельные попытки
  занять тот же или другие init-аккаунты расходуют blocking threads, хотя
  Argon2 ограничен четырьмя permits. При заполнении общего blocking pool
  перестают своевременно выполняться обычные cache-miss логины, DNS и
  файловые операции, использующие тот же executor. Клиентский timeout
  освобождает client permit, но уже запущенная синхронная работа продолжает
  ждать. Это условный отказ обслуживания: нужен доступный init-аккаунт и
  задержавшийся persist, например внешний users-file lock или медленное I/O.
  Обхода проверки пароля этим пунктом не утверждается.
- Concrete evidence:
  - crates/resocks5/src/auth/state/verify.rs:39–59: hashing permit живёт
    только в phase 1; каждый Prepared::Claim запускает отдельный
    spawn_blocking для phase 2 без отдельного admission permit.
  - crates/resocks5/src/auth/state/claim.rs:164: closure блокируется на
    общем std::sync::Mutex до проверки уже завершившегося claim.
  - crates/resocks5/src/config/users/users_file/lock.rs:16,38–68:
    users-file lock может удерживать победителя до 10 секунд; время
    ожидания claim_lock в эти 10 секунд не входит.
  - crates/resocks5/src/server/bootstrap/runtime.rs:52–54: используется
    общий Tokio blocking pool с настройками по умолчанию.
  - crates/resocks5/src/server/run_server.rs:150,176–177 и
    server/handle/handle_client.rs:56–70: cap привязан к handler, а не
    к уже запущенному blocking closure.
  - Введено разделением фаз в 47367d1; переносы в каталоги не исправили
    эту границу. Тест auth/state/tests.rs:1293 проверяет только один
    припаркованный claim и поэтому не доказывает устойчивость к очереди.
- Reproduction / reasoning: удержать users-file lock; допустить несколько
  verify_async для ещё не заявленного пользователя. Phase 1 последовательно
  освобождает свои permits, а phase 2 накапливает threads за claim_lock.
  На runtime с малым max_blocking_threads это воспроизводится несколькими
  claims без нагрузки: обычный verify, поставленный после них, ждёт worker,
  несмотря на свободный verify_slots. При timeout клиента такая работа
  автоматически не отменяется. Семантика запущенного spawn_blocking
  проверена по исходникам разрешённого Tokio 1.43.1; claim_lock не является
  асинхронной очередью и занимает thread на каждого допущенного ожидающего.
  Не утверждается буквально бесконечное число OS threads: его ограничивает
  Tokio, но это одновременно предел общего ресурса, который исчерпывается.
- Recommendation: оставить разделение CPU и persistence, но добавить
  независимое ограничение admission для claims до spawn_blocking либо
  один bounded persistence worker. Ожидание своей очереди должно происходить
  асинхронно; permit принятой работы должен сохраняться до её действительного
  окончания, включая отмену клиента. Полезна дедупликация claims по аккаунту.
- Release gate: детерминированный тест с малым blocking pool, удержанным
  file lock, несколькими claims и обычным cache-miss логином; последний
  проходит до освобождения file lock. Отдельно проверить cancellation.
  До исправления не включать init-on-first-login в обслуживаемый сценарий.

## P2-01 — Feature tls меняет арность публичного API и ломает feature unification

- Severity: P2 / high.
- Confidence: подтверждено компилятором, E0061.
- Impact: библиотека A с lean-зависимостью собирается самостоятельно, но
  перестаёт собираться в приложении B, если другой компонент B включает tls
  или default features resocks5-net. A не может узнать это через собственный
  cfg(feature = "tls"): features зависимостей не становятся features A.
  Получается несоставимый SDK, даже когда все отдельные сочетания features
  внутри самого SDK успешно собираются.
- Concrete evidence:
  - crates/resocks5-net/src/connect/proxy_connect/connect_proxy.rs:31–37
    и 121–127: #[cfg(feature = "tls")] стоит на параметре tls_connector.
  - crates/resocks5-net/Cargo.toml:36: tls входит в default.
  - crates/resocks5-net/examples/connect_through_proxy.rs содержит
    feature-зависимые варианты вызова: это пример внутри того же package,
    а не доказательство downstream-совместимости.
  - Изменение 2582f7e; CHANGELOG.md описывает разные сигнатуры, но не устраняет
    проблему объединения features.
- Reproduction / reasoning: отдельный временный package с зависимостью
  resocks5-net через path и default-features = false вызывает:

      drop(connect_proxy_once(target, &proxy, connect_timeout, handshake_timeout));

  cargo check этого package без tls завершился с code 0. Неизменённый
  исходник с включённым resocks5-net/tls завершился с code 101:
  «this function takes 5 arguments but 4 arguments were supplied».
  Это тот же итог, который даст второй зависимый package, включивший tls.
  [Cargo требует аддитивности features и объединяет их для общей зависимости](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification).
- Recommendation: сохранить одну сигнатуру plain/универсального entry point
  при всех features; TLS добавлять отдельным методом/функцией или через
  устойчивый options/builder type. Не пытаться исправить это только
  условными вызовами в README.
- Release gate: downstream fixture с двумя зависимыми crates: один использует
  lean API, другой включает tls. Оба собираются вместе и отдельно без
  изменения исходников lean consumer.

## P2-02 — HTTPS через gate не получает подтверждение transport progress

- Severity: P2 / high.
- Confidence: высокая, подтверждена трассировкой фактических типов и calls.
- Impact: исправление ложного idle/stall для медленно дренирующего TLS
  работает только на прямом HTTPS connector. Gate-цепочка с HTTPS на любом
  hop по-прежнему может закрыть работающий поток, пока внешний flush или
  shutdown остаётся Pending дольше idle, хотя нижний TCP передаёт байты.
- Concrete evidence:
  - crates/resocks5-net/src/connect/tls/upstream_tls.rs:35–45:
    прямой connector создаёт TlsStream<ProgressReportingWriter<UpstreamStream>>.
  - crates/resocks5/src/server/connect/establish_connection/dial.rs:82:
    tunnel_hop вызывает connector.connect(server_name, stream).
  - Там же :131: исходный gate_stream помещается в Box без
    ProgressReportingWriter; результат двух hops возвращается как
    AnyUpstream::Gate.
  - crates/resocks5-net/src/pool/proxy_pool/stream.rs:64–83: сырые write
    и write_vectored не сообщают progress.
  - crates/resocks5-net/src/pool/any_upstream.rs:28–69: для
    ProgressReportingWriter отсутствует AsyncReadWrite implementation.
    Просто добавить SDK-обёртку в BoxedUpstream извне также недостаточно.
  - Исправление 0b0c7ea инструментирует AnyUpstream::Tls, но use_gate не
    вызывает эту ветку connect_proxy.
- Reproduction / reasoning: HTTP→HTTPS, HTTPS→HTTP или HTTPS→HTTPS gate
  с transport, который регулярно принимает ciphertext, но не завершает
  один flush за idle. Ни один элемент реальной gate-цепочки не увеличивает
  FlushProgress. flush_bounded_by_confirmed_progress видит нулевую дельту
  и возвращает Stalled; tunnel tracking также не видит скрытый drain.
  Существующий тест uninstrumented_flush_keeps_single_idle_window прошёл
  и подтверждает поведение неинструментированной обёртки. Полный gate E2E
  для этого сценария в данном ревью не исполнялся.
- Recommendation: инструментировать единственный raw TCP transport до
  первого TLS hop; обеспечить проброс AsyncReadWrite/as_tcp/set_nodelay
  через ProgressReportingWriter. При nested TLS не считать буферизованные
  промежуточным TLS plaintext-байты подтверждением записи в TCP.
- Release gate: byte-for-byte тест медленного drain через каждый HTTPS gate
  вариант; отдельный отрицательный контроль без нижней instrumentation
  должен терять ожидаемую устойчивость. Сохранить нулевой-progress timeout.

## P2-03 — Progress, выполненный внутри Pending poll_write, игнорируется

- Severity: P2 / high.
- Confidence: высокая для пропуска в коде; длительный real-TCP сценарий
  с таким расположением backpressure отдельно не воспроизводился.
- Impact: даже при правильно установленной ProgressReportingWriter
  туннель или bounded send могут признать TLS writer неактивным, когда он
  дренирует ранее принятые записи, но пока не принимает новый plaintext.
  Ложный timeout зависит от скорости drain, размера TLS-буферов и idle.
- Concrete evidence:
  - crates/resocks5-net/src/connect/tunnel.rs:123–132: Tracked::poll_write
    обновляет activity только на внешнем Ready(Ok(n > 0)).
  - Там же :135–151: дельта confirmed.total() проверяется исключительно
    в poll_flush и poll_shutdown.
  - crates/resocks5-net/src/connect/tls/tls_fragment/mod.rs:186–205:
    запись обёрнута в один timeout(idle, writer.write(...)); счётчик progress
    учитывается только в последующем flush helper :229–245.
  - В разрешённом tokio-rustls 0.26.4, src/common/mod.rs:279–312,
    poll_write после writer().write может выполнять write_io, передать
    часть ранее буферизованного ciphertext и вернуть Pending, если новый
    plaintext пока не принят: ветвь (0, true).
  - Это неполное покрытие новых progress-путей из 7812fd0 и 0b0c7ea.
- Reproduction / reasoning: у buffering writer есть старый pending buffer.
  Каждый poll_write нового payload продвигает старый buffer через
  ProgressReportingWriter, затем возвращает Pending до освобождения места.
  Нижний counter растёт чаще idle, но timeout записи не продлевается,
  а Tracked::poll_write не фиксирует activity. Внешний write может законно
  оставаться Pending: он ещё не потребил байты нового аргумента.
  Нынешние DripWriter-тесты возвращают Ready при каждом принятом куске,
  а BufferedAcceptor переносит весь drain в poll_flush — обе модели обходят
  рассматриваемую ветку.
- Recommendation: учитывать подтверждённую нижним transport запись на любом
  poll, способном её выполнить, включая poll_write; bounded send должен
  продлевать ожидание по этому же событию, не перезапуская частичную операцию.
  Простые wakeups или очередной Pending не должны продлевать deadline.
- Release gate: paused-time test с bounded buffering writer, который
  дренирует старые bytes в poll_write и остаётся Pending для новых.
  Send и tunnel сохраняются при progress и завершаются при его прекращении;
  при успехе сравнивается полный payload, при cancellation нет повторной записи.

## P2-04 — Публичный Debug для ProxyConfig раскрывает proxy credentials

- Severity: P2 / high.
- Confidence: подтверждено полями и derive, без предположения об утечке в текущем сервере.
- Impact: обычный debug-лог SDK consumer, dbg!, tracing field или panic
  diagnostic с ProxyConfig выводит username и password открытым текстом.
  Вложенный gate раскрывается рекурсивно. Для reusable SDK это опасный
  стандартный путь диагностики, обходящий аккуратные сообщения connector.
- Concrete evidence:
  - crates/resocks5-net/src/types/proxy_config.rs:13–31:
    derive(Clone, Debug), публичные user/password и gate.
  - crates/resocks5-net/src/connect/util/parse_proxy_str.rs:38–57:
    parser сохраняет обе credential strings в этом типе.
  - crates/resocks5-net/src/pool/proxy_pool/mod.rs:93–102 специально
    исключает оба credential поля из upstream_endpoint, однако Debug
    использует независимый путь. Последняя неделя его не изменила;
    это существующий SDK-дефект, а не приписанная новым коммитам регрессия.
- Reproduction / reasoning: format!("{:?}", parse_proxy_str(
  "demo:fixture-secret@127.0.0.1:1080", ProxyProtocol::Socks5, IP::V4))
  содержит fixture-secret по определению derived Debug. В отчёт не
  включены настоящие credentials. В production logging приложения
  использование Debug полного ProxyConfig не обнаружено.
- Recommendation: ручной redacted Debug, включая вложенный gate;
  при необходимости отдельный явный diagnostic view без credentials.
- Release gate: test с различными фиктивными secrets в upstream и gate:
  ни password, ни username не встречаются в Debug-строке; endpoint виден.

## P2-05 — TLS helper имеет недокументированное требование process-global provider

- Severity: P2 / high для downstream TLS-интеграции.
- Confidence: panic воспроизведён; ветвь одновременного ring/aws-lc проверена
  по исходникам rustls 0.23.40, без отдельной сборки aws-lc.
- Impact: успешное добавление SDK к другому TLS consumer может закончиться
  panic при make_tls_connector, до сетевого соединения. Это не обход
  certificate verification и не дефект криптографии rustls: приложение
  должно управлять выбором provider, а SDK этот prerequisite не сообщает.
- Concrete evidence:
  - Cargo.toml:28–29 включает ring у rustls/tokio-rustls.
  - crates/resocks5-net/src/connect/tls/upstream_tls.rs:80–90:
    helper без Result и без секции Panics вызывает ClientConfig::builder().
  - rustls 0.23.40, crypto/mod.rs:243–283: при отсутствии установленного
    default provider автоматический выбор возвращает None как для
    ring + aws_lc_rs, так и для custom-provider; последующий expect паникует.
  - SDK README рекомендует готовый connector, но не описывает эту глобальную
    предпосылку. Существовало до недельного range; существенно для SDK release.
- Reproduction / reasoning: отдельный package включил SDK/tls и
  rustls =0.23.40 с custom-provider, затем вызвал make_tls_connector без
  process-global установки. cargo run завершился code 101 с
  «Could not automatically determine the process-level CryptoProvider».
  custom-provider использован как компактный отрицательный контроль той же
  ветви; обычный default consumer, включивший aws-lc рядом с SDK/ring,
  создаёт второе условие неоднозначности.
  [Rustls описывает ответственность приложения за default provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html#using-the-per-process-default-cryptoprovider).
- Recommendation: явно определить SDK-контракт: документировать обязательную
  установку provider приложением и дать рабочий composable пример либо
  добавить fallible helper/вариант с передаваемым provider. Не устанавливать
  глобальный ring из SDK без согласования с политикой приложения; переданный
  пользователем TlsConnector уже является доступным способом явной настройки.
- Release gate: downstream tests с одним provider, обоими built-in providers
  и custom-provider; ожидаемая ошибка настройки не должна выглядеть как
  неожиданная авария документированного готового пути.

## Проверенные области и результаты без дополнительных P0–P2

| Область | Фактический результат и граница вывода |
| --- | --- |
| SDK feature graph | Все 12 различных closure-наборов обычных features собраны отдельно: none; tls; serde; rating; rotator; tls+serde; tls+rating; tls+rotator; serde+rating; serde+rotator; tls+serde+rating; tls+serde+rotator. rotator включает rating. Дополнительно собран test-instrumentation. Команда каждого варианта: cargo check -p resocks5-net --all-targets --no-default-features --features SET --locked --offline -j 2, RUSTFLAGS=-D warnings; для none параметр features опущен. Все code 0. |
| Default features | Default остаётся tls+serde+rating+rotator. Его эквивалент проверен в matrix; focused tests и package verification исполнялись с обычными defaults. |
| Progress | Это всегда доступный module, а не Cargo feature. Нет feature progress. Lean SDK сохраняет fragmentation/progress без rustls; rating/rotator корректно скрыты. |
| Rustdoc | cargo doc -p resocks5-net --no-default-features --no-deps --locked --offline -j 2 и вариант --all-features, оба с RUSTDOCFLAGS=-D warnings: code 0. Проверенные intra-doc links целы; все промежуточные rustdoc combinations отдельно не строились. |
| MSRV / приложение | cargo +1.88.0 check --workspace --all-targets --locked --offline -j 2 с RUSTFLAGS=-D warnings: code 0 на x86_64-pc-windows-msvc. Это включает компиляцию test/example targets, не исполнение всех тестов. |
| Regression tests | cargo test -p resocks5-net --lib --locked --offline -j 2 с фильтром connect::tls::tls_fragment::tests: 25 passed; connect::proxy_connect::connect_proxy::tests: 2 passed; connect::tls::upstream_tls::tests: 3 passed. Последние три используют настоящий loopback TLS; все 30 прошли, без падений/повторов для получения зелёного результата. |
| SDK packaging | cargo package -p resocks5-net --locked --offline, CARGO_BUILD_JOBS=2: code 0, 42 файла; Cargo проверил сборку извлечённого пакета. --list и --no-verify также выполнены. Это не публикация в registry. |
| Downstream | Независимый lean consumer компилируется. Включение tls воспроизводит P2-01; отдельный runtime probe воспроизводит P2-05. Fixtures размещались только среди игнорируемых артефактов собственного worktree. |
| Protocol / error paths | Просмотрены сохранение coalesced CONNECT payload, ограничение headers, SOCKS5 DOMAINNAME validation до upstream dial, shared client deadline, проверка истёкшего бюджета до первого poll, ранние ответы recovery и ограничение attempts. Новых подтверждённых дефектов сверх записанных нет. |
| Auth / persistence | В diff проверены post-claim-lock recheck, lazy fallback snapshot, предел 255 bytes для нового пароля, освобождение writer-lock до stdout, отдельная загрузка users для CLI, private atomic initial configs. Не переоткрываются исправленные stale-snapshot overwrite и plaintext config initialization. |
| Security-sensitive primitives | Argon2id 0.5.3 с существующей заявленной политикой m=5120,t=2,p=1; случайная 16-byte соль; HMAC-SHA256 и constant-time cache comparison; rustls 0.23.40/ring 0.17.14 и Mozilla roots. TLS verifier bypass в production-коде не найден. Это inspection, не независимый криптоаудит параметров. |
| Unsafe / FFI | В SDK unsafe не найден. В приложении проверены ownership/error capture вокруг users_file/platform_windows.rs и platform_unix.rs: File/HANDLE, LocalFree, flock/LockFileEx, ReplaceFileW. Не обнаружено нового нарушения в перенесённом коде; это не замена native Unix/Windows runtime tests. |
| Performance | Hoist pick_order и guard attempt budget сохранены; diagnostic atomic исключён из обычных builds; proxy groups перемещаются вместо глубокого clone; lazy users snapshot не копируется в обычном existing-file claim; sorting ratings выполняется после освобождения mutex. Новых измеренных performance-регрессий нет. |

Toolchain основной проверки: rustc 1.97.0 (2d8144b78 2026-07-07),
Cargo 1.97.0 (c980f4866 2026-06-30), x86_64-pc-windows-msvc.
Locked runtime dependencies: Tokio 1.43.1, tokio-rustls 0.26.4,
rustls 0.23.40, serde 1.0.228, anyhow 1.0.103, ktav 0.6.1.
Временный downstream package разрешал зависимости самостоятельно offline:
в частности Tokio 1.53.1 и tokio-rustls 0.26.5; для provider probe rustls
явно закреплён на =0.23.40. Его результаты не выданы за locked-workspace tests.

## SDK assessment и открытые verification / release gaps

- Public API: основной набор пригоден для повторного использования:
  generic AsyncRead/AsyncWrite, собственные ProxyConfig/HostPort, типизированный
  AtCapacity для capacity-policy, always-on progress, non_exhaustive
  AnyUpstream и отдельный one-shot connector. До SDK release нужны P2-01
  и P2-04/P2-05; одного успешного примера из собственного workspace недостаточно.
  Большинство connector errors остаются anyhow; structured protocol/timeout
  error enum и fallible empty-rotator selection были бы полезными будущими
  улучшениями, но сами по себе не объявлены high-дефектами.
- Уже известный public checkout: pool/proxy_pool/mod.rs:358–359 возвращает
  bare TcpStream, а permit отпускается немедленно при разборе PreWarmed.
  Это явно документированное zero-accounting исключение, ранее отмеченное
  в REVIEW-2026-09-08-round-2.md и REVIEW-2026-09-09-round-5.md.
  Оно не переоткрыто как регрессия сервера: production использует acquire.
  Для SDK стоит выделить такой escape hatch именем/документацией или
  перейти на guard-returning API до стабилизации; потребителю нельзя
  обещать hard cap для произвольного использования checkout.
- Progress API: FlushProgress публичен, но confirmed_scope и запись в sink
  crate-private. Внешний consumer может оборачивать transport для встроенных
  send/tunnel helpers, но не подключать собственный sink обычным public API.
  Следует определить, действительно ли внешний instrumentation sink является
  поддерживаемым SDK-сценарием; сейчас описание «reusable plumbing» шире
  самостоятельной применимости FlushProgress.
- Package/application: cargo package -p resocks5 --no-verify --locked
  --offline воспроизводимо завершился code 101: dependency resocks5-net
  does not specify a version. Причина — path-only normal/dev dependency
  в crates/resocks5/Cargo.toml:14,37. Это gate, если планируется публикация
  приложения в crates.io. Сборке native binary и заявленной git/path installation
  это не мешает, поэтому результат не повышен до универсального P0.
  В текущем release workflow вообще нет registry publication SDK.
- Package/legal assets: в списке SDK-пакета нет LICENSE-MIT/LICENSE-APACHE,
  хотя manifest и README указывают dual license; root license-файлы входят
  в native archives, но не в crate автоматически. Перед registry publication
  проверить комплект лицензий в самом архиве. Юридическая оценка не проводилась.
- CI: на проверенном HEAD .github/workflows/ci.yml собирает workspace с
  defaults; приложение всегда включает весь SDK. Постоянного SDK feature
  matrix и смешанного downstream graph в этом HEAD нет. Локальная матрица
  этого ревью закрывает текущую сборку, но не будущие регрессии.
  Работа на других ветках в выводы о c85d961 не включена.
- Документация: rustdoc links проверены, но docs/ARCHITECTURE.md продолжает
  ссылаться на старые пути server/handle_client.rs, auth/state.rs,
  pool/proxy_pool.rs и connect/tls_fragment.rs после реорганизации.
  README SDK называет одинаковые веса «uniform round-robin», тогда как
  weighted_order делает случайную перестановку; get_next действительно
  round-robin. ProxyConfig.gate doc описывает «inner proxy», хотя use_gate
  хранит/читает в этом поле внешний gate. Эти уточнения нужны до SDK release,
  но не выданы за самостоятельные critical/high runtime-дефекты.
- Docker documentation: README recipe использует bind mount и -p, при этом
  nonroot UID должен иметь права на host directory, а default listen_host
  остаётся 127.0.0.1 внутри контейнера. Copy-paste recipe требует объяснения
  подготовки volume, внешнего bind и auth policy. Docker image и фактическая
  опубликованная multiarch manifest в этом ревью не запускались/не проверялись.
- Performance opportunities без неподтверждённых чисел: connect_proxy_once
  всё ещё создаёт две DashMap и semaphore через временный ProxyPool на
  каждый dial; это честно описано в его подробном rustdoc. Для частых
  одноразовых соединений целесообразно измерить allocator/syscall cost и
  затем выделить прямой transport acquire. В fragmentation также есть
  sleep после последнего chunk, хотя описание обещает паузу между chunks.
  Искусственной нагрузки и benchmark-гонок не проводилось.
- Release/debug parity: профиль release использует LTO и обычный unwind;
  runtime teardown защищён catch_unwind и shutdown_timeout. Release runtime
  tests и arm64/macOS/Linux execution в этом ревью не запускались.
  Windows/MSRV check не доказывает работу native ACL/fsync на других ОС.
- Test oracles: новые paused-time drip tests сравнивают payload и не полагаются
  только на число байтов; auth race 2780d40 использует реальные probe events.
  Однако real-TLS tests с 60 KiB fragments и idle 5 s требуют лишь общего
  send >6 s, а не доказанного единственного Pending flush >5 s.
  Нужен mutation/negative control именно удаления instrumentation из
  production path. Не заявляется, что уже измерено прохождение этих тестов
  на мутированном коде. В claim-racer test остаются настоящие 10-second
  file-lock timeout и sleeps в phase B; длительное scheduling starvation
  требует отдельной проверки, искусственно создавать его не пытались.
- Compatibility/security gates: semver-checks против выбранного прошлого
  опубликованного SDK, полный тестовый suite, cargo audit/cargo deny,
  обновлённая advisory database, fuzz/Miri и release-tag workflow в этом
  ревью не исполнялись. Intentional breaking progress-path migration
  99eec2c должна соответствовать выбранной release version; версии не менялись.
  Успешные locked builds не являются утверждением «advisories отсутствуют».

## Фиксация отчёта

Единственный изменённый tracked-файл:
docs/REVIEW-2026-09-21-weekly-release.md.

Коммит отчёта определяется без неоднозначности:

    git log -1 --format=%H -- docs/REVIEW-2026-09-21-weekly-release.md

Его фактический SHA возвращается вместе с результатом ревью. Вставить SHA
того же коммита внутрь собственного содержимого невозможно без изменения
этого SHA; здесь сознательно указан воспроизводимый идентификатор-запрос,
а не устаревший hash предыдущей редакции. Commit message:
docs: add weekly release P-notes review.
