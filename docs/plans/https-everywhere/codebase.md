# Карта кода

Что и где лежит на коммите `a6cc00d`. Номера строк приблизительны: ищи по имени, а не по номеру.

## 1. Репозиторий

| Путь | Что |
|---|---|
| `crates/resocks5-net` | SDK: библиотека, публикуется на crates.io |
| `crates/resocks5` | Приложение: прокси-сервер и CLI |
| `tests/feature_unification` | Отдельный workspace-фикстура со своим `Cargo.lock`: проверяет объединение features |
| `docs/REFERENCE.md` | Справочник; встроен в бинарник и печатается командой `resocks5 config` |
| `docs/ARCHITECTURE.md` | Архитектура |
| `deny.toml` | Разрешённые лицензии и источники |
| `.github/workflows/ci.yml`, `.github/scripts/` | CI и проверки структуры |

Версии: workspace `0.5.2`, MSRV `1.88`, `rustls 0.23` (провайдер `ring`, без `aws-lc-rs`), `tokio-rustls 0.26`, `webpki-roots 0.26`, `sha2 0.11`, формат конфигов `ktav 0.8`.

## 2. SDK (`crates/resocks5-net/src`)

Features: `tls`, `pool`, `serde`, `rating`, `rotator`, `secure-auth`, `zeroize`, `test-instrumentation`. По умолчанию включены `pool`, `tls`, `serde`, `rating`, `rotator`, `secure-auth`. Модули `session/*` подключаются в `lib.rs` через `#[path]` и снаружи видны как `resocks5_net::pool`, `rating`, `rotator`, `chain`.

| Что | Где | Зачем знать |
|---|---|---|
| `ProxyConfig` | `types/proxy_config.rs` | `#[non_exhaustive]`; конструкторы `socks5`, `http`, `https`; построители `with_auth`, `secure_only`, `with_gate`; сюда добавляются `with_tls` и `tls_only` |
| `ProxyConfig::preflight_auth` | `types/proxy_config.rs` | Общая предпроверка узла. У неё ранние выходы для `secure_only` и для `Https` — новые проверки ставятся до них |
| `ProxyProtocol` | `types/proxy_protocol.rs` | `Socks5`, `Http`, `Https` |
| `ConnectError`, `Stage`, `TimeoutKind` | `error/mod.rs` | `#[non_exhaustive]`; сюда добавляются три варианта |
| Классификация ошибок | `error/classify.rs` | `is_upstream_down`, `suggested_reply`, `counts_against_upstream` — каждый новый вариант нужно внести во все три |
| `dial`, `dial_plain`, `dial_tcp`, `DialOptions` | `connect/dial/mod.rs` | Путь без пула. `dial_inner` вызывает предпроверку до `tcp_dial` |
| `dial_chain`, `dial_chain_over`, `hop`, `https_hop`, `check_tls`, `run_chain_hops` | `connect/dial/chain.rs` | Цепочки. `hop` разбирает протокол узла; `https_hop` делает TLS поверх туннеля и CONNECT |
| `connect_chain` | `connect/dial/chain_pool.rs` | Цепочка через пул: `pool.acquire` для первого узла, разрешения для остальных |
| `Budget`, `tcp_dial` | `connect/dial/tcp_dial.rs` | Общий срок соединения |
| `connect_proxy`, `connect_proxy_on`, `connect_proxy_once`, `TlsConnector` | `connect/proxy_connect/connect_proxy.rs` | Путь через пул. `TlsConnector` — собственная обёртка SDK, существует и без feature `tls` как пустой слот |
| `connect_hedged` | `connect/proxy_connect/hedged.rs` | Гонка соединений через несколько узлов |
| `http_connect_handshake` | `connect/proxy_connect/connect_http_proxy.rs` | CONNECT поверх переданного потока; вызывает предпроверку |
| `connect_socks5_proxy` | `connect/proxy_connect/connect_socks5_proxy.rs` | Ядро SOCKS5; вызывает предпроверку |
| `https_on_stream`, `connect_https_proxy`, `make_tls_connector`, `make_tls_connector_with_provider` | `connect/tls/upstream_tls.rs` | TLS к узлу на пути с пулом; построение клиента TLS с корнями Mozilla |
| `FragmentSpec`, `send_possibly_fragmented` | `connect/tls/tls_fragment/mod.rs` | Фрагментация ClientHello клиента. Это функция отправки буфера, а не обёртка потока |
| `AnyUpstream`, `AsyncReadWrite`, `BoxedUpstream` | `connect/util/any_upstream.rs` | `AsyncReadWrite` реализован для каждого типа отдельно, общей реализации нет. Новой обёртке потока нужна своя реализация |
| `handshake_over_stream`, `socks5_handshake` | `connect/util/handshake_over_stream/mod.rs` | SOCKS5 поверх чужого потока без `ProxyConfig`: политики узла здесь нет |
| `parse_proxy_str`, `parse_proxy_uri` | `connect/util/parse_proxy_str.rs` | Разбор строки списка. Файл на 992 строки из 1000 |
| `ProxyRotator` | `session/rotator/mod.rs` | Выбор узлов: `pick_order`, `pick_iter`, `get_next`, карантин, пробы |
| `probe_due`, `probe_due_with`, `probe_all` | `session/rotator/probe.rs` | Проба TCP-достижимости узлов после карантина |
| `Ratings`, `QuarantinePolicy`, `Health` | `session/rating/` | Рейтинг и карантин по индексам узлов |
| `GateLevels`, `ChainPlan`, `ChainPick` | `session/chain/mod.rs` | Перебор цепочек «мосты × выходы» |
| `ProxyPool` | `session/pool/proxy_pool/mod.rs` | Тёплые сокеты и ограничение `max_per_upstream` |
| `accept`, `accept_with`, `accept_secure` | `server/mod.rs` | Разбор входящего SOCKS5 и HTTP CONNECT; обобщены по потоку |

**Свойства, которые легко сломать.**

- `ProxyRotator::pick_order` при отсутствии здоровых узлов возвращает **все** узлы, игнорируя карантин. Поэтому карантином нельзя блокировать несверенный узел, а пауза должна исключать узел всегда.
- `ProxyRotator::get_next` возвращает узел, а не `Option`, и паникует на пустом ротаторе.
- `same_upstream` и `upstream_hash` (`session/rotator/mod.rs`) сравнивают `host`, `port`, `protocol`, `user`, `password`, `gate_level`. Новые поля `ProxyConfig` туда не добавляются.
- На пути с пулом (`connect_proxy`, `connect_chain`, `connect_hedged`) сокет берётся из пула раньше, чем ядро протокола вызывает предпроверку.
- Проверка сертификата узла использует `node.host` как имя сервера (`https_hop`, `https_on_stream`).
- `ChainPlan`: слой, где все кандидаты отмечены мёртвыми, завершает план.
- `ProxyRotator` строится из готового списка узлов; добавить узел позже нельзя.

## 3. Приложение (`crates/resocks5/src`)

| Что | Где | Зачем знать |
|---|---|---|
| Точка входа и разбор команд | `main.rs`, `cli/command.rs`, `cli/app.rs` | Команды сейчас: `Users { action }`, `Config`. Без команды запускается сервер |
| Команда `users` | `cli/run_user_command.rs`, `cli/user_action.rs` | Образец CLI, который правит файл под блокировкой. Правки действуют после перезапуска сервера |
| Печать справочника | `cli/print_config_docs.rs` | `resocks5 config` печатает `docs/REFERENCE.md` |
| Основной конфиг | `config/main/main_config.rs` и соседние файлы | `MainConfig`: `port`, `listen_host`, `auth`, `upstream_auth`, `log`, `pool`, `tls_fragment`, `network`, `file_log`, `allowed_clients` |
| Список прокси | `config/proxy_list/proxy_list_config.rs` | `ProxyListConfig`: шесть массивов строк |
| Загрузка и создание конфигов | `config/load_or_init.rs` | `load_or_init`, шаблоны файлов по умолчанию |
| Атомарная запись и блокировка | `config/users/users_file/` | `write_atomic`, `write_atomic_text`, `UsersFileLock`, `sibling_path`; права `0600` на Unix, DACL на Windows (`platform_windows.rs`) |
| Запуск | `server/bootstrap/startup.rs` | `run_server_inner`: разбор списков (`parse_proxy_list`), флаг строки `;secure_only` (`split_secure_only_option`), группы мостов, ротаторы, пул, здоровье, `has_https`, создание `TlsConnector` |
| Приём клиентов | `server/run_server.rs` | `run_server`: `TcpListener`, ограничение `max_concurrent_clients`, срок клиента, запуск `handle_client` |
| Обработка клиента | `server/handle/handle_client.rs` | `handle_client(client_stream: TcpStream, …)`: `accept_with`, затем SOCKS5 или HTTP. Файл на 955 строк |
| SOCKS5-клиент | `server/handle/handle_socks5_client/{negotiate,recover}.rs` | Принимают `TcpStream` |
| HTTP-клиент | `http_proxy/handle_http_client/{mod,recovery}.rs` | Принимают `TcpStream` |
| Выбор пути и набор | `server/connect/establish_connection/dial.rs` | `establish_connection`: `ChainPlan`, перебор попыток, запуск проб при каждом запросе (`spawn_chain_probes`) |
| Пробы | `server/connect/establish_connection/{probes,route}.rs` | `probe_chain` (проба через живой префикс мостов), `spawn_due_probes` |
| Здоровье узлов | `server/health/mod.rs` | `resocks5.health.ktav`: `HealthFile`, `HealthGroup`, `restore`, `HealthSaver`. Включается только при `health_save_sec > 0` и `quarantine_threshold > 0` |
| Туннель | `server/tunnel/` | Пересылка данных, фрагментация ClientHello клиента |

**Свойства, которые легко сломать.**

- Узлы `_v4` и `_v6` живут в двух ротаторах, но при обслуживании запроса выходы берутся из обоих сразу.
- Строка списка, которую не удалось разобрать, сейчас пропускается с предупреждением (`skipped_line_message`), а не останавливает запуск. Сообщение намеренно не печатает саму строку.
- `warn_obsolete_cb_keys` и `warn_obsolete_gssapi_keys` ищут устаревшие ключи текстом и только предупреждают.
- Пробы запускаются не по таймеру, а из обработки клиентского запроса.

## 4. Ограничения структуры

Проверяются задачей `structure` в CI: `.github/scripts/check-dir-entries.sh` (7 записей в каталоге, считаются отслеживаемые git файлы и подкаталоги) и `check-line-limit.sh` (1000 строк в файле Rust).

Каталоги, заполненные до предела (7 из 7) — новый файл туда добавить нельзя:

| Каталог | Что делать |
|---|---|
| `resocks5-net/src/connect` | новый код — в существующие подкаталоги |
| `resocks5-net/src/connect/dial` | править существующие файлы |
| `resocks5-net/src/connect/proxy_connect` | править существующие файлы |
| `resocks5-net/src/types` | править существующие файлы |
| `resocks5-net/src/session/rotator` | сначала перенести четыре файла тестов в `rotator/tests/` |
| `resocks5-net/src/session/rating` | править существующие файлы; `mod.rs` на 825 строк |
| `resocks5-net/src/server` | править существующие файлы |
| `resocks5/src` | новый код — в существующие подкаталоги |
| `resocks5/src/config` | новый код — в `config/main/` или `config/proxy_list/` |
| `resocks5/src/config/main` | `tls_fragment_config.rs` превращается в каталог `tls/` |
| `resocks5/src/server` | новый код — в существующие подкаталоги |
| `resocks5/src/server/connect/establish_connection` | новый код сверки — в новый каталог `server/connect/verify/` |
| `docs` | `plans/` — седьмая запись; новых записей в `docs/` не добавлять |

Каталоги со свободным местом: `connect/tls` (5), `connect/tls/tls_fragment` (2), `session/pool` (3), `resocks5/src/cli` (6), `server/handle` (5), `server/bootstrap` (6), `server/health` (3), `server/connect` (5), `config/proxy_list` (3).

Файлы близко к пределу строк: `parse_proxy_str.rs` (992), `handle_client.rs` (955), `dial/tests.rs` (884), `rotator/tests.rs` (854), `probes.rs` (855), `health/mod.rs` (844), `rating/mod.rs` (825), `rotator/mod.rs` (816), `startup.rs` (799), `proxy_config.rs` (752).

Куда класть новое:

| Новое | Место |
|---|---|
| Настройки TLS узла, пин, хранилище, верификатор, правило свидетельств | `resocks5-net/src/connect/tls/trust/` |
| Обёртка потока для фрагментации нашего ClientHello | `resocks5-net/src/connect/tls/tls_fragment/` |
| Конфиг `tls`, `listen_tls`, `tls_fragment` | `resocks5/src/config/main/tls/` |
| Объект `verify`, строгие проверки конфига | `resocks5/src/config/proxy_list/` |
| Файл пинов | `resocks5/src/server/health/pins.rs` |
| Сверка по каналам | `resocks5/src/server/connect/verify/` |
| Тип клиентского потока и приём TLS | `resocks5/src/server/handle/` |
| Команды `pins`, `tls`, `config check` | `resocks5/src/cli/keys/` и существующие файлы `cli/` |

## 5. CI

Задачи `ci.yml`, которые задевает эта работа:

| Задача | Что делает |
|---|---|
| `changes` | По изменённым путям решает, какие сегменты запускать (`.github/scripts/changed-areas.sh`). Правка только SDK или только приложения запускает не всё |
| `test` | `cargo build --all-targets` и `cargo test` на трёх ОС |
| `release-behavior` | Отдельные тесты в release-режиме по именам модулей: `handle_client::`, `allowed_clients::`, `print_config_docs::`, `budget_tests::`, `probes_tests::`, `strict_http`, `dial::` |
| `lint` | `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings` |
| `structure` | 1000 строк, 7 записей, нет доктестов, тест классификатора путей |
| `msrv` | `cargo check --workspace --all-targets --locked` на Rust 1.88 |
| `doc` | `cargo doc` с `-D warnings`: у каждого публичного элемента SDK должна быть документация |
| `net-features` | `cargo test -p resocks5-net` по матрице комбинаций features |
| `clippy-net-lean`, `doc-net-lean` | SDK без features и с одним `pool`; граф без `dashmap`, `crossbeam`, `rustls` |
| `crypto-provider-contract` | Поведение `make_tls_connector` без установленного провайдера |
| `feature-unification` | Сборка фикстуры `tests/feature_unification` |
| `portable-builds` | Статическая сборка под `musl` и другие цели |
| `deny`, `third-party-licenses` | Лицензии зависимостей; `cargo about` собирает тексты |

Все сборки идут с `--locked`: при добавлении зависимости обновляются оба файла, `Cargo.lock` и `tests/feature_unification/Cargo.lock`.

## 6. Ловушки

- **Код под features.** Элемент, используемый только при одной feature, без неё даёт `dead_code`. Ставь `#[cfg(feature = "…")]` на сам элемент и проверяй `clippy` в четырёх комбинациях (см. `README.md`).
- **`TlsConnector` без `tls`.** Слот существует всегда; без feature он может быть только `None`. Новый код под `tls` не должен менять подписи функций, видимых без feature.
- **Тестовые модули.** Подключаются через `#[cfg(test)] #[path = "…_tests.rs"] mod tests;` рядом с кодом. Новый файл тестов — это новая запись в каталоге.
- **Тесты времени.** Сроки проверяются на остановленных часах (`#[tokio::test(start_paused = true)]`) поверх потоков в памяти; настоящие сокеты — только там, где проверяется сам сокет.
- **Git Bash на Windows.** Python в текстовом режиме превращает LF в CRLF: пиши файлы с `newline=''`. Печать кириллицы из Python в консоль падает на кодировке.
- **Справочник встроен в бинарник.** Правка `docs/REFERENCE.md` меняет вывод `resocks5 config`; его проверяют тесты `print_config_docs::`.
- **Сообщения об ошибках списка.** Не печатай строку списка: в ней пароль.
- **Криптопровайдер `rustls`.** В графе приложения включён только `ring`, поэтому `rustls` выбирает его сам и `install_default` нигде не вызывается. `make_tls_connector` паникует лишь в графе, где провайдер определить нельзя (это проверяет задача `crypto-provider-contract`). Новый код, строящий `ClientConfig` или `ServerConfig`, должен вести себя так же: либо обычный построитель, либо явный провайдер, как в `make_tls_connector_with_provider`.
- **Готовые тестовые стабы.** В SDK — статические CA и лист с SAN `127.0.0.1` в тестах `connect/tls/upstream_tls.rs`. В приложении — стабы узлов всех трёх протоколов в `server/connect/establish_connection/tests/matrix.rs` (`spawn_protocol_stub`, `StubPhase`, `StubLog`, `stub_tls_connector`). Новые тесты строятся на них, а не рядом с ними.
