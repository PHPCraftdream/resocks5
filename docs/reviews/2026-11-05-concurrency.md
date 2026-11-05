# Аудит concurrency и state — 2026-11-05

Автор исследования: агент `@oh`, модуль rust-intel `concurrency-and-state.md`. HEAD: `870caa2bfa9b6afd8594fabe4df9659bca585760`; приоритетный диапазон: `c927e71..HEAD`.

Агент вернул результаты сообщением: его окружение запретило запись Markdown. Этот файл сохраняет результаты агента средствами основного сеанса. Код не изменялся; никаких сборок, тестов, проверок или измерений не выполнялось. Ниже «статически подтверждено агентом» не означает воспроизведение тестом. Основной сеанс начал независимую проверку; окончательные решения — в сводном отчёте.

## Находки

### CON-01. Уже запущенные hedge-кандидаты могут одновременно отправить CONNECT

- Severity: Medium. Confidence агента: High. Новый код.
- Место: `crates/resocks5-net/src/connect/proxy_connect/hedged.rs:145–165`.
- Контракт: SDK README и пользовательский справочник обещают отсутствие дублирующих CONNECT из-за hedging.
- Механизм: TCP A pending; после hedge delay запускается B. B получает socket и начинает handshake. Затем A получает socket до успеха B, видит `won == false`, увеличивает `handshaking` и тоже вызывает `connect_proxy_on`. Счётчик запрещает старт новых кандидатов, но не вход уже запущенных кандидатов в handshake.
- Последствие: два upstream открывают соединения к одной цели. Повторная отправка прикладного payload этим не доказана.
- Предложение: эксклюзивный, RAII-защищённый переход TCP-ready → handshake, с повторной проверкой победителя после admission.
- Тест-кандидат: управляемо завершить acquisition A после начала CONNECT B, но до его результата. Второй CONNECT не должен появляться до отказа B; при успехе B A закрывается без CONNECT. Отдельно delay=0.
- Mutation: убрать эксклюзивный gate, оставив `fetch_add`; тест должен увидеть второй CONNECT.
- Проверка основного сеанса: прочитаны строки 137–166; отсутствие эксклюзивного admission и описанный переход подтверждены статически. Проверка формулировки контракта продолжается.

### CON-02. `spawn_refill_for` / `forget` могут потерять владение refill-задачей

- Severity: Medium. Confidence агента: High. Существовало до приоритетного диапазона.
- Место: `crates/resocks5-net/src/session/pool/proxy_pool/mod.rs:386–397,423–449,518–521`.
- Interleaving: A публикует очередь, но ещё не регистрирует task handle. B выполняет `forget`, затем создаёт новую очередь и задачу B. A продолжает и заменяет handle B своим handle A. Уничтожение handle B отсоединяет задачу, не отменяя её. Последующие forget/Drop не могут её остановить.
- Последствие: неучтённые refill-задачи и sockets. Runtime-вызовов `forget` в приложении агент не обнаружил; риск относится прежде всего к конкурентным SDK-потребителям.
- Предложение: одна lifecycle-критическая секция для создания endpoint state, регистрации task и удаления, с фиксированным lock ordering.
- Тест-кандидат: barrier между публикацией очереди A и регистрацией handle; forget/recreate B; продолжение A; финальный forget/Drop. Ни одна генерация не должна продолжать подключения. Дополнительно конкурентные spawn без forget дают одну задачу.
- Mutation: регистрация handle вне общей lifecycle-секции.
- Не является находкой: новая semaphore-генерация после forget не учитывает старые выданные permits — это отдельно документированный контракт.

### CON-03. Локальная нехватка permits штрафует проверяемый внутренний gate

- Severity: Medium. Confidence агента: High. Новый код.
- Место: `crates/resocks5/src/server/connect/establish_connection/probes.rs:76–109`.
- Вход: внутренний gate на probation; здоровый внешний prefix исчерпал `max_per_upstream`. `connect_chain` возвращает `AtCapacity`; `probe_chain` сводит ошибку к false; outcome вызывает hard failure проверяемого gate.
- Последствие: узел, до которого не пытались подключиться, получает удвоенный карантин; локальная ёмкость ошибочно трактуется как недоступность upstream.
- Предложение: сохранить `ChainError`, различать success, down проверяемого узла и inconclusive/local-capacity/prefix failure. Последние не должны увеличивать sand/streak/backoff проверяемого gate.
- Тест-кандидат: удерживать единственный permit prefix, запустить due probe, проверить неизменность trips/consecutive/backoff; после release проверка повторяется. Реальный отказ проверяемого gate отдельно увеличивает backoff.
- Mutation: вернуть `.is_ok()` вместо классификации.

### CON-04. Probe lease не учитывает все handshakes prefix

- Severity: Medium. Confidence агента: High. Новый код.
- Места: `crates/resocks5/src/server/bootstrap/startup.rs:337–352`; `crates/resocks5/src/server/connect/establish_connection/probes.rs:48–108`; `crates/resocks5-net/src/session/rating/quarantine.rs:239–247`.
- Механизм: lease = connect timeout + один handshake timeout + 5 секунд; chain probe проходит несколько gates с отдельным timeout каждого. При трёх внешних gates defaults допускают примерно 40 секунд против lease 25 секунд. До завершения первой проверки может выдаваться вторая; результаты не несут generation/token.
- Последствие: перекрывающиеся проверки и устаревший success, способный очистить более новый карантин.
- Предложение: абсолютный бюджет всей probe, согласованный с lease, и generation/token для отклонения устаревших результатов. Простого увеличения lease недостаточно для произвольного scheduler delay.
- Тест-кандидат: контролируемые handshakes нескольких gates, выдача probe на границе lease, поздний результат предыдущей generation и cancellation владельца.
- Mutation: вернуть одно-hop lease либо удалить generation check.

### CON-05. TCP probes обходят per-upstream cap

- Severity: Medium. Confidence агента: High. Новый код.
- Место: `crates/resocks5-net/src/session/rotator/probe.rs:42–45,86–89,112–115`.
- Вход: единственный permit endpoint уже занят tunnel/spare; startup probe делает прямой `TcpStream::connect` вне semaphore пула.
- Последствие: фактическое число sockets выше `max_per_upstream`; provider quota может отвергнуть лишнее подключение, а probe — объявить исправный upstream мёртвым.
- Предложение: приложение использует общий pool accounting; capacity означает отложить проверку. Pool-free SDK API может иметь явное исключение, но это не делает capped-интеграцию приложения корректной автоматически.
- Тест-кандидат: listener считает одновременные подключения; заполненный cap + startup/due probe не повышает счётчик и не карантинит endpoint. После освобождения permit probe выполняется.
- Mutation: прямой connect вместо pool acquisition.

### CON-06. Restore health проверяет внутренние gates напрямую

- Severity: Medium. Confidence агента: High. Новый код.
- Места: `crates/resocks5/src/server/bootstrap/startup.rs:465–476`; `crates/resocks5/src/server/health/mod.rs:231–248`.
- Механизм: список health rotators включает все уровни gates; после restore `health::start` вызывает обычный `spawn_due_probes` для каждого, а не topology-aware chain probe.
- Вход: внутренний gate на probation доступен только через внешний prefix.
- Последствие: после рестарта узел проверяется неверным маршрутом и получает новый карантин. Прямой success тоже не доказывает доступность требуемого маршрута.
- Предложение: отделить restore от dispatch probes; использовать topology-aware dispatcher с GateLevels, exits, pool и TLS. Прямо проверять только outermost gates и exits.
- Тест-кандидат: восстановить probation внутреннего gate и проверить CONNECT через внешний stub перед восстановлением здоровья. Недоступный prefix не равен неисправному внутреннему gate.
- Mutation: обычные due probes по всем rotators вместо topology-aware dispatch.
- Проверка основного сеанса: прочитан `health::start`, цикл обычных probes после restore подтверждён; состав rotators и вызываемый маршрут ещё проверяются.

## Кандидаты производительности — без измерений

1. `pick_order`: O(N) весов и random keys под ratings mutex; O(N log N) сортировка уже снаружи. `RwLock` не автоматическое улучшение: выбор меняет RNG. Сокращение секции должно сохранить distribution и quarantine snapshot.
2. Due-probe coordinator на клиентском пути сканирует upstream slots даже без due probes: порядка O(R × N) при частоте запросов R. Один topology-aware background coordinator может убрать повторные сканы, но меняет scheduling/recovery delay.
3. Sticky cache: lookup обновляет LRU под эксклюзивным mutex, индексы O(log C), C по умолчанию 4096. Concurrent map без общей координации не сохраняет строгий LRU/hard cap.
4. Sticky-chain resolution ищет identity линейно по каждому уровню: O(ΣNᵢ). Индекс может ускорить, но должен сохранить правила identity и дубликатов.
5. Startup probes создают O(N) tasks/connects. Bounded scheduler ограничит пик до O(K), но полный обход займёт примерно ceil(N/K) × timeout; это связано с leases.

## Inventory и ограничения

- Resolved: Tokio 1.54.1, DashMap 6.1.0, crossbeam-queue 0.3.12, rustls 0.23.46, tokio-rustls 0.26.4.
- Relaxed publication payload и доказанного unsafe data race агент не обнаружил. `won` использует Release/Acquire; CON-01 относится к протоколу admission.
- В просмотренных production-путях DashMap guards не пересекают await; CON-02 между отдельными map operations. Подтверждённого ABBA не найдено.
- Client admission до spawn, defaults 1024 live clients / 256 direct; completed JoinSet entries собираются. Hedge fan-out ограничен candidate slice и app attempt budget (default 10); drain losers намеренно отсоединён.
- Pool endpoint queue bounded; в приложении maps ограничены конфигурацией. Динамический SDK требует forget/Drop.
- Sticky cache: 4096 entries / TTL 600 секунд по умолчанию, индексы под одним mutex.
- Auth state ограничен startup users; hashing admission 4, persistence 2; guards/permits переносятся в blocking closure.
- Log channel bounded 2048, drop-newest разрешён контрактом; форматирование после admission.
- Конечный config-derived probe fan-out не равен attacker-controlled unbounded registry, но пик O(N) остаётся cost-кандидатом.
- Отсутствие находки не доказывает отсутствие всех races. Это статическое исследование без исполнения, stress, loom и измерений.
