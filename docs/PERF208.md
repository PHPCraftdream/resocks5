# #208 — детерминированные счётчики перед оптимизацией

## Статус

Получены локальный baseline и результат пяти узких оптимизаций в одном
Windows/Rust1.97 окружении. Счётчики подтвердили снижение аллокаций; timing,
latency и throughput не измерялись. Полное закрытие всех кандидатов #208
не заявляется: weighted order, pool keys, линейный resolve и retention
credentials пока оставлены без изменений.

Исходные 48 пар счётчиков, параметры сборки и статусы прогонов сохранены в
[PERF208-RESULTS.json](PERF208-RESULTS.json). Оба результата приняты runner
с общим лимитом 15 секунд на прогон; компиляция выполнялась отдельно.
GitHub CI в этой сессии не запускался.

Исходная ревизия для этой работы: `4fc5968`. Git blob исходного `Cargo.lock`:
`21b918f3b72c33829d5f4cde306cff5ae1da3095`. Lock-файл не изменён.
Существенные resolved versions: Tokio 1.54.1, DashMap 6.1.0,
crossbeam-queue 0.3.12, serde 1.0.228, rustls 0.23.46.

## Измерительная граница

Закрытый модуль `perf` подключается в каждом unit-test binary только при
`cfg(all(test, feature = "test-instrumentation"))`. Публичные SDK-типы,
сигнатуры и traits не изменяются. Обычная сборка, даже с этой фичей,
не включает новый allocator или счётчики #208. Уже существующая SDK-фича
сохраняет прежнюю instrumentation; приложению добавлена одноимённая фича,
передающая её SDK.

`measure` считает синхронную работу текущего потока. Настройка fixture,
инициализация TLS счётчиков, assertions над результатом и печать отчёта
выполняются вне scope. Возвращаемый объект живёт после scope: его последующее
освобождение не входит в число `dealloc`. Временные объекты, уничтоженные
внутри вызова, входят. Вложенные scopes запрещены; RAII выключает счётчик
при panic. Переносить scope через `.await` или между потоками нельзя.

Allocator — обёртка над `std::alloc::System`, без собственного хранения
блоков. Метрики:

- `alloc`, `alloc_zeroed`, `realloc`, `dealloc`: вызовы соответствующих
  методов `GlobalAlloc`, а не предположение об аллокациях по синтаксису;
- `requested_bytes`: сумма запрошенных размеров для `alloc`, `alloc_zeroed`
  и новых размеров для `realloc`. Это не RSS, peak memory, live bytes,
  копируемые байты или размер блоков внутри системного allocator;
- `config_clones`: явно отмеченные вызовы клонирования в `mark_dead`,
  `singleton_key`, цикле `ProxyConfig::chain` и `ChainPick::config`, не все
  Clone в процессе;
- `chain_builds`, `chain_nodes`, `hash_nodes`, `resolve_comparisons`,
  `weighted_keys`, `sort_comparisons`, `gate_formats`: выполненные операции
  в соответствующих production-компонентах.

Счётчики не выделяют память. Allocator использует непаникующий доступ к TLS
при завершении потока. Тест калибровки проверяет пустой scope, известную
аллокацию, освобождение, realloc и восстановление после panic; отдельный тест —
изоляцию маркера операций между потоками. Это не доказательство отсутствия
аллокаций внутри платформенного ожидания `Barrier`.

## Матрица кандидатов

| Кандидат | Сценарий | Что результат докажет | Что не покрыто |
|---|---|---|---|
| DT-03: `mark_dead` | Первое и повторное исключение одного proxy | Аллокации вызова и clone-sites до/после оптимизации | Другие распределения capacity HashSet |
| DT-04 / GA-04: gate label | 0, 1, 4, 16 gates | Стоимость одного реального formatter | Частота cached failures и end-to-end стоимость dial |
| CC-06: pool key | Cold/warm reserve, capacity refusal, empty checkout и checkout+reserve | Стоимость map key и semaphore-path без сокетов | Живые spares, DNS, connect, конкуренция |
| P02: двойная materialization | `plan.next()` отдельно от `pick.config()`, 1/4/16 nodes | Число chain builds, nodes и аллокации каждого вызова | Частота этих путей в реальном трафике |
| Полный weighted order при малом бюджете | N=1/8/64/256, seed=208, consumption budget=1/3 | Ключи для всего N и сравнения сортировки независимо от consumption | Общая стоимость Ratings lock/quarantine; timings |
| `ChainKey::hash` собирает Vec | Depth=1/4/16/64 | Аллокации hash и посещённые nodes | Частота hash в реальном запросе |
| Cached resolve | First/last/miss в exit-rotator, N=1/8/64/256 | Сравнения при линейном поиске и аллокации | Несколько gate levels и exit groups |
| Raw credentials | Retention duplicate: UTF-8, invalid raw bytes, HTTP Basic | Аллокации реального `Credentials::duplicate`, сохранность полей | Остальные копии при парсинге и весь handshake |
| Предварительный log formatting | Реальный tunnel report с выключенными категориями + Logger control | Затраты вокруг отключённого Logger и отсутствие затрат самого closure | Все logging call sites приложения |
| Три Arc на туннель | `Counters::default` отдельно от `Counters::clone` | Allocator requests при создании и refcount-only clone | Общая стоимость tunnel setup и atomics под конкуренцией |

В baseline gate formatter вынесен в закрытую `gate_label` без изменения
алгоритма, условий и количества вызовов. После измерений вызовы перенесены
в `log_chain_attempt`: label строится только внутри принятого Logger closure,
один раз для конкретного результата, а не заранее и повторно при cached
failure. Алгоритм formatter и текст логов не менялись. Проверены включённая
и выключенная категория, а также заполненная очередь: в последних двух
случаях число gate formats и аллокаций равно нулю. Компонентные строки
`gate_label/depth=*` намеренно остались одинаковыми в A/B; это цена formatter,
а не частота его вызова в реальном трафике.

Сценарии проверяют свойства результатов: permutation, identity, исключение
мёртвого узла, capacity, сохранение credentials. Повторные вызовы с одинаковым
входом в ряде сценариев сверяют и счётчики. Это не замена существующим
функциональным и конкурентным тестам.

## Локальное A/B: фактические результаты

Окружение: rustc/Cargo 1.97.0, target `x86_64-pc-windows-msvc`, allocator
`System`, профиль `test` с `opt-level=0`, `RUSTFLAGS=-D warnings`, incremental
отключён. Для SDK включены defaults, zeroize и test-instrumentation; для
приложения — test-instrumentation и обычные dependency defaults.

Параметры и полные dependency artifact graphs A/B совпали: 89 артефактов
SDK и 129 приложения. Их fingerprints сохранены в JSON. Lock-файл не
изменялся. Измерены два этапа незакоммиченного рабочего дерева на базе
`4fc5968`, а не два отдельных Git-коммита.

| Сценарий | До: alloc / realloc | После: alloc / realloc | Запрошено байт: до → после |
|---|---:|---:|---:|
| `mark_dead`, первый вызов | 10 / 0 | 5 / 0 | 402 → 211 |
| `mark_dead`, повтор | 9 / 0 | 4 / 0 | 350 → 159 |
| Hash, 1 или 4 узла | 1 / 0 | 0 / 0 | 32 → 0 |
| Hash, 16 узлов | 1 / 2 | 0 / 0 | 224 → 0 |
| Hash, 64 узла | 1 / 4 | 0 / 0 | 992 → 0 |
| `pick.config()`, 1 узел | 4 / 0 | 3 / 0 | 159 → 47 |
| `pick.config()`, 4 узла | 16 / 0 | 3 / 0 | 636 → 47 |
| `pick.config()`, 16 узлов | 64 / 0 | 3 / 0 | 2550 → 47 |
| Tunnel counters, создание | 3 / 0 | 1 / 0 | 72 → 40 |
| Tunnel report, категории выключены | 2 / 1 | 0 / 0 | 63 → 0 |

`mark_dead` теперь выполняет один отмеченный Clone вместо двух.
`pick.config()` больше не строит цепочку повторно: один Clone корневого
узла вместо 1/4/16 клонирований узлов и нового связывания; неизменяемые gates
разделяются через существующие Arc. Проверено, что изменения возвращённого
корня и `Arc::make_mut` gate не изменяют сохранённый ключ.

Hash сохраняет прежнюю последовательность хешируемых значений. Для цепочек
до `MAX_CHAIN_NODES=64` используется стековый буфер из 64 ссылок — 512 байт
на этом target. Это обмен heap allocations на ограниченный stack footprint;
снижение CPU cost не доказано. Более длинные невалидированные цепочки не
отвергаются и используют прежнюю Vec-ветку. Границы 64/65 и глубина 128
проверены сравнением с прежним потоком байтов Hasher.

У tunnel counters сохранены все три атомарных поля, их Ordering и совместное
время жизни, но теперь они находятся в одной Arc allocation. Изменение
cache-line/contention поведения под конкуренцией не измерялось. У report
проверены комбинации категорий и warning-only случай; текст логов сохранён.

Неизменённые кандидаты тоже получили baseline:

- weighted order при N=256 генерирует 256 ключей и делает 2112 сравнений
  для consumption budget как 1, так и 3. Частичный порядок требует отдельной
  проверки распределения и интеграции с маршрутным бюджетом;
- warm pool reserve — одна аллокация, empty checkout + reserve — две.
  Borrowed lookup пока не вводился;
- resolve по последнему/отсутствующему элементу при N=256 — 256 сравнений;
- retention duplicate — 2/4/3 аллокации для UTF-8/raw/Basic. Это owning copies
  по действующему контракту, а не автоматически лишние копии.

Baseline: 15 выполнений тестов, общий wall time runner 0,047 секунды.
После оптимизации: 58 выполнений тестов, включая короткие функциональные
фильтры, общий wall time 0,125 секунды. Logger control выполнен повторно
в отдельном функциональном фильтре. Эти времена подтверждают соблюдение
лимита, а не ускорение: наборы проверок различаются, время runner шумит.
Дополнительно прошли четыре mock-теста deadline runner. Сообщение panic
`scope cleanup` в калибровке намеренно перехватывается `catch_unwind`;
это не падение теста.

## Воспроизводимость и CI

Отдельный workflow `.github/workflows/perf.yml` запускает только тесты с
фильтром `perf208_`, последовательно. Это небольшой конечный набор
компонентных тестов, не нагрузочный benchmark. Внешние подключения, реальные
proxy, sleeps и измерение latency для этих сценариев не нужны.

Фиксированные параметры CI (отличаются от локального A/B):

- rustc/Cargo 1.88.0;
- target `x86_64-unknown-linux-gnu`;
- allocator wrapper над `std::alloc::System`;
- профиль `test`, `RUSTFLAGS=-D warnings`, incremental отключён;
- SDK с defaults и `zeroize,test-instrumentation`, как в обычной сборке приложения;
  в частности, сохраняются размеры конфигураций с TLS/secure-auth;
- приложение с обычными dependency defaults и `test-instrumentation`;
- `--locked`, неизменённый `Cargo.lock`, один test thread;
- синтетические credentials и endpoints `.invalid`.

Окружение GitHub runner не является immutable image: `ubuntu-24.04`
обновляется. Поэтому artifact сохраняет `ImageVersion`, kernel, glibc,
полные `rustc -Vv`, `cargo -V`, RUSTFLAGS, target, revision, SHA-256 lock-файла,
сам lock-файл и feature trees обоих прогонов. Для строгого A/B принимаются
только результаты с одинаковым fingerprint окружения и графом фич. При
расхождении требуется повтор baseline в том же окружении; сравнивать числа
как будто окружение одинаково нельзя. Commit SHA различается при A/B
ожидаемо, но должен быть указан у каждого результата.

Workflow сохраняет исходный вывод `PERF208` в artifact `perf208-counters`.
Ожидается 40 SDK-строк и 8 строк приложения; проверка количества защищает
от пустого/случайно суженного фильтра. Runner проверяет exit code каждого
бинарника и непустой успешный libtest summary, включая дополнительные
функциональные фильтры. Upload с `always()` сохраняет доступные свидетельства
ошибки; наличие artifact само по себе не означает успешный прогон.

### Общий лимит выполнения — 15 секунд

Компиляция вынесена в отдельные вызовы `cargo test --no-run`. Затем
`tests/perf208/run.py` извлекает точные пути бинарников из Cargo JSON и
запускает их напрямую, без Cargo/shell между runner и тестом. Оба прогона
делят один monotonic deadline на 15 секунд, а не получают по 15 секунд каждый.
Ожидание дочернего процесса ограничено остатком бюджета; при timeout runner
завершает только свой test executable и сохраняет частичный вывод со статусом
`accepted: false`. Подтверждение завершения процесса и сохранение диагностики
после timeout могут занять дополнительное системное время; продолжать
измерения после deadline нельзя.

Создание fixtures, assertions и печать результатов также входят в бюджет
выполнения. Компиляция, подготовка окружения и проверка mock-runner — нет.
Дополнительные функциональные фильтры `--check sdk:filter` и `--check app:filter`
используют тот же оставшийся бюджет. Пустой фильтр, ненулевой exit code,
неполное число PERF208-строк и превышение deadline отклоняют весь результат.
Каталог результата создаётся заново; повторно использовать старый каталог
нельзя, чтобы прежний успешный статус не маскировал ошибку нового прогона.

Команды CI:

```sh
cargo test --locked -p resocks5-net --lib --target x86_64-unknown-linux-gnu --features zeroize,test-instrumentation --no-run --message-format=json > perf-results/sdk-build.json
cargo test --locked -p resocks5 --bin resocks5 --target x86_64-unknown-linux-gnu --features test-instrumentation --no-run --message-format=json > perf-results/app-build.json
python -I tests/perf208/run.py --sdk perf-results/sdk-build.json --app perf-results/app-build.json --output perf-results/counters
```

Локальные измерения отдельно разрешены пользователем. Их Windows/Rust1.97
baseline нельзя смешивать с Linux/Rust1.88 CI baseline; A/B выполняется
целиком в одном окружении.

Абсолютные времена общего runner не являются acceptance criterion.
Instrumentation меняет стоимость операций, поэтому измерять её timings
как production performance нельзя. Число сравнений зависит от реализации
sort в закреплённом compiler; при смене compiler baseline снимается заново.

## Правила последующих оптимизаций

1. Проверить успех обоих jobs/steps, калибровку и fingerprint; перенести
   фактические числа в таблицу с revision и ссылкой на artifact.
2. Выбрать кандидат только по подтверждённой стоимости. Компонентная
   экономия не доказывает влияние на throughput всего приложения.
3. Изменить узкий внутренний слой без изменения публичных контрактов,
   семантики identity/hash, weighted distribution, fallback/attempt budget,
   сохранности/очистки credentials, логирования и lifetime permits.
4. Сравнить A/B в одинаковом окружении и с теми же fixtures. Functional
   assertions сохранить; baseline assertions обновлять только с объяснением
   фактического устранённого механизма.
5. Для кандидатов с неполным path coverage сначала добавить соответствующий
   детерминированный сценарий, а не экстраполировать компонентный результат.

Локальный этап A/B выполнен для перечисленных узких механизмов. Для остальных
кандидатов сначала нужны соответствующие проверки контрактов и дополнительные
сценарии, а не правки на глаз. Отдельный Linux/Rust1.88 CI baseline ещё не
получен. Commit, push и запуск workflow извне в этой сессии не выполнялись.
