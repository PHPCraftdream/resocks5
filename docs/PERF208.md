# #208 — детерминированные счётчики аллокаций и копирований

## Статус

Работа #208 измеряет не время, а счётчики: вызовы allocator, запрошенные
байты, явно отмеченные клонирования и выполненные операции в production-
компонентах. Timing, latency и throughput не измерялись и не заявляются.
Компонентная экономия не доказывает влияние на пропускную способность всего
приложения, а экономия разных строк не складывается.

Каждый кандидат из сводной таблицы ниже имеет итоговый статус. Для CoW-этапа есть
Linux/Rust 1.88 baseline из CI (блок «CI-baseline»), сверяемый тестом и
workflow; более ранние этапы подтверждены локальным Windows/Rust 1.97 A/B,
исторические цифры которого приведены в своих отчётах.

## Сводная таблица кандидатов

| Кандидат | Статус | Коммит | Доказательство | Счётчики до → после | Не покрыто |
|---|---|---|---|---|---|
| DT-03: `mark_dead` | сделано: один Clone вместо двух | `14ee842` | [PERF208-RESULTS.json](PERF208-RESULTS.json) | первый вызов 10 → 5 alloc, 402 → 211 B; повтор 9 → 4 | другие распределения capacity HashSet |
| `ChainKey::hash` собирал Vec | сделано: стековый буфер до 64 узлов | `14ee842` | [PERF208-RESULTS.json](PERF208-RESULTS.json) | 1/4/16/64 узла: 1 → 0 alloc (16 и 64 узла: ещё 2/4 realloc → 0) | CPU не измерялся; цепочки длиннее 64 идут прежней Vec-веткой |
| P02: двойная materialization `pick.config()` | сделано: один Clone корня | `14ee842` | [PERF208-RESULTS.json](PERF208-RESULTS.json) | 1/4/16 узлов: 4/16/64 → 3 alloc | частота пути в реальном трафике |
| Три Arc на туннель | сделано: одна Arc-аллокация | `14ee842` | [PERF208-RESULTS.json](PERF208-RESULTS.json) | создание 3 → 1 alloc, 72 → 40 B | contention атомарных полей |
| Предварительный log formatting | сделано: отключённые категории не форматируют | `14ee842` | [PERF208-RESULTS.json](PERF208-RESULTS.json) | report с выключенными категориями 2/1 → 0/0 | остальные места логирования |
| DT-04 / GA-04: gate label | сделано: один буфер | `14ee842` | [gate-formatter](perf208/reports/gate-formatter.md) | depth16: 18 alloc + 16 realloc → 1 / 0; 1987 → 659 B | частота cached failures; end-to-end dial |
| CC-06: pool key | сделано: borrowed lookup | `14ee842` | [pool](perf208/reports/pool.md) | warm lookup 1 → 0 alloc; checkout + reserve 2 → 0; cold insert без изменений | живые spares, DNS, конкуренция |
| Cached resolve | сделано: индекс по identity | `14ee842` | [resolve](perf208/reports/resolve.md) | N=256, last/miss: 256 → 1/0 сравнений | несколько gate levels и exit groups |
| Полный weighted order при малом бюджете | сделано: внутренний lazy-план; публичный `pick_order` остался контрольным | `14ee842` | [weighted](perf208/reports/weighted.md) | N=256, первый кандидат: 1042 → 12 alloc, 2138 → 255 сравнений; полный drain: 2138 → 5018 сравнений | ускорение полного drain не заявляется |
| Raw credentials | снято: код `Credentials`, разбор Basic/UNAME и тесты `wire/*`, `credentials/*` удалены вместе с clear-text путями | `14ee842`, удаление — ветка `chore/remove-cleartext` | [credentials](perf208/reports/credentials.md) (историческая) | Basic retain 11 → 10 alloc; plain 8 → 7 (до удаления) | — |
| `mark_dead` и singleton при росте числа ротаторов | только счётчики, оптимизаций продукта нет | `14ee842` | [mark-dead](perf208/reports/mark-dead.md) | R=256, непересекающиеся: 0 сравнений против 32640 у eager-эталона | большие декартовы планы проверяются выборочно |
| Dial-путь: singleton route key, `ChainPick::config_arc`, borrowed `link_proxy`, общий hedge target | сделано | `736f709`, счётчики `d285826` | CI-baseline ниже | см. таблицу CI-baseline | hedge target проверен тестом, строк PERF208 нет |
| Прямой путь: порядок кандидатов по мере потребления | сделано: `ProxyRotator::pick_iter` | `e63c735` | CI-baseline ниже | 1 из 256: 2138 → 255 сравнений | ускорение полного drain не заявляется |
| `ProxyConfig::chain_arc` для ключей `ChainPlan`, `percent_decode` без копии | сделано | `014c500` | CI-baseline ниже | 1 узел: 6 → 0 alloc; 4 узла: 18 → 12 | `percent_decode` проверен тестами borrowed/owned, строк PERF208 нет |
| Снимок health в Arc | отклонено: холодный путь, риск в конкурентной зоне | — | — | — | — |
| Пароль как `Arc<str>` | отклонено: ломает `wipe_credentials` и zeroize | — | — | — | — |

## CI-baseline: CoW-этап (Linux, Rust 1.88)

Окружение: `ubuntu-24.04`, rustc/Cargo 1.88.0, target
`x86_64-unknown-linux-gnu`, allocator `std::alloc::System`, профиль `test`,
`RUSTFLAGS=-D warnings`, SDK с `zeroize,test-instrumentation`. Значения взяты
из artifact `perf208-counters` прогона на коммите `ac7eace`
([baseline/cow.json](perf208/baseline/cow.json)). Ячейка — «до → после».
«До» — дословные replica прежнего кода в самих тестах, «после» — текущий код.

<!-- perf208:cow:begin -->
| Сценарий | `alloc` | `realloc` | `requested_bytes` | `config_clones` | `sort_comparisons` |
|---|---:|---:|---:|---:|---:|
| singleton route key, gate-less node | 5 → 0 | 0 → 0 | 271 → 0 | 1 → 0 | 0 → 0 |
| singleton route key, gated node | 5 → 4 | 0 → 0 | 271 → 159 | 1 → 1 | 0 → 0 |
| ChainPick::config_arc, 1 hop | 4 → 0 | 0 → 0 | 159 → 0 | 1 → 0 | 0 → 0 |
| ChainPick::config_arc, 4 hops | 4 → 0 | 0 → 0 | 159 → 0 | 1 → 0 | 0 → 0 |
| ChainPick::config_arc, 16 hops | 4 → 0 | 0 → 0 | 159 → 0 | 1 → 0 | 0 → 0 |
| link_proxy, known address | 1 → 0 | 0 → 0 | 18 → 0 | 0 → 0 | 0 → 0 |
| link_proxy, new address | 5 → 4 | 0 → 0 | 1157 → 1140 | 0 → 0 | 0 → 0 |
| ProxyConfig::chain_arc, 1 node | 6 → 0 | 0 → 0 | 279 → 0 | 1 → 0 | 0 → 0 |
| ProxyConfig::chain_arc, 4 nodes | 18 → 12 | 0 → 0 | 780 → 477 | 4 → 3 | 0 → 0 |
| direct order, 1 of 256 consumed | 1032 → 1032 | 0 → 0 | 131650 → 131650 | 0 → 0 | 2138 → 255 |
<!-- perf208:cow:end -->

Блок между маркерами генерирует `tests/perf208/render.py`; руками его не
правят. Workflow `perf.yml` вызывает `render.py check`: он сравнивает блок с
`baseline/cow.json` и сохранённые значения со свежими строками `PERF208`. Если
счётчики изменились намеренно, обновить оба места командой
`python -I tests/perf208/render.py update --counters <каталог counters из artifact>`.

## Измерительная граница

Закрытый модуль `perf` подключается в каждом unit-test binary только при
`cfg(all(test, feature = "test-instrumentation"))`. Публичные SDK-типы,
сигнатуры и traits не изменяются. Обычная сборка, даже с этой фичей,
не включает allocator или счётчики #208. Приложение имеет одноимённую фичу,
передающую её SDK.

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
- `config_clones`: явно отмеченные вызовы клонирования в `singleton_key`
  (его использует `mark_dead`), `ChainKey::singleton`, циклах
  `ProxyConfig::chain` и `ProxyConfig::chain_arc`, `ChainPick::config`; не все
  Clone в процессе;
- `chain_builds`, `chain_nodes`, `hash_nodes`, `resolve_comparisons`,
  `weighted_keys`, `sort_comparisons`, `gate_formats` и счётчики singleton/
  `mark_dead`: выполненные операции в соответствующих production-компонентах.
  `pick_order_calls` считает и `pick_order`, и `pick_iter`.

Счётчики не выделяют память. Allocator использует непаникующий доступ к TLS
при завершении потока. Тест калибровки проверяет пустой scope, известную
аллокацию, освобождение, realloc и восстановление после panic; отдельный тест —
изоляцию маркера операций между потоками. Это не доказательство отсутствия
аллокаций внутри платформенного ожидания `Barrier`. Сообщение panic
`scope cleanup` в калибровке перехватывается `catch_unwind` и не является
падением теста.

Сценарии проверяют свойства результатов: permutation, identity, исключение
мёртвого узла, capacity, сохранение credentials. Они не заменяют
функциональные и конкурентные тесты.

## Историческое локальное A/B (Windows, Rust 1.97, до `14ee842`)

Окружение: rustc/Cargo 1.97.0, target `x86_64-pc-windows-msvc`, allocator
`System`, профиль `test` с `opt-level=0`, `RUSTFLAGS=-D warnings`, incremental
отключён. Параметры и dependency artifact graphs до и после совпали (89
артефактов SDK, 129 приложения), `Cargo.lock` не менялся. Базовая ревизия
`4fc5968`. Полные пары счётчиков и fingerprints — в
[PERF208-RESULTS.json](PERF208-RESULTS.json). Эти цифры нельзя смешивать с
Linux/Rust 1.88 baseline.

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

`mark_dead` выполняет один отмеченный Clone вместо двух. `pick.config()` не
строит цепочку повторно: один Clone корневого узла вместо 1/4/16
клонирований и нового связывания; неизменяемые gates разделяются через
существующие Arc. Изменения возвращённого корня и `Arc::make_mut` gate не
изменяют сохранённый ключ.

Hash сохраняет прежнюю последовательность хешируемых значений. Для цепочек
до `MAX_CHAIN_NODES=64` используется стековый буфер из 64 ссылок — 512 байт на
этом target. Это обмен heap allocations на ограниченный stack footprint;
снижение CPU cost не доказано. Более длинные невалидированные цепочки не
отвергаются и используют прежнюю Vec-ветку. Границы 64/65 и глубина 128
проверены сравнением с прежним потоком байтов Hasher.

У tunnel counters сохранены все три атомарных поля, их Ordering и совместное
время жизни, но теперь они находятся в одной Arc allocation. Изменение
cache-line/contention поведения под конкуренцией не измерялось. У report
проверены комбинации категорий и warning-only случай; текст логов сохранён.

Gate label строится только внутри принятого Logger closure, один раз для
конкретного результата, а не заранее и повторно при cached failure. Алгоритм
formatter и текст логов не менялись; при выключенной категории и заполненной
очереди число gate formats и аллокаций равно нулю. Строки
`gate_label/depth=*` одинаковы в A/B намеренно: это цена formatter, а не
частота его вызова.

## Воспроизводимость и CI

Workflow `.github/workflows/perf.yml` запускает только тесты с фильтром
`perf208_`, последовательно. Это небольшой конечный набор компонентных тестов,
не нагрузочный benchmark. Внешние подключения, реальные proxy, sleeps и
измерение latency не нужны.

Фиксированные параметры CI:

- rustc/Cargo 1.88.0;
- target `x86_64-unknown-linux-gnu`;
- allocator wrapper над `std::alloc::System`;
- профиль `test`, `RUSTFLAGS=-D warnings`, incremental отключён;
- SDK с defaults и `zeroize,test-instrumentation`, как в обычной сборке
  приложения; в частности, сохраняются размеры конфигураций с TLS/secure-auth;
- приложение с обычными dependency defaults и `test-instrumentation`;
- `--locked`, неизменённый `Cargo.lock`, один test thread;
- синтетические credentials и endpoints `.invalid`.

Окружение GitHub runner не является immutable image: `ubuntu-24.04`
обновляется. Поэтому artifact сохраняет `ImageVersion`, kernel, glibc,
полные `rustc -Vv`, `cargo -V`, RUSTFLAGS, target, revision, SHA-256 lock-файла,
сам lock-файл и feature trees обоих прогонов. Для строгого A/B принимаются
только результаты с одинаковым fingerprint окружения и графом фич. При
расхождении требуется повтор baseline в том же окружении; сравнивать числа
как будто окружение одинаково нельзя. Commit SHA при A/B различается ожидаемо,
но указывается у каждого результата.

Workflow сохраняет исходный вывод `PERF208` в artifact `perf208-counters`.
Ожидаемое число строк задано в `EXPECTED_ROWS` файла `tests/perf208/run.py`
(сейчас 199 строк SDK и 24 приложения); проверка защищает от пустого или
случайно суженного фильтра. Runner проверяет exit code каждого бинарника и
непустой успешный libtest summary, включая дополнительные функциональные
фильтры. Upload с `always()` сохраняет доступные свидетельства ошибки; наличие
artifact само по себе не означает успешный прогон.

### Общий лимит выполнения — 15 секунд

Компиляция вынесена в отдельные вызовы `cargo test --no-run`. Затем
`tests/perf208/run.py` извлекает точные пути бинарников из Cargo JSON и
запускает их напрямую, без Cargo/shell между runner и тестом. Оба прогона
делят один monotonic deadline на 15 секунд, а не получают по 15 секунд каждый.
Ожидание дочернего процесса ограничено остатком бюджета; при timeout runner
завершает только свой test executable и сохраняет частичный вывод со статусом
`accepted: false`. Продолжать измерения после deadline нельзя.

Создание fixtures, assertions и печать результатов входят в бюджет выполнения.
Компиляция, подготовка окружения и проверка mock-runner — нет. Дополнительные
функциональные фильтры `--check sdk:filter` и `--check app:filter` используют
тот же оставшийся бюджет. Пустой фильтр, ненулевой exit code, неполное число
PERF208-строк и превышение deadline отклоняют весь результат. Каталог
результата создаётся заново, чтобы прежний успешный статус не маскировал
ошибку нового прогона.

Команды CI:

```sh
cargo test --locked -p resocks5-net --lib --target x86_64-unknown-linux-gnu --features zeroize,test-instrumentation --no-run --message-format=json > perf-results/sdk-build.json
cargo test --locked -p resocks5 --bin resocks5 --target x86_64-unknown-linux-gnu --features test-instrumentation --no-run --message-format=json > perf-results/app-build.json
python -I tests/perf208/run.py --sdk perf-results/sdk-build.json --app perf-results/app-build.json --output perf-results/counters
python -I tests/perf208/render.py check --counters perf-results/counters
```

Абсолютные времена общего runner не являются acceptance criterion.
Instrumentation меняет стоимость операций, поэтому её timings нельзя
выдавать за production performance. Число сравнений зависит от реализации
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
6. Новые строки добавлять в `EXPECTED_ROWS`; значения для сводной таблицы —
   в `baseline/cow.json` (или новый файл того же формата) и обновлять через
   `render.py update`.
