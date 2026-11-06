# #208, этап pool lookup — borrowed-ключи на горячем поиске

## Статус

Горячий lookup в `ProxyPool` больше не строит временный owning-ключ
`(String, u16)`. Три горячих чтения — `upstream_semaphore`,
`reserve_permit`, `checkout_prewarmed` — идут через borrowed-форму
ключа; вставки сохраняют owning-ключ. Счётчики A/B получены локально
в этом worktree; timing, latency и throughput не измерялись и не
заявляются. Историческое свидетельство предыдущего этапа
([PERF208.md](../../PERF208.md), [PERF208-RESULTS.json](../../PERF208-RESULTS.json))
не менялось; цифры этого этапа собраны в этом файле.

## Механизм

Ключи трёх коллекций пула — `type ProxyKey = (String, u16)`. `std`
реализует `Borrow<str> for String`, но borrowed-формы кортежа нет,
поэтому каждый `get` требовал сначала построить owning-ключ — одну
аллокацию `host`-строки. В модуле введён закрытый trait
`ProxyEndpoint` с реализациями для `ProxyKey` и `(&str, u16)`, ручные
`Hash`/`PartialEq`/`Eq` для `dyn ProxyEndpoint` и
`impl<'a> Borrow<dyn ProxyEndpoint + 'a> for ProxyKey`. `DashMap::get`
принимает `Q: Hash + Eq + ?Sized`, поэтому lookup получает
`&dyn ProxyEndpoint`, собранный на стеке из `&str`/`u16`. Хеш и
равенство читают те же поля в том же порядке, что и производные impls
кортежа, — контракт `Borrow` соблюдён, результат поиска не меняется.

Прямая передача `&(&str, u16)` в `get` не компилируется: вывод
выбирает `Q = (&str, u16)` и требует несуществующий
`(String, u16): Borrow<(&str, u16)>`. На местах вызова добавлена
явная привязка `let key: &dyn ProxyEndpoint = ...`, задающая unsized
coercion; временное значение ключа живёт в рамках оператора вызова.

Без изменений остались: тип ключа `(host, port)`, путь вставки
(`entry` с owning-ключом, race-safe insert под тем же комментарием),
`forget`/`spawn_refill_for` (холодные пути с owning-ключами), порядок
блокировок `refill_tasks` → `pools`/`upstream_caps`, выдача,
удержание и освобождение permits, refill/drop, семантика credentials
(ключ пула их не содержит). Новых зависимостей, unsafe и публичной
поверхности нет: trait и impls приватны для модуля пула;
`test-instrumentation`-инструментация в production не попадает.

## A/B: фактические счётчики

Окружение идентично локальному A/B из PERF208.md: rustc/Cargo 1.97.0,
host target `x86_64-pc-windows-msvc`, allocator `std::alloc::System`,
профиль `test` (`opt-level=0`), `RUSTFLAGS=-D warnings`,
`CARGO_INCREMENTAL=0`, `--locked`. SDK: defaults +
`zeroize,test-instrumentation`; приложение: обычные defaults +
`test-instrumentation`. Графы артефактов A/B совпали между собой и с
предыдущим этапом: 89 SDK / 129 приложение. Blob `Cargo.lock` не
изменён: `21b918f3b72c33829d5f4cde306cff5ae1da3095`. A/B — два
состояния одного незакоммиченного рабочего дерева (baseline снят до
правки, после — после правки), не два Git-коммита.

Сценарий CC-06 (`perf208_pool_reservation_cold_warm_and_capacity`),
SDK binary, test profile, Windows:

| Сценарий | До: alloc / realloc | После: alloc / realloc | Запрошено байт: до → после |
|---|---:|---:|---:|
| `pool/reserve/cold` (первый reserve: semaphore создаётся) | 3 / 0 | 3 / 0 | 251 → 251 |
| `pool/reserve/warm` | 1 / 0 | 0 / 0 | 15 → 0 |
| `pool/reserve/capacity` | 3 / 0 | 1 / 0 | 45 → 15 |
| `pool/checkout/empty` | 1 / 0 | 0 / 0 | 15 → 0 |
| `pool/checkout_then_reserve/warm` | 2 / 0 | 0 / 0 | 30 → 0 |

Каждая устранённая аллокация — 15 байт, `len("proxy-0.invalid")`:
`host`-строка временного owning-ключа. Warm reserve — 1→0; empty
checkout + reserve — 2→0: локальный baseline воспроизвёл цифры
предыдущего этапа (1 и 2 аллокации) до правки. Холодный путь не стал
«дешевле» и не должен: первый reserve по-прежнему строит owning-ключ
для `entry` и создаёт semaphore — 3 аллокации, 251 байт, без
изменений. Отказ по capacity остался видимым: 15 байт — это
`host.clone()` внутри `AtCapacity`, контракт ошибки, а не lookup;
две lookup-аллокации из 45 байт исчезли.

Остальные 43 строки счётчиков — 35 non-pool строк SDK (mark_dead,
chain_hash, pick, resolve, weighted_order, credentials) и все 8 строк
приложения (gate_label, tunnel, logger) — побайтово совпали с
baseline; из пяти pool-строк не изменилась и `pool/reserve/cold`.
Экономия не оплачена переносом аллокаций в другие компоненты.
Повторный warm reserve детерминирован: встроенная проверка
`warm_counts == repeated` прошла во всех прогонах.

## Проверки и команды

Компиляция отдельно от бюджета измерений (локально, host target):

```sh
RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
cargo test --locked -j 2 -p resocks5-net --lib \
  --features zeroize,test-instrumentation --no-run --message-format=json \
  > perf-results/sdk-baseline-build.json
RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
cargo test --locked -j 2 -p resocks5 --bin resocks5 \
  --features test-instrumentation --no-run --message-format=json \
  > perf-results/app-baseline-build.json
```

После правки — те же команды; финальные артефакты сборки —
`sdk-fix-build.json` / `app-fix-build.json`. Прогон — runner с общим лимитом 15 секунд:

```sh
python -I tests/perf208/run.py \
  --sdk perf-results/sdk-baseline-build.json \
  --app perf-results/app-baseline-build.json \
  --output perf-results/baseline-counters
python -I tests/perf208/run.py \
  --sdk perf-results/sdk-fix-build.json \
  --app perf-results/app-fix-build.json \
  --output perf-results/fix-counters \
  --check sdk:pool::
```

- Baseline: `accepted: true`, elapsed 0,047 с (счётчики SDK и
  приложения). Совпало с baseline предыдущего этапа (0,047 с).
- Финальный прогон: `accepted: true`, elapsed 7,844 с — те же
  счётчики плюс функциональный фильтр `sdk:pool::`: 39 тестов,
  0 провалов, из них 26 тестов `pool::proxy_pool` (21 функциональных,
  2 lifecycle-гонки и 3 прямые проверки контракта borrowed-ключа:
  поток Hasher, eq, lookup с hostname/UTF-8/IPv6/пустым host и
  граничными портами) и 13 интеграционных `connect::dial::chain_pool` (reserve_permit, AtCapacity и освобождение slots через
  реальные dial-пути). На фильтр ушло 7,78 с из общего бюджета.

`tests/perf208/run.py`, `perf_cases.rs` и `.github/workflows/perf.yml`
не менялись: набор измерительных строк прежний (40 SDK + 8 приложение),
EXPECTED_ROWS runner не требует правки — сценарий CC-06 уже покрывал
все изменённые пути. Один транзиентный отказ sccache при первой
сборке приложения (os error 10054) после повторной попытки прошёл;
на счётчики влияние исключено (compile-level кэш). Файлы прогонов
сохранены в `perf-results/` внутри worktree (build JSON, stdout
бинарников, `status.json`); каталог не в `.gitignore` и оставлен
основному исполнителю на усмотрение.

## Ограничения и риски

- Заявлена только экономия аллокаций. Замена аллокации на
  виртуальные вызовы hash/eq CPU-бенчмарком не покрывалась; timings
  инструментированной сборки нельзя считать production
  производительностью (PERF208.md).
- Checkout с непустой очередью требует реального входящего сокета и
  счётчиками не покрывается; его путь `pools.get` идентичен
  `checkout/empty`, функционально он покрыт тестами
  `acquire_hands_out_a_healthy_spare...` и `guarded_checkout...`.
- Локальные Windows/Rust1.97 числа нельзя смешивать с будущим
  Linux/Rust1.88 CI baseline; CI workflow не менялся и продолжит
  гнать прежний набор строк.
- Контракт `Borrow` держится на порядке полей в ручных
  `Hash`/`PartialEq` impls (`host`, затем `port`); консистентность
  owning и borrowed представлений покрыта прямыми тестами
  `pool::proxy_pool::key_tests` (поток Hasher, eq, lookup) и всеми
  функциональными тестами, где owning-вставка находится
  borrowed-lookup'ом.

## Личная проверка основного исполнителя

Повторная сборка обоих test binaries выполнена самостоятельно с `--locked`,
`-D warnings`, `CARGO_INCREMENTAL=0`, максимум двумя jobs и отключённой
compile-wrapper. Runner принят: **97 выполнений тестов, 0 провалов, 7,750 с**
при общем deadline15 секунд. Помимо 39 pool-регрессий проверены chain identity,
selection/accounting, tunnel logging и Logger. Все 48 пар счётчиков и
совпавшие графы 89/129 артефактов сохранены в
[results/pool.json](../results/pool.json). Неизменённые non-pool строки
совпали с собственным baseline основного исполнителя.
