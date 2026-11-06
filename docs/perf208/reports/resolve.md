# #208, этап indexed cached resolve — hash+bucket вместо линейного скана

## Статус

`GateLevels::resolve` при cached-цепочках больше не сканирует
`rotator.all_proxies()` линейно: поиск узла идёт через один hash по
identity-полям и один probe construction-time индекса
`by_identity: HashMap<u64, Vec<usize>>`. Счётчики A/B получены локально
в этом worktree; timing, latency и throughput не измерялись и не
заявляются. Историческое свидетельство предыдущего этапа
([PERF208.md](../../PERF208.md),
[results/pool.json](../results/pool.json)) не менялось; цифры этого
этапа собраны в этом файле и в
[results/resolve.json](../results/resolve.json).

## Механизм

Раньше каждый узел искался через
`rotator.all_proxies().iter().find(|c| same_node(c, node))` — при N
апстримах до N сравнений на узел (измеренный baseline last/miss при
N=256 — 256 сравнений). Теперь resolve вызывает новый
`pub(crate) ProxyRotator::resolve_identity`
(`crates/resocks5-net/src/session/rotator/mod.rs`): один hash шести
identity-полей (`upstream_hash`, без аллокаций) + один probe индекса +
скан bucket со сравнением полей `same_upstream`.

Hash-совпадение — только отбор кандидатов: identity доказывается
сравнением полей, поэтому коллизии разрешаются корректно
(принудительный collision-тест это закрепляет). Индекс уже строился при
конструкции ротатора для `index_of` — новая стоимость построения равна
нулю, `index_of` не тронут. Функция `same_node` из chain удалена: её
шесть полей — те же шесть полей `same_upstream` (protocol, host, port,
user, password, gate_level); поле `gate` (LINK) в identity не входит —
реальный cached-composite из sticky cache матчится с plain-прокси.
Порядок bucket = порядок слотов ротатора → возвращается тот же первый
слот, что при линейном поиске; для exits — первый содержащий ротатор
среза (routing-group owner) сохранён; gate rank проверяется до lookup;
длина/порядок цепочки, missing behavior, построение hops/ChainKey не
менялись. Публичный API, deps, unsafe, версии, Cargo-файлы — без
изменений. Счётчик `resolve_comparisons` перенесён на реальные
сравнения bucket нового пути, а не на обход instrumentation.

## A/B: фактические счётчики

Окружение идентично этапу pool: rustc/Cargo 1.97.0, host target
`x86_64-pc-windows-msvc`, allocator `std::alloc::System`, профиль
`test` (`opt-level=0`), `RUSTFLAGS=-D warnings`,
`CARGO_INCREMENTAL=0`, `--locked`, максимум 2 jobs. SDK: defaults +
`zeroize,test-instrumentation`; приложение: обычные defaults +
`test-instrumentation`. Blob `Cargo.lock` не изменён:
`21b918f3b72c33829d5f4cde306cff5ae1da3095`. A/B — два состояния одного
незакоммиченного рабочего дерева на базе 4fc5968 (baseline снят до
правки), не два Git-коммита. Фича-деревья захешированы: SDK
`a58705aa…daa67`, app `f513cdea…c4714` (полные sha256 в JSON).

SDK binary, test profile, Windows; изменился только
`resolve_comparisons` (alloc/realloc/requested_bytes/config_clones/
chain_builds/chain_nodes всех строк побайтово совпали):

| Строка | resolve_comparisons до → после |
|---|---:|
| `resolve/first/n={1,8,64,256}` | 1 → 1 (побайтово без изменений) |
| `resolve/last/n=8` | 8 → 1 |
| `resolve/last/n=64` | 64 → 1 |
| `resolve/last/n=256` | 256 → 1 |
| `resolve/miss/n=1` | 1 → 0 |
| `resolve/miss/n=8` | 8 → 0 |
| `resolve/miss/n=64` | 64 → 0 |
| `resolve/miss/n=256` | 256 → 0 |

Побайтовая сверка всех 48 пар baseline-строк: 41 строка идентична
(включая все 8 app-строк и 5 pool-строк), 7 строк выше изменились
только в `resolve_comparisons`, OTHER_CHANGED = 0, GONE = 0. Экономия
не оплачена переносом стоимости: все остальные поля каждой строки побайтово совпали с baseline (у hit-строк resolve requested_bytes 319–321 в зависимости от N, у miss — 2 alloc / 48 байт).

## Новые строки и проверки

Честное расширение набора: EXPECTED_ROWS sdk 40 → 44 в
`tests/perf208/run.py` (app 8 без изменений).

- `resolve/gates2_owner=first`: 3 сравнения (bucket 1+1+1); owner
  подтверждён `Arc::ptr_eq` первого exit-ротатора;
- `resolve/gates2_owner=second`: 3 (1+1+0+1 — bucket первого
  exit-ротатора пуст: 0 сравнений), owner — второй;
- `resolve/exit/cached_gate_composite`: 3 (1+1+1) — exit-узел несёт
  gate-ссылку (LINK, реальная форма sticky-cache записи), identity её
  игнорирует;
- `resolve/collision/bucket=2`: 2 сравнения, 0 аллокаций —
  принудительная коллизия (мутацией `by_identity` собран bucket
  [чужой, свой]; путь досканировал bucket и вернул свой слот;
  hash-совпадение не является доказательством identity).

Также функционально проверено: неверный gate rank → None с 0 сравнений
(отсечка до lookup); неверный пароль exit-узла → None (сравнения только
gate-уровней, exit-hash bucket'и пусты). Оракул в perf-тестах —
`identity_scan_expectation`: позиция совпавшего слота в bucket (hit) или
длина bucket (miss); корректен для произвольных коллизий и раннего
совпадения, без предположения об их отсутствии. Принудительные fixture
в rotator-тестах закрепляют target в начале/середине/конце bucket из
трёх слотов и miss при непустом bucket: результат и фактическое число
сравнений (1/2/3 и длина bucket).

## Проверки и команды

Компиляция отдельно от бюджета измерений (baseline — холодная сборка,
fix — инкрементальная; binary пересобран после исправления оракула):

```sh
RUSTC_WRAPPER= RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
cargo test --locked -j 2 -p resocks5-net --lib \
  --features zeroize,test-instrumentation --no-run --message-format=json \
  > perf-results/resolve/sdk-baseline-build.json
RUSTC_WRAPPER= RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
cargo test --locked -j 2 -p resocks5 --bin resocks5 \
  --features test-instrumentation --no-run --message-format=json \
  > perf-results/resolve/app-baseline-build.json
python -I tests/perf208/run.py \
  --sdk perf-results/resolve/sdk-baseline-build.json \
  --app perf-results/resolve/app-baseline-build.json \
  --output perf-results/resolve/baseline-counters
python -I tests/perf208/run.py \
  --sdk perf-results/resolve/sdk-fix-build.json \
  --app perf-results/resolve/app-fix-build.json \
  --output perf-results/resolve/fix-counters \
  --check sdk:chain:: --check sdk:rotator::
```

- Baseline: `accepted: true`, elapsed 0,047 с — те же 40 строк, что у
  принятого pool-этапа.
- Fix: `accepted: true`, elapsed 9,484 с при общем deadline 15 с:
  44 SDK-строки (13 perf-тестов SDK, 0 провалов) + 8 app-строк (7
  тестов); фильтр `sdk:chain::` — 45 тестов, 0 провалов (5,19 с);
  фильтр `sdk:rotator::` — 67 тестов, 0 провалов (4,24 с).
- Сравнивать elapsed 0,047 (без фильтров) и 9,484 (с двумя фильтрами, 132 теста: 13 SDK + 7 app + 45 chain + 67
rotator) нельзя — наборы проверок различаются; оба числа
  подтверждают соблюдение лимита, а не ускорение.
- `python -I -B tests/perf208/test_run.py` (mock-тесты deadline runner)
  — прошёл.

## Ограничения и риски

- Заявлена только экономия сравнений candidate resolve и неизменность
  аллокаций/остальных счётчиков; timing, latency и throughput не
  измерялись и не заявляются.
- Стоимость нового пути вне счётчика сравнений: один hash шести полей +
  один probe HashMap — CPU-стоимость hash-вычисления и probe счётчиком
  `resolve_comparisons` не отражается (это не candidate comparison);
  аллокаций нет (строки побайтово идентичны).
- miss = 0 означает пустой bucket — отсутствие кандидатов с совпавшим
  hash, а не обход счётчика: при непустом bucket счётчик равен числу
  просмотренных слотов (fixture начала/середины/конца и miss при
  непустом bucket). Тесты не зависят от отсутствия коллизий и по-прежнему
  ловят возврат линейного скана (miss-ожидание 0 против N) и обход hook.
- Принудительная коллизия сделана мутацией `by_identity` из unit-теста
  (child-модуль) — детерминированная симуляция состояния, которое
  реально может дать `HashMap<u64,_>`; реальные SipHash-коллизии не
  форсились.
- Замена линейного скана на hash+probe+bucket — обмен O(N) сравнений на
  O(1) hash/probe; влияние на CPU под нагрузкой не бенчмарчилось, как и
  в предыдущих этапах.
- Локальные Windows/Rust1.97 числа нельзя смешивать с Linux/Rust1.88 CI
  baseline; `.github/workflows/perf.yml` не менялся (число строк
  проверяет `run.py`, workflow лишь вызывает его; ожидается 44 SDK +
  8 app).
- Существующие функциональные тесты не ослаблялись; baseline-утверждения
  `perf208_cached_resolve_first_last_and_miss` обновлены с объяснением
  устранённого механизма (правило 4 PERF208.md).

## Личная проверка основного исполнителя

Оба test binaries пересобраны независимо с прежними фичами/профилем и
`--locked`, максимум двумя jobs. Runner принят: **155 выполнений тестов,
0 провалов, 9,516 с из общего deadline15 секунд**. Проверены chain, rotator,
chain identity, tunnel logging и Logger. В 48 общих строках изменились
только 7 значений resolve_comparisons; остальные поля и 41 строка совпали.
Добавлены 4 отдельные строки. Полные 52 измерения и совпавшие dependency
artifact graphs 89/129 записаны в results/resolve.json. Найденные rustfmt
расхождения устранены форматтером; повторные rustfmt check и diff check прошли.
