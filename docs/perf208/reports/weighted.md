# #208, этап weighted — bounded/lazy выбор при малом потреблении

## Статус

Внутренний (публичный SDK API не расширялся) ленивый путь взвешенного
выбора: снимок выборки формируется как прежде (eligibility + все N ключей +
все N значений RNG под одним взятием mutex, в прежний момент), а
сортировка/материализация кандидатов происходят по мере фактического
потребления (advance одометра отложен). Публичные `Ratings::pick_order`,
`ProxyRotator::pick_order`, `weighted_order` и их полный результат остались
контрольным полным порядком. По итогам ТРЁХ раундов родительской проверки
этап дополнен: фиче-гейтингом, production-free ZST-наблюдателем,
восстановленным allow на 10-аргументном API, дословным legacy-референсом,
устранением look-ahead, реальными рангами multi-layer fixtures и
консервативным ВНУТРЕННИМ eager fast path вырожденных слоёв с не более
чем двумя курсорами — измеренная регрессия singleton-планов (N=1: 22 alloc/1510 B против legacy
15/778 B в состоянии fix-counters-5) устранена: теперь 11 alloc/599 B —
не хуже legacy по alloc/realloc/requested_bytes. Все числа этого файла —
из авторитетного прогона `fix-counters-6` (accepted, 7.672s). Исторические
отчёты и результаты предыдущих этапов не менялись.

## Feature-gating (блокер первого раунда, устранён)

`cargo check --no-default-features --features rating` падал по dead_code:
ленивый слой rating имеет production-потребителя только через `rotator`.
Исправление — гейтинг по `cfg(feature = "rotator")` на
`LazyOrder`/`OrderSnapshot`/`pick_order_lazy*`; test-only методы и тесты —
`cfg(all(test, feature = "rotator"))`; без allow/expect(dead_code),
pub-подъёмов и изменения фич. Повторено родителем (exit0) и лично:
check-формы rating / rotator / rating,rotator — exit 0; test-only
rating-only сборка — exit 0; полная test-сборка — chain::/rating::/rotator::
зелёные.

## Production-free app-наблюдатель построения плана

Наблюдатель — трейт со статической диспетчеризацией (dial.rs:19-42):
`trait PlanBuildRecorder { fn record(&mut self, gate_levels: usize,
exit_rotators: usize); }`; production-обёртка `establish_connection`
(сигнатура прежняя) создаёт `NoopPlanBuildRecorder` — ZST без полей, тело
`record` пустое: пустая функция не может аллоцировать — гарантия
конструктивная, не LTO/DCE. Тестовый наблюдатель — `PlanBuildTrace =
Vec<(usize, usize)>` с impl-трейтом; `establish_connection_traced<R:
PlanBuildRecorder>` (generic, не dyn) пишет на обоих сайтах построения
(пустой план — `(0, 0)`). Тест `noop_plan_build_recorder_is_zero_sized`
закрепляет `size_of == 0`. SDK API не менялся; смысл `pick_order_calls()`
прежний (только полный `pick_order`, rotator/mod.rs:689). Отрицательные
контролы (budget / cache-hit / foreign-quarantine / budget=1: в trace нет
`(g>0)` или trace пуст) и позитивный (`owning_exit_copy…`: `trace ==
[(1, 2)]`) сохранены. Комментарии seam/тестов — по-русски.

## Clippy

`cargo clippy --locked -j2 -p resocks5 --bin resocks5 --features
test-instrumentation -- -D warnings` — exit 0 (повторено лично дважды,
последний раз на финальном дереве): `allow(clippy::too_many_arguments)`
возвращён на 10-аргументный `pub establish_connection`; попутный
`clippy::box_collection` на промежуточном `Option<Box<HashSet>>` устранён
(`Option<HashSet>` — None и так не аллоцирует).

## Механизм

1. `select.rs`: `LazyOrder` — курсор точного порядка `order_keys`;
   расширение префикса геометрическое (`select_nth_unstable_by` + локальный
   `sort_unstable_by`), при `остаток <= 8·step` пул досортировывается
   целиком. Полное исчерпание — O(N log N). Общий компаратор
   `compare_keyed` для обоих путей, каждый вызов — в `sort_comparisons`.
2. `rating/mod.rs`: единый `eligible_and_keyed` под lock (объём под mutex
   прежний: eligibility + N ключей + N значений RNG); `OrderSnapshot`
   отдаёт данные через `into_parts` — без копий; публичный `pick_order` —
   на `order_keys`.
3. `rotator/mod.rs`: `LazyCandidates` — Arc-клон прокси по потреблению;
   eligible передаётся перемещением.
4. `chain/mod.rs`: слои из ленивых курсоров (production-wiring: `ChainPlan::new`
   зовётся dial'ом); отложенный advance (`need_advance`, рус. комментарий)
   — потребление k → материализация ровно k; два режима слоя:
   - **lazy** (хотя бы один ротатор слоя имеет >1 eligible): курсоры,
     кандидаты по требованию, dedup через ленивую таблицу
     `emitted: Option<HashSet<ChainKey>>` (None не аллоцирует),
     mark_dead по eligible-снимкам;
   - **eager** (все ротаторы слоя ≤1 eligible — упорядочивать нечего):
     курсоры не создаются, кандидаты материализованы при construction в
     порядке ротаторов, dedup — линейным сканом `same_upstream`
     (меж-ротаторные дубликаты возможны и здесь), mark_dead — прежний скан
     по ключам (candidates уникальны по идентичности ⇒ один decrement на
     слой); `pull` естественно Err (курсоров нет).
   `live`: single-rotator слой — `eligible.len()` (инвариант: ротатор
   дедуплицирует при construction по `same_upstream`, doc «One rating slot
   per unique identity»); multi-rotator — `distinct_identities` (бакеты по
   `upstream_hash`, коллизии — `same_upstream`). `mark_dead` —
   `rotator.index_of` + `eligible.contains` для lazy-слоёв. `singleton_key_arc`
   для узлов без gate-ссылки заимствует Arc без клона конфига; при наличии
   gate-ссылки — прежний клон со снятием gate (fallback, корректность при
   нарушении допущения сохранена). Тяжёлый клон — один на обработанную
   позицию и один на вызов `mark_dead` (в `plan.dead`).

Snapshot-семантика закреплена тестами (quarantine-заморозка, идентичное
продвижение RNG, удержание снимка до drop курсора/плана).

## Граница охвата (честно)

App direct-путь и `probes::healthy_prefix` остались на полном контрольном
пути (покрытие требовало бы расширения публичного SDK API). Покрыт
внутренний planner-путь SDK (ChainPlan).

## Отрицательные/позитивные app-оракулы и fast-path семантика

PlanBuildTrace-оракулы (см. выше) сохранены. Добавлен SDK-оракул
`singleton_plan_semantics_and_no_extra_materialization` (chain/lazy_oracle_tests.rs):
singleton-план (gates 2/1/0 по 1 узлу) — обход == декартову произведению
twin-эталонов, владельцы/ranks [2,1,0]; пустые планы; mark_dead до/после
первого next(); повторный next() после исчерпания — None, при этом
`measure` вокруг него даёт нули по всем счётчикам (лишней материализации
нет); construction singleton-плана — chain_builds/config_clones/
sort_comparisons == 0; exclude.

## Total-cost A/B: дословный legacy-референс

`LegacyChainPlan` в perf_cases.rs — дословная реплика baseline `ChainPlan`
(`Layer{candidates: Vec<Candidate>, live, index}` + `Vec<Layer>`,
`current_pick` строит `Vec<Hop>` с клоном ОБЕИХ Arc на каждый pick,
немедленный advance, холостые `dead/seen.contains`, `ProxyConfig::chain` +
`ChainKey::new` на каждый pick; pick создаётся и уничтожается в
потребителе), поверх публичного SDK API, на тех же fixture (свежие
ротаторы, двойной прогон — равенство picks и Counts). Поля, читавшиеся в
baseline только через непереносимые методы (`record_success`/`mark_dead`/
`hops()`/`exit()` — не измеряются), помечены точечными allow(dead_code) с
русскими комментариями; стоимость их клонов в `current_pick` сохранена.

Авторитетные пары (`fix-counters-6`; alloc/realloc, requested_bytes,
config_clones, sort_comparisons; weighted_keys у обоих путей равен N):

| Сценарий | legacy | new | исход |
|---|---|---|---|
| exits-only N=1 (любое потребление) | 15/0, 778 B, 2 кл., 0 cmp | **11/0, 599 B, 1 кл., 0 cmp** | new не хуже (меньше) |
| exits-only N=8 consumed=1 | 45/1, 2 499 B, 9 кл., 19 cmp | **12/0, 819 B, 1 кл., 19 cmp** | new лучше |
| exits-only N=8 full | 87/1, 4 508 B, 16 кл., 19 cmp | **56/1, 3 268 B, 8 кл., 19 cmp** | new лучше |
| exits-only N=64 consumed=1 | 272/4, 17 554 B, 65 кл., 387 cmp | **12/0, 2 164 B, 1 кл., 63 cmp** | new лучше |
| exits-only N=64 full | 650/4, 35 688 B, 128 кл., 387 cmp | **395/4, 25 490 B, 64 кл., 686 cmp** | alloc/байты/клоны лучше, сравнений больше |
| exits-only N=256 consumed=1 | 1042/6, 69 199 B, 257 кл., 2138 cmp | **12/0, 6 773 B, 1 кл., 255 cmp** | new лучше по всем полям |
| exits-only N=256 full | 2572/6, 142 784 B, 512 кл., 2138 cmp | **1549/6, 101 710 B, 256 кл., 5018 cmp** | alloc/байты/клоны лучше, сравнений больше |
| singleton gates 2/1/0, по 1 узлу | 39/1, 1 870 B, 6 кл., 0 cmp | **27/0, 1 573 B, 3 кл., 0 cmp** | new лучше по всем полям |
| gates2x16 consumed=1 | 228/7, 13 507 B, 51 кл., 187 cmp | **30/0, 2 809 B, 3 кл., 45 cmp** | new лучше |
| gates2x16 full | 57558/7, 2 626 630 B, 12 336 кл., 187 cmp | **57369/6, 2 619 316 B, 12 288 кл., 237 cmp** | ≈паритет, new чуть лучше |

Единственная остающаяся плата нового пути — число сравнений при полном
исчерпании (5018 vs 2138 на N=256 — константа геометрической перестройки,
класс O(N log N), не O(N²)); по alloc/realloc/байтам/клонам new теперь не
хуже legacy во всех измеренных парах, на вырожденных входах — строго лучше.
Ранние формулировки «не регрессия»/«на малых N регрессии нет» по
comparator-counts сняты как недостаточные — итог основан на полных
total-cost парах.

## История чисел (superseded, не скрывать)

- `fix-counters-4` (82 SDK): state до дословного legacy и до устранения
  look-ahead; все chain_plan-цифры superseded.
- `fix-counters-5` (90 SDK, accepted 7.718s): дословный legacy + отложенный
  advance, но БЕЗ устранения overhead machinery — singleton-регрессия
  измерена: N=1 new 22/1510 vs legacy 15/778; singleton_gates new 42/2566
  vs legacy 39/1870; chain_plan/n=256/c=1 284/53514. Эти числа SUPERSEDED
  фиксацией FIX-A–E + eager fast path (fix-counters-6); значения сохранены
  в weighted.json (`superseded_runs`).
- `fix-counters-6` (текущий, accepted 7.672s): авторитетный.

## A/B: фактические счётчики

Окружение: rustc/Cargo 1.97.0, x86_64-pc-windows-msvc, `std::alloc::System`,
профиль test, `RUSTFLAGS=-D warnings`, `CARGO_INCREMENTAL=0`, `--locked`,
максимум 2 jobs. Cargo.lock не изменён. Baseline — до правок этапа
(44 SDK + 24 app; контроль weighted_order/n=256 = 256/2112 совпал с
gate-formatter.json).

`fix-counters-6`: accepted, 7.672s из 15s — 90 SDK + 24 app строк; checks в
том же deadline: sdk:chain:: 52/0, sdk:lazy 16/0, app-оракулы budget/cache
1/0+1/0+2/0+1/0. Полная личная сверка родителя на окончательной версии:
все 68 прежних строк идентичны (включая `pick/depth=*`, full-sort контроль,
mark_dead, resolve, pool, credentials и все 24 app-строки), новых строк 46
(24 ленивых/контрольных + 14 legacy + 6 new N=1/8 + 2 singleton_gates),
пропавших строк нет. Схема Counts не расширялась.

Промежуточные значения `pick/depth=*` 6→12 / 18→42 / 66→162 и
config_clones 1→2 / 4→8 / 16→32 относились к состоянию до eager fast path
и больше не описывают итог. После вырожденного пути все три строки снова
равны baseline; прежняя ошибочная сводка сохранена в JSON как
`superseded_reported_ab_comparison`. Соседние `pick_config/depth=*`
также не изменились.

## Оракулы

- select.rs / rating / rotator: точность курсора против полных порядков
  (матрицы фиксированных seed), заморозка eligibility, идентичное
  продвижение RNG.
- chain/lazy_oracle_tests.rs (7): traversal против twin-эталонов;
  first-owner и порядок exit-групп; заморозка снапшота; mark_dead до/во
  время; исчерпание (steps==0); gate-link дубликаты; singleton
  fast-path-семантика с measure-нулями (см. выше).
- perf: `weighted_keys == N`; детерминизм; относительный контроль
  `lazy(consumed=1) < full`; legacy == rotator-контроль (2138==2138);
  chain full == произведение слоёв; strict no-regression asserts
  singleton_gates + N=1 (new <= legacy по alloc/realloc/bytes/cmp/clones).
- app: PlanBuildTrace — 4 отрицательных + 1 позитивный + ZST-тест.

## Проверки и команды

```sh
cargo check --locked -j 2 -p resocks5-net --lib \
  --no-default-features --features rating   # exit 0
cargo clippy --locked -j2 -p resocks5 --bin resocks5 \
  --features test-instrumentation -- -D warnings   # exit 0 (повторено лично)
cargo test --locked -j 2 -p resocks5-net --lib \
  --features zeroize,test-instrumentation --no-run --message-format=json \
  > target/perf-results/weighted/sdk-final4-build.json
cargo test --locked -j 2 -p resocks5 --bin resocks5 \
  --features test-instrumentation --no-run --message-format=json \
  > target/perf-results/weighted/app-final4-build.json
python -I tests/perf208/run.py \
  --sdk target/perf-results/weighted/sdk-final4-build.json \
  --app target/perf-results/weighted/app-final4-build.json \
  --output target/perf-results/weighted/fix-counters-6 \
  --check sdk:chain:: --check sdk:lazy \
  --check app:budget_exhausted_by_cache_failure \
  --check app:healthy_cached_chain \
  --check app:quarantined_foreign_exit_copy \
  --check app:owning_exit_copy
```

- `fix-counters-6`: accepted, 7.672s — 90 SDK + 24 app строк, все checks
  зелёные. `fix-counters-4`/`-5` superseded (см. «История чисел»).
- НЕ выбранные checks (обозначено): sdk:rating:: (94), sdk:rotator:: (68),
  app:tests_chain_failures (2), остальные тесты tests_unit/tests_quarantine
  — зелёные отдельными прогонами этого хода.
- run.py: EXPECTED_ROWS sdk 68 → 82 → 88 → 90 (этапные расширения);
  остальной runner не менялся; `.github/workflows/perf.yml` не менялся.
- rustfmt --edition 2021 --check по всем 10 изменённым файлам — чисто.

## Ограничения и риски

- Заявлена только экономия счётчиков; timing/latency/throughput не
  измерялись.
- Полное исчерпание: сравнений больше у ленивого пути (5018 vs 2138 на
  N=256) — константа, класс O(N log N); полный публичный путь — контроль.
- Порог досортировки `8·step` и триггер eager-слоя (`все ротаторы ≤1
  eligible`) — константы класса алгоритма; eager-слой опирается на
  документированный инвариант ротатора (дедуп при construction) — при
  нарушении инварианта в будущих версиях ротатора emitted-путь lazy-слоёв
  и mark_dead lazy-режим остаются корректными, eager-слой потребовал бы
  пересмотра (задокументировано в комментариях).
- `singleton_key_arc` заимствует Arc только при gate=None; при наличии
  gate-ссылки — полный клон со снятием gate (fallback в коде).
- Локальные Windows/Rust1.97 числа нельзя смешивать с Linux/Rust1.88 CI.
- run.py изменён только EXPECTED_ROWS; существующие тесты не ослаблялись;
  исторические артефакты других этапов не менялись.

## Личная итоговая проверка основного исполнителя

Повторены lean SDK rating/rotator checks, rating-only test build, app Clippy
с -D warnings и полные scoped-сборки test binaries. Runner принят: **128
выполнений тестов, 0 провалов, 7,672 с из общего deadline15 секунд**.
Графы dependency artifacts/feature/profile совпали:89SDK/129app. Полные114
строк сохранены в parent_measurements JSON; из68 общих строк изменились 0
(актуальная сверка родителя, supersedes промежуточные pick/depth оценки).

При чтении родитель ограничил eager singleton fast path двумя курсорами:
иначе линейный dedup одноэлементных ротаторов становился бы O(R²). Для
R>2 используется индексный/lazy путь; эта одноусловная правка включена в
личные сборки и прогоны. Отдельный scaling regression закреплён в задаче81.

Новые singleton результаты лично подтверждены: N1=11alloc/599B против
legacy15/778; прочие per-case значения берутся из parent_measurements.
Аллокационные выигрыши не выдаются за throughput или latency.
