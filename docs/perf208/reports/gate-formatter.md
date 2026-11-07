# #208, этап gate formatter — gate_label в один буфер

## Статус

`gate_label` при включённом логировании теперь строится в один
`String` с предварительной ёмкостью: вместо отдельного `String` на
каждый gate (`format!` + realloc) + `collect::<Vec<_>>` + `join(" -> ")`
— закрытый helper `push_cfg` пишет байты прямо в единый буфер.
Счётчики A/B получены локально в этом worktree; timing, latency и
throughput не измерялись и не заявляются. Историческое свидетельство
предыдущих этапов ([PERF208.md](../../PERF208.md),
[results/pool.json](../results/pool.json),
[results/resolve.json](../results/resolve.json)) не менялось; цифры
этого этапа собраны в этом файле и в
[results/gate-formatter.json](../results/gate-formatter.json).

## Механизм

Старый путь: per-gate `print_cfg` (отдельный `String` на каждый gate,
`format!` + realloc) + `collect::<Vec<_>>` + `join(" -> ")`.
Новый: закрытый helper `pub(crate) push_cfg` в
`crates/resocks5/src/server/connect/print_cfg.rs` пишет тот же
`format!` (`"ip {} - {:?}://{}:{}"` — family_label, protocol, host,
port; байты идентичны, user/password не логируются) прямо в единый
`String::with_capacity` по верхней границе: сумма host-байтов + 23 на
gate + 4 на разделитель. Константа 23 — длина литерала
`"ip V6 - Socks5://:65535"`: максимум Debug протокола (`Socks5` = 6) +
фиксированные части. Занижение оценки (например, будущий более
длинный Debug протокола) вызвало бы realloc — это ловит perf-assertion
(ровно 1 аллокация при depth>0, 0 realloc). Завышение не может вызвать
realloc: оно создаёт лишь ограниченный запас (порт короче 5 цифр,
Debug протокола короче `Socks5` — до ~4 байт на gate), который
assertion не видит; запас описан явно в «Ограничениях».
Тело `print_cfg` сохранено ДОСЛОВНО прежним (`format!` с его
собственной оценкой capacity): обычные прямые/probe/error логи
(`dial.rs`, `probes.rs` и пр.) зовут его же и сохраняют прежний
allocator path. `push_cfg` — закрытый helper, используется только
`gate_label`; байтовое совпадение `push_cfg` ↔ прежний `format!`
держат оракулы `push_cfg_matches_legacy_reference` и
`perf208_print_cfg_matches_legacy_allocations` (второй также сравнивает
alloc/alloc_zeroed/realloc/requested_bytes и защищает plain
`print_cfg` от будущих ухудшений).
`crates/resocks5/src/server/connect/establish_connection/route.rs`:
`gate_label` собирается в единый буфер с `GATE_OVERHEAD = 23` и
`HOP_SEPARATOR = " -> "`.

Инструментация `gate_formats` сохранена (1 на вызов).
`log_chain_attempt` не менялся: label строится только внутри принятого
`Logger` closure; disabled/full-queue ветки дают 0 formats/alloc
(perf-тест это подтверждает, регрессии сохранены). Порядок hops,
разделители и семейство (V4/V6) определяются прежним обходом
`pick.hops()` и прежним `family_label`. Cargo.toml/lock/SDK,
`tests/perf208/run.py`: EXPECTED_ROWS app 8 → 24 (16 print_cfg-строк),
остальной runner не менялся (44 SDK + 24 app строк).

## A/B: фактические счётчики

Окружение идентично предыдущим этапам: rustc/Cargo 1.97.0, host target
`x86_64-pc-windows-msvc`, allocator `std::alloc::System`, профиль
`test` (`opt-level=0`), `RUSTFLAGS=-D warnings`,
`CARGO_INCREMENTAL=0`, `RUSTC_WRAPPER=` (обёртки отключены),
`--locked`, максимум 2 jobs. SDK: defaults + `zeroize,test-instrumentation`;
приложение: обычные defaults + `test-instrumentation`. Blob
`Cargo.lock` не изменён: `21b918f3b72c33829d5f4cde306cff5ae1da3095`
(совпал с задокументированным). A/B — два состояния одного
незакоммиченного рабочего дерева на базе 4fc5968 (baseline снят до
правки). Фича-деревья захешированы: SDK
`0e5e7b29…67bf`, app `62e9c91a…5ab2` (полные sha256 в JSON).

Изменились только 3 строки `gate_label` (alloc/realloc/dealloc/
requested_bytes до → после; dealloc — парный к исчезнувшим
промежуточным буферам):

| Строка | alloc | realloc | dealloc | requested_bytes |
|---|---|---|---|---|
| `gate_label/depth=0` | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| `gate_label/depth=1` | 3 → 1 | 1 → 0 | 2 → 0 | 120 → 37 |
| `gate_label/depth=4` | 6 → 1 | 4 → 0 | 5 → 0 | 492 → 160 |
| `gate_label/depth=16` | 18 → 1 | 16 → 0 | 17 → 0 | 1987 → 659 |

Побайтовая сверка всех 52 пар baseline-строк по всем 13 полям Counts
(программная): 49 строк идентичны, OTHER_CHANGED = 0. Строка
`gate_label/depth=0` идентична: пустой label и прежний путь не
аллоцировали. Для `depth=16` ёмкость верхней границы подтверждена
счётчиком: 659 = сумма host-байтов (231) + 16×23 (GATE_OVERHEAD) +
15×4 (разделители); `requested_bytes` равен ровно одной аллокации
буфера. Экономия не оплачена переносом стоимости: все остальные поля
каждой строки побайтово совпали с baseline.

### Plain print_cfg (новые 16 строк)

В fix-прогоне добавлены строки `print_cfg/legacy|current/<label>` —
8 конфигураций × 2, legacy и current ИДЕНТИЧНЫ во всех 8
(alloc/realloc/requested_bytes):

| Конфигурации | alloc | realloc | requested_bytes |
|---|---|---|---|
| 7× (socks5_ipv4, http_ipv6, https_domain, socks5_utf8, socks5_empty, http_port1, socks5_ipv6_brackets) | 1 | 1 | 60 |
| `socks5_long300_maxport` | 1 | 2 | 971 |

Инцидент `fix-counters-3` (ОТКЛОНЁН runner'ом, exit 101):
промежуточный вариант переписывал `print_cfg` на `String::new()` +
`push_cfg` — это меняло allocator path обычных логов. Guard-assertion
`perf208_print_cfg_matches_legacy_allocations` упал на первой
конфигурации (`socks5_ipv4: realloc`, panic `print_cfg.rs:151`):
push_cfg-вариант дороже прежнего `format!` по realloc. Отчёты
print_cfg в том прогоне не напечатались (report идёт после guard),
точные счётчики push_cfg-варианта НЕ сохранены. Тело `print_cfg`
возвращено РОВНО прежнему `format!`.

Вывод: стоимость НЕ перенесена в обычные логи — путь `print_cfg`
побайтово тот же прежний и теперь измерен строками `print_cfg/*`.

## Эквивалентность прежнему formatter

Оракулы не «новая функция против себя»:

- `route::tests::reference_gate_label` воспроизводит прежний pipeline
  (`format!` из старого `print_cfg` на каждый gate + `collect` +
  `join`) и сравнивается побайтово на матрице: 0/1/3/16 gates ×
  протоколы Socks5/Http/Https × IPv4 / IPv6-литерал / IPv6 в скобках
  (ProxyConfig снимает скобки) / домен / UTF-8 домен / пустой host,
  + повторные вызовы + exit не входит + разделитель ровно `" -> "`
  между gates (15 на 16 gates) + порядок (явный литерал a → b по
  dial-порядку). Equivalence-тест
  `gate_label_matches_legacy_formatter` закрепляет результат.
- `print_cfg::tests::push_cfg_matches_legacy_reference` — helper
  против прежнего `format!` на 8 конфигурациях, включая credentials
  (user/password не появляются), UTF-8, пустой host, host длиной 300,
  порт 65535.
- Существующие `print_cfg_format_is_unchanged` и
  `family_label_classifies_by_host` зелёные.

Найденный нюанс порядка hops: первый fix-прогон был отклонён runner'ом
(exit 101) — тест-литерал порядка hops ошибочно предполагал
возрастание рангов, тогда как `GateLevels::iter` отдаёт уровни по
убыванию ранга (`crates/resocks5-net/src/session/chain/mod.rs`, doc
"in descending rank order"). Исправлен ТОЛЬКО fixture теста (ранги в
dial-порядке: первый элемент — максимальный ранг); formatter и оракул
не менялись, все in-loop сравнения с оракулом проходили и до фикса.

## Проверки и команды

Сборка отдельно от бюджета измерений (baseline — до правок, fix —
после; каталоги `target/perf-results/gate-formatter/…`):

```sh
# до правок
RUSTC_WRAPPER= RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
cargo test --locked -j 2 -p resocks5-net --lib \
  --features zeroize,test-instrumentation --no-run --message-format=json \
  > target/perf-results/gate-formatter/sdk-baseline-build.json
RUSTC_WRAPPER= RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
cargo test --locked -j 2 -p resocks5 --bin resocks5 \
  --features test-instrumentation --no-run --message-format=json \
  > target/perf-results/gate-formatter/app-baseline-build.json

# после правок (SDK не менялся с прошлого прогона, пересборка для полноты)
RUSTC_WRAPPER= RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
cargo test --locked -j 2 -p resocks5-net --lib \
  --features zeroize,test-instrumentation --no-run --message-format=json \
  > target/perf-results/gate-formatter/sdk-fix-build.json
RUSTC_WRAPPER= RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
cargo test --locked -j 2 -p resocks5 --bin resocks5 \
  --features test-instrumentation --no-run --message-format=json \
  > target/perf-results/gate-formatter/app-fix-build.json

# финальная сборка app после revert тела print_cfg
RUSTC_WRAPPER= RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
cargo test --locked -j 2 -p resocks5 --bin resocks5 \
  --features test-instrumentation --no-run --message-format=json \
  > target/perf-results/gate-formatter/app-fix2-build.json

python -I tests/perf208/run.py \
  --sdk target/perf-results/gate-formatter/sdk-baseline-build.json \
  --app target/perf-results/gate-formatter/app-baseline-build.json \
  --output target/perf-results/gate-formatter/baseline-counters
python -I tests/perf208/run.py \
  --sdk target/perf-results/gate-formatter/sdk-fix-build.json \
  --app target/perf-results/gate-formatter/app-fix2-build.json \
  --output target/perf-results/gate-formatter/fix-counters-4 \
  --check app:print_cfg \
  --check app:gate_label_matches_legacy_formatter \
  --check app:full_queue_does_not_format_dropped_entries \
  --check app:closure_never_called_when_flag_is_off
rustfmt --check --edition 2021 \
  crates/resocks5/src/server/connect/print_cfg.rs \
  crates/resocks5/src/server/connect/establish_connection/route.rs
```

- Baseline: `accepted: true`, elapsed 0,109 с — те же 44 SDK + 8 app
  строк (снято до правок, при старом EXPECTED_ROWS app=8), что у
  принятого resolve-этапа.
- Финальный fix (`fix-counters-4`): `accepted: true`, elapsed 0,047 с
  при общем deadline 15 с: 44 SDK-строки (13 perf-тестов SDK) +
  24 app-строки (8 тестов); 4 check-фильтра: `app:print_cfg` — 4 теста
  (теперь включает `perf208_print_cfg_matches_legacy_allocations`),
  `app:gate_label_matches_legacy_formatter` — 1,
  `app:full_queue_does_not_format_dropped_entries` — 1,
  `app:closure_never_called_when_flag_is_off` — 1; все 0 провалов.
- Всего 28 выполнений тестов: 13 SDK + 8 app + 4+1+1+1 check. Сравнивать
  elapsed baseline (без фильтров) и fix (с четырьмя фильтрами) нельзя —
  наборы проверок различаются; оба числа подтверждают соблюдение
  лимита, а не ускорение.
- Два отклонённых прогона (оба runner'ом, exit 101; промежуточный
  `fix-counters-2` был принят с прежним набором строк, заменён
  авторитетным `fix-counters-4`):
  - `fix-counters` — fixture-ошибка порядка hops, см.
    раздел «Эквивалентность»;
  - `fix-counters-3` — guard поймал realloc-регрессию
    push_cfg-варианта plain `print_cfg`, см. подраздел «Plain
    print_cfg»; тело возвращено к `format!`.
- rustfmt check прошёл; разногласий после форматтера не осталось.
- `tests/perf208/run.py`: EXPECTED_ROWS app 8 → 24 (16 print_cfg-строк),
  остальной runner не менялся: 44 SDK + 24 app строк.

## Ограничения и риски

- Заявлена только экономия аллокаций (alloc/realloc/dealloc и
  requested_bytes строк gate_label); timing, latency и throughput не
  измерялись и не заявляются.
- CPU-стоимость одного `write!` против `format!` + `Vec` + `join` не
  бенчмарчилась (в production `push_cfg` используется только внутри
  `gate_label`; plain `print_cfg` вернулся к `format!`).
- `requested_bytes` — запрошенные аллокатору байты, не RSS.
- host-байты и разделители ёмкость считает ТОЧНО; запас только на
  порт/Debug протокола: порт короче 5 цифр, Debug короче `Socks5` —
  до ~4 байт на gate, не возвращается аллокатору в пределах жизни
  буфера; излишний резерв не виден perf-assertion. ЗАНИЖЕНИЕ оценки
  (realloc) ловит perf-assertion; ЗАВЫШЕНИЕ не может вызвать realloc.
- Точные счётчики отклонённого push_cfg-варианта `print_cfg`
  (`fix-counters-3`) не сохранены: guard сработал до report.
- Локальные Windows/Rust1.97 числа нельзя смешивать с Linux/Rust1.88
  CI baseline; `.github/workflows/perf.yml` не менялся.
- `docs/PERF208.md`, `PERF208-RESULTS.json`, результаты этапов
  pool/resolve не менялись; EXPECTED_ROWS изменён только как описано
  выше (app 8 → 24).
- Существующие функциональные тесты не ослаблялись; новые assertions
  perf-теста `perf208_gate_label_component` (ровно 1 аллокация при
  depth>0, 0 realloc) закрепляют устранённый механизм (правило 4
  PERF208.md).

## Проверки исполнителя

Сверка A/B выполнена программно: все 52 пары строк baseline/fix по
всем 13 полям Counts; 49 идентичны, изменились только 3 gate_label
строки. Числа тестов (13 SDK + 8 app + 4+1+1+1 check = 28 выполнений)
взяты из фактических строк `test result:` stdout прогонов; 68 строк в
parent_measurements = 52 прежних пар (before=baseline-counters,
after=fix-counters-4) + 16 новых print_cfg-строк (before==after,
new). Родитель
повторит проверки сам.

## Личная проверка основного исполнителя

Независимая пересборка обоих test binaries прошла с --locked, -D warnings
и максимум двумя jobs. Runner принят: **161 выполнений тестов,
0 провалов, 9,656 с из общего deadline15 секунд**. В 52 общих строках
изменены только allocator-поля трёх непустых gate_label; 49 строк совпали.
Все 8 plain-print_cfg controls равны legacy по полным Counts. Прежнее тело
print_cfg также сверено побайтово с baseline. Полные dependency artifact
graphs 89/129 совпали с принятым resolve-этапом; это другой метод счёта,
чем unique package_id76/114 в отчёте исполнителя. Полные 68 измерений
и собственные результаты сохранены в results/gate-formatter.json.
