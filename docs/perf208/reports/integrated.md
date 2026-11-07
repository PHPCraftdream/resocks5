# PERF208 — итоговая интеграционная приёмка

## Результат

Этапы #76–81 приняты и перенесены в основной незакоммиченный checkout. Все созданные для них worktrees и branches удалены после личной проверки, побайтового переноса и сохранения доказательств. Commit и push не выполнялись. Пользовательский `docs/REFERENCE.md` сохранён без изменения со стороны исполнителя.

Итоговая личная проверка интегрированного кода: **124 успешных исполнения**, 213 строк PERF208 (189 SDK + 24 app), общий runner **0,687 секунды из 15 секунд**, `accepted=true`. Все 213×27 значений counters точно совпали с принятой матрицей mark-dead. Scoped SDK/app сборки и Clippy обоих packages завершились с exit 0. Время runner подтверждает только соблюдение бюджета, не прирост throughput или снижение latency.

Результат в машиночитаемом виде: [`../results/integrated.json`](../results/integrated.json). Сырые manifests, stdout, stderr, status и acceptance: `target/perf208/integrated-final/`.

## Принятые улучшения

Значения относятся к отдельным сопоставимым сценариям, а не к суммарной стоимости одного соединения. Складывать экономию разных строк нельзя.

| Механизм | Доказанный результат | Подробности |
|---|---|---|
| Borrowed pool lookup | warm lookup 1→0 alloc; checkout+reserve 2→0; cold insertion без изменений | [pool](pool.md) |
| Indexed cached resolve | last-hit/miss при N=256: 256→1/0 identity comparisons; allocator profile сохранён | [resolve](resolve.md) |
| Gate formatter | depth16: 18 alloc +16 realloc →1 alloc, 0 realloc; 1987→659 requested bytes; plain formatter controls равны | [gate formatter](gate-formatter.md) |
| Внутренний lazy weighted planner | N=256, первый кандидат: 1042→12 alloc, 257→1 config clones, 2138→255 comparisons | [weighted](weighted.md) |
| HTTP Basic payload ownership | retain 11→10 alloc, 6094→6084 requested bytes; plain 8→7, 6075→6065; остальные 119 контролей без изменений | [credentials](credentials.md) |
| mark_dead/scaling | Новых продуктовых оптимизаций нет. Добавлены 92 сценария; R=256 disjoint construction: 0 identity comparisons против 32640 у выполненного eager-reference | [mark-dead](mark-dead.md) |

Начальные улучшения до этих этапов — устранение лишнего Clone в mark_dead, stack hashing до 64 узлов, sharing gates в pick.config(), объединение tunnel counters и ранний выход отключённых логов — описаны в `docs/PERF208.md` и историческом `docs/PERF208-RESULTS.json`. Исторические результаты не заменены новым интеграционным замером.

## Границы и компромиссы

- Публичный SDK API, traits, версии, зависимости и Cargo.lock не изменены. В непубликуемом app добавлена только feature `test-instrumentation`, включающая существующую SDK feature. Счётчики и allocator wrapper подключаются только в unit-test instrumentation world; Drop observer — только при `test + zeroize`, без изменения layout Credentials.
- Публичный full `pick_order` сохраняется. Lazy path оптимизирует ограниченное потребление; полный drain N=256 требует больше comparisons: 2138→5018, хотя allocation/copy costs снижены. Ускорение полного drain не заявляется.
- Eager singleton fast path ограничен двумя cursors; R≥3 проверен через indexed/lazy path. Присутствуют guards first-owner, overlap, repeated death, pruning, reset, exclusion и exhaustion. Большие Cartesian plans проверяются выборочно, не полным перебором.
- Необходимые owning retention copies credentials сохранены: UTF-8/raw/Basic — 2/4/3 allocations в соответствующих duplicate fixtures. Perf guard обнаруживает возврат лишней Basic payload copy; Drop/cancel observer проверяет живые поля после реального wipe. Очистка всех compiler/host copies не доказана, freed memory не читается.
- SDK unit `cfg(test)` разрешает cleartext для wire fixtures. Эти тесты не доказывают normal default no-cleartext policy. Security #68–70 не выполнялись.
- В исторической делегированной mark-dead проверке broad rotator filter включил bounded hammer; это нарушение запрета нагрузки раскрыто в отчёте. Личная targeted приёмка и итоговый интеграционный runner не включают hammer и не используют тот broad run как доказательство соблюдения scope.
- Локальный world: Rust/Cargo1.97.0, `x86_64-pc-windows-msvc`, System allocator, test profile opt0, `RUSTFLAGS=-D warnings`, `CARGO_INCREMENTAL=0`, `--locked`, максимум2 build jobs. SDK defaults + `zeroize,test-instrumentation`; app `test-instrumentation` с обычными dependency defaults.
- Dependency graphs независимо совпали с принятой credentials-базой: SDK89, app129. Cargo.lock SHA-256: `dc3acbef3693ce42b520478640cacde26cced2ee45dc714b10ef3f51003bd4f0`.
- Linux/Rust1.88 CI world не запускался. Локальная приёмка не заменяет CI/MSRV; #71 остаётся pending. `requested_bytes` — сумма allocator requests, не RSS/peak memory.

## Состав итогового runner

Один deadline 15 секунд на весь набор:

- SDK perf208: 22 теста; app perf208: 8.
- Chain selection/lazy oracle/accounting: 12 +7 +5.
- Два targeted rotator tests: 1 +1, без broad rotator filter.
- Credentials/raw credentials/I/O failures/framing: 22 +15 +11 +20.
- Всего: **124**, ошибок0. Компиляция и Clippy выполнялись отдельно от измерительного бюджета.

Для повторения использовать `tests/perf208/run.py` с manifests от scoped `cargo test --no-run --message-format=json` и новым, ещё не существующим output-каталогом. Не переиспользовать сохранённые success-каталоги; не сравнивать counters разных compiler/target/features/allocator worlds как одно A/B.
