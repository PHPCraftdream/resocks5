# PERF208 mark-dead — отчёт о воспроизводимости и счётчиках

## Вывод

Это **повторяемый операционный/аллокаторный замер**, не сравнение до/после и не заявление об ускорении: честной матрицы mark-dead до правок не было. Изменения продукта/оптимизации не вносились: обычный `contains` восстановлен; новые счётчики действуют только в test cfg. Исторический `credentials.json` использован только как контроль прежних полей, а не как baseline mark-dead.

Исторические run1/run2 завершились с кодом 0: каждый имел SDK 22/22, app 8/8 и проверки 12 + 7 + 5 + 25 = 49, всего 79 выполнений за запуск (не 56). Широкий rotator filter включил bounded hammer-тест и был нарушением требуемого узкого scope; его нельзя повторять. Эти результаты остаются историческими и не являются новым целевым запуском. Строки счетчиков и другие результаты не изменялись.

Полные два вывода SDK/app и четыре check-файла обработаны локально Python по UTF-8. Регулярным выражением разобраны все поля `Counts`: 213 уникальных сценариев, 27 полей; все значения run1 и run2 равны. См. `../results/mark-dead.json`: сценарии хранятся отдельными строками объектов JSON, без потери счётчиков.

Исторический контроль `docs/perf208/results/credentials.json`: 121 сценарий, 121 имя совпало; все 13 старых полей `after` на совпадающих именах точно равны текущим. Сравнение не означает наличие предшествующего замера mark-dead; новые поля перечислены в JSON.

## Точные таблицы счётчиков

Значения сняты из `counter_rows` файла результата. `bytes` — `requested_bytes`, не RSS; `visits` — `mark_dead_layer_visits`; `lookups` — `mark_dead_index_lookups`; `eligible` — `mark_dead_eligible_checks`.

### Слои: первый mark и повторный mark

| layers / width | Сценарий | alloc | dealloc | requested bytes | visits | lookups | eligible |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 / 2 | gate | 3 | 0 | 187 | 2 | 2 | 2 |
| 1 / 2 | repeat | 2 | 2 | 135 | 0 | 0 | 0 |
| 3 / 8 | gate | 3 | 0 | 187 | 4 | 4 | 2 |
| 3 / 8 | repeat | 2 | 2 | 135 | 0 | 0 | 0 |
| 8 / 64 | gate | 3 | 0 | 187 | 9 | 9 | 19 |
| 8 / 64 | repeat | 2 | 2 | 135 | 0 | 0 | 0 |

### Singleton: построение и владельцы

`R` — число ротаторов. `comparisons` — `singleton_dedup_comparisons` при construction. `first-owner steps` — `chain_plan_steps` при выборе первого владельца (в каждой строке 1). Для позднего владельца указаны именно счётчики mark-dead: `cursor visits / lookups / eligible`, где cursor visits = `mark_dead_cursor_visits`, lookups = `mark_dead_index_lookups`, eligible = `mark_dead_eligible_checks`. `disjoint` и `overlap` — разные сценарии.

| R | Владельцы | construction alloc | realloc | requested bytes | comparisons | first-owner steps | late-owner cursor visits / lookups / eligible |
|---:|---|---:|---:|---:|---:|---:|---:|
| 2 | disjoint | 7 | 0 | 408 | 1 | 1 | 0 / 0 / 0* |
| 2 | overlap | 7 | 0 | 408 | 1 | 1 | 0 / 0 / 0* |
| 3 | disjoint | 13 | 0 | 724 | 0 | 1 | 3 / 3 / 1 |
| 3 | overlap | 11 | 0 | 660 | 2 | 1 | 1 / 1 / 1 |
| 8 | disjoint | 30 | 0 | 2,308 | 0 | 1 | 8 / 8 / 1 |
| 8 | overlap | 21 | 0 | 1,260 | 7 | 1 | 1 / 1 / 1 |
| 64 | disjoint | 201 | 0 | 18,260 | 0 | 1 | 64 / 64 / 1 |
| 64 | overlap | 133 | 0 | 7,980 | 63 | 1 | 1 / 1 / 1 |
| 256 | disjoint | 779 | 0 | 72,820 | 0 | 1 | 256 / 256 / 1 |
| 256 | overlap | 517 | 0 | 31,020 | 255 | 1 | 1 / 1 / 1 |

\* Для R=2 соответствующий поздний-owner вызов завершился до cursor/lookups/eligible счётчиков; он зафиксировал `mark_dead_membership_checks` 2 (disjoint) и 1 (overlap). Cursor counters равны 0 в этих случаях.

Фактически выполненный тестовый eager reference loop считает disjoint R*(R−1)/2: R=2/3/8/64/256 → 1/3/28/2016/32640; overlap R−1 → 1/2/7/63/255. Это реальный подсчёт сравнений same_upstream в reference loop, не product mutation.

Финальный post-format build и runner для `target/perf208/mark-dead-final` завершились с exit 0 (наблюдение оркестратора); проверка счётчиков независимо сравнила все 213 строк и подтвердила точное совпадение.

Счётчики не вакуумны: construction при R=3 имеет 0 eager inserts; для R≥8 disjoint construction не выполняет дедуп-сравнений, overlap comparisons равны R−1, тогда как eager reference растёт треугольно. Проверка идентичности владельца использует `Arc::ptr_eq`. Для поздней смерти disjoint visits растут как R, overlap остаётся на 1; повторная смерть в слоистой таблице посещает 0. Сценарии слоёв подтверждают reset: 8 уникальных выходов, exclusion: 15, exhaustion: 0.

## Запуски, графы и история исправлений

Точная воспроизводящая последовательность (команды совпадают с JSON reproduction). План: 189 SDK PERF208 строк + 24 app строки; SDK 22 теста, app 8 тестов; проверки 12+7+5+1+1=26, всего 56. Ожидаемые значения основаны на существующих артефактах, не являются результатом нового запуска. Каталог `mark-dead-review-reproduce-01` проверен и отсутствует; перед повторным использованием выберите новый свободный суффикс. Команды сборки ниже создают manifests, необходимые следующей команде runner; пропускать их можно только при подстановке существующих manifests от проверенной сборки того же исходного кода и feature-world.

```text
RUSTFLAGS='-D warnings' CARGO_INCREMENTAL=0 cargo test --locked -j2 -p resocks5-net --lib --features zeroize,test-instrumentation --no-run --message-format=json > target/perf208/mark-dead-review-reproduce-sdk-build.json
RUSTFLAGS='-D warnings' CARGO_INCREMENTAL=0 cargo test --locked -j2 -p resocks5 --bin resocks5 --features test-instrumentation --no-run --message-format=json > target/perf208/mark-dead-review-reproduce-app-build.json
python -I tests/perf208/run.py --sdk target/perf208/mark-dead-review-reproduce-sdk-build.json --app target/perf208/mark-dead-review-reproduce-app-build.json --output target/perf208/mark-dead-review-reproduce-01 --check sdk:chain::selection_tests:: --check sdk:chain::lazy_oracle_tests:: --check sdk:chain::accounting_tests:: --check sdk:rotator::tests::lazy_candidates_match_pick_order_exactly --check sdk:rotator::tests::rating_index_checks_identity_on_hash_collision
```

При подготовке этой коррекции использованы только существующие артефакты; новые builds, tests и runner не выполнялись. Исторические 79 выполнений на запуск не являются целевым планом из 56.


Фактические коды завершения по имеющимся статусам/сообщению оркестратора: начальная no-run компиляция — 101; исправленные scoped SDK и app no-run — 0/0; первый seeded runner — 1; следующий runner — 1; final verified и repeat runner — 0/0. Первый compile выявил три E0369 в тестовом oracle для равенства `ProxyConfig`; тест исправлен на `same_upstream`. Первый seeded runner провалил одну SDK-проверку с неверным ожиданием eager lookup R2. Следующий — из-за ожидаемого 189 при фактическом 199: удалён дублирующий late-loop. Это исправления тестовых oracle/ожиданий, не изменения оптимизации продукта.

Также clippy завершился с фактическим exit 0 по оркестраторскому сообщению, команда:

```text
RUSTFLAGS='-D warnings' CARGO_INCREMENTAL=0 cargo clippy --locked -j2 -p resocks5-net --lib --tests --features zeroize,test-instrumentation -- -D warnings > target/perf208/mark-dead-clippy.txt 2>&1
```

Toolchain и среда: rustc 1.97.0 (2d8144b78 2026-07-07), cargo 1.97.0 (c980f4866 2026-06-30), host `x86_64-pc-windows-msvc`, test profile, opt-level 0, `-Dwarnings`, incremental=0, locked, jobs=2, allocator `std::alloc::System`. Нормализация графов: `package@version`, target name, отсортированные kind и уникальные отсортированные features. Фактические графы SDK 89 строк, app 129; оба совпадают со своими историческими графами без добавлений/удалений. Cargo.lock SHA-256 `dc3acbef3693ce42b520478640cacde26cced2ee45dc714b10ef3f51003bd4f0`, совпадает с историческим. SDK features: default,pool,rating,rotator,secure-auth,serde,test-instrumentation,tls,zeroize; app features: test-instrumentation. Полные графы и пути runner не включались; локальные/private paths не публикуются.

## Ограничения

Покрытие больших product случаев ограничено 8 выборками; coupling проверен на 3 точках levels×width, а не на полном декартовом произведении. Не заявляются глобальная latency или throughput. `requested_bytes` — сумма запрошенных allocator bytes, не RSS. Результаты аллокаций привязаны к `System` и указанной платформе. MSRV-компилятор не запускался; production instrumentation нет. Негативный mutation run не выполнялся и не заявляется. Не читались credentials/secrets. При подготовке этих документов тесты, сборки и новые замеры не запускались; обновлены только эти два новых документа.

## Личная приёмка родителя

После исправления воспроизведения выполнены scoped SDK/app сборки и SDK Clippy (exit 0), затем targeted runner без hammer: 56 исполнений, accepted=true, 0,250 с из общего бюджета 15 секунд. Все 213×27 counters совпали с сохранённым результатом; все 121 исторических контролей сохранили прежние 13 полей. Независимо сверены оба dependency graph: SDK 89 и app 129, без изменений. Доказательства: `target/perf208/wrush-proof/mark-dead/agent-artifacts/parent-review/`. Исторические broad runs с hammer не используются как доказательство соблюдения scope.
