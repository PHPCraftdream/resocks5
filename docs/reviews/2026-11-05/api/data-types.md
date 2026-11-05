# Аудит аллокаций, типов и сложности — 2026-11-05

Исследователь `@oh`, `data-and-types.md`. HEAD `870caa2bfa9b6afd8594fabe4df9659bca585760`, диапазон `c927e71..HEAD`. Основной сеанс сохраняет ответ агента, которому запрещена запись Markdown. Никаких прогонов/измерений; продукт не менялся. Оценки ниже статические и агентские до независимой сводной проверки.

## Bugs

### DT-B01 — Исчерпанный слой допускает экспоненциальный Cartesian traversal

High/High, новый код. `crates/resocks5-net/src/session/chain/mod.rs:223–245,273–289,360–364`; `crates/resocks5/src/server/connect/establish_connection/dial.rs:191–198`.

d gate levels по два кандидата, единственный exit. Первый next возвращает pick и заранее advance. Target error mark_dead(exit). Следующий next видит dead exit последнего слоя; jump_subtree(singleton last layer) переносит odometer в предыдущие gates. Все оставшиеся gate combinations перебираются с тем же dead exit. Нет проверки полного исчерпания слоя.

Стоимость после одной ошибки до 2^d−1 бесполезных combinations; при d20 — 1048575 (число, не время). Synchronous next без await не ограничен max_upstream_attempts, который расходуется после возвращения pick. Fallback задерживается; dead.contains дополнительно вызывает allocating Hash.

Предложение: alive-count/exclusion по слою; при полностью dead слое немедленный done, сохраняя порядок остальных combinations/subtree skip. Тест: небольшой binary-layer plan+singleton exit, первый pick→mark exit dead→None, deterministic transition counter bounded размером слоёв, не product. Positive: один из двух exits dead, другой выдаётся в прежнем порядке. Mutation убрать exhausted-layer termination. Не создавать огромную нагрузку для oracle.

### DT-B02 — Duplicate identities обходят quarantine

Medium/High. `crates/resocks5-net/src/session/rotator/mod.rs:375–393,465–495`; `session/rating/mod.rs:248–275`; `session/rotator/tests.rs:53–59`.

[A,A,B] создаёт три state cells, by_identity(A) хранит последний slot1. Failure/quarantine обновляет slot1, selection включает untouched slot0; event от slot0 снова обновляет slot1. При здоровом B мёртвый A остаётся selectable. Старый identity-дизайн стал correctness issue с новым quarantine.

Предложение: явная duplicates policy — dedup либо multiplicity как вес при общей state. Не удваивать consecutive failures aliases на одном probe. Тест threshold1: после failure(A) pick_order не содержит никакого A при здоровом B, после success возвращается по policy. Mutation separate cells+last index.

### DT-B03 — Cached chain не проверяет gate health

Medium/High, новый код. `crates/resocks5-net/src/session/rotator/mod.rs:430–435`; `session/chain/mod.rs:49–85`; `crates/resocks5/src/server/connect/establish_connection/dial.rs:75–126`.

Cached G_bad→E, G_bad quarantined другим запросом, G_good healthy, E healthy. get_linked проверяет E; resolve identity-only находит G_bad; app сразу connect_chain. Новый plan исключил бы G_bad, cache его обходит.

Предложение: app cached path проверяет каждый Hop eligibility через свой rotator, fallback plan при quarantined/probation. Не менять identity-only resolve contract, используемый SDK tests. Тест no connect bad/healthy route, recovery control; mutation убрать per-hop check.

### DT-B04 — Duration::MAX hedge delay вызывает Instant addition panic

Medium/High, новый public API boundary, не wire. `crates/resocks5-net/src/connect/proxy_connect/hedged.rs:42–45,277,301–302`.

HedgeOptions принимает произвольный Duration; now()+Duration::MAX непредставим, даже при одном candidate. Вместо Result panic. Предложение checked_add, явная overflow policy no-next-hedge либо validation rejection; singleton timer не нужен. Тест один/несколько candidates с MAX, controlled connect outcome, без ожидания огромного срока. Mutation обычный +.

### DT-B05 — Backoff capped exponent20 не достигает допустимого max

Low/High, новый код. `crates/resocks5-net/src/session/rating/quarantine.rs:100–128`.

shift=trips.saturating_sub(1).min(20), validation допускает max>initial×2^20. initial1ms/max1h: trip21=1048576ms, trip22 должен2097152ms, фактически прежний. Defaults30s/600s не затронуты.

Предложение bounded saturating doubling до max, bound разрядностью Duration, не trips. Exact tests trips21/22/23/u32MAX, mutation min20.

## Performance candidates — измерений нет

### DT-P01 — Успешный ordinary sticky hit заранее строит fallback weighted order

Высокий приоритет для измерения, High для механизма; регрессия относительно c927e71. `crates/resocks5/src/server/connect/establish_connection/dial.rs:75–88,278–322`; `crates/resocks5-net/src/session/rating/mod.rs:248–275`.

Ungated cached proxy добавляется candidates, затем до connect_hedged выполняется полный pick_order всех rotators, keys и buffers. В baseline cached success возвращался до сортировки. Теперь O(N) RNG/weights, O(NlogN) sort, O(N) temp memory даже если cached TCP быстрый и fallback не нужен.

Предложение lazy fallback source: cached prefix немедленно, order только когда реально нужен next launch. Не возвращаться к sequential cached dial: это теряет hedging медленного cached TCP. Окупается high hit ratio/large pool; misses/hedges платят прежнюю full стоимость. Тест quick hit→fallback pick_order_calls0, slow cached TCP→order на hedge launch. Mutation eager order.

### DT-P02 — Identity materialization и allocation внутри Hash

Средний приоритет, High механизм. `crates/resocks5-net/src/types/chain.rs:12–22,89–104`; `types/proxy_config.rs:140–148`; `session/chain/mod.rs:145–147,251–260,309–312`.

Hash вызывает nodes→Vec pointers+reverse. singleton_key клонирует host/user/password лишь для удаления gate. current_pick строит chain key, pick.config ещё одну chain для dial; resolve тоже reconstruct cached config.

Для h hops/S total string bytes каждый full chain копирует примерно S и создаёт h Arc allocations; key+config два прохода; каждый hash O(h) временная pointer materialization. Предложение allocation-free linked Hash (length отдельно, согласованный field encoding), existing Arc для ungated singleton, read-only reuse key.exit/indices и одна owned materialization. Public String→Arc<str> не делать без API решения. Preserve identity fields/protocol/rank/order/length/is_gate semantics. Тест отдельный allocation oracle Hash без HashSet growth; mutation nodes Vec/second reconstruction. Текущие Hash/Eq согласованы, не correctness bug.

### DT-P03 — Лишние credential copies

Средний приоритет/High. `crates/resocks5-net/src/server/mod.rs:337–381`; `server/credentials.rs:55–62`.

Default UTF8 username имеет identity clone и второй clone в Credentials, original больше не нужен. Можно move original: минус allocation и U bytes. Raw conversion from_utf8(user.clone/password.clone) можно делать consuming и восстанавливать invalid bytes через FromUtf8Error::into_bytes: ещё минус2 allocations и U+P bytes на valid UTF8. Вместе raw-valid до3 allocations/2U+P copied bytes устранимы. Retention duplicate может быть необходим: closure получает ownership, request нужна независимая копия.

Тест valid/invalid UTF8,1/255,split codepoint,retain on/off, consuming closure, scoped allocation counter. Mutation clone возврат. Exact identity/lossy/retention сохраняются.

### DT-P04 — Eager logs и три Arc counters

Средний приоритет/High. `crates/resocks5/src/server/connect/establish_connection/dial.rs:51–54,111–117,201–207`; `server/tunnel/tunnel_log.rs:22–28,129–145`; `logger/log.rs:24–28`.

Logger admission lazy, но callers заранее format ctag/end и gate map(print_cfg).collect.join даже при disabled/full sink. Gate path g Strings+Vec+join. Counters три Arc<Atomic> allocations/tunnel вместо одного Arc<Inner>. Предложение borrowed Display wrappers внутри closure, aggregate counters Arc. Counters не выключать при tunnels=false: нужны zero-upstream-byte warnings. Tradeoff atomic locality/false sharing не измерен.

Тест counting/panicking Display не вызывается при disabled и full channel; active text/escaping сохраняются. Mutation eager format. Измеренный выигрыш не заявлен.

### DT-P05 — Header collections/lowercase allocations

Средний приоритет/High. `crates/resocks5-net/src/server/mod.rs:540–560,615–639`; `server/strict_http.rs:26–33,110–117`.

Header_lines Vec<&[u8]> всегда, даже permissive, затем один auth search. Strict lowercase allocation/name ради двух names; split request-line collect перед проверкой трёх pieces. H slices на64bit≈16H bytes, strict H allocations/B_names copies. Всё bounded16KiB, не unbounded DoS.

Предложение borrowed iterator повторно, eq_ignore_ascii_case, fixed3 pieces+четвёртый detection. Сохранить first-auth permissive/strict duplicate/OWS/obs-text/pipeline/limit. Тест independent vectors+scoped allocation oracle, mutation collect/lowercase возврат. Functional tests alone allocation не ловят.

## Hypotheses / contracts

DT-H01: persisted identity исключает password (`crates/resocks5/src/server/health/mod.rs:80–85,138–149`), runtime включает (`session/rotator/mod.rs:85–102`). Два password variants одного endpoint/user/rank coalesce в HashMap, then одно state применяется обоим. Документация явно password не сохраняет, нужна policy ambiguous groups, не безусловный баг только по password difference. Не сохранять password/обычный hash в health. Test opposite states/order reversal.

DT-H02: recovery parsing повторно проходит growing fragmented ClientHello (`connect/util/recover_host.rs:40–85`, `connect/tls/tls_records.rs:82–142`), потенциально O(n²) суммарно по chunks; app cap/deadline ограничивают масштаб. Нет достаточного perf доказательства, incremental parser без профиля/корпуса не предлагать как готовый fix.

## Снятые подозрения

Hash/Eq fields согласованы; RandomState + collision equality, не weak runtime hasher. Leading * UTF8-safe/u8 rank checked. IP mask zip равных arrays. total_cmp+index tie-break. HTTP delimiter scan с old_end−3, не полное rescan. take_pipeline move, split_off bounded read-ahead. SOCKS byte lengths checked. Serde Option absent/null без PATCH requirement не дефект.

## Coverage и limits

Прочитаны docs/manifests/lock, chain/types/validation/rotator/rating/health, cached+hedged routing/probes, ingress credentials/strict/prefixed, outbound/pool keys, logs/auth cache/recovery/TLS records/IP masks и relevant tests. Не построчный аудит всех tests/всех категорий. Resolved serde1.0.228/ktav0.8/Tokio1.54.1/DashMap6.1/regex1.11.1/base640.22.1/zeroize1.8.2; MSRV1.88. Registry sources не читались. Cost estimates аналитические, benchmarks/mutations/alloc counting не выполнялись.
