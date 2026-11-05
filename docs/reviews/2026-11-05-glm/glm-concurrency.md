# Rust Intel: аудит concurrency & state — 2026-11-05 (GLM, второй проход)

## Ревизия и метод

HEAD: `6237994` (ветка `fix/audit-2026-11-05`); база предыдущего аудита: `870caa2`. Промежуточные содержательные коммиты: `dfe3606` (V-фиксы), `2c548e3` и `b4ab336` (тест-фиксы), `b7eab13` (вторая волна фиксов). docs-коммиты (`6e12a1e`, `3a94207`) не рассматривались.

Модуль rust-intel: `concurrency-and-state.md` (§A2, §B9, §B10, §B13, §B14, §B17, §B19, §C8, §E4), trigger-таблицы прогнаны по коду. Прочитаны целиком: `session/chain/mod.rs`, `session/rating/**` (mod, quarantine, select, sand, rng, health, policy-использование), `session/rotator/**` (mod, probe, record_error), `session/pool/proxy_pool/mod.rs`, `types/chain.rs`; выборочно: `server/health/mod.rs`, `config/users/users_file/**` (mod, lock, platform_unix, platform_windows), `auth/state/**` (mod, claim, verify), `server/connect/establish_connection/{dial,probes,route}.rs`, `bootstrap/startup.rs`, `connect/proxy_connect/hedged.rs`, `connect/dial/chain.rs` (diff). Прочитаны контекст предыдущего аудита (`summary.md`, `runtime/concurrency.md`) и полные диффы `870caa2..HEAD` по этим файлам.

**Запреты соблюдены:** cargo/скрипты/приложение/тесты/бенчи не запускались; код, конфиги, зависимости, Cargo.lock не менялись; commit/push/worktree — нет. Единственная запись — этот отчёт. Это статическая проверка механизмов: «VERIFIED_STATIC» означает, что сценарий следует из исходников и документированной семантики (tokio/OS), а не воспроизведение рантаймом.

## 1. Новые изменения: проверка фиксов V01–V18

Все фиксы, относящиеся к concurrency/state, проверены чтением финального кода на HEAD. Сломанного соседнего кода не найдено, кроме одного остаточного зазора (CC-01, V02) — см. findings.

| V-id | Фикс | Проверенное место | Статус |
|---|---|---|---|
| V01 | exhausted-layer termination | `session/chain/mod.rs:124-129` (`Layer.live`), `:225` (`done` при пустом слое на построении), `:269-286` (`mark_dead` → `done` при `live==0`) | ВСТАЛ. Пример `[A0,A1]×[B0,B1]×[E]`: `mark_dead(E)` обнуляет `live` exit-слоя → план завершён после первого pick. Прогресс `jump_subtree` (`:314-331`) гарантирован: либо инкремент, либо `done`. |
| V03 | эксклюзивный handshake admission | `hedged.rs:129` (`handshake_slot: Mutex<()>`), `:152-177` (check won → lock slot → re-check won → handshake → publish won под слотом), `:336-344` (tick не запускает рядом с handshaking) | ВСТАЛ. Двойной CONNECT невозможен: публикация `won` (Release) до освобождения слота, ожидание перепроверяет под слотом (Acquire). |
| V04 | единый launch budget | `dial.rs:44-49` (`direct_reserve`), `:87-89` (queued sticky владеет слотом), `:120-126`, `:213` (`attempts + direct_reserve < max`), `:301-313` (останова pick_order), `:325` (`truncate(max - attempts)`) | ВСТАЛ. Сумма chain-попыток + queued + hedged ≤ `max_attempts` во всех прослеженных ветках, включая gates-only (reserve=0) и кейс «оба rotator'а с кэшами». |
| V05 | cached chain через владеющий rotator + quarantine gate-хопов | `dial.rs:97-115` (`gates.resolve(from_ref(rotator), …)`; отказ → `unlink`; проверка `is_quarantined` по всем хопам кроме exit) | ВСТАЛ. Exit не перепроверяется — корректно: `get_linked` уже скрыл quarantined exit этого rotator'а (`rotator/mod.rs:443-449`). |
| V06 | дедупликация при построении | `rotator/mod.rs:389-404` (unique-вектор, первый вхождение), `index_of` doc обновлён (`:479-490`) | ВСТАЛ. Но doc-комментарий `same_upstream` противоречит коду — CC-04. |
| V07 | typed probe outcome | `probes.rs:36-62` (`ProbeVerdict`, только `Target`+`ProxyRejected` = HardFailure), `:243-271` (классификация), `:509-582` (таблица-тест) | ВСТАЛ. Capacity/prefix/deadline — inconclusive, health tested-узла не меняется. |
| V08 | lease покрывает глубину, absolute deadline, settlement fence | `probes.rs:71-97` (общие helper'ы `probe_deadline`/`probe_lease`), `:117-153` (claim до `take_probes`, deadline = claimed + budget−1s), `:230-242` (fence по `lease_until`), `startup.rs:385-399` (lease из той же формулы) | ВСТАЛ. Арифметика согласована: `deadline(ct,ht,d) ≤ ct + (count)·ht − 1s < ct + (count+1)·ht + 5s = lease`; fence консервативен в безопасную сторону (поздний результат после нового claim невозможен — новый claim требует истечения cell-lease ≥ fence-lease). |
| V09 | restore-probes только directly-dialed | `startup.rs:479-491` (все группы — только snapshot/restore), `health/mod.rs:374-383` (`spawn_due_probes` по `direct`), `probes.rs:109-155` (outermost+exits — direct, глубже — chain probe) | ВСТАЛ. |
| V10 | group-дискриминатор | `health/mod.rs:48-49` (`group` в записи), `:140-154` (signature с group), `:163-181` (ключ `(upstream, gate, group)`, пустой group — legacy-fallback на все группы) | ВСТАЛ. |
| V02 | health writer lifecycle | `health/mod.rs:254-313` (`HealthSaver`, stop-протокол, `FINISH_BUDGET`), `:346-357` (lock до cleanup), `:388-401` (baseline до probes, один owner), `:452-462` (offloaded write + reclaim temp перед каждой попыткой) | ВСТАЛ, с остатком — CC-01: ветка таймаута/abort'а освобождает lock при возможном незавершённом spawn_blocking-сохранении. |
| V11 | single-node stage | `connect/dial/chain.rs:302-310` (`on_tcp` → `progress.store(Target)`) | ВСТАЛ. |
| V12 | hedge deadline overflow | `hedged.rs:219-224` (`checked_add` → None = never hedge) | ВСТАЛ. |
| V16 | back-off достигает max | `quarantine.rs:127-138` (`duration_for` — saturating doubling + `min(max)`), тесты `:292-331` (trips 21/22/23/u32::MAX) | ВСТАЛ. |
| V17 | refill lifecycle serialization | `proxy_pool/mod.rs:164-169` (lock order задокументирован), `:399-413` (`forget` под тем же lock), `:447-470` + `:551-559` (публикация очереди, spawn и регистрация handle под одной критической секцией) | ВСТАЛ. Защёлкивание A↔B (publish↔forget↔recreate) более невозможно: обе операции требуют `refill_tasks` lock. |
| V18 | probe caps | `rotator/probe.rs:108-145` (`probe_due_with`/`probe_all_with` + reserve-hook, permit живёт до settle), `probes.rs:211-223` (`reserve_permit` для tested-узла chain probe), `route.rs:59-65` (defer при capacity), `startup.rs:581-586` (startup check с reserve) | ВСТАЛ. Capacity → defer без rating-изменения; lease истекает, probe повторяется. |
| — | `b4ab336` (Windows health poll, cached-chain quarantine setup) | `health/tests.rs` (poll на читаемый файл), `tests/quarantine.rs` (реальный долгий карантин gate-rotator'а) | Тест-фиксы, oracle'и стали честнее. |

## 2. Findings

### CC-01 — Medium | VERIFIED_STATIC | `crates/resocks5/src/server/health/mod.rs:294-311, 452-462`

**Механизм.** `HealthSaver::finish` на ветке таймаута (`Err(_) => { task.abort(); …; return; }`, `:300-309`) и `save_final` на ветке своего таймаута (`:470-481`) возвращают управление, а `lock` (cross-process lock файла здоровья, `:311`) освобождается при выходе из `finish`. Но `save_offloaded` выполняет serialization+I/O в `tokio::task::spawn_blocking` (`:452-462`), а блокирующая задача tokio **не отменяется** abort'ом JoinHandle и не отменяется таймаутом будущего — уже начавшийся `reclaim_own_temp` + `write_atomic` (+`platform::commit` = `ReplaceFileW`/`rename`) дорабатывает отсоединённо. После `return` из `finish` и drop(`lock`) второй инстанс может захватить lock и начать свои `resume`/`remove_stale_temp`/запись, пока orphan-запись первого процесса ещё идёт: удаление его temp вторым инстансом (POSIX удалит открытый файл; на Windows temp создан с `FILE_SHARE_DELETE` — тоже удалится), затем orphan-коммит публикует устаревший снимок под чужой lock-владением. Инвариант «lock освобождается только после финальной записи» (`:247-253`) на этих ветках не выполняется. Триггер: `FINISH_BUDGET` (3s) истёк при медленном storage, блокировке blocking-pool или загруженном runtime — типично именно при shutdown под нагрузкой, т.е. сценарий не экзотический, хотя для публикации нужно совпадение со стартом второго инстанса.

**Сценарий отказа.** shutdown с зависшей на >3s записью → второй инстанс стартует с lock'ом → orphan первого публикует снимок, сделанный до остановки первого, поверх/вместо свежих данных второго; либо `remove_stale_temp` второго удаляет temp orphan'а → orphan'у достаётся undetermined-ветка `commit` (ошибка «target may no longer contain the old content») → потеря снимка и мусорное состояние temp.

**Направление решения.** Не отпускать lock до фактического завершения blocking-записи: (а) передавать владение lock'ом в финальную blocking-задачу (release внутри closure после commit) и в `finish` await'ить JoinHandle записи без ограничения бюджета бюджета отчёта (отчёт — по таймауту, освобождение — по факту); либо (б) `saved_at`/epoch-маркер и отбрасывание orphan-коммита следующим владельцем. `task.abort()` на ветке таймаута оставить только для select-цикла, не для in-flight записи.

**Тест-кандидат.** В `writer_tests.rs` нет ни одного теста ветки таймаута `finish` (см. CC-05). Плюс positive control: seam, задерживающий `write_atomic` (test-only обёртка над save) > `FINISH_BUDGET`; после `finish` — повторный `UsersFileLock::acquire_with_timeout` должен быть единственным писателем: файл не меняется после возврата `finish` (poll 1s), temp отсутствует. Mutation: вернуть текущий `return` по таймауту — тест видит поздний коммит.

### CC-02 — Low | VERIFIED_STATIC | `crates/resocks5-net/src/session/rating/quarantine.rs:258-267`

**Механизм.** `Cell::try_lease` ставит `lease_until = now.checked_add(policy.probe_lease).unwrap_or(now)`. При непредставимом `now + probe_lease` lease становится нулевым: каждый следующий `try_lease` в тот же момент возвращает `true` — эксклюзивность probation-слота теряется полностью, это не деградация, а переключение режима. `QuarantinePolicy` — публичный API; `validate` (`:100-121`) требует только `probe_lease > 0`, т.е. `with_probe_lease(Duration::MAX)` — валидная конфигурация SDK-потребителя. Соседний `deadline()` (`:154-159`) тот же случай обрабатывает FAR-fallback'ом (100 лет) — несогласованность внутри одного файла.

**Сценарий отказа.** SDK-потребитель с `probe_lease = Duration::MAX` (легально проходит валидацию): на каждый due-apstream параллельно стартует сколько угодно probe-попыток (каждый вызов `take_probes` забирает узел), перекрывающиеся проверки, `record_hard_failure` от каждой — избыточные re-trip'ы; для app-пути (probe_lease из `probe_lease()` helper'а) недостижимо.

**Направление решения.** Единый FAR-fallback как в `deadline()`: `checked_add(probe_lease).or(checked_add(FAR)).unwrap_or(now)` — или запретить в `validate()` значения, не представимые `Instant + FAR`.

**Тест-кандидат.** `probe_lease = Duration::MAX`, два `take_probes_at(t)` подряд в один момент: второй обязан вернуть пустой вектор. Mutation: оставить `unwrap_or(now)` — второй вызов вернёт узел (positive control: обычный lease блокирует повтор — уже покрыто `:514-515`).

### CC-03 — Low | VERIFIED_STATIC | `crates/resocks5-net/src/session/rotator/probe.rs:174-188`

**Механизм.** `probe_all_with` классифицирует отказ как «upstream down» через два раздельных захвата ratings-мутекса: `!self.is_quarantined(&proxy)` (check) и затем `self.quarantine_now(&proxy)` (act). Между ними клиентский путь может вызвать `record_hard_failure` для того же узла: `hard_failure` трипнет карантин (`trips=1`), после чего `quarantine_now` добавит **второй** trip за одно и то же единственное свидетельство отказа → `duration_for(2)` вместо `duration_for(1)`, backoff удвоен без второго факта. Симметрично: два параллельных `probe_all` по одному списку (сейчас startup вызывает один раз, но API публичный) оба пройдут check до act. Внутренний защитник `Cell::hard_failure` («ignore внутри активного карантина», `quarantine.rs:193-195`) здесь не помогает: между двумя act-ами карантин ещё не активен либо уже активен для второго — второй `trip_now` игнорирует состояние и всегда `trips += 1` (`:210-217`).

**Сценарий отказа.** Стартовый reachability-check: узел refuses TCP, одновременно первый клиентский запрос к нему же fail'ится → `trips=2`, первоначальный карантин 2× длине. Одноразовый сдвиг, не накапливается, но искажает «двойной карантин за одно свидетельство».

**Направление решения.** Убрать check-then-act: `quarantine_now` сам атомарно решает (например, вернуть `None` если уже tripped, — сейчас он трипает безусловно), либо perform `trip_now` только если `Cell.state == Healthy` под тем же захватом мутекса (одна операция в `Ratings`).

**Тест-кандидат.** Deterministic требует seam (test-instrumentation): барьер между check и act в `probe_all_with` при параллельном `record_hard_failure`; assertion `trips == 1` и `health().consecutive == 1`. Positive control: обычный отказ без конкуренции → trips 1; mutation: удалить предпроверку — поведение в гонке не меняется (это и показывает, что защита не атомарна).

### CC-04 — Low | VERIFIED_STATIC (doc/код) | `crates/resocks5-net/src/session/rotator/mod.rs:76-103`

**Механизм.** Doc-комментарий `same_upstream` (`:78-84`) утверждает: «gate is deliberately excluded — … rating a gate-composite still lands on the plain upstream's slot». Код делает противоположное: `a.gate_level == b.gate_level` в `same_upstream` (`:88`) и `proxy.gate_level` в `upstream_hash` (`:101`). Фактическая семантика (gate_level — часть идентичности) подтверждена остальной системой: health-файл ключует записи по `(upstream, gate, group)` (`health/mod.rs:44-49,180`), тест `health/tests.rs:249-260` «same_address_at_another_gate_level_is_a_different_upstream». Т.е. ошибка — в комментарии, он вводит в заблуждение SDK-потребителя: `record_*`/`is_quarantined` с gate-composite конфигом в rotator'е из plain-конфигов молча no-op (`index_of` → None), чего комментарий обещает не делать.

**Сценарий отказа.** Не рантайм-отказ, а контрактный: потребитель верит доке, строит composite `with_gate_level(n)` и ожидает общего rating-слота с plain-конфигом; фиаско молчаливое (record теряется).

**Направление решения.** Переписать комментарий под фактическую семантику («gate_level входит в идентичность; composite и plain — разные rating-слоты; совпадение требуется с rotator'ом, владеющим уровнем»). Alternative — поменять код под доку: нет, это сломало бы health-ключение и V06-смысл.

**Тест-кандидат.** Doc-pin тест: `rotator([plain])`, `record_hard_failure(composite)` → `is_quarantined(plain) == false`, weights unchanged — фиксирует фактическую семантику против будущей «правки» в любую сторону.

### CC-05 — Low | TEST_GAP | `crates/resocks5/src/server/health/writer_tests.rs:18-296`

Покрытие writer'а: held lock (`:19`), temp midrun reclaim (`:100`), ранний probe-результат в baseline (`:148`), finish с мёртвым/полным log-каналом (`:212`), failed final save (`:266`), битый файл (`:294`). Не покрыто: (а) ветка `FINISH_BUDGET`-таймаута `finish` с in-flight blocking-записью — единственный путь, где нарушается заявленный инвариант (CC-01); (б) повторный захват lock после `finish` при медленной финальной записи. Кандидат описан в CC-01; mutation — «return по таймауту без ожидания записи».

### CC-06 — Low | PERF_CANDIDATE | `crates/resocks5-net/src/session/pool/proxy_pool/mod.rs:219, 260-279, 328-335`

**Механизм.** Каждый вызов `reserve_permit` аллоцирует минимум две `(String, u16)`-ключа: `upstream_semaphore` (`:219` `host.to_string()`) и `pools.get` (`:264` `proxy.host.clone()`); `acquire` добавляет третий в `checkout_prewarmed` (`:332`). Это на горячем пути каждого upstream-попытки (dial, gate-хоп, probe). Строки короткие, но это чистые heap-аллокации + hash по строке на каждую попытку.

**Оценка.** Видимая стоимость есть, практический выигрыш не измерен. Направление: ключ `DashMap<(Arc<str>…)>` нельзя искать по `&str` без `Borrow`-обёртки; реалистичный шаг — `upstream_semaphore`/`pools.get` принимать `(&str, u16)` через кастомный key-тип с `Borrow`-проекцией (эко`entry()` всё равно требует owned — оставить owned только для вставки), либо кэшировать `(host, port)`-ключ внутри `ProxyConfig` (one-time). Tradeoff: усложнение типов; делать только после профилей. Hash уже SipHash — при доверенном (config-derived) ключе допустим `foldhash`/FxHashMap-хэшер для обоих DashMap (§E4), attacker-влияния на ключ нет.

### CC-07 — Low | HARDENING | `crates/resocks5/src/server/health/mod.rs:338-390` + `bootstrap/startup.rs:493-507`

`health::start` — sync-функция, вызывается внутри async `run_server_inner` (под `runtime.block_on`, `runtime.rs:56`). Внутри: `resume` — чтение + ktav-парс файла (`:338`), `UsersFileLock::acquire_with_timeout(&path, 200ms)` — poll-цикл с `std::thread::sleep(10ms)` (`lock.rs:52-76`), `remove_stale_temp` (`:389`). Это разовый startup-блокинг текущего потока block_on (не воркера): типично <1ms, при контеншене lock — до ~200ms задержки bind'а listener'а. Не дефект производительности в обыденном смысле; отметить как §B11-гигиену: если переносить — целиком в один `spawn_blocking` вместе с resume+lock+cleanup (возвращая уже готовый `Resumed`). Priority низкая; сейчас корректно, просто синхронно.

### CC-08 — Low | HARDENING (unbounded artifact) | `crates/resocks5/src/config/users/users_file/lock.rs:45-59`

Sentinel `<target>.lock` открывается с `truncate(false)` и никогда не урезается и не удаляется; каждое приобретение дописывает строку `pid` (`:58`). Файл растёт монотонно со временем жизни каталога (каждый рестарт сервера + каждая init-claim persist + каждая CLI-операция). Скорость — байты, отказ невозможен; это §B14 «insert-only, no drain» в миниатюре, скорее гигиена. Направление: либо убрать диагностическую запись вовсе, либо писать pid по offset 0 (захватив lock, `seek(0)` + `set_len`), либо ограничитьappend периодической усечкой под lock. Тест не нужен.

### CC-09 — Low | HARDENING | `crates/resocks5-net/src/session/chain/mod.rs:28-31`

`GateLevels::new` — публичный SDK API — валидирует уникальность rank'ов только `debug_assert!`; в release дубликаты молча проходят (сортировка ставит их рядом; поведение далее определено: `healthy_prefix` включит оба уровня как prefix, `resolve` свярит `node.gate_level` с каждым рангом). Контракт «конфигурация — ошибка, а не инвариант» (§B14-дисциплина про `debug_assert` в release) уместен: конфигурация пользователя → конструктор должен возвращать `Err` (как это делают `RatingPolicy`/`QuarantinePolicy::validate`). Паника в debug/тишина в release — расхождение поведения между профилями. Тест-кандидат: `GateLevels::new(vec![(1,a),(1,b)])` → `Err`; mutation: убрать проверку.

### CC-10 — Low | code smell | `probes.rs:158-176`, `route.rs:66-88`

Сообщения об **успехе** probe («is reachable again - back in rotation») публикуются через `logger.proxy_failure(...)` — категория отказов. Оператор, фильтрующий журнал по категории, увидит «восстановление» только если читает failure-канал. Направление: отдельная категория (`lifecycle`/`recovery`) либо переименование. Поведенческой нагрузки нет.

## 3. Что проверено и отклонено (не findings)

- **`run_saver` stop-протокол**: `select!` biased с `stop.notified()` — `notify_one` сохраняет permit, lost-wakeup между раундами невозможен (tokio-семантика); break происходит только между раундами, in-flight save не пересекается с `save_final`. Ок.
- **Fence probe'ов** (V08): новое claim невозможно до истечения cell-lease, а cell-lease ≥ fence-lease (claim читается до `take_probes`) — приём результата после нового claim невозможен математически. Ок.
- **Relaxed-публикация payload'ов**: red-tier проверка по всему production-коду (`grep` по `Ordering`) — все Relaxed-атомы либо standalone-счётчики (`tunnel_log`, `tracked.rs` nanos — диагностический scalar), либо test-only (`recovery.rs:117` — `#[cfg(test)]`). Публикующего Relaxed нет; `won` — Release/Acquire. Ок.
- **`AuthState`**: граф lock'ов `claim_gate → claim_slots → claim_lock → users RwLock → users-file lock` — ацикличен и однонаправлен во всех путях; re-check после каждого wait'а на месте (R6-01); cancellation-safe владение permit+gate в blocking closure. Ок.
- **`StickyCache`**: get/insert/remove под одним `&mut` — инвариант «одна recency+expiry запись на entry» выдержан; generation-break tie корректен; LRU+TTL+cap присутствуют. Lock-порядок sticky→ratings единственный (обратного пути нет) — ABBA нет.
- **Refill-потеря wakeup**: `Notify::notify_one` сохраняет permit — уведомления между итерациями refill-цикла не теряются; fill-цикл перепроверяет `queue.len()`. Ок.
- **`connect_hedged`**: empty-slice → `Err(0 attempts)` без паники; `Ok(None)` от `join_next` на пустом set не даёт busy-spin (loop-top перезапускает/возвращает); индексация `launched[index]`/`candidates[index]` согласована. Ок.
- **Perf-остатки предыдущего аудита** (P01 pick_order O(N) RNG под мутексом; P02 ChainKey Hash/`nodes()` allocations; resolve O(ΣNᵢ); O(R×N) скан due-probe на клиентском пути) — не изменились, повторно не репортятся.

## 4. Фокус заказчика — сводка

1. **Лишние аллокации/клоны на hot path**: CC-06 (ключи pool'а, 2–3 String-аллокации на каждую upstream-попытку) — единственное новое; остальное — известные P02/P04.
2. **Ускорение типов/представлений**: новое не найдено; ChainKey/`nodes()` — P02, без изменений.
3. **Сложность**: новое не найдено; resolve O(ΣNᵢ), pick_order O(N)-под-мутексом — прежние P-кандидаты.
4. **Contention**: ratings под одним `Mutex` — оставить: выбор распределения держится на общем RNG; sharding/lock-free сломает детерминизм отбора, выигрыш не доказан (прошлая аудиторская вывод сохраняется). Locks короткие, без I/O под guard'ами (запись вынесена в spawn_blocking, DashMap guards не пересекают await).
5. **TEST_GAP**: CC-05 (timeout-ветка finish), CC-03 (детерминированный тест double-trip), CC-02 (lease overflow), CC-04 (identity doc-pin), CC-09 (duplicate rank).
6. **Фактические баги**: CC-01 (orphan-запись при shutdown — механизм и сценарий в findings), CC-02, CC-03.
7. **Smell**: CC-04 (doc≠код), CC-08 (рост sentinel), CC-10 (успех в failure-канале).

## 5. Топ приоритетных

1. **CC-01** (Med) — `finish` по таймауту отпускает cross-process lock при живом отсоединённом `spawn_blocking`-сохранении: orphan-коммит под чужим lock'ом.
2. **CC-03** (Low) — TOCTOU check→act в `probe_all_with`: двойной trip за одно свидетельство.
3. **CC-02** (Low) — `try_lease` overflow → нулевой lease → потеря эксклюзивности probe при `probe_lease = MAX`.
4. **CC-05** (TEST_GAP) — нет теста timeout-ветки `finish` (закрывается вместе с CC-01).
5. **CC-04** (Low) — doc `same_upstream` противоречит коду (gate в идентичности).
6. **CC-06** (PERF) — аллокации ключей pool'а на горячем пути; измерять перед правкой.

Ограничения: статическая проверка без исполнения; tokio/Win32/POSIX-семантики приняты по документации; смежные зоны (strict HTTP, TLS, wire) — не в этом модуле и не проверялись здесь повторно.
