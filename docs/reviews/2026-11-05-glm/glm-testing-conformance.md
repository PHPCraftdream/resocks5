# Rust Intel (glm): тесты и конформность resocks5 — 2026-11-05

## Ревизия и метод

HEAD: `6237994` (после `b7eab13`). Диапазон новой работы: diff `870caa2..HEAD` — коммиты `dfe3606` (фиксы V01–V18), `2c548e3`, `b4ab336`, `6237994` (правки тестов), `b7eab13` (вторая волна ревью), docs-коммиты `6e12a1e`/`3a94207` (игнорированы). База сравнения — аудит `docs/reviews/2026-11-05/` (V01–V18, TEST-01…11, CONF-01…08).

Метод: только статическое чтение (Read/Grep/read-only git). Trigger-таблицы категорий D1, D1a, D2, D3, D4, D5, E6, F1, F2, F3, F4 (rust-intel testing.md + semantics-and-conformance.md) прогнаны по: инлайн `#[cfg(test)]` модулям chain/probes/quarantine/hedged/pool/rotator/strict_http, `crates/resocks5-net/tests/*`, `crates/resocks5/…/tests/*`, `tests/feature_unification`, `.github/workflows/ci.yml`, `.github/scripts/*`, контрактам README/SDK README/SECURITY.md/CHANGELOG, round-trip парам (SOCKS5 reply encode, HostPort parse/format, strict Host grammar) и lifecycle туннелей/probes/hedge.

**Никаких прогонов** (cargo, скрипты, приложение, тесты) не выполнялось; код/конфиги/зависимости не менялись; git read-only; единственная запись — этот отчёт. Статусы: VERIFIED_STATIC / PLAUSIBLE / HARDENING / TEST_GAP / REJECTED — как в предыдущем аудите.

---

## Часть A. Проверка: фиксы и тесты реально встали

Все позиции проверены чтением кода и тестов на HEAD. Регрессий не найдено; каждый пункт ниже — подтверждение механизма, повторно не репортится.

| ID | Механизм фикса на HEAD | Подтверждение |
|---|---|---|
| V01 | `ChainPlan`: `Layer.live`, `mark_dead` обнуляет `done` при `live==0`; `ChainPlan::new` помечает `done` на пустом слое. `crates/resocks5-net/src/session/chain/mod.rs:124–129,225,269–286` | Тесты с work-bound oracle через `#[cfg(test)] steps`: `fully_dead_exit_layer_ends_plan_without_sweeping_gates` (bound 13 против 81-комбо), `fully_dead_gate_layer_ends_the_plan`, positive control `one_dead_exit_keeps_remaining_exits_in_original_order`, `partially_dead_gate_layer_still_enumerates_through_the_live_gate`, `exclude_and_mark_dead_stay_independent_sets`. `selection_tests.rs:369–482` |
| V02 | Offloaded writer (`save_offloaded` на `spawn_blocking`, reclaim temp перед каждой записью), stop-протокол (`finish`: notify → join ≤FINISH_BUDGET → final save → drop lock), cross-process lock до любых записей, orphan temp recovery, baseline до post-restore probes. `crates/resocks5/src/server/health/mod.rs:282–312,346–401,417–462` | `repeated_finish_cycles_leave_a_valid_file_and_no_temp`, `a_stale_temp_from_a_crashed_run_is_reclaimed_instead_of_blocking_saves`, `finish_writes_the_final_snapshot_without_waiting_for_a_tick`, `a_temp_that_appears_midrun_is_reclaimed_before_the_next_write`, `a_held_health_lock_disables_persistence_and_touches_nothing` (полный текст warning после 6237994), `an_early_probe_result_is_still_persisted_on_a_later_round` (400 filler-групп как slow-snapshot харнесс). `writer_tests.rs`, `health/tests.rs:868–977` |
| V03 | Эксклюзивный `handshake_slot: Mutex<()>`; recheck `won` после admission; победитель публикует `won` (Release) до освобождения слота. `hedged.rs:123–130,144–178` | `holder_success_reports_tcp_ready_sibling_lost_without_connect` (сиблинг молчит 150ms пока слот занят, закрывает сокет после win; mutation-заметка: неэксклюзивный admission/нет recheck/нет publish — каждый ловится), `holder_failure_lets_waiting_sibling_perform_its_own_connect`, `slow_handshake_suppresses_second_candidate_until_first_fails`, `a_slow_target_answer_is_not_hedged` (app e2e: второй CONNECT не стартует). `hedged_tests.rs:613–806`, `tests/quarantine.rs:419–471` |
| V04 | `direct_reserve` растёт с очередью sticky (`max(candidates.len())`), chain-loop `attempts + direct_reserve < max`, hedged slice `truncate(max−attempts)`. `dial.rs:41–49,87–89,210–213,300–325` | `queued_sticky_routes_stay_within_one_launch_budget` (wire attempts ≤3 по логам + счётчикам accept; mutation: убрать рост резерва и/или clamp), `spent_budget_truncates_the_queued_sticky_slice` (mutation: убрать truncate → Ok вместо ошибки), `budget_exhausted_by_cache_failure_makes_no_further_attempts` (pick_order_calls==0). `tests/unit.rs:572–924` |
| V05 | Cached gated chain: resolve через rotator-владелец; admission проверяет quarantine каждого gate-hop; exit не ре-check (get_linked уже скрывает). `dial.rs:97–115`; `rotator/mod.rs:443–449` | `a_cached_chain_with_a_quarantined_gate_is_not_dialed` (bad_accepts==0, relink на healthy), positive control `a_healthy_cached_chain_is_still_a_cache_hit` (pick_order_calls==0, «Cache used for»), dual-exit тройка: foreign quarantine не роняет cache / собственный quarantine уводит в план / budget=1. `tests/quarantine.rs:581–961` |
| V06 | Dedup идентичных upstreams при конструкции (`same_upstream`/`upstream_hash`), один rating slot на identity. `rotator/mod.rs:85–103,384–415` | `duplicate_upstreams_collapse_onto_one_slot` (threshold1, один failure → все алиасы вне order при живом b), `near_duplicates_with_different_accounts_or_gate_levels_stay_distinct`, `single_upstream_survives_dedup_unchanged`. `rotator/quarantine_tests.rs:201–248` |
| V07 | `classify_probe_error`: только Target-stage `ProxyRejected` = HardFailure; prefix/capacity/таймауты inconclusive. `probes.rs:33–62` | Таблица классификации `classification_target_proxy_rejected_is_the_only_hard_failure` (+ mutation-заметки), интеграция `inconclusive_prefix_failure_leaves_tested_node_health_unchanged`. `probes.rs:501–636` |
| V08 | `probe_deadline`/`probe_lease` — общая helper-пара (deadline+5s margin), абсолютный deadline от claim, settlement fence `now >= lease_until → discard`. `probes.rs:64–97,122,136–151,230–242`; startup lease из той же формулы. `startup.rs:347–360` | `probe_deadline_stays_below_lease_for_several_depths`, `probe_deadline_saturates_on_huge_and_zero_inputs`, `settlement_after_lease_is_discarded` (positive control: попытка реально завершилась), `deadline_is_measured_from_the_claim`, `probe_deadline_cancels_silent_prefix_and_keeps_health_unchanged`. `probes.rs:638–976` |
| V09 | Restore/startup probes/pool refill — только `directly_dialed_rotators` (outermost gate + exits). `startup.rs:172–183,447–527`; `health/mod.rs:374–383` | `start_probes_only_the_directly_dialed_rotators` (gate_hits==0, exit_hits≥1, gate сохраняет probation). `health/tests.rs:794–865` |
| V10 | `HealthEntry.group`, restore key `(upstream, gate, group)`, legacy empty-group → применяется ко всем группам. `health/mod.rs:39–61,163–207` | `the_same_upstream_in_two_groups_keeps_two_health_cells` (оба порядка declaration), `an_old_record_without_a_group_applies_to_every_matching_group` (mutation), `signature_changes_when_only_the_group_differs`, `same_address_at_another_gate_level_is_a_different_upstream`, `a_different_user_at_the_same_address_is_a_different_upstream`. `health/tests.rs:249–378,467–510` |
| V11 | Single-node `chain_inner`: `on_tcp` обновляет progress → total-timeout после TCP = `Target`. `dial/chain.rs:304–327`; `dial/mod.rs:200–202` | `without_gate_total_timeout_after_tcp_reports_target_stage`. `chain_tests.rs:805–831` |
| V12 | `hedge_deadline` = `checked_add`, overflow → None («never hedge»), таймер не armится. `hedged.rs:217–224,331–345` | `max_hedge_delay_never_panics_and_never_hedges` (второй кандидат не запускается, 150ms negative), `max_hedge_delay_with_single_candidate_wins_without_timer`. `hedged_tests.rs:808–883` |
| V13 | CONNECT authority grammar: 3 части, без control/tab, strict version, bracketed IPv6 / host grammar (`valid_authority_host`), порт 1..=65535, нет path/userinfo/query/fragment. `strict_http.rs:84–148` | Таблица 58 reject / 25 accept + e2e «400 до auth» (path, `@`, `?`, `#`, `\`, bad pct). `server/tests/strict_http.rs:26–223,357–470` |
| V14 | CTL-байты в field values (`<0x20 && !HTAB` и 0x7F) → 400; generic для всех заголовков, включая Host и Proxy-Authorization. `strict_http.rs:176–178` | NUL/0x1F/0x7F в value и Host → reject до auth (e2e п.3–5), HTAB/obs-text — accept (positive). `strict_http.rs:117–138,204–209,390–428,455–466` |
| V15 | `take_username` → `discard_wiped` (in-place zeroize raw до free). `server/mod.rs:154–161,732–747` | Witness-тест `take_username_zeroizes_raw_bytes_before_free` (in-place zeroize, ровно один Drop; mutation: убрать wipe). `raw_credentials.rs:563–603` |
| V16 | `duration_for` — итеративное saturating doubling с cap; `deadline` = `checked_add` + FAR-fallback. `quarantine.rs:123–138,152–159` | `duration_reaches_the_cap_beyond_the_shift_limit` (trip 20/21/22/23, u32::MAX), `hard_failure_with_unrepresentable_deadline_stays_quarantined`, `retrip_with_unrepresentable_deadline_stays_quarantined`, `restore_with_unrepresentable_left_stays_quarantined`, `normal_deadlines_are_exact`. `quarantine.rs:282–519` |
| V17 | `refill_tasks` lock: spawn+publication+registration и forget под одним lock, fixed order; `won_race`. `pool/proxy_pool/mod.rs:399–460,547–560` | `forget_spawn_race_never_leaves_an_orphaned_refill_task` (200 итераций hammer + orphan-oracle по accepts), `forget_then_respawn_leaves_exactly_one_live_task` (paused clock, счётчики поколений). `lifecycle_tests.rs:22–167` |
| V18 | `reserve_permit` для tested node в chain probe; `probe_due_with`/`probe_all_with` с reserve hook для direct probes; capacity → defer без rating. `probes.rs:207–223`; `rotator/probe.rs:98–189`; `route.rs:59–91`; `startup.rs:583–586` | `capacity_of_tested_node_defers_the_probe` (accepts==0, health unchanged, затем восстановление), `spawn_due_probes_defers_at_capacity_and_recovers_once_free`, `capacity_is_a_no_op` (weights unchanged), `connect_chain_capacity_is_typed_and_composite_holds_exit_permit`. `probes.rs:831–911`; `route.rs:115–173` |
| TEST-01 | `changed-areas.sh:146–150`: `session/chain/*` → `net_f chain::` + `app_f server::` (не generic `--no-run`). | Правило на месте;_ci full текущих коммитов обходило классификатор, будущие chain-изменения теперь прогоняют engine-тесты. |
| TEST-03 | Saver-тесты переведены на `until(check)`-поллинг + `start_paused` + auto-advance fallback вместо 8 «слепых» yield. | `health/tests.rs:512–606`. Резидуал — TQ-07 ниже. |
| TEST-06 | Старые TEST-NET hedge/probe тесты заменены контролируемыми loopback-стабами с oneshot-синхронизацией (holder/sibling), где pending-TCP гарантируется. | `hedged_tests.rs` целиком; старый gap больше не применим к этим кейсам. |
| TEST-09 | Частично: lifecycle-witness для `take_username` + raw wipe тест; `Credentials` Drop-wipe остаётся без owned-witness на всех путях. | `raw_credentials.rs:522–603`. Остальное — прежний TEST-09. |
| 2c548e3 | e2e HTAB-фрейм несёт Proxy-Authorization (`strict_http.rs:455–466`); witness zeroize in place (`raw_credentials.rs:572–577`); cached-chain тест строит gate rotator с реальным 60s quarantine (`tests/quarantine.rs:597–609`). | Все три на месте. |
| b4ab336 | `ProxyRotator::try_with_quarantine` + `record_hard_failure` вместо рас.Oxypass (`quarantine.rs` setup); health-тесты поллят читаемый файл, а не любой `load()` (`health/tests.rs:310–317,731–742`; `writer_tests.rs:78`). | На месте. |
| 6237994 | lock-warning assert по полному тексту (`writer_tests.rs:55`); handshake budget 10s под Windows refused-loopback (`probes.rs:470–478`). | На месте. |

**Открытым остаётся** (не чинилось и не заявлялось): TEST-02 (fixture вне CI), TEST-04/05 (TLS drip диагностика/drop-detach), TEST-07 (вероятностный oracle `frac < 0.30` не изменён — `rotator/tests.rs:62–90`), TEST-08 (accounting matrix без soft-penalty weights), TEST-10, TEST-11 (нет release behavioral leg). Это не регрессии — повторно не репортятся, кроме TEST-02, который прямо входит в зону задания (см. TQ-03).

---

## Часть B. Findings

### TQ-01 — Low: abort-path `finish()` отпускает lock, пока in-flight blocking write ещё пишет
Статус: HARDENING (резидент V02-класса); **Новые изменения** (введено b7eab13).
`crates/resocks5/src/server/health/mod.rs:294–309` (timeout → `task.abort(); return;` — `lock` роняется при выходе), `:452–462` (`spawn_blocking` нельзя отменить).

Механизм: нормальный shutdown корректен (join до final write). Но при истечении `FINISH_BUDGET` (3s, медленный storage) цикл абортится, однако уже запущенный `save_offloaded` на blocking-pool продолжает: reclaim → create_new temp → rename. `finish` возвращается, lock освобождается. Второй инстанс: (а) Windows — `remove_stale_temp` не может удалить открытый orphan'ом temp → «could not remove», затем `create_new` падает, каждая запись фейлится, пока orphan не закончит; (б) Unix — orphan's rename публикует устаревший снапшот поверх более нового файла нового инстанса (атомарность файла не ломается, но state откатывается). Комментарий «snapshot is lost on purpose instead of racing a second writer» описывает нормальный путь; abort-путь гонку допускает.

Сценарий отказа: stalled FS >3s на shutdown + рестарт сервиса watchdog'ом → второй инстанс стартует с «could not remove»/фейлящими save или откатывает health-картину на ~round назад.

Направление: `run_saver` возвращает/хранит JoinHandle текущей `save_offloaded`; `finish` после abort awaited'ит его (тем же budget) до `drop(lock)`. Либо задокументировать loss-policy abort-пути явно.

Тест-кандидат: выделить helper «abort + await in-flight blocking write» и witness-тест порядка (await завершается до возврата finish); mutation: убрать await — witness фиксирует пересечение с drop(lock). Positive control: быстрый путь без budget-таймаута.

### TQ-02 — Low: password-различные алиасы одного endpoint схлопываются в одну health-запись при restore
Статус: HARDENING (резидуал V10, направление «нельзя писать password ради identity» подтверждено предыдущим аудитом — но policy/тест так и не появились); **Новые изменения** (group-key фикс V10 не закрыл этот случай).
`crates/resocks5/src/server/health/mod.rs:100–106` (`upstream_label` без password), `:165–169` (HashMap last-wins).

Механизм: после V06 dedup rotator держит оба entry (identity включает password), runtime health — две независимые ячейки. Snapshot пишет две записи с одинаковым `(label, gate, group)` (label = `protocol://user@host:port`), restore-HashMap оставляет последнюю, и ОНА применяется к ОБЕИМ ячейкам (`restore_health` per index); trips в файле задвоены.

Сценарий: оператор меняет пароль апстрима, обе строки временно в конфиге → обе ячейки получают одну quarantine/probation-историю после рестарта.

Направление: задокументировать ambiguity в REFERENCE + выбрать policy (first-wins / skip с warning «ambiguous health label»), тест пинит выбор. Писать password/salted hash — по-прежнему не предлагается.

Тест-кандидат: snapshot двух entries (same user, diff password) → restore → asserts по выбранной policy; mutation: перестановка порядка записей файла меняет результат — тест красный. Сейчас аналогичного теста нет (`a_different_user_at_the_same_address…` покрывает только user).

### TQ-03 — Med: `tests/feature_unification` по-прежнему не подключён к CI (TEST-02 не закрыт)
Статус: TEST_GAP; зона задания («проверь зачем и корректно ли»).
`Cargo.toml:5–7` (exclude), `tests/feature_unification/README.md`, `.github/scripts/changed-areas.sh:158–161`, `.github/workflows/ci.yml` (нет job).

Само исключение **корректно**: fixture — собственный workspace с двумя downstream-крейтами (`lean-consumer` без default features, `tls-consumer` с tls) на path-зависимости; внутрь root workspace его включить нельзя без разрушения проверяемого свойства (unification per build graph). `target/` не трекается (`tests/feature_unification/.gitignore`), `Cargo.lock` fixture трекается — `--locked` возможен. README фиксирует одноразовую ручную sensitivity-проверку (P2-01 arity, R2-P2-01 private type).

Но compile-гейт выполняется только если кто-то вспомнит локально: CI leg'а нет (изменения fixture → `net_touched` → `--no-run`, сам fixture не билдится). Обе задокументированные mutation-регрессии (E0061 arity, E0603 private) снова пройдут CI незамеченными.

Направление: один ubuntu-job: `cargo build --workspace --locked` + `cargo build -p lean-consumer --locked` из `tests/feature_unification` (~минута), триггер — изменения `crates/resocks5-net/**` или самого fixture.

Тест-кандидат (mutation, из README): вернуть `#[cfg(feature = "tls")]` на параметр `connect_proxy` — leg обязан покраснеть с E0061.

### TQ-04 — Low: у CI-job'ов test/lint/msrv/portable нет `timeout-minutes` (D4/D5)
Статус: HARDENING; **Новые изменения** (класс Windows-хрупкости, которую фиксили b4ab336/6237994, остаётся незащищённой от зависания).
`.github/workflows/ci.yml:88–102,104–117,135–148,262–307`; единственный job с бюджетом — installers (`:76`).

Механизм: libtest не имеет per-test timeout; зависший тест (в suite остались real-time ожидания до ~2.6s и poll-циклы, плюс Windows refused-loopback ~2s) держит job до GitHub-дефолта 360 минут. На self-hosted runner это дополнительно даёт LNK1104-каскад (§D5). Красный job с таймаутом сделал бы hang видимым сразу.

Направление: `timeout-minutes: 30–60` на test/portable (и на lint/msrv для симметрии); CARGO_TARGET_DIR изоляция на self-hosted — только если такие появятся (hosted — свежие VM).

### TQ-05 — Low: документация `connect_hedged` обещает «callback panic unwinds the caller» и для drain-репортов
Статус: VERIFIED_STATIC (doc-расхождение, **Новые изменения**: текст введён dfe3606/b7eab13).
`crates/resocks5-net/src/connect/proxy_connect/hedged.rs:243–244` (док) против `:317–318` (`tokio::spawn(drain(...))`) и `:204–215` (callback внутри drain).

Механизм: после победителя оставшиеся репорты доставляет отдельный task. Паник колбэка там не разматывает вызывающего — он убивает drain (JoinHandle брошен → тихо), оставшиеся репорты теряются, контракт «every launched attempt is reported exactly once» (`:239`) молча нарушается. Для coordinator-репортов (до winner) unwind — правда.

Сценарий: паникующий колбэк-логгер в app → часть Failed/Lost репортов пропадает, ratings не обновляются, без diagnostics.

Направление: уточнить док («reports delivered by the background drain swallow a panic; remaining reports are lost»), либо `catch_unwind` в drain с best-effort логом.

Тест-кандидат: колбэк, паникующий на drain-репорте; assert: caller получил `Ok`, оставшиеся репорты не доставлены — пинит фактическое (ныне недокументированное) поведение; mutation: перевод drain на прямой вызов — тест красный.

### TQ-06 — Low: исключительный handshake admission делает «TCP-живой, SOCKS5-молчащий» апстрим дороже, чем до фикса, и у него нет пути в quarantine
Статус: HARDENING (design tension, не bug); **Новые изменения** (поведение введено V03-фиксом).
`hedged.rs:156–177` (waiter держит сокет и ждёт слот весь handshake_timeout); `crates/resocks5/src/server/connect/establish_connection/tests/quarantine.rs:419–471` (задокументировано как намеренное: `other_accepts == 0`); классификация soft: `rotator/record_error.rs:14–23`, пин `tests/quarantine.rs:64–86` (Socks5Handshake timeout — не hard).

Механизм: holder, дошедший до апстрима, держит слот до исхода handshake (до 10s по умолчанию); hedge-tick в это время не запускает второй кандидат (гарантия «target не видит двух CONNECT»). Для апстрима, принимающего TCP, но не отвечающего на SOCKS5: (1) каждый запрос, где он lead, платит handshake_timeout вместо прежних hedge_delay; (2) handshake timeout классифицируется soft (ambiguity с target'ом корректна для CONNECT-фазы), поэтому трафик никогда не отправляет его в quarantine; (3) direct probe тоже вернёт Recovered (TCP-only). Итог: такой узел держится в ротации на min_weight до мягкого drain'а весов, периодически давая 10s-запросы.

Калибровка: это цена явного обещания SDK README (`no duplicate CONNECTs`) плюс корректной ambiguity-классификации; client deadline ограничивает каждый запрос. Но в diff нет ни документирования этой latency-стороны, ни смягчения.

Направление: (а) задокументировать в SDK README рядом с admission-абзацем; (б) опционально — отдельный TimeoutKind для метод-negotiation (до отправки CONNECT таймаут однозначно вина апстрима → hard), CONNECT-фаза остаётся soft.

Тест-кандидат: stub, принимающий TCP и молчащий после greeting; assert: запрос завершается handshake_timeout'ом, узел получает soft-штраф, в quarantine не попадает (пин текущего контракта); при выборе (б) — mutation-вариант с hard по greeting-фазе.

### TQ-07 — Low: startup-синхронизация saver-тестов по-прежнему через `settle()` (8 yield), а не явный ack (резидуал TEST-03, смягчён)
Статус: TEST_GAP.
`crates/resocks5/src/server/health/tests.rs:512–537,539–650,581–650`.

Механизм: `until(check)` с auto-advance fallback и последующие poll-циклы делают тесты практически устойчивыми (даже если spawned task ещё не создал interval к первому `advance`, fallback-sleeps под paused clock двигают время и тик отрабатывает). Но формального happens-before «interval создан» нет: корректность опирается на побочный эффект auto-advance и на щедрые slack'и (≥10s), что отмечено в комментарии. Оракул слабее прямого startup-ack (oneshot от `run_saver` после первого `ticker.tick().await`).

Сценарий: будущий рефакторинг `run_saver` (например, отложенная инициализация interval) не сделает тесты красными — они само-подгонятся через auto-advance и потеряют чувствительность к моменту старта.

Направление: startup-ack + per-tick ack (watch/mpsc с sequence), как рекомендовал TEST-03; затраты малы, тесты уже почти в этой форме.

### TQ-08 — Low: CI-классификатор не имеет собственных тестов; правило для `session/chain` может молча отвалиться
Статус: TEST_GAP (D4-смежный).
`.github/scripts/changed-areas.sh:146–150`; при изменении самого скрипта — full run (`:106–108`), так что refactor-ошибка внутри скрипта ловится только полным прогоном, а не таблицей ожиданий.

Направление: sh-юзабельные кейсы (подаётся EVENT/BASE/HEAD фикстурой через временный git-repo или выделенная чистая функция классификации) — по одному asserts-блоку на правило (chain → `chain::`+`server::`, server → `server:: http_proxy::`, fixture → `--no-run`). Низкий приоритет: правило молодое, full-override страхует.

---

## Часть C. Фокус заказчика

**1) Фактические баги через Tier F (claims → контрпример).** Новых VERIFIED_STATIC продуктовых багов на diff не найдено; единственные подтверждённые расхождения — TQ-05 (doc-контракт «exactly once» при панике в drain) и TQ-01/TQ-02 (граничные lifecycle/persistence-кейсы, статусы HARDENING). Контрпример-прогоны по заявкам фиксов: V01 — пример `[A0,A1]×[B0,B1]×[E]` теперь даёт 1 следующую попытку и `None` (bound 13<81 в тесте); V03 — управляемый holder/sibling показывает отсутствие второго CONNECT; V04 — счётчик wire attempts ≤3.

**2) Слепые зоны тестов.** Тайминги: оставшиеся wall-clock asserts — легитимные «timeout fires» (порог fires ≤ generous bound: `probe_deadline_cancels…` <3s, `an_unknown_dead_upstream…` <2s) либо wait-for-lease (`sleep(400ms)` после 300ms quarantine — гарантирует ≥порог по монотонным часам). Единственный нижний-bound на производительность — `a_slow_target_answer_is_not_hedged` (`took ≥ 1400ms`) — не может ложно упасть. Слабые оракулы: TQ-07 (yields), TEST-07 (не изменён), TEST-08 (не изменён). Windows: b4ab336/6237994 патчи на месте (poll за читаемым файлом `health/tests.rs:310–317,731–742`; 10s handshake budget `probes.rs:470–478`; TCO-тесты с портами 1/2 останутся медленными на Windows, но не flaky). Mutation-чувствительность новых тестов высокая — почти каждый несёт «Mutation caught»-заметку (selection_tests, hedged_tests, probes.rs, lifecycle_tests, app quarantine/unit, writer_tests). Negative controls присутствуют: strict 58-корпус rejects, auth-count==0 assertions, capacity-defers, foreign/own quarantine инверсии, orphan temp, dead-logger channel.

**3) Нехватающие boundary-тесты (конкретные кандидаты).** (а) TQ-01: abort+in-flight blocking write порядок; (б) TQ-02: same-user-diff-password restore policy; (в) hedge drop-before-winner: отменить future до победителя — все запущенные сокеты закрыты, permits возвращены, ни одного репорта (документировано `hedged.rs:244–246`, теста нет); (г) `run_saver`: файл удалён внешне при неизменной signature — до следующего изменения не восстанавливается (pin или fix); (д) `strict_http::validate` на 16KiB-границе вместе со strict (обрыв до/после заголовка) — покрытие в framing/io_failures не проверено построчно; (е) classifier rule-тесты (TQ-08).

**4) F3/F1 конформность.** Абсолютный клиентский deadline подтверждён: `ServerOptions::deadline` → `phase()` (`server/mod.rs:281–292`) — единый budget на detect/framing/auth, без renew; app якорит `Instant::now() + client_protocol_timeout_sec` на accept (`run_server.rs:172`). SOCKS5 REP-коды reply-таблицы соответствуют RFC 1928 §6 (reply.rs:48–67; unsupported CMD→REP 7, ATYP→REP 8, DOMAINNAME-invalid→REP 4). Half-close/drain: `forward_tunnel.rs:134` (upstream EOF → закрывает напр. безbusy-loop), тесты `partial_prefix_survives_upstream_half_close`;Prefixed exact-once пинится. Probe deadlines: genuinely finite (абсолютный от claim, fence по lease) — §F3 REQUIRED выполнен; direct probe — TCP-only по дизайну (док `probe.rs:13`), TQ-06 описывает цену. F1 wildcard-arms в protocol-матчах отсутствуют (`strict_http`, `socks()` ATYP/CMD репортят REP 7/8 явно; `record_error` полная таблица пинится тестами).

**5) Пахнущий код тестов (точечно).** `dual_exit`-фикстура и `spawn_counting_chained_stub` дублируются между `tests/quarantine.rs` и `tests/unit.rs` (два почти одинаковых stub'а) — candidates для общего helper; `tests/quarantine.rs:419` комментарий про «loaded parallel run» — принятый residual, задокументирован. `unique_dir` (pid+counter) — корректная изоляция, общей mutable state между тестами не нашлено (D1 чисто). `#[should_panic]` без expected не найдено (подтверждает прежний аудит).

**6) Лишние аллокации (только видимые из тестов-оракулов, низкий приоритет).** `mark_dead` клонирует `ProxyConfig` для singleton key при каждом вызове (`chain/mod.rs:270` — `Arc::new(proxy.clone())`); cold path, не оракулится тестами — вне E6-дисциплины без измерения. Прежние PERF_CANDIDATE P01–P09 не переоткрывались.

---

## Топ приоритетных

1. **TQ-03** (Med, TEST_GAP) — CI leg для `tests/feature_unification`: закрывает единственную незакрытую regression-класс с задокументированными mutation'ами.
2. **TQ-01** (Low, HARDENING) — `finish()` abort-path: await in-flight blocking write до drop(lock).
3. **TQ-06** (Low, HARDENING) — задокументировать latency-сторону «TCP-живой/SOCKS5-молчащий» при exclusive admission; опционально hard-classификация greeting-фазы.
4. **TQ-02** (Low, HARDENING) — policy + тест для password-алиасных health label (резидент V10).
5. **TQ-05** (Low, VERIFIED_STATIC) — док правка контракта репортов при панике в drain.
6. **TQ-04** (Low, HARDENING) — `timeout-minutes` на CI test-заданиях.
7. **TQ-07/TQ-08** (Low, TEST_GAP) — startup-ack в saver-тестах; rule-тесты классификатора.

Fix-верификация: V01–V18, TEST-01 — подтверждены на HEAD, регрессий не найдено; TEST-02/04/05/07/08/10/11 остаются открытыми (не заявлялись к починке; TEST-02 переоткрыт как TQ-03 в силу зоны задания).

Границы: статическая проверка; без runtime-воспроизведений, замеров, mutation-запусков и полной RFC-сверки. CI-результаты последнего прогона не проверялись.
