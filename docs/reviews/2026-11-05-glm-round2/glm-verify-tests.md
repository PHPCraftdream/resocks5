# glm-verify-tests: верификация регрессионных тестов третьего раунда — 2026-11-05

Ревизия: HEAD `af69681` (фиксы `2dd1621`, правка тестов после CI `af69681`, CI `2fe2ace`). Diff-база `c0246c3..af69681`.
Метод: только чтение кода/диффов (Read/Grep/git show); cargo/скрипты не запускались, код не менялся. Критерии — §D1/§D1a/D3 rust-intel: какую мутацию ловит тест, оракул, синхронизация, положительный/отрицательный контроль.

Заявление коммита «Fixes …, each with regression tests» — **подтверждается**: каждый пункт списка фиксов имеет тест(ы); ревертирующая мутация в подавляющем большинстве пунктов даёт красный тест. Оговорки — в «Слепые/хрупкие» и «Отсутствующие».

---

## 1. health (crates/resocks5/src/server/health)

| Фикс | Тест | Статус |
|---|---|---|
| (A) lock outlives blocking write (H1/CC-01) | `a_parked_round_write_keeps_the_lock_after_finish_gave_up` writer_tests.rs:375; `a_parked_final_write_keeps_the_lock_after_finish_returned` :433; `the_lock_is_ours_again_right_after_a_round_write_completes` :470 | TEST_OK |
| (B) dirty baseline after failed commit | `a_failed_commit_forces_a_rewrite_when_the_picture_returns` writer_tests.rs:508; vanish-вариант :568 | TEST_OK |
| (C) expiry in compared state | `a_retrip_with_identical_counters_still_writes_the_new_deadline` writer_tests.rs:607 + negative control `a_quarantine_countdown_alone_writes_nothing` :659 | TEST_OK |
| (D) duplicate/ambiguous records (DT-07, label-collision) | `duplicate_records_are_dropped_whole_with_one_warning` writer_tests.rs:689; `an_ambiguous_record_is_restored_for_no_upstream_and_warned_once` :717; save-side `aliasing_upstreams_are_saved_without_secrets_and_never_restored` :758 | TEST_OK |

Комментарий: парковка записи — продуктовый test-seam (`park_for_tests`, health/mod.rs:685), а не sleep; мутации названы в комментариях («guard only in the async owner» → :411-414 `acquire_with_timeout(...).is_err()` красный). (B)/(C) на `start_paused` + `until()` с ограничением; (C) имеет парный контроль «ход времени не пишет». af69681 честно ослабил :470 (lock освобождается после `finish`, не в момент коммита) — соответствует контракту фикса.

## 2. quarantine / rating (resocks5-net)

| Фикс | Тест | Статус |
|---|---|---|
| checked probe lease (H2/F-SDK) | `probe_lease_with_unrepresentable_length_still_excludes` quarantine.rs:548 | TEST_OK |
| probe outcomes bound to generation claim (E) | rotator: `probe_claims_go_stale_when_the_slot_changes_hands` probe_tests.rs:289, `probe_due_with_drops_a_success_that_lost_its_claim` :329, `…_failure_…` :358; ratings: `stale_probe_claims_change_nothing_after_reset_and_retrip` rating/mod.rs:733, `fresh_claim_failure_requarantines_and_soft_failures_do_not_invalidate` :772; app wire: `stale_settlement_after_a_newer_claim_is_discarded` probes_tests.rs:424, `outcome_applies_only_through_the_live_claim` probes.rs:499 | TEST_OK |
| atomic quarantine_now_unless_tripped (H3) | `quarantine_now_unless_tripped_is_a_noop_for_a_tripped_upstream` rating/mod.rs:792; `quarantine_now_unless_tripped_skips_a_tripped_upstream` probe_tests.rs:381; race-half `concurrent_quarantine_of_one_upstream_trips_once` :397 (8 real threads + barrier) | TEST_OK |

Мутации в комментариях; claim-таблица детерминирована `_at`-вариантами (приватный seam `record_hard_failure_for_at` — для виртуального времени, допустимо). `Duration::MAX`-lease: второй `try_lease` в тот же момент → `None` — ровно мутация `.unwrap_or(now)`.

## 3. destination-unreachable классификация (finding D)

| Тест | Статус |
|---|---|
| таблица `classification_only_destination_unreachable_is_a_hard_failure` probes_tests.rs:176 (REP 3-6 / 502-504 → Hard; REP 1,2,7,8,256, `None`, 403/407/500/501/505, `None`, auth/method/timeout/io, prefix-стадии, AtCapacity → Inconclusive) | TEST_OK |
| wire-negative `prefix_policy_refusals_are_inconclusive_for_the_tested_node` :282 (407/403/мусорный статус/REP 2: tested node не dialed, health не тронут) | TEST_OK |
| wire-positive `destination_unreachable_replies_retrip_the_tested_node` :356 (REP 4/5, 502/504 → trips=2, backoff×2) | TEST_OK |

Оба направления + peer-stub'ы; реверс к «всякий target-ProxyRejected — hard» и обратный («всё inconclusive») оба красные.

## 4. hedged connect (resocks5-net)

| Фикс | Тест | Статус |
|---|---|---|
| no-launch-after-win | `hedge_tick_after_published_win_does_not_launch_pending_candidate` hedged_extra_tests.rs:68 (DelayedWakes открывает tick-окно; pending listener молчит; reports == только won) | TEST_OK (см. «хрупкие»: вероятностный catch) |
| drain callback panic caught (H8) | `drain_catches_callback_panic_and_still_delivers_remaining_reports` :130 (callback паникует на 1-м отчёте; drain завершается, 2-й доставлен, invocations==2) | TEST_OK |
| caller-path unwind (отрицательный контроль к catch_unwind) | `caller_path_callback_panic_still_unwinds_the_caller` :208 | TEST_OK |
| HedgeError::source | `hedge_error_source_exposes_last_error_only` :244 (source==ConnectError, empty→None) | TEST_OK |

## 5. strict HTTP / reply / raw credentials (resocks5-net/server)

| Фикс | Тест | Статус |
|---|---|---|
| strict Host per RFC 9110 (H5/DT-01) | `strict_validate_table_rejects_and_accepts_per_rule` tests/strict_http.rs:26 — reject-строки :139-151 (`Host: h:abc`, `h:1a`, `bad/path`, `user@`, `bad%zz`, `[::1`, `a b`, `::1`, кривой IPvFuture), accept-строки :213-228 (`example.com:`, `h:000443`, `h:0`, `h:99999`, `[v1.a:b]`); e2e :263 | TEST_OK |
| http_error fallback (DT-05) | `http_error_unknown_status_falls_back_to_a_500_head` tests/credentials.rs:686 (418/0/599 → 500-head; 407/503 → пины) | TEST_OK |
| DT-06 base64/scheme strictness pin | `proxy_authorization_token_strictness_is_pinned` tests/framing.rs:150 | TEST_OK |
| DT-08 permissive target grammar pin | `permissive_targets_accept_at_slash_percent_in_host` tests/framing.rs:248 | TEST_OK |
| raw credentials байты/лимиты | tests/raw_credentials.rs целиком (non-UTF-8 raw-on/off :51/:82, split-255 `€` :153, byte-identical :208, RFC-лимиты :242, identity :354, no-leak в err/Debug :427) | TEST_OK |
| wipe | `take_username_zeroizes_raw_bytes_before_free` :565; `drop_secret_zeroizes_rejected_bytes_before_free` :626 (witness-Drop — видит память перед free); `raw_zeroize_wipes_raw_byte_vectors` :525 | TEST_OK (zeroize-gated, CI-ряд есть — см. CI) |
| «без клонов» (consume-форма) | прямой тест отсутствует — реверс к `clone()` поведенчески невидим (аллокации/незатёртая память исходного Vec) | TEST_WEAK по этой мутации; контракт байтов+wipe покрыт |

Решение по H5 зафиксировано обе стороны: CONNECT authority сохраняет 1..=65535 (строка 53 таблицы), Host = RFC `*DIGIT` без range-check (accept-строки 219-220) — док и код сходятся, тест пинит.

## 6. chain / types / greeting (resocks5-net)

| Фикс | Тест | Статус |
|---|---|---|
| GateLevels::try_new (CC-09) | `try_new_rejects_duplicate_ranks` chain/mod.rs:497 (+sort :513, empty :527) | TEST_OK (юнит); прод-путь не переключён — см. «Отсутствующие» |
| MAX_CHAIN_NODES / ChainTooLong | `validate_rejects_chains_longer_than_max_nodes` validate_tests.rs:719; boundary `validate_accepts_chain_of_exactly_max_nodes` :740; precedence `chain_depth_error_wins_over_node_errors` :750; текст ошибки без host-leak | TEST_OK |
| flat Debug gate chain | `debug_renders_the_gate_chain_flat_not_nested` proxy_config.rs:363 + deep-stack вариант (~:390, 64 узла в отдельном потоке); af69681 уточнил паттерн до `, gate: ` | TEST_OK |
| TimeoutKind::Socks5Greeting → upstream-down | `socks5_silent_greeting_yields_greeting_timeout_and_upstream_down` error/tests.rs:146; контр-тест «сталл CONNECT-reply ≠ upstream-down» `socks5_silent_connect_reply_stays_handshake_timeout_not_upstream_down` :194; dial/tests.rs:314; exhaustive-таблица classify.rs:69,157 | TEST_OK |

## 7. tunnel (crates/resocks5/src/server)

| Фикс | Тест | Статус |
|---|---|---|
| half-close в recovery (R3-I) | http: `half_closed_client_still_receives_the_server_first_banner` recovery_halfclose_tests.rs:93 (FIN долетает до target, баннер возвращён, сессия Ok), RST `client_reset_still_ends_the_session_promptly` :188, контроль unreachable :268; socks5-зеркало recover_halfclose_tests.rs:93/187/266 | TEST_OK |
| progress-aware relay (R3-H) | `slow_client_relay_outlasts_idle_window` forward_tunnel_progress_tests.rs:30 (start_paused, 1024 B по 8 B/200 ms ≈ 25.6 s виртуальных); negative `silent_client_relay_stalls_within_one_idle_window` :84 (окно 0.9-3 s виртуальных, префикс < payload); counterfactual-пара `controlled_pair_with/without_reports…` tests/progress.rs:352/:384 с instance-scoped oracle `ProgressScopeProbe` (exact == payload / == 0); dead-transport контроль :416 | TEST_OK |

af69681 добавил `client.readable().await` перед drop в RST-тестах — закрыл реальную гонку «close до записи → FIN вместо RST» правильной синхронизацией (readable-событие, не sleep).

## 8. dial budget / network bounds / accept deadline (crates/resocks5)

| Фикс | Тест | Статус |
|---|---|---|
| cached-chain budget reserve (J) | `second_cached_chain_cannot_spend_the_reserved_fallback_attempt` budget_tests.rs:107; `budget_one_still_serves_the_cache_first` :135; `ample_budget_keeps_the_cache_first` :195; `budget_one_spends_no_second_cached_chain` :242 | TEST_OK |
| network.* bounds (F-APP/G) | `validation_rejects_u64_max_seconds_and_names_the_key` network_config.rs:432 (все 9 ключей); `validation_rejects_huge_limits_and_names_the_key` :479 (4 ключа); boundary+defaults `validation_accepts_boundary_values_and_defaults` :508 | TEST_OK |
| checked accept deadline | `deadline_after_now_saturates_for_duration_max` run_server.rs:385 (u64::MAX → ≥1 год; 60 s остаётся дедлайном) | TEST_OK |

## 9. auth (crates/resocks5/src/auth)

| Фикс | Тест | Статус |
|---|---|---|
| Argon2id m=19456 | `production_params_meet_owasp_minimum` params.rs:41 — контракт-пин (внешний контракт OWASP, не тавтология по §D1) | TEST_OK |
| v19-only verify (SEC-05) | `foreign_algorithm_phc_rejected_fail_closed` verify_tests.rs:77; `old_version_phc_rejected_fail_closed` :95; `invalid_params_phc_rejected_fail_closed` :108 (m/t/p-tamper; no-migration пин m=64 verify=TRUE) — все с позитивными контролами | TEST_OK (контракт); реверт явной pre-check строки в verify.rs:232-236 поведенчески неуловим — argon2-крейт сам отвергает; это belt-and-suspenders, не дыра |
| equalised rejection (SEC-03) | `unknown_name_still_runs_hmac_and_rejects` verify_tests.rs:37; `disabled_name_still_runs_hmac_and_rejects` :49; `known_name_hmac_step_and_results_unchanged` :61 (счётчик `hmac_probe_count` через test-seam `cache_hmac`) | TEST_OK (механизм; wall-clock равность намеренно не проверяется) |
| M_KIB в тестах | `TEST_M_KIB=1024` — реальный 19 MiB путь не исполняется тестами; пин константы компенсирует | осознанный разрыв, отмечен в доке |

## 10. users_file sentinel (SEC-04/CC-08)

| Тест | Статус |
|---|---|
| `a_symlinked_sentinel_is_refused` users_file/tests.rs:390 — refusal, victim не тронут, ссылка не подменена; env без symlink-привилегии — честный skip | TEST_OK |
| `the_sentinel_holds_exactly_one_pid_line_across_acquisitions` :437 — 5 раундов, ≤16 B, ровно один pid | TEST_OK |

af69681 перенёс чтение sentinel за `drop(lock)` (Windows byte-range lock) — синхронизация корректная.

## 11. bootstrap log-drain

`shutdown_drain_flushes_queued_message_to_file` bootstrap/tests.rs:413; `file_write_error_diagnostic_names_path_and_recovery` :452; bounded teardown `runtime_teardown_is_bounded_with_a_stuck_blocking_write` :476 (измерение на границах helper-потока, hang-cap с запасом, нижняя граница бюджета) и `panic_in_body_still_tears_down_bounded_and_reraises` :565. TEST_OK.

---

## Слепые/хрупкие тесты

1. `probe_all_reports_many_dead_upstreams` probe_tests.rs:146 — wall-clock assert `elapsed < 2s` как доказательство параллельности (24 серийных probe по 150 ms = 3.6 s; запас ~1.8×). §D1: на загруженном runner возможен ложный красный; это единственный «скоростной» порог в новых тестах.
2. `client_reset_still_ends_the_session_promptly` (оба зеркала, ~:255) — `elapsed < 3s` при дедлайне 5 s: promptness-assertion допустима по §D1 (дедлайн-поведение), но запас 2 s на Windows-runner небогатый.
3. `settle()` (8×yield) в трёх negative-пинах health/tests.rs:570-571, :603, :677: направление риска — пропуск мутации (spawn_blocking-запись при регрессии может не успеть за 8 yield'ов → «nothing written» зелёный под мутацией), не false-red. TQ-07 закрыт частично: у `spawn_saver` явный started-ack, но settle остался.
4. `hedge_tick_after_published_win…` — детерминизм вероятностный (tokio random-ready: catch мутации ~1/2 за прогон; 12 прогонов → miss 2⁻¹²). Задокументировано в самом тесте; честно, но не 100%.
5. af69681 — 8 тестов третьего раунда упали на CI и правились (Debug-счётчик, rating-семантика t2=Probation, health lock-порядок, sentinel read, RST-vs-FIN, `upstreams[0]`-паники на half-written file, sleep до probation в probes.rs:499). Паттерн «agent-written tests failed on CI» повторился третий раунд подряд; каждая правка точечная и оракул стал честнее, но сам факт — маркер хрупкости первичных версий. `outcome_applies_only_through_the_live_claim` теперь ждёт probation `sleep(80ms) > 50ms` — at-least семантика делает это детерминированным (не раса), только медленно.

## Отсутствующие тесты

1. **GateLevels::try_new не подключён к прод-пути** — `crates/resocks5/src/server/bootstrap/startup.rs:385` по-прежнему вызывает `GateLevels::new` (дубликат-ранг отклоняется только debug_assert). CC-09 закрыт как API + юнит-тест, но в release-билде дубликаты по-прежнему проходят. TEST_MISSING на реальном пути (риск низкий: конфиг-ошибка, не сетевой путь).
2. **H4 same_upstream identity (gate_level)** — пин `gate_composite_maps_to_original_rating_slot` rotator/tests.rs:433 покрывает composite без rank (`gate`-поле). Мутация «добавить `gate_level` в `same_upstream`» не ловится никаким тестом rotator-уровня; асимметрия hash (включает `gate_level`, mod.rs:108-117) vs eq (не включает, :99-106) не запинена. TEST_WEAK (doc-сторона контракта приведена в порядок, half пункта glm «+ тест на identity» выполнен частично).
3. **Реверс «raw credentials → clone»** поведенчески неуловим (см. §5) — если считать no-clone частью контракта фикса, это TEST_MISSING; wipe-половина покрыта.
4. **`socks5_on_acquired` (connect_socks5_proxy.rs:~78): новый unchecked `Instant::now() + handshake_timeout`** — тот же класс, что чинили `claim_instant_plus`/`deadline_after_now`; SDK-консьюмер с огромным `handshake_timeout` получает панику. Теста нет; app-путь прикрыт network.validate. PLAUSIBLE (residual фикса, не регрессия тестов).
5. Мелочь: PHC с отсутствующим `v=` (version=None принимается `is_some_and`) — ни accept-, ни reject-пина. PLAUSIBLE.

## CI

- **feature_unification job** (ci.yml:302-319) — реальный: `cargo check -p lean-consumer --locked` + `cargo build --workspace --locked` в fixture-workspace (working-directory tests/feature_unification, отдельный rust-cache). Не «echo». H7/TQ-03 закрыт. TEST_OK.
- **timeout-minutes** — есть на всех содержательных джобах ci.yml (test 30, release-behavior 30, lint/msrv/portable 30, остальные 15, включая новые feature-unification/net-features/clippy-net-lean/doc-net-lean). TQ-02 закрыт. Хвост: `changes` и `ci-result` без таймаута (мгновенные), **release.yml — ни одной timeout-minutes** (build/release/docker/publish). TEST_OK с хвостом.
- **classifier self-test** (changed-areas.sh:70-226, запуск ci.yml:159 в structure job безусловно) — реальный: 10 кейсов × пин выходов через `CHANGED_FILES`-seam, `exit 1` при расхождении; кейсы покрывают chain/rating/rotator/net-server/generic/fixture/sdk-core/app-server/manifests/full-marker/docs-only. Удаление маппинга ловится. TEST_OK.
- **zeroize-гейтинг** — net-features матрица содержит ряды `zeroize` (`--no-default-features --features zeroize`) и `all` (`--all-features`); `cargo test -p resocks5-net` — wipe-тесты (:525/:565/:626) CI-visible, не `#[ignore]`-аналог. TEST_OK.
- Прочее из коммита: release-mode lane (`release-behavior`, реальные `cargo test --release` с тремя фильтрами — заявлен как «few fast suites», скромно и честно; workspace-wide release-прогона нет, §D3 покрыт частично), least-privilege release.yml (workflow read-only, release job `contents: write`, publish `id-token: write`), package-then-publish (`cargo package` без секрета → `publish --no-verify`). TEST_OK.

## Вывод

30/30 пунктов списка фиксов имеют регрессионные тесты; заявление «each with regression tests» подтверждено. Из них TEST_WEAK: no-clone-реверс, H4-gate_level, hedge-tick (вероятностный); TEST_MISSING: прод-путь try_new; PLAUSIBLE: unchecked deadline в `socks5_on_acquired`, version=None PHC. Тесты в целом заметно дисциплинированнее прошлых раундов: мутации названы в комментариях, виртуальное время вместо sleep'ов, witness-паттерн для wipe, counterfactual-пары, явные ack вместо yield-синхронизации — но третий раунд подряд потребовал пост-фикса тестов на CI (af69681).
