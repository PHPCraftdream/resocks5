# glm: верификация фиксов третьего раунда — 2026-11-05

Ревизия: HEAD `af69681` (фиксы `2dd1621`, тестовые правки `af69681`, CI-only `2fe2ace`); база `c0246c3`. Diff `c0246c3..HEAD`.

Метод: только чтение (Read/Grep/git diff). Cargo/скрипты/приложение не запускались — всё в GitHub CI. Код/конфиги/зависимости не менялись. Каждое заявление из сообщения `2dd1621` сверено с кодом, не с текстом коммита. Fix-код прогнан по категориям rust-intel (async, concurrency-and-state, security, drop-and-raii, data-and-types).

Статусы: VERIFIED — механизм подтверждён чтением; PARTIAL — частично; NOT_FIXED — не сделано; REGRESSION — новый дефект (механизм+сценарий).

## 1. Верификация по пунктам

### H1/CC-01 — health `finish` не останавливал spawn_blocking — VERIFIED

`crates/resocks5/src/server/health/mod.rs:346` (`lock: Option<Arc<UsersFileLock>>` в `HealthSaver`), `:560-580` (`save_offloaded`: `Arc`-клон лока уходит ВНУТРЬ blocking-замыкания, `let _health_lock = lock;` :564 — OS-лок держится до фактического конца записи), `:390-402` (таймаут `FINISH_BUDGET` → `task.abort()`, лог, ранний return БЕЗ финальной записи; лок живёт в orphan-записи), `:587-611` (`save_final` только после успешного join задачи — наложения с финальной записью нет).

Гонка glm-находки устранена сменой владельца лока: orphan-запись дорабатывает ПОД локом (второй инстанс не может ни захватить лок, ни трогать temp — `remove_stale_temp`/`reclaim_own_temp` только под локом, `:491-493`, `:522-543`). Инвариант single-writer восстановлен. dirty baseline: `run_saver` `:796-806` — на Err `last = None`, следующий раунд пишет всегда; тесты `writer_tests.rs:508,568` (commit-неопределённость Publish/Vanish), `:607` (re-trip с идентичными счётчиками пишет новый дедлайн), `:659` (один countdown не пишет). Expiry в compared state: `unchanged` `:166-172` сравнивает абсолютный дедлайн `saved_at + remaining_sec` (допуск ≤ интервала сохранения), `deadline()` `:177-183`. Duplicate/ambiguous restore: `:204-260` (дубликат ключа отбрасывается целиком с одним warning; ключ с >1 живым апстримом группы, отличающимися только секретом, никому не восстанавливается) — тесты `writer_tests.rs:689,717,758`. Orphan-сценарий покрыт `writer_tests.rs:375,433` (parked blocking write держит лок после `finish`, contender не допускается до реального конца записи).

Замечание (не дефект): эвристика `unchanged` — re-trip с идентичными счётчиками, чей новый дедлайн попадает в пределы `every` от старого, пропускает запись до смены state; в файле остаётся устаревший (более короткий) дедлайн, после рестарда — ранний probation. Дрейф ограничен одним интервалом сохранения, поведение задокументировано в доке `unchanged` частично («moves it far enough» — не всегда).

### H2/CC-02 — `try_lease` overflow — VERIFIED

`crates/resocks5-net/src/session/rating/quarantine.rs:154-159` — единый helper `deadline()`: `checked_add` с FAR-fallback (100 лет), `.unwrap_or(now)` убран; `try_lease` `:287` использует `deadline(now, policy.probe_lease)` — непредставимый lease больше не даёт мгновенно истекающий слот; тот же helper в `hard_failure`/`trip_now`/`restore` (асимметрия с `deadline()` устранена). Тест `quarantine.rs:548-564` (`probe_lease = Duration::MAX` → второй `try_lease` в тот же instant = `None`).

### H3/CC-03 — probe double-trip / stale outcomes — VERIFIED

Три под-механизма:
1. Generation claims: `Cell.generation` (`quarantine.rs:169-171`), bump в `hard_failure`/`trip_now`/`restore`/`success`/`try_lease`; `take_probe_claims_at` `rating/mod.rs:392-406` выдаёт `ProbeClaim{index, token}` при гранте lease; `record_success_for` `:178-192` и `record_hard_failure_for_at` `:203-218` проверяют `generation() == claim.token` ПОД ТЕМ ЖЕ локом перед применением. Тесты `rating/mod.rs:733-785` (stale success/failure меняют ничего, fresh claim применяется), мутационные комментарии на месте.
2. Atomic `quarantine_now_unless_tripped`: `rating/mod.rs:241-252` — check `is_tripped` + `trip_now` в одном захвате мутекса; rotator-обёртка `rotator/mod.rs:587-590`; `probe_all_with` использует её в drain (`rotator/probe.rs:188`). Гонка H3 (is_quarantined → record_hard_failure → quarantine_now = backoff ×2) закрыта. Тесты `rating/mod.rs:792-830` (включая 8-поточный race: ровно один trippit, trips==1).
3. Destination-unreachable только про тестируемый gate: `crates/resocks5/src/server/connect/establish_connection/probes.rs:57-80` (`classify_probe_error`: HardFailure только `ChainStage::Target` + SOCKS REP 3..=6 / HTTP 502..=504; 407/403, REP 2, `code: None`, любые prefix-stage ошибки — Inconclusive); `probe_chain` `:240-310` применяет исход через claim, при capacity — defer без rating change (`reserve_permit` :256-268), дедлайн от claim-instant (`:152`, `claim_instant_plus` :102-111, бюджет `probe_deadline` :89-96 < lease `probe_lease` :124-130 с общим `PROBE_LEASE_MARGIN` :117).

Соседнее: `probe_due_with` берёт claims до reserve/spawn (`:120-132`), at-capacity → no task, lease истекает естественно (задокументировано `:97-110`). Ок.

### H4/CC-04 — `same_upstream` doc≠код — NOT_FIXED

`crates/resocks5-net/src/session/rotator/mod.rs:90-106` — док по-прежнему утверждает «`gate` is deliberately excluded … rating a gate-composite still lands on the plain upstream's slot», а код по-прежнему сравнивает `a.gate_level == b.gate_level` (:102) и включает `gate_level` в `upstream_hash` (:108-117). В `c0246c3..HEAD` ни док, ни код этого блока не менялись (весь diff rotator/mod.rs — 92 строки, только claim-plumbing H3). Противоречие воспроизведено на HEAD. Замечание о серьёзности: в dial.rs record-пути получают plain-конфиги (`candidate.proxy`), gate-composite идёт через `gates.resolve`/`pick.record_success()`, поэтому наблюдаемое расхождение ограничено рассинхроном семантики документа, а не доказанным багом квоты — но находка glm не закрыта ни на одной из двух сторон.

### H5/DT-01 — strict Host порт — VERIFIED (контракт определён через док, обе стороны сведены)

`crates/resocks5-net/src/server/strict_http.rs:73-78` — док теперь фиксирует контракт: Host per RFC 9110 §7.2 = `uri-host [ ":" port ]`, `port = *DIGIT`, БЕЗ range-check («the 1..=65535 rule is the CONNECT authority policy, not Host syntax»); `valid_host_value` `:79-100` этому соответствует (пустой порт и любая цифра допустимы, `[v1.a:b]` IPvFuture, bare-IPv6 без скобок отклоняется). CONNECT-authority путь ДОБАВИЛ range-check `:163-172`: длина ≤5, parse u32, 1..=65535; Host-грамматика объявлена намеренно иной и приведена в соответствие с RFC 9110. Противоречие doc≠код из находки устранено пересмотром контракта (законная сторона: glm предлагал «определиться, какая сторона — контракт»). Тесты `server/tests/strict_http.rs`: `h:0`, `h:99999`, `[::1]:0`, `h:000443` — валидны; `h:abc`, `h:1a` — 400; authority `h:0` — отвергается.

### H6/API-02/03/06 — raw credentials без клонов + wipe + zeroize — VERIFIED

`crates/resocks5-net/src/server/mod.rs:298-306` — `decode_raw_field(Vec<u8>)`: consume-форма, валидный UTF-8 конвертирует аллокацию на месте, невалидный возвращает исходные байты из `FromUtf8Error::into_bytes()` — клон исчез; `:312-318` — `drop_secret` (zeroize под feature, plain drop иначе); `:381,392` — отклонённые буферы username/password протираются до free. `Credentials::with_raw` (`credentials.rs:27-39`) принимает всё by value; оставшийся `username.clone()` на :397 — необходим (identity + Credentials), raw-клонов больше нет. `Credentials` wipe-on-drop под zeroize (`credentials.rs:111-116`). API-06: `crates/resocks5/Cargo.toml:20` — `zeroize` включён в фичах resocks5-net → wipe активен в бинарнике; `resocks5-net/Cargo.toml:57,83` — фича/опц. dep корректны. Тесты `server/tests/raw_credentials.rs` (+52).

### H8/TQ-05 — hedged drain-паника + `HedgeError::source` — VERIFIED

`crates/resocks5-net/src/connect/proxy_connect/hedged.rs:212-227` — `drain` оборачивает `report` в `catch_unwind(AssertUnwindSafe)`, паника callback в detached drain перехватывается, оставшиеся репорты доставляются; док `:251-257` обновлён (caller-path panic unwinds, drain-path caught). `:125-129` — `HedgeError::source()` возвращает `last` (API-L03 закрыт). Бонус-механизм «no launch after a published win»: hedge-tick проверяет `!race.won` перед запуском `:350-359`, win публикуется до освобождения handshake-slot (`attempt` :180-184) и до spawn drain (`:329-334`; drain только если `!running.is_empty()`). Тесты `hedged_extra_tests.rs` (+267).

### CC-09 — `GateLevels` debug_assert → Err — PARTIAL

Механизм добавлен: `crates/resocks5-net/src/session/chain/mod.rs:53-64` — `GateLevels::try_new` + `GateLevelsError{duplicated_rank}` (sort → windows(2) → Err), `new` сохранён с честным доком («rejected only in debug builds»); тесты `chain/mod.rs:481+` (reject/sort/empty, мутационные). НО единственный прод-вызов `crates/resocks5/src/server/bootstrap/startup.rs:385` по-прежнему использует `GateLevels::new` — в release дубликаты там не отклоняются try_new. Практический риск закрыт построением: вход `gate_groups` — результат `group_gate_levels` (группировка по рангу через map, `startup.rs:145-153`), дубликаты рангов невозможны по построению. Итог: Err-API есть, но контракту «Err как у политик» прод-путь удовлетворяет только косвенно; для прямых API-пользователей try_new корректен.

Сопутствующее из того же пункта заявлений — VERIFIED: `MAX_CHAIN_NODES = 64` (`types/validate.rs:12`), `ChainTooLong` в `validate()` (`:240-249`, тесты `validate_tests.rs:720-760` вкл. границу ровно 64); flat Debug цепочки без рекурсии (`types/proxy_config.rs:163-197`, NodeDebug/GateChainDebug + тест на 256 KiB стеке с 64 узлами).

### DT-05 — `http_error` unreachable — VERIFIED

`crates/resocks5-net/src/server/reply.rs:47-49` — fallback `RESP_500` вместо `unreachable!`; новое значение u16-домена деградирует до 500 вместо паники на сетевом пути.

### SEC-03 — timing-enumeration verify — VERIFIED (заявленный уровень)

`crates/resocks5/src/auth/state/verify.rs:44-47` — unknown/disabled → `reject_equalised`; `:153-162` — тот же дешёвый HMAC-шаг (`cache_hmac`), затем constant-time `DUMMY_HMAC.ct_eq` (subtle), результат отброшен, `false`. Гарантия честно ограничена доком `:18-26`: Argon2 cache-miss путь НЕ выравниван (осознанно — цена CPU). DUMMY_HMAC ровно 32 байта. Test-seam `hmac_probes` (`state/mod.rs:131-141`, `state/probes.rs:14-16`) — только `#[cfg(test)]`.

### SEC-04/CC-08 — sentinel `.lock` — VERIFIED (с задокументированным остатком)

`crates/resocks5/src/config/users/users_file/lock.rs:61-77` — перед open `symlink_metadata` (не следует по ссылке): reparse point (win, `:21-29`) / symlink (unix, `:32-35`) → отказ; `:80-86` — `create(true)` + `truncate(false)`, truncate только ПОСЛЕ победы `:90-97` (`set_len(0)` + одна pid-строка) — монотонный рост устранён. Остаток: TOCTOU stat→open остаётся (std без O_NOFOLLOW) — задокументировано в комментарии `:63-65`; окно уже прежнего (open больше не следует по ссылке в нормальном пути). Drop не удаляет sentinel (flock-unlink race, `:118-129`) — корректно.

### Argon2 — m=19456 / v19 verify-only — VERIFIED

`crates/resocks5/src/auth/params.rs:15-17` — `M_KIB=19456, T=2, P=1` (OWASP minimum; тест-пин `:41-45`), verify читает m/t/p из PHC-строки (без rehash-on-login — задокументировано `:9-14` и `auth/mod.rs`). `verify.rs:228-241` — `argon2_verify` fail-closed: `ARGON2ID_IDENT` и version 0x13 (или absent), иное (argon2i/v16) → `false`. Доки/тесты обновлены (`auth/mod.rs`, `user.rs`, `run_user_command.rs` — m=19456). SEC-05 negative-контроли: `verify_tests.rs` (+127).

### tunnel — half-close в recovery + progress-aware relay — VERIFIED

Half-close («R3-I»): `crates/resocks5/src/server/tunnel/recovery.rs` — три пути client-EOF: grace-путь `:78-85` (`half_closed_upstream`: додial по IP → `upstream.shutdown()` (проброс FIN) → `banner_after_fin`), post-grace `:91-103` (EOF в select возобновляет прерванный dial `:98`), live-upstream `:113-133` (FIN пробрасывается, greeting ждётся). Read-ошибка (RST) НЕ маппится на half-close — тест `:378-401`; unreachable upstream — прежний чистый close `:143-150`, тест `:360-372`. Оба вызывающих (`http_proxy/.../recovery.rs:53-57`, `handle_socks5_client/recover.rs:43-48`) обновили комментарий `ClientClosed`; `banner_after_fin` без своего таймаута, но весь `peek_recovery` обёрнут остатком client-protocol бюджета (оба вызова: `Err(budget)` arm — Deadline). Тесты `recovery_halfclose_tests.rs` (+338), `recover_halfclose_tests.rs` (+334).

Progress-aware relay: `crates/resocks5/src/server/tunnel/forward_tunnel.rs:139-161` — server-first блок вынесен из select-шага; `write_with_idle_windows` `:206-241`: свежее окно idle на каждый `write`-attempt, каждый принятый чанк обновляет прогресс, окно без принятого байта → `Ok(false)` → терминально, без replay (R3-02); `Ok(0)` → WriteZero (семантика write_all), `Duration::ZERO` disables. Регресс-проверка прежнего поведения: раньше медленный клиент на большом блоке ловил idle-таймаут внутри write_all (отмена с частично ушедшими байтами) — теперь это штатный прогресс. Cancel-safety задокументирована (`:198-200`). Тесты `forward_tunnel_progress_tests.rs` (+135).

### dial — бюджет cached chains / network bounds / accept deadline — VERIFIED

`crates/resocks5/src/server/connect/establish_connection/dial.rs:44-49` — `direct_reserve` (1 при живом direct-rotator, поднят до числа queued sticky `:89`); `:120-127` — cached-chain admission `attempts + direct_reserve < max_attempts || (max_attempts == 1 && attempts == 0)`: несколько sticky-цепочек больше не съедают зарезервированный direct-попыток; `max_attempts==1` остаётся cache-first (намеренно); прежний ранний `return Err` заменён на `continue` с падением до hedged-пути — суммарные попытки ограничены, прямой фолбэк гарантированно получает свой слот (трассировка max=2/3 сходится). Тесты `budget_tests.rs` (+263).

`network.* bounds`: `config/main/network_config.rs:285-339` — `MAX_TIMEOUT_SEC=86400`, `MAX_TIMEOUT_MS`, `MAX_LIMIT=1<<30` (Semaphore-panic-граница), все 9 timeout-ключей + hedge_delay_ms + 4 лимита; вызов `run_server.rs:66-71` до bind; мутационные тесты `network_config.rs:431-503` (u64::MAX/usize::MAX называют ключ).

Checked accept deadline: `run_server.rs:40-47` — `deadline_after_now` (checked_add с far-future stand-in 100 лет), `:188` — вместо сырого `now + Duration`; тест `:379-403` (u64::MAX не паникует, обычное значение остаётся дедлайном). Двойная линия защиты с validate — корректно.

### CC-10/GA-05 — каналы probe-сообщений и detached-комментарии — VERIFIED

`route.rs:68-73` — `Recovered` через `logger.lifecycle` (был proxy_failure); re-quarantine остаётся на proxy_failure. `probes.rs:192-222` (`outcome`) — то же разделение для chain-probes. Detached-by-design комментарии: `route.rs:59-61`, `probes.rs:161-163`.

### TimeoutKind::Socks5Greeting как upstream-down — VERIFIED

`error/mod.rs:44-54` (новый kind с доком), `connect_socks5_proxy.rs:65-97` — единый абсолютный дедлайн (`timeout_at`) на greeting+CONNECT: stall greeting → `Socks5Greeting` (CONNECT ещё не отправлен — виноват upstream), stall reply → `Socks5Handshake`; `handshake_over_stream.rs:50-90,151-175` — расщепление на `socks5_greeting`/`socks5_connect_request` (композиция `socks5_handshake` сохранена, pre-write target-чеки перенесены раньше — те же отклонения); `classify.rs` — `is_upstream_down` включает `Socks5Greeting` с док-обоснованием и мутационными тестами. Полный handshake-бюджет не изменился (один дедлайн на обе фазы) — соседнее поведение сохранено.

### API-01 — грамматики parse_proxy_str/validate — VERIFIED (doc-side fix)

Расхождение не устранено унификацией, а зафиксировано как контракт: `parse_proxy_str.rs:49-58` («# Leniency»: ` host:80`, порт 0 парсятся; `validate` — строгие ворота; dial validate НЕ вызывает), `host_port.rs:34-38` (host-байты не грамматик-чекаются: `@`,`/`,`%` проходят — SOCKS DOMAINNAME/permissive HTTP; strict HTTP строже; DT-08 закрыт док-комментарием и в `server/mod.rs:454-457,628-629`), `validate.rs:207-214` (зеркальная ссылка). Тесты-пины: `parse_proxy_str.rs:294-330` (lenient vs strict таблица; IPv6 parse≡validate), `host_port.rs:127-141` (мутация: allowlist в parse ломает тест). Это законное разрешение находки (документирование осознанного расхождения).

### TQ-04 / CI — VERIFIED

`ci.yml`: `timeout-minutes` на всех job (test/release-behavior/msrv/portable 30, lint/structure/doc/net/clippy/deny/licenses/feature-unification 15). Новый `feature-unification` job (`ci.yml:294-320`): `cargo check -p lean-consumer --locked` + `cargo build --workspace --locked` в fixture-workspace, гейт `run_unification` из классификатора; включён в `needs` check-суммы (`:443`). Classifier self-test: `structure` job запускает `changed-areas.sh --self-test` (скрипт `:63-228`: таблица кейсов, включая `run_unification`/`run_release_lane`). Release lane: job `release-behavior` (release-profile тесты budgets/stages/parsers, гейт `run_release_lane`). `release.yml`: least-privilege (топ `contents: read`, `contents: write` только в release-job), `persist-credentials: false` на checkout'ах, package-then-publish: `cargo package --locked` + проверка .crate БЕЗ секретов в среде, затем publish `--no-verify` (токен только в env шага) — заявленное в коммите подтверждено. `2fe2ace` — только YAML-кавычки в release lane, кода не трогает.

### zeroize включён / ProgressScopeProbe — VERIFIED

`resocks5/Cargo.toml:20` — фича включена (см. H6). `session/progress.rs:200-322` — `ProgressScopeProbe` только под `test-instrumentation`, чистый pass-through (observe до/после каждого poll_write/vectored/flush/shutdown), instance-scoped oracle против глобального загрязнения; прод-код не затронут.

### af69681 (тестовые правки) — чисто

Единственная продуктовая правка — рефакторинг `record_hard_failure_for` → `record_hard_failure_for_at(claim, now)` (`rating/mod.rs:199-218`): прод-путь передаёт `Instant::now()`, поведение идентично; остальное — тесты (probation-ожидание, sleep до probation, Debug-подсчёт `, gate: `, rustdoc-ссылка `fn@crate::connect::parse_proxy_str`). Регрессий нет.

## 2. Новые дефекты в fix-коде

REGRESSION-уровня не найдено. Замечания (ниже порога дефекта, все с ограниченным радиусом):

1. `health/mod.rs:166-172` — эвристика `unchanged`: re-trip с идентичными счётчиками и новым дедлайном в пределах `every` от старого пропускает запись; в файле остаётся более короткий устаревший дедлайн до смены state (дрейф ≤ одного интервала сохранения; после рестарда — ранний probation на величину дрейфа). Осознанный trade-off, в доке функции отражён частично.
2. `establish_connection/probes.rs:210-221` + `:284-290` — probe-неудача, применённая, но не триппнувшая (threshold > 1), логируется как «settled stale - result discarded, health unchanged», хотя sand/consecutive обновлены. Книга состояний корректна; вводящий в заблуждение лог. Достижимо только при повышении threshold на живом процессе.
3. `quarantine.rs:154-159` — FAR-fallback 100 лет сам может переполниться при `now` у края диапазона `Instant` (fallback-цепочка кончается `.unwrap_or(now)` — возврат мгновенно истекающего дедлайна). Требует одновременно API-конфига с `Duration::MAX` и часа X платформы; конфиг-путь закрыт `network.validate` (86400 s). Угол случая.
4. `users_file/lock.rs:63-66` — TOCTOU между `symlink_metadata` и `open` остаётся (задокументировано: std без O_NOFOLLOW). Hardening, не аиртайт; окно много уже прежнего.

## 3. Нераскрытые пункты

1. **H4/CC-04 — NOT_FIXED.** `same_upstream` doc («gate deliberately excluded») vs код (`gate_level` сравнивается и хэшируется) — ни док, ни код не тронуты в `c0246c3..HEAD` (`rotator/mod.rs:90-117`). Формулировка из коммита «connect_hedged/strict/raw…» этот пункт не заявляет; в сводке задачи он приписан к rotator/mod.rs (+60), но +60 — это целиком claim-plumbing H3.
2. **CC-09 — PARTIAL.** `GateLevels::try_new` добавлен и протестирован, но прод (`bootstrap/startup.rs:385`) не переключён; безопасность опирается на уникальность рангов в `group_gate_levels` (map-группировка), а не на Err-путь. Для external API — закрыто, для прод-инварианта — косвенно.
