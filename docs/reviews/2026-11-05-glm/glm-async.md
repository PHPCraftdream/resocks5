# GLM async/drop-RAII аудит resocks5 — 2026-11-05

Ревизия: HEAD `6237994` (ветка fix/audit-2026-11-05), база предыдущего аудита `870caa2`. Метод: только статическое чтение (Read/Grep/read-only git); cargo, тесты, скрипты, приложение не запускались; код/конфиги/зависимости не менялись. Модули rust-intel: async.md (B2, B3, B3a, B4a, B8, B11, B15a–e, B21, B22, B23, C3, C9, E1) и drop-and-raii.md (B4). Прочитаны целиком: `connect/proxy_connect/hedged.rs`, `connect/tunnel/**`, `connect/dial/chain.rs`+`mod.rs`, `server/prefixed.rs`, `server/mod.rs` (SDK), `server/strict_http.rs`, `session/chain/mod.rs`, `session/rotator/{mod,probe,record_error}.rs`, `session/rating/quarantine.rs`, `session/pool/proxy_pool/mod.rs` (дифф), `server/bootstrap/{startup,log_drain}.rs`, `server/health/mod.rs`, `server/connect/establish_connection/{dial,probes,route,mod}.rs`, `http_proxy/**`, `logger/**`, `config/users/users_file/{mod,lock}.rs`.

## 1. Проверка фиксов V01–V18 (зона async/drop)

| V-id | Фикс встал | Проверка | Регрессия |
|---|---|---|---|
| V01 | да | `chain/mod.rs:269–286` — `mark_dead` декрементирует `layer.live`, `live==0 → done=true`; `next_pick` + `jump_subtree` корректно пропускают поддеревья; exhausted exit-слой завершает план немедленно. Дубликат ключа не может дважды декрементировать (`dead.insert` early-return). Нет | — |
| V02 | да | `health/mod.rs:452–462` spawn_blocking writer; `:282–313` stop-протокол (notify → bounded join → единственный финальный save); `:417–438` reclaim temp под lock. Найден остаточный зомби-запись — GA-01 | GA-01 (Low) |
| V03 | да | `hedged.rs:156–178` эксклюзивный `handshake_slot` (tokio Mutex), win публикуется до освобождения слота, waiter пере-проверяет `won` после захвата. Тесты `hedged_tests.rs:614,719` покрывают ровно эту гонку | нет |
| V04 | да | `dial.rs:87–89` queued sticky в `direct_reserve`, `:301,311` guard `attempts+candidates.len()`, `:325` truncate. Сценарий двух caches больше не превышает budget | нет |
| V05 | да | `dial.rs:97–115` resolve через владеющий rotator + проверка quarantine/probation всех gate-hops до dial; exit не ре-чекается (контракт get_linked сохранён) | нет |
| V06 | да | `rotator/mod.rs:389–404` дедуп по identity при构造; `index_of` collision-bucket; `same_upstream` согласован с `upstream_hash` | нет |
| V07 | да | `probes.rs:55–62` типизированный вердикт: только Target+ProxyRejected = HardFailure; prefix/capacity/таймаут — Inconclusive. Таблица покрыта тестом `:509–582` | нет |
| V08 | да | `probes.rs:71–97` общие `probe_deadline`/`probe_lease`; `:137–150` абсолютный deadline от claim; `:233–242` settlement-фенс; startup `startup.rs:347–360` берёт lease из того же хелпера — формулы согласованы | нет |
| V09 | да | `health/mod.rs:376–383` restore-probes только direct; `startup.rs:519–528` startup-check тоже только `directly_dialed_rotators` | нет |
| V10 | да | `health/mod.rs:163–207` ключ `(upstream, gate, group)`; пустой group — документированный fallback на все группы | нет |
| V11 | да | `dial/chain.rs:304–308` `on_tcp` переводит progress в Target после TCP в single-node ветке; публичный `dial` передаёт no-op (`dial/mod.rs:130`) без semver-эффекта | нет |
| V12 | да | `hedged.rs:219–224` `checked_add` → None = «never hedge»; тесты `:809,851` | нет |
| V13/V14 | да | `strict_http.rs:21–76,84–211` authority grammar до auth, Host-грамматика, CTL-байты в values отвергаются; тчары/скобочный IPv6/1–5-значный порт корректны | нет |
| V15 | да | `server/mod.rs:736–741` `discard_wiped` zeroize-in-place до `take()`; вызван из `take_username:159` | нет |
| V16 | да | `quarantine.rs:127–138` насыщающее удвоение с ранним выходом; `:154–159` FAR-fallback для deadline. Остаток того же класса в lease — GA-02 | GA-02 (Low) |
| V17 | да | `proxy_pool/mod.rs` — `refill_tasks` lock держится через публикацию очереди + spawn + регистрацию; `forget` под тем же lock; порядок lock задокументирован | нет |

## 2. Новые изменения (findings по diff 870caa2..HEAD)

### GA-01 — Low · VERIFIED_STATIC: abort saver'а не останавливает зомби-запись, lock освобождается под неё

`crates/resocks5/src/server/health/mod.rs:300–311` (`Err(_)` ветка `finish`: `task.abort(); return;` → `drop(lock)`), `:452–462` (`save_offloaded` через `spawn_blocking`), `:265–268` (комментарий FINISH_BUDGET).

Механизм: `tokio` abort не влияет на уже начавшийся `spawn_blocking` closure (§B11) — он продолжает владеть `path`/`file` и выполняет `reclaim_own_temp` + `save` после того, как `finish` вернулся и **cross-process lock снят**. Комментарий обещает «past the budget the snapshot is lost on purpose instead of racing a second writer» — это не гарантируется: запись не потеряна, она гонится с новым владельцем, который вообще не виден зомби (зомби lock не берёт).

Сценарий: shutdown при медленной записи > 3 c → timeout → abort → lock снят → в окне до завершения процесса (log-drain ≤ 5 c + teardown) стартует второй инстанс: (a) снимает stale-temp в момент, когда зомби уже создал свой temp → зомби удаляет **его** temp → его `save` падает (NotFound/AlreadyExists), серия failing-сохранений; (b) зомби коммитит **после** первого сохранения нового владельца — на диске устаревший снимок (класс V02 «stale published», новый носитель).

Направление: не освобождать lock до завершения in-flight блокирующей записи — счётчик in-flight writes + bounded `Notify`-ожидание перед `drop(lock)`; либо передавать lock (Arc) в само запись и освобождать по её завершению; при таймауте — явно помечать «файл требует recovery при следующем старте».

Тест-кандидат: под test-хуком (cfg(test) барьер внутри blocking-closure перед create_new) — стартовать saver, дождаться in-flight, `finish` с бюджетом меньше барьера, вторым `UsersFileLock::acquire_with_timeout` + `remove_stale_temp`+`save` проверить, что они не падают и их коммит финален. Positive control: быстрый writer — финальный B сохраняется. Mutation: убрать ожидание in-flight → тест ловит AlreadyExists/потерю коммита.

### GA-02 — Low · VERIFIED_STATIC: непредставимый `probe_lease` обнуляет lease вместо FAR-fallback

`crates/resocks5-net/src/session/rating/quarantine.rs:265` — `now.checked_add(policy.probe_lease).unwrap_or(now)`; контраст: `:154–159` `deadline()` для карантина использует FAR (100 лет) fallback.

Механизм: при `probe_lease`, не помещающемся в `Instant` (экзотический config: огромные connect/handshake timeouts → `probe_lease` хелпер), `lease_until = now` → lease мгновенно истекает: `take_probes` выдаёт узел повторно без эксклюзивности → шторм параллельных probes одного узла (каждая с резервом cap-пермита, GA-класс V18). Симметричный кейс для quarantine-дедлайна уже обработан FAR'ом (тесты `:452–491`).

Направление: в `try_lease` использовать тот же `deadline(now, policy.probe_lease)`-паттерн (FAR-fallback) или валидировать `probe_lease` сверху в `QuarantinePolicy::validate`.

Тест-кандидат: policy с `probe_lease = Duration::MAX` → `try_lease` дважды с одного `now`: второй должен вернуть false. Mutation: убрать FAR-fallback → lease теряется.

### GA-03 — Low · PERF_CANDIDATE: блокирующий sleep-poll acquisition lock'а health-файла в async-старте

`crates/resocks5/src/config/users/users_file/lock.rs:45–76` (`std::thread::sleep(LOCK_POLL)` цикл, sync `OpenOptions::open`), вызывается из `health/mod.rs:346` внутри async `run_server_inner`.

Механизм: при живом втором инстансе (lock держится весь ран) worker блокируется до LOCK_BUDGET=200 мс (§B11). Одноразово на старте, до поднятия listener — влияние ограничено, но это единственное место, где sync-ожидание осталось в async-контексте после фикса V02.

Направление: неблокирующая первая попытка + `tokio::time::sleep` между попытками, либо `spawn_blocking` обёртка; синхронный open sentinel — безвреден, оставить.

Тест-кандидат: не обязательный (поведение верно, вопрос только worker-времени); оракул — время возврата `start()` при зумированном holder.

### GA-04 — Low · PERF_CANDIDATE: двойная сборка gate-строки на failure-пути cached-chain; P03/P04 остаются открытыми

`crates/resocks5/src/server/connect/establish_connection/dial.rs:133–139` (`gate` собран до `match`) и `:166–172` (пересобран заново в `Err`-ветке).

Механизм: на провале кэшированной цепочки строка `h1 -> h2` собирается дважды (первая — мертвая нагрузка); обе — до вызова lazy `logger.attempt`/`proxy_failure` (P04-класс: eager format до admission). Также в этой же зоне остаются P03-клоны (`server/mod.rs:350,361,374–380`: `user.clone()`/`password.clone()`/`identity`/`username_raw.clone()` — до 3 лишних String/Vec на auth) и P02-клоны ключей (`dial.rs:78–80,305–307` — `ProxyConfig::chain` + `ChainKey::new` на каждый candidate каждый запрос). Это подтверждение «не исправлено», не новый дефект.

Направление: собирать `gate` внутри замыканий логгера (или один `gate` пере-использовать в обеих ветках); P03 — move-семантика после одной identity-копии; P02 — reuse `key.exit`/singleton Arc.

Тест-кандидат: scoped allocation counter на cached-chain failure (см. оракулы P01–P04).

### GA-05 — Low · HARDENING: detached spawn'ы без «detached by design»-комментария (§B21)

`crates/resocks5/src/server/connect/establish_connection/route.rs:59` (`spawn_due_probes` — JoinHandle сброшен), `:131` в `crates/.../establish_connection/probes.rs` (`tokio::spawn` на каждый chain-probe, handle сброшен). Задачи самотерминальные и безрезультатные — поведение корректно, но REQUIRED-артефакт B21 (явное «fire-and-forget: detached by design — task terminates after N probes») отсутствует; следующий читатель не отличит намеренный detach от потерянного handle (ср. V17). Аналогичный spawn в `hedged.rs:318` покрыт doc-контрактом `connect_hedged` — ок.

Направление: однострочные комментарии на обоих сайтах (или возвращать JoinHandle в test-варианте).

### GA-06 — Low · TEST_GAP: shutdown-зомби и второй владелец lock не покрыты тестами

Прямое следствие GA-01: ни `health/writer_tests.rs`, ни `health/tests.rs` не моделируют «блокирующая запись in-flight при `finish` + второй владелец». Плюс нет негативного теста на `try_lease` с вырожденным lease (GA-02). Конкретные кандидаты — в GA-01/GA-02. Отдельно: поведение «Windows показывает файл мгновенно отсутствующим при replace» (`b4ab336`) принято в тестах поллингом — в production `load()` читается только до старта writer'а, гонки читатель/писатель нет; тест-долга нет.

## 3. Фокус заказчика

1. **Лишние аллокации/клоны на hot path**: GA-04 (gate×2, P03 raw-auth клоны не исправлены, P02 ключи цепочек на каждый запрос). Нового сверх P02–P04 не найдено.
2. **Ускорение типов/представлений**: без нового; `StickyCache` (recency/expiry BTreeSet + generation) корректен и O(log C); `index_of` O(1)-bucket с collision-сравнением без клонов — ок.
3. **Алгоритмическая сложность**: V01-фикс устраняет экспоненту; новый O(...)-роста не найден. O(ΣN) scan'ов per request (`spawn_chain_probes` при каждом `establish_connection`, `dial.rs:64–72` → `probe_due_with` → `take_probes`) — это прежний P07, не изменился.
4. **Прочие ускорения**: GA-03 (200 мс sleep-poll на worker'е, startup-only). Serial awaits в `dial.rs` (cached chains последовательно) — след budget-порядка, не дефект. Hedge: 3 пустых `spawn_due_probes`-задачи на запрос даже при выключенном quarantine (threshold=0, всё равно `tokio::spawn`×3) — микрозатрата, кандидат на early-out по флагу (Low).
5. **Граничные условия без тестов**: GA-06 (зомби/второй владелец; вырожденный lease). Дополнительно: `valid_host_value` не покрыт кейсом `%`-escape в конце хоста (`ex%4` → отвергается, `ex%41` → принимается literal — поведение верное, теста нет; Low).
6. **Фактические баги**: GA-01 (механизм+сценарий выше; единственный новый с реальным отказ-сценарием), GA-02 (только при вырожденном config).
7. **Пахнущий код**: GA-05 (без комментариев detach); `outcome()` в `probes.rs:158–176` логгирует «reachable again» через `proxy_failure`-канал (смысловая путаница каналов, не дефект); дублирование gate-строки (GA-04).

## 4. Отрицательные результаты (проверено — чисто)

- B2: ни одного guard'а (std Mutex/DashMap/Ref) через `.await` в затронутых модулях; `StickyCache`/`refill_tasks` — sync-only; `handshake_slot` — tokio Mutex по правилу §B2.
- B3/B23: cancel-safety задокументирована на границах (`accept/socks/http/reply`, `Prefixed`, `peek_recovery`, `tunnel_with_timeouts`, `connect_hedged`, `dial_chain_over`); side effects в select-arms отсутствуют; pinned futures пере-используются, не пересоздаются (`tunnel/mod.rs:104–127`, `hedged` sleep_until с абсолютным instant).
- B15e: `run_saver` поглощает первый тик + `MissedTickBehavior::Delay`; `biased;` там, где приоритет важен; single-consumer `Notify` без церемонии — корректно.
- B21: `run_saver` handle held+awaited/aborted; drain'ы намеренно detached (кроме GA-05-комментариев); Periodic-владельцев через сильный Arc не найдено.
- B22: async-Drop не появился; `IncomingRequest::drop` — sync wipe-in-place (V15); `UsersFileLock::drop` — sync unlock, sentinel не удаляется (flock-unlink race задокументирован).
- B4: `write_atomic` — explicit sync_all до commit, error-path удаляет temp; commit-после-ошибки undetermined задокументирован; health reclaim не трогает users-recovery temp.
- B3a: `run_saver` на persistent error не спинится (tick-bounded, log-once) — livelock-паттерна нет.

## 5. Топ приоритетных

1. **GA-01** — зомби spawn_blocking-запись после abort гонит нового владельца health-файла под снятым lock (ед. новый отказ-сценарий; исправление — освобождать lock после in-flight).
2. **GA-06** — TEST_GAP к GA-01 (+GA-02 lease-граница).
3. **GA-02** — `try_lease` unwrap_or(now) при непредставимом lease — потеря эксклюзивности probe.
4. **GA-03** — блокирующий lock-acquire в async-старте (worker до 200 мс).
5. **GA-04/GA-05** — точечные перф/гигиена: двойная gate-строка, P03/P04 без движения, detach-комментарии.
