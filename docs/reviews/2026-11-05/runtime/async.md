# Аудит async и cancellation — 2026-11-05

Исследователь: агент `@oh`, `async.md`. HEAD `870caa2bfa9b6afd8594fabe4df9659bca585760`, приоритет `c927e71..HEAD`. Результат агента сохранён основным сеансом: окружение агента запретило запись Markdown. Продукт не менялся, никаких прогонов и измерений. Findings ниже статически подтверждены агентом; независимая проверка и дедупликация — в сводке.

## Findings

### ASYNC-01 — Синхронный health writer обходит bounded shutdown и допускает конкуренцию writers

P1 для bounded shutdown, confidence High.

Места: `crates/resocks5/src/server/health/mod.rs:292`; `crates/resocks5/src/server/bootstrap/startup.rs:525–527`; `crates/resocks5/src/config/users/users_file/mod.rs:99–153`.

Saver вызывает синхронные serialization/fs/write_all/sync_all/commit внутри async task. При задержке storage worker блокируется; abort не прерывает syscall. Shutdown выполняет `abort(); save_now()` синхронно до достижения `runtime.shutdown_timeout`: пятисекундный runtime teardown эту часть не ограничивает. Если saver уже создал фиксированный `.tmp` со старым снимком, финальный save может отказать на существующем temp, а продолжающийся saver — закоммитить старый снимок.

Решение-кандидат: единственный владелец persistence и bounded blocking worker; shutdown handoff последнего снимка и ack с бюджетом, без второго writer. Timeout вокруг spawn_blocking не отменяет начавшийся syscall; bounded-exit policy должна это учитывать.

Тест-кандидат: управляемый writer после создания temp; сменить health, начать shutdown, проверить ограниченный возврат, отсутствие параллельного writer, последний snapshot при штатном завершении. Mutation: inline sync_all либо abort+save_now.

### ASYNC-02 — Restore health запускает прямые probes внутренних gates

P2, High. Места: `crates/resocks5/src/server/health/mod.rs:242–247`; `crates/resocks5/src/server/connect/establish_connection/route.rs:49–57`; `crates/resocks5-net/src/session/rotator/probe.rs:42–45`.

Все rotators после restore передаются обычному probe_due. Внутренний B за внешним A проверяется прямым TCP с сервера вместо healthy_prefix/connect_chain. B, доступный только через A, штрафуется; обратная топология может ошибочно восстановить B. Прямой probe раскрывает адрес сервера диагностическому узлу.

Решение: restore не dispatch-ит topology-blind probes; единый topology-aware dispatcher, прямой dial только outermost и exits.

Тест: восстановить B на probation; запретить direct B, разрешить путь A→B; проверить обращение к A и восстановление B. Обратный случай тоже. Mutation: обычный цикл spawn_due_probes по всем rotators.

### ASYNC-03 — Lease chain probe короче полного handshake budget

P2, High. Места: `crates/resocks5/src/server/bootstrap/startup.rs:337–352`; `crates/resocks5/src/server/connect/establish_connection/probes.rs:48–109`; `crates/resocks5-net/src/connect/dial/chain.rs:365–373`; `crates/resocks5-net/src/session/rating/quarantine.rs:239–247`.

Lease = connect + один handshake + 5 секунд, defaults 25 секунд. Три успешных hop по 9 секунд уже занимают 27 секунд. Выдаётся повторный probe того же узла, пока старый активен; settlement без generation позволяет старому результату отменять новое состояние.

Решение: абсолютный whole-probe deadline, согласованный с lease, и generation/token при settlement. Тест: управляемые часы/handshakes, граница lease, late result предыдущего поколения, cancellation владельца. Mutation: одно-hop формула либо отсутствие generation check.

### ASYNC-04 — Одновременный CONNECT уже запущенных hedge attempts

P2, High. `crates/resocks5-net/src/connect/proxy_connect/hedged.rs:145–162,301–305`; обещание `crates/resocks5/src/server/connect/establish_connection/dial.rs:268–277`.

A pending TCP, запускается B. A начинает handshake; затем B заканчивает TCP до winner и тоже начинает handshake. `handshaking` блокирует новые launches, не admission уже запущенных attempts. Возможны duplicate target connections, но не доказано дублирование payload.

Решение: конкурентный TCP, эксклюзивный handshake admission, winner публикуется до освобождения admission. Тест: управляемо завершить оба TCP при заблокированном ответе первого CONNECT; до отказа первого CONNECT ровно один. Mutation: заменить gate счётчиком. Существующий slow_handshake_suppresses_second_candidate_until_first_fails проверяет ещё не запущенный второй attempt, а не эту гонку.

### ASYNC-05 — Single-node dial_chain total timeout получает неверный ChainStage

P2, High. `crates/resocks5-net/src/connect/dial/chain.rs:146–148,175–183,304–323`; `crates/resocks5-net/src/connect/dial/mod.rs:199–235`.

У single upstream TCP успешен, handshake pending, total timeout меньше handshake timeout. Progress инициализирован Connect, но single-node dial_inner не обновляет его. Внешний total timeout возвращает Connect вместо Target. Это неверный публичный stage, способный влиять на policy потребителя.

Решение: обновить progress после TCP acquisition и в single-node ветке. Тест: upstream получает greeting/CONNECT и держит ответ; проверить Total+Target. Отдельно pending TCP→Connect. Mutation: удалить обновление progress. Существующий stage test использует gate/Hop(0), не эту границу.

### ASYNC-06 — Probe fan-out O(N) вне pool admission

P2 условно для крупных конфигураций, High для механизма. `crates/resocks5-net/src/session/rotator/probe.rs:53–69,112–115`; `crates/resocks5/src/server/bootstrap/startup.rs:490–497,542–570`; `crates/resocks5/src/server/connect/establish_connection/route.rs:56–57`.

Startup без health создаёт task на каждый upstream с прямым connect. Cap clients/pool не участвует. O(N) sockets/tasks; local exhaustion может стать false upstream-down. Lease одного identity не ограничивает общий fan-out.

Решение: bounded launcher ДО spawn, local capacity/resource errors не штрафуют upstream. Тест: N контролируемых probes, active≤B, остальные ещё не spawned/dialed; injected local-capacity не карантинит. Mutation: прямой for spawn либо неверная классификация.

## Performance — аналитика, не измерения

- Health snapshot/serialization остаётся O(N), перенос в single blocking owner разгружает async workers, добавляет handoff/ack и shutdown loss policy.
- Probes: O(N) in-flight → O(B), полный обход до ceil(N/B)×T.
- Hedge: один handshake вместо K, TCP остаётся конкурентным; готовые sockets ждут.
- Pool-routed request вызывает spawn_chain_probes до sticky hit: scans порядка O(ΣN) и dispatcher submissions даже без due probes. Кандидат — supervised dispatcher/due-index; cadence и ownership требуют решения.
- Refill retries без jitter могут синхронизироваться после outage; масштаб не измерен.

## Inventory и корректные границы

- Inbound accept имеет абсолютный accept-anchored deadline; partial framing terminal, stream нельзя повторно использовать.
- Auth blocking closure удерживает permits и claim gate до фактического завершения, включая отмену клиента.
- TLS+CONNECT одного hop делят абсолютный deadline. Fragmented writes и tunnel copy сохраняют pinned future между timer iterations, не перезапускают side effect.
- Prefixed progress/waker в просмотренном wrapper корректен.
- Refill handles хранятся; pool Drop abort-ит их, self-owning Arc пула не найден.
- Dropped production handles: startup reachability `startup.rs:493`, due dispatcher `route.rs:56`, inner probe `probes.rs:57`: политика supervision/panic/shutdown должна быть явной; это не автоматическое доказательство утечки.
- Hedge drain `hedged.rs:288` намеренно detached, не finding сам по себе.
- Test cleanup `crates/resocks5-net/src/connect/tls/upstream_tls.rs:711–713`: комментарий считает drop(server) отменой, но JoinHandle::drop detaches. Предложение abort+await; test mutation abort→drop с drop flag до teardown runtime. В штатном tokio::test teardown runtime отменяет задачу, поэтому production leak этим не доказан.
- Unsafe Pin, nested block_on и async Drop в просмотренных product paths не найдены.

## Покрытие и ограничения

Resolved Tokio 1.54.1, tokio-rustls 0.26.4, rustls 0.23.46, DashMap 6.1.0. Прочитаны root/SDK README, ARCHITECTURE, manifests, lockfile; детально chain, hedge, probes, health, auth admission, listener lifecycle, inbound framing, TLS progress, tunnel/recovery, pool refill. Это тематический, не построчный аудит всего workspace. TLS timer-tick причина не доказана; diagnostics не являются исправлением. Никаких тестов/mutations/измерений не выполнялось.
