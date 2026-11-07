# Независимое ревью исправлений и слепой аудит @ox — раунд 3

Дата: 2026-11-05.

## Объект и метод

- Стартовая ревизия: `b7eab13506ac37ab2907a26626ad3dd205794fb2`.
- Четыре независимых агента `@ox` проверили исправления относительно `b4ab336`.
- Десять свежих агентов `@ox` исследовали текущую репозиторию по десяти тематическим модулям rust-intel. Им не передавались прежние находки; чтение истории, diff, CHANGELOG, старых отчётов и checkpoints было запрещено. Разрешались текущие исходники, тесты, manifests, lockfile и публичные контракты README/REFERENCE/ARCHITECTURE.
- Финальный независимый `@ox` проверил существенные сценарии, достижимость, контракты, дубли и severity. Основной сеанс дополнительно просмотрел ключевые участки health ownership/signature, recovery EOF, fragmentation prelude, cached budget и его обещание в README.
- Во время чтения checkout перешёл на `6237994a92aa29c79b594c8fd9b5ff33fcb9afdf`: относительно стартовой ревизии изменились только два тестовых участка — timeout refused-пробы и assertion health-логов.
- Финальная проверка: `5dc95afe78e8f535e663e21a0c65ce9dd350d0f9`. Его tracked-дерево совпадает с `6237994`. Поэтому production-выводы применимы к обоим деревьям; замечание к уже исправленному тесту не переносится на итоговую ревизию.

Все результаты получены статическим чтением. Компиляции, build/test/check/clippy/fmt/bench, сканеры, скрипты проверки, приложения, mutations и нагрузка **не запускались**. Worktree не создавались. Наличие тестов не означает их прохождение. CI не проверялся. Runtime secrets и внешние dependency implementations не читались.

Агенты вернули отчёты текстом. Этот файл — сводка основного сеанса после независимой проверки, а не утверждение о сохранении отдельных полных протоколов всех агентов. Параллельные отчёты других исполнителей в эту сводку не включались.

## Краткий вердикт

**P1 по проверенным сценариям не подтверждены. Подтверждены девять P2-механизмов**, несколько P3 и отдельные test/hardening/performance gaps. «Подтверждено» здесь означает причинный статический trace, не runtime-воспроизведение.

## Подтверждённые P2

### A. Межпроцессный health lock освобождается до окончания blocking writer

Уверенность: высокая. Совпадение targeted и слепых async/Drop/concurrency/conformance исследований.

Места: `crates/resocks5/src/server/health/mod.rs:294–311,452–457,468–481`.

`UsersFileLock` принадлежит `HealthSaver`/`finish`, но не closure `spawn_blocking`. Если periodic writer не завершился за три секунды, `finish` abort-ит async-задачу и возвращается, освобождая lock. Уже работающая blocking closure продолжает файловые операции. Аналогично timeout финальной записи прекращает ожидание до `drop(lock)`.

Другой процесс получает lock и начинает reclaim/write того же `.tmp`. На Unix достижим unlink/recreate/rename interleaving: старый writer может выполнить commit содержимого чужого temp. Как минимум нарушены single-writer ownership и сохранность snapshot; одинаковый итог на каждой платформе не утверждается.

**Направление:** совместное владение guard, захваченное каждой blocking closure до её фактического завершения. Bounded shutdown может перестать ждать, но не объявлять ещё занятый ресурс свободным. Не заменять это неограниченным join.

**Тест-кандидат:** barrier внутри blocking writer после создания temp. После timeout `finish` второй contender не получает lock и не трогает temp до release writer. Отдельно periodic/final/cancellation. Mutation: убрать guard из closure, оставить только в async owner.

### B. Ошибка commit не инвалидирует baseline

Уверенность: высокая. Targeted health finding.

Место: `crates/resocks5/src/server/health/mod.rs:518–535`.

Сценарий: A сохранён → попытка B изменила target, но вернула ошибку → runtime вернулся к A. Unix rename B может завершиться до ошибки directory sync; Windows helper отдельно учитывает partial commit 1176/1177 с неопределённым target. `last` остаётся A. Проверка signature выполняет skip даже при `failing=true`, хотя на диске может оставаться B либо отсутствовать target.

Сужение: пропуск продолжается до следующего изменения signature или успешного финального сохранения, не обязательно навсегда при любых условиях.

**Направление:** dirty state после ошибки, запрещающий equality-skip до подтверждённого успешного save.

**Тест-кандидат:** injected commit устанавливает B, затем возвращает ошибку; runtime снова A; следующий подтверждённый tick обязан записать A. Отдельно missing-target outcome. Mutation: снова разрешить skip при `failing`.

### C. Signature не различает новый quarantine deadline при одинаковых счётчиках

Уверенность: высокая. Добавлено слепым conformance-аудитом.

Место: `crates/resocks5/src/server/health/mod.rs:138–153`.

Сохранён quarantine с trips=1/failures=T/expiry=40. Между ticks происходят success/reset и новый trip с теми же trips/failures, но expiry=48. Signature исключает remaining и timestamp, поэтому смысловое изменение не записывается. После рестарта восстанавливается старый срок, вплоть до преждевременной probation.

**Направление:** учитывать стабильное представление expiry или generation изменения health. Обычный countdown должен оставаться write-free, но новый период должен считаться изменением.

**Тест-кандидат:** reset/retrip между ticks с одинаковыми counters и разным expiry; проверить save/load/restore нового срока. Positive control: простой ход времени с прежним expiry не вызывает write. Mutation: signature без expiry/generation.

B и C не дубли: B — недостоверный baseline после ошибки I/O; C — недостаточная семантика сравнения при успешном baseline.

### D. ProxyRejected от prefix не доказывает отказ проверяемого узла

Уверенность: высокая. Совпадение targeted и слепого conformance-аудита.

Места: `crates/resocks5/src/server/connect/establish_connection/probes.rs:55–59`; источники — `crates/resocks5-net/src/connect/proxy_connect/connect_http_proxy.rs:214–241`, `connect/util/handshake_over_stream.rs:161–166`.

`ChainStage::Target` здесь обозначает финальный handshake prefix-прокси для достижения B, не ответ самого B. Текущая ветка `Target + ProxyRejected` штрафует B и для HTTP 407, HTTP 403, malformed status с code=None и SOCKS REP 2. Все они возможны без подключения к B: это auth/policy/protocol отказ prefix.

Dedicated greeting/auth/TLS variants уже стали inconclusive. Исправление частичное, не отсутствующее.

**Направление:** протокольно-специфичная классификация destination failures. Prefix-local auth/policy/malformed ответы не должны менять health B.

**Тест-кандидат:** prefix-stub отвечает 407/403/malformed/REP2, listener B не получает connect, health/trips/failures B неизменны. Отдельные positive controls выбранных destination-unreachable кодов. Mutation: все Target+ProxyRejected снова HardFailure.

### E. Settlement probe не привязан к поколению claim

Уверенность: высокая. Совпадение targeted и слепого concurrency-аудита; один ownership defect с двумя путями.

Места: `crates/resocks5/src/server/connect/establish_connection/probes.rs:233–251`; `crates/resocks5-net/src/session/rotator/probe.rs:117–143`.

**Chain path:** P1 получает claim. Обычный fail-open запрос успешно использует узел и сбрасывает lease. Новые failures снова карантинят его, после короткого backoff P2 получает новый claim. Успех P1 приходит до его исходного lease_until, проходит временной fence и стирает состояние P2. Кроме того, проверка времени и изменение ratings не атомарны.

**SDK direct path:** `probe_due_with` получает claims до reservation/spawn, затем даёт reachable свежий относительный timeout и безусловно применяет результат. Задержанный reserve/start/settlement позволяет старому результату пережить lease и перезаписать новое состояние.

**Направление:** token/generation и условное settlement под тем же ratings lock. Absolute deadline ограничивает работу, но не доказывает ownership.

**Тест-кандидат:** управляемые P1/P2, success обычного запроса между ними, повторный quarantine/claim; settlement P1 не меняет health и владение P2. Отдельно direct API с задержкой reserve/start. Mutation: удалить generation comparison.

### H. Fragmentation prelude использует whole-operation timeout вместо idle timeout

Уверенность: высокая. Добавлено слепым async-аудитом.

Место: `crates/resocks5/src/server/tunnel/forward_tunnel.rs:108–147`.

При `frag.enabled` и пустом/неопределённом либо незавершённом ClientHello prefix ожидание upstream-read и последующий `client.write_all` блока до 1024 bytes входят в один `within_idle`. Клиент принимает части каждые 200ms, весь transfer длится больше idle=1s — tunnel закрывается при непрерывном прогрессе. Часть окна уже могла уйти на ожидание upstream.

Документированный idle — отсутствие передачи bytes, не максимальная длительность целого блока. Default30s снижает вероятность, но не меняет механизм.

**Направление:** progress-aware relay, обновление idle по успешным частичным I/O; после terminal cancellation не replay-ить prefix.

**Тест-кандидат:** server-first1024bytes, controlled slow writer, весь transfer дольше idle при каждом progress раньше deadline. Позитив полностью доставляется, настоящий stall закрывается. Mutation: whole-write timeout либо отсутствие stall limit.

### I. Recovery превращает write-half-close в полное закрытие клиента

Уверенность: высокая. Добавлено слепым conformance-аудитом.

Места: `crates/resocks5/src/server/tunnel/recovery.rs:43–52,71–78`; SOCKS `server/handle/handle_socks5_client/recover.rs:123`; HTTP `http_proxy/handle_http_client/recovery.rs:128`.

Клиент CONNECT к literal IP получает early success, делает только shutdown(write) и продолжает читать server-first banner. Пустой EOF становится ClientClosed, handler возвращается и закрывает обратное направление, возможно до egress. EOF read-направления не означает отказ клиента получать ответ.

**Направление:** EOF завершает recovery-read, но позволяет IP fallback, перенос FIN upstream и чтение обратного потока под прежними бюджетами.

**Тест-кандидат:** SOCKS и HTTP с recovery, после success client shutdown(write), target получает EOF и отправляет banner/FIN; клиент получает banner полностью. Recovery-off control. Mutation: пустой EOF снова ClientClosed→return.

### J. Full cached chains обходят резерв ordinary fallback

Уверенность: высокая в расхождении с публичным контрактом. Добавлено слепым conformance-аудитом, независимо перепроверено.

Места: `crates/resocks5/src/server/connect/establish_connection/dial.rs:120–128,210–213`; контракт `README.md:483–486`.

README прямо обещает общий attempts budget «with at least one attempt reserved for fallback». При cap2 две разные full cached chains в v6/v4 с ещё не quarantined плохими gates расходуют обе попытки; доступный ordinary exit не получает fallback. Reserve применяется к новому Cartesian plan, не full-cache фазе.

Existing budget1 test закрепляет cache-first и непревышение cap, но не опровергает обещание резерва при budget≥2.

**Направление:** согласовать cached-chain admission с ordinary reserve; исключение budget1 явно определить в контракте.

**Тест-кандидат:** две cached chains/bad gates/cap2/live ordinary exit; успех fallback при attempts≤2. Mutation: cached admission проверяет только общий cap.

### N. Ошибка file logger блокирует async worker синхронной диагностикой

Уверенность: высокая в механизме; impact условен. Добавлено слепым async-аудитом.

Места: `crates/resocks5/src/server/bootstrap/log_drain.rs:55–59,79–81`.

Ошибка открытия/записи файла вызывает eprintln прямо в async task. Заполненный stderr pipe без читателя блокирует worker. Single-worker runtime останавливается; multi-thread теряет worker, не обязательно весь сервер. Наблюдавшегося зависания не заявляется.

Это не отменяет исправление health shutdown logging: там уже используется неблокирующий logger channel.

**Направление:** diagnostic без sync write на async worker, с bounded/best-effort lifecycle и без рекурсивного логирования собственной ошибки.

**Тест-кандидат:** изолированный subprocess с контролируемым stderr, invalid file-log path и heartbeat; failure path не останавливает heartbeat. Только проверка текста сообщения отсутствие блокировки не доказывает.

## Подтверждённые P3 и условные границы

| ID | Место | Механизм и калибровка |
|---|---|---|
| F-SDK | `crates/resocks5-net/src/session/rating/quarantine.rs:258–266` | Accepted probe_lease=Duration::MAX, checked_add overflow→now, немедленная повторная выдача. SDK policy boundary, не remote input. Нужна explicit validation/overflow representation, не now. Два последовательных claims должны быть exclusive. |
| F-APP/G | `crates/resocks5/src/server/connect/establish_connection/probes.rs:140,150`; `crates/resocks5/src/server/run_server.rs:171–172` | Saturating Duration не делает безопасным bare Instant+duration. Huge config может panic-нуть probe task или accept body до spawn. Misconfiguration, не клиентское управление timeout. Нужны startup validation и checked construction. |
| K | `crates/resocks5-net/src/server/strict_http.rs:49–75` | Host-port1..5digits/nonempty и IPv6-only уже URI grammar. RFC9110§7.2 Host=uri-host[:port], RFC3986§3.2.3 port=*DIGIT, §3.2.2 IPvFuture. Valid Host example.com:,example.com:000443,[v1.example] отвергаются при обычном valid CONNECT target. Нормативный текст проверен финальным verifier. Разделить Host syntax/operational target policy либо документировать дополнительную policy. |
| M | `crates/resocks5-net/src/connect/proxy_connect/hedged.rs:338–342` | Winner опубликован/slot свободен, timer выбран раньше join, нет won-check→лишний acquire/TCP launch. Handshake всё ещё не отправляется после win; это не duplicate CONNECT. Existing механизм, не регрессия Lost.after_win fix. |

Quarantine helper `deadline` заменяет непредставимый срок горизонтом100лет. Это устраняет immediate probation для обычного current Instant при MAX duration, но не сохраняет точную accepted duration. Последний fallback now теоретически остаётся. Ни столетнее ожидание, ни practically reachable remote attack не наблюдались. Нужна явная policy/representation, не измеренный performance fix.

## Hardening и inventory, не основные blockers

- **Password-distinct persistence aliases:** runtime identity включает password, persisted label/gate/group — нет. В одной группе разные passwords могут схлопнуть health records. Механизм подтверждён, но password-free persistence — публичный дизайн; нужна ambiguity policy, а не безусловный claim новой регрессии. Не сохранять password или его обычный digest. Консервативный вариант — skip ambiguous restore с warning.
- **SDK depth:** public gate/with_gate/chain не ограничивают глубину, recursive Arc destruction и Debug могут исчерпать стек. Remote arbitrary-depth путь штатного CLI не доказан; ranked CLI ограничен u8. Iterative teardown требует API review: добавление Drop к public-field type может изменить допустимые moves.
- **Примеры:** connect_through_proxy и соответствующий README read_to_end остаются без size/time bound. Это example/копирующий consumer, не production bounded tunnel. dial_chain_over уже ограничен64KiB.
- **Error chain:** HedgeError.last не включён в Error::source. Низкоприоритетная diagnostic limitation, не P2 security. AtCapacity source-chain тоже ограничен; typed matching/classifiers доступны.
- **Release permissions:** workflow contents:write наследуется build jobs, checkout сохраняет credentials. Build-time код получает лишнюю capability. Least-privilege hardening, не установленный P1 exploit или compromise. Write оставить release job, build read-only.
- **Publish token:** secret-free dry-run затем token-bearing publish без no-verify допускает повторное build execution. Реальный запуск зависит от reuse/cache; фактическая утечка/доступный token-bearing artifact не установлены. Нужна secret-free verification тех же bytes и upload-only boundary.
- **Argon2/memory hygiene:** параметры ниже baseline security skill и неочищаемые parser/auth копии — hardening более сильного offline/memory-disclosure threat model. Не найден remote auth bypass. Актуальные внешние advisory/OWASP данные не проверялись; параметры/версии сами по себе не аттестуют безопасность.

## Тестовые и CI gaps

Все проекты тестов/мутаций выше и ниже не выполнялись.

1. Probe guard test проверяет drops==1 после завершения, не lifetime во время pending connect. Mutation early drop может пройти. Нужен pending seam/active permit observation и cancellation.
2. `crypto_provider_contract.rs:55–78`: panic-ветка проверяет текст, но не требует EXPECT_PANIC_ENV. Unexpected same-text panic может пройти normal graph. Expected outcome должен проверяться симметрично в отдельных процессах.
3. Feature-unification fixture исключён из root workspace; собственный manifest не запускается workflows. SDK package matrix не заменяет совместный downstream graph.
4. Windows-specific behavioral changes по умолчанию получают Ubuntu-only targeted tests; portable build/help не доказывает semantics. Это coverage policy, не обнаруженный Windows runtime bug.
5. `bootstrap/tests.rs:638–654`: paused Tokio time и std::time::Instant<1s не доказывают5s virtual timeout и зависят от runner. Нужны virtual boundary+ack.
6. Process-global CONFIRMED_WRITE_PROGRESS_TOTAL загрязняется чужими concurrent tests. Lower-bound delta не доказывает progress проверяемой chain; нужен instance-scoped observer и decoy control.
7. Slow-drain negative использует другие idle/payload, чем positives; это не строгий контрфакт renewal semantics. Нужен один pending flush дольше idle с контролируемым progress, одинаковые параметры instrumentation on/off.
8. Health tests не останавливают настоящую blocking closure после timeout. Отдельно отсутствуют failed-commit→old-signature и reset/retrip→new-expiry controls.
9. Probe classification table не различает HTTP407/403/malformed и SOCKS destination failure. Deadline tests с manually supplied instants не доказывают claim ownership.
10. Существующий targeted chain classifier fix зачтён; таблица самого classifier и downstream/release behavioral lanes остаются полезными отдельными controls. Yank gate — policy; актуальный yanked pin не найден и внешне не проверялся.

## Performance: подтверждённые операции, не измеренные ускорения

- Полный weighted order O(NlogN) при малом remaining attempt budget; bounded prefix потенциально O(N+klogk), но должен сохранить keys/order/filtered+tried semantics.
- Temporary nodes Vec в ChainKey::hash; singleton identity строит owned config с копиями host/credentials, хотя исходный Arc уже есть.
- ChainPick::config повторяет materialization уже сохранённой linked chain.
- Cached resolve линейно ищет hops при существующем identity index: O(ΣNᵢ) против expected indexed O(h) с учётом hash bytes/collisions.
- Raw credential clones, eager log formatting, три Arc counter allocations/tunnel, lowercase/header collections.
- Повторный recovery parsing growing prefix потенциально O(n²), масштаб ограничен16KiB/deadline; incremental parser усложняет state machine.

Величина ущерба, bottleneck и speedup не измерены. Full weighted order не выполняется на каждом healthy full-chain cache hit: этот путь откладывает plan. Не смешивать его с ordinary cached candidate/fallback preparation. Для будущих проверок — allocation/operation counters в фиксированной compiler/target/allocator/feature среде; shared-runner wallclock не hard gate.

## Какие исправления зачтены

| Область | Итог |
|---|---|
| Cached exit owner | Resolve ограничен owning rotator; чужой health больше не подставляется. |
| Lost.after_win | Coordinator учитывает опубликованный win. M — другая гонка launch, не возврат старой metadata-ошибки. |
| Probe permits | Direct/startup probes держат reservation guard; chain probe резервирует tested endpoint и prefix permits. Capacity не штрафует tested узел. |
| Baseline до dispatch | Initial snapshot берётся до post-restore probes. C относится к новому интервалу после reset, B — к failed I/O. |
| Health async/stderr | Serialization/I/O offloaded; shutdown reports неблокирующие. N — отдельный file-log error path. |
| Attempts cap | Queued sticky slice ограничен remaining budget. J относится к обещанному reserve, не превышению cap. |
| Startup lock/temp | Обычный второй startup без lock не удаляет temp; reclaim перед каждым save. A — lifetime после timeout/cancel. |
| Quarantine exponent | Старый произвольный cap20 устранён. Extreme Instant policy и SDK lease overflow остаются отдельными границами. |
| Host malformed syntax | Старые bad/path,user@host,bad%zz,a b закрыты; K — новый чрезмерный отказ корректной синтаксической формы. |

## Сопоставление групп

Targeted проверка подтвердила исправленные узкие механизмы и нашла остатки ownership/attribution. Слепая группа независимо получила A/D/E, что снижает риск повторения лишь заранее подсказанных claims. Она также добавила C/G/H/I/J/K/M/N, SDK/resource inventory и новые тестовые контроли.

Совпадения сведены; B/C и chain/direct E не потеряны при дедупликации. Сильные claims о P1 exploit, actual token leak, remote duration control, auth bypass и универсальной RFC-conformance не перенесены в итог без доказательства.

## Ограничения и дальнейшие действия

Это исследование выбранных contracts и механизмов, не построчный сертификат всего workspace. Нет runtime reproductions, executed mutations, measurements, stack thresholds, independent interoperability или актуальной advisory-чистоты. Исторические отчёты и эта сводка фиксируют свои ревизии; последующие исправления требуют нового review.

Рекомендуемая последовательность: A/D/E → B/C → I/H/J → N → P3 boundaries и test gates. Performance changes — после focused измерений без изменения публичных контрактов. В рамках этого ревью исправления не выполнялись.
