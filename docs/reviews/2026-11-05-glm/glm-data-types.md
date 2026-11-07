# Аудит data-and-types (B6/B16/B20/B26–B29, C4, E2/E3) — 2026-11-05, вторая волна

Ревизия: HEAD `b7eab13` (ветка `fix/audit-2026-11-05`), diff-база `870caa2..HEAD`, содержательные коммиты `dfe3606`, `2c548e3`, `b4ab336`, `b7eab13`.

Метод: rust-intel `data-and-types.md` (§B6, §B16, §B20, §B26–§B29, §C4, §E2, §E3 + Substitution catalog), прочитан целиком и прогнан по коду. Зона приоритета прочитана целиком: `resocks5-net/src/types/**` (chain, validate, proxy_config, proxy_protocol), `server/{reply,strict_http,credentials,prefixed,mod}`, `connect/util/**` (host_port, parse_proxy_str, recover_host, any_upstream, handshake_over_stream, tls_fragment), `error/**`, `resocks5/src/config/**` (network, main, auth, file_log, tls_fragment, allowed_clients, load_or_init, users, user), `cli/**` (app, command, user_action, run_user_command, print_config_docs выборочно). Плюс фикс-поверхность: `session/chain/mod.rs`, `session/rating/{mod,quarantine,sand,policy,select}.rs`, `session/rotator/{mod,probe}.rs`, `session/pool/proxy_pool/mod.rs` (дифф), `connect/proxy_connect/hedged.rs`, `connect/dial/chain.rs` (дифф), `server/connect/establish_connection/{dial,probes,route}.rs`, `server/health/mod.rs`, `server/bootstrap/startup.rs`, `server/handle/.../negotiate.rs` (выборочно).

Никаких прогонов: cargo/скрипты/приложение/тесты не запускались; ничего не менялось; единственная запись — этот файл. Все выводы — статическая проверка механизмов чтением.

Прошлый аудит: `docs/reviews/2026-11-05/summary.md` (V01–V18, P01–P09, TEST-01..11) и `docs/reviews/2026-11-05/api/data-types.md` (DT-B01..B05, DT-P01..P05, DT-H01/H02) — прочитаны. Уже исправленное повторно не репортится; не исправленные и ранее зарепорченные позиции (DT-P02 Hash-аллокации, DT-P03 credential copies, DT-P04/P05 eager logs/header collections, DT-H02 re-parse ClientHello) ниже не дублируются.

## 1. Проверка фиксов V01–V17 (diff 870caa2..HEAD)

Все относящиеся к теме фиксы встали; регрессий соседнего поведения не найдено. Детали:

| V-id | Статус | Место | Что проверено |
|---|---|---|---|
| V01 | VERIFIED (встал) | `session/chain/mod.rs:124–129,225,237–255,269–286` | `Layer.live` + `done` при исчерпании слоя; `ChainPlan::new` завершает план на пустом слое; `mark_dead` защищён от двойного декремента через `dead.insert()==false`. Work-bound тесты с mutation-комментариями и positive controls (`selection_tests.rs:369–463`). Единственное замечание — DT-03 ниже. |
| V03 | VERIFIED | `connect/proxy_connect/hedged.rs:123–178,336–344` | `handshake_slot` эксклюзивен; победитель пишет `won`(Release) ДО освобождения слота; вейтер перепроверяет `won` после захвата; hedge-tick не запускает новых кандидатов при активном handshake (`try_lock`). Documented cost: вейтер держит уже приобретённый сокет+permit, ожидая слота — это контракт, не дефект. Взаимоблокировок нет (один мьютекс, атомик для `won`, tokio-Mutex lock cancel-safe). |
| V04 | VERIFIED | `establish_connection/dial.rs:44–49,87–89,120–128,301–325` | Единый бюджет: queued sticky участвуют в `candidates.len()`, direct-loop ограничен `attempts + candidates.len()`, финальный `truncate(max_attempts - attempts)` — суммарно ≤ max на запрос. Аналитически перепроверено на max=3 с двумя cached и одним gate-пиком: ровно 3. |
| V05 | VERIFIED | `dial.rs:97–115`; `session/chain/mod.rs:50–90` | Cached chain: resolve скоупится на владеющий rotator (`std::slice::from_ref(rotator)` — чужой quarantine не задействуется), каждый hop кроме exit проверяется `is_quarantined`, иначе unlink и fall-through к плану. Exit не перепроверяется обоснованно: `get_linked` уже скрыл quarantined exit. |
| V06 | VERIFIED | `session/rotator/mod.rs:85–103,384–414,484–490` | Dedup на construction; `upstream_hash` и `same_upstream` покрывают одни и те же поля (host, port, protocol discriminant, user, password, gate_level) — контракт `a==b ⇒ hash(a)==hash(b)` соблюдён (B16 проверен явно). Buckets в `Vec<usize>` — только коллизии, O(1) ожидаемо. |
| V07 | VERIFIED | `establish_connection/probes.rs:35–62,243–271` | `classify_probe_error`: только `Target`+`ProxyRejected` → HardFailure; prefix/capacity/timeout → Inconclusive без изменения health. Таблица классификации покрыта тестами с mutation-комментариями. |
| V08 | VERIFIED | `probes.rs:71–97,117–152,230–242`; `startup.rs:347–360` | `probe_deadline`/`probe_lease` — одна пара хелперов с saturating-арифметикой; deadline и fence — абсолютные от claim (`claimed` читается ДО `take_probes`, чтобы не быть позже SDK lease-start); settlement fence `now >= lease_until` отбрасывает. Startup кладёт в `QuarantinePolicy` lease из того же хелпера — расхождение бюджетов исключено (это было главное условие корректности фенса). Тесты: saturate на MAX/ZERO, stale claim, lease-fence. |
| V02 | Встал; остаток — DT-02 | `server/health/mod.rs:254–538` | Stop-протокол (notify → bounded join → один финальный writer), `spawn_blocking` для I/O, `reclaim_own_temp` перед каждой записью и на старте под lock, cross-process lock на весь run, `UsersFileLock` с budget 200ms. Остаточное окно — см. DT-02. |
| V09 | VERIFIED | `health/mod.rs:329–411`; `startup.rs:479–527` | Post-restore пробы только для `directly_dialed_rotators` (outermost gate + exits); chain-пробы в `spawn_chain_probes` идут по `gates.iter().skip(1)` через healthy-prefix. At-capacity → defer без rating (`reserve_permit` и в прямых, и в chain-пробах, и в startup-check). |
| V10 | VERIFIED | `health/mod.rs:39–49,117–136,163–207` | Запись key=(upstream,gate,group); restore сначала новый ключ, пустой group — легаси-fallback на все группы (документирован). Password не пишется (`upstream_label` без password). |
| V11 | VERIFIED | `connect/dial/chain.rs:302–311` (дифф), `session/progress.rs` (дифф) | Single-node dial_chain ставит `progress=Target.encode()` после TCP; total timeout после TCP репортит Target. Заодно закрыт UFFI-03 (Ok(0)-spin в doc-примере). Побочная мелочь: `ChainStage::encode` — `Hop(usize::MAX-1)` коллирует с Target-сентинелом, но такой depth недостижим (не репортится). |
| V12 | VERIFIED | `hedged.rs:219–224,331–345` | `hedge_deadline` → `Option<Instant>` через `checked_add`; None = «никогда не хеджировать», таймер не ставится; doc обновлён. |
| V13 | Встал; остаток — DT-01 | `server/strict_http.rs:19–76,84–211`; `server/mod.rs:559–569` | Authority-грамматика: userinfo (`@`), path/query/fragment, `%ZZ`-обрезки отвергаются; request-line части без табов/CTL; скобочный IPv6 требует порт; bare IPv6 → отказ. Strict вызывается до auth-поиска. |
| V14 | VERIFIED | `strict_http.rs:154–189` | CTL/0x7F в value → 400 (HTAB разрешён — комментарий корректен: CRLF до валидатора не доходит); whitespace-before-colon, empty name, non-tchar name, obs-fold — всё отвергается. |
| V15 | VERIFIED | `server/mod.rs:157–160,732–747,750–770`; `credentials.rs:94–116` | `take_username` прокидывает `discard_wiped(&mut username_raw)`; под `zeroize` raw перезаписывается до free; `Drop` IncomingRequest wipes username/raw/credentials (pipeline — payload, stays; документировано). `into_parts` через `mem::take` — Drop-совместимо. |
| V16 | VERIFIED | `session/rating/quarantine.rs:127–138,270–332` | Bounded saturating doubling (`saturating_mul` + stuck-detection + `>=max` break; цикл ≤ ~100 итераций при любом `trips` включая `u32::MAX`; validate отвергает initial=0). Тесты: 1ms→1h trips 20/21/22/23, u32::MAX, nanos, max==initial. |
| V17 | VERIFIED | `session/pool/proxy_pool/mod.rs` (дифф dfe3606) | Lock order `refill_tasks` → `pools`/`upstream_caps` зафиксирован и документирован; `spawn_refill_for` держит lock через публикацию очереди+spawn+регистрацию (весь блок синхронный); `forget` держит lock через все три удаления; заменённый handle явно `abort()` (не detach). `endpoint_state`/`refill_task_finished` соблюдают порядок. |

Смежные проверки B-категорий по фикс-коду: B26 — все `saturating_*`/`checked_add` на местах (`quarantine.rs:129–137,154–159,197,203,213,247,265`; `health/mod.rs:164,182`; `probes.rs:76–77,96,138–140`); narrowing `as u8` в исходящих handshake только после guard ≤255 (`handshake_over_stream.rs:83–94,136–144`); B27 — только tokio `Instant` для дедлайнов, `SystemTime` только для persisted `saved_at` c `map_or(0)` (`health/mod.rs:94–98`); B28 — `eq_ignore_ascii_case`/`to_ascii_lowercase` для протокольных токенов, срезы через `get`/`split_once`/`position`, `from_utf8` с обработкой Err; B29 — `zip` только по равным массивам (`allowed_clients.rs:105–121`), `chunks(0)` защищён (`tls_fragment/mod.rs:146 fragment_size.max(1)`), «голого» `Vec::dedup` нет; B20 — `HealthEntry`/`User` serde-defaults покрыты round-trip тестами, untagged нет.

## 2. Новые изменения (findings на diff 870caa2..HEAD)

### DT-01 — Low / VERIFIED_STATIC + TEST_GAP: строгая грамматика Host-заголовка принимает порт 0 и >65535

`crates/resocks5-net/src/server/strict_http.rs:50–52,57–76` против `139–148`; введено фиксом V13 (b7eab13).

Механизм: `valid_port_digits` проверяет только «непусто, ≤5 цифр, все цифры», и `valid_host_value` не делает range-check — `Host: h:0`, `Host: h:99999`, `Host: [::1]:0` проходят strict validate. CONNECT authority в той же функции проверяет `1..=65535` (`strict_http.rs:139–148`). Doc-комментарий `valid_host_value` заявляет «mirroring the CONNECT authority rules» — расхождение с собственным контрактом.

Сценарий: строгий режим обещает RFC 9112-гигиену; клиент присылает `Host` с синтаксически недопустимым по диапазону портом — запрос принимается как валидный. Host в dialing не участвует (цель — из authority), поэтому это не обход, а несоответствие заявленной грамматике и несимметричность двух путей одного валидатора.

Решение: в `valid_host_value` после `valid_port_digits` добавить тот же `parse::<u32>()` + `1..=65535` (или переиспользовать один хелпер для обоих путей).

Тест-кандидат: в corpus `server/tests/strict_http.rs:139–147` добавить `("CONNECT h:443 HTTP/1.1", &["Host: h:99999"], "strict HTTP: invalid Host header")` и `Host: [::1]:0`; positive control уже есть (`Host: h:65535` на authority-стороне, `Host: h:443`). Mutation: убрать range-check из authority-пути — тест на authority должен продолжить падать.

### DT-02 — Low / PLAUSIBLE (остаток V02): abort не останавливает стартовавший spawn_blocking — запись может завершиться после снятия lock

`crates/resocks5/src/server/health/mod.rs:268,294–311,452–462`.

Механизм: `HealthSaver::finish` ждёт writer 3s (`FINISH_BUDGET`); по таймауту — `task.abort()` + `return` без финальной записи. Abort tokio-задачи не прерывает уже выполняющийся `spawn_blocking`-closure: round-запись, начавшаяся до stop, доработает после возврата `finish` и `drop(lock)`. Дальше: (а) снапшот, снятый до остановки, публикуется с задержкой (stale при следующем старте — терпимо); (б) lock уже отпущен — параллельно стартовавший новый instance может одновременно делать `reclaim_own_temp`+`create_new` с этой дорабатывающей записью: конкуренция двух writers над одним temp, ради которой stop-протокол и строился. Комментарий в коде (`probes of budget`: «cannot be cancelled … lost on purpose») фиксирует осознанность, но (б) в комментарии не названо.

Достижимость: требует stall storage >3s (нормальная запись — мс). Отсюда Low/PLAUSIBLE, не регрессия: окно осталось от прежнего V02.2 в сильно суженном виде.

Решение (направление): финальная запись не на «abort+return», а на handshake-флаге «round in flight» (writer подтверждает завершение раунда до выхода из цикла; `finish` ждёт подтверждение, а не join), либо owner-token/generation в temp-имени, чтобы чужой `create_new` не пересекался.

Тест-кандидат: writer-barrier внутри `save_offloaded` (blocked storage), `finish` с budget < block, затем release: assert — файл либо не изменился, либо изменён ровно один writer; отсутствие AlreadyExists у следующего старта. Positive control: обычный shutdown без block. Mutation: убрать ожидание loop перед `save_final`.

### DT-03 — Low / PERF_CANDIDATE: `ChainPlan::mark_dead` делает два глубоких клона ProxyConfig (с credentials) на каждый провал попытки

`crates/resocks5-net/src/session/chain/mod.rs:269–271` и `350–354`; скоуп функции правился фиксом V01, сам шаблон существовал до 870caa2.

Механизм: `singleton_key(&Arc::new(proxy.clone()))` — первый `proxy.clone()` копирует `host`/`user`/`password` Strings (deep), `Arc::new` — heap; внутри `singleton_key` второй `(**proxy).clone()` — ещё один deep-копийный проход и второй Arc. Один клон достаточен. Плюс фикс V01 добавил в `mark_dead` линейный проход `layers × candidates` с `ChainKey::eq` (O(S) на кандидата, где S — суммарные байты строк синглтона) — при десятках кандидатов и сотнях байт это микроскопически, но на каждый failed attempt.

Сценарий отказа: нет (только лишние аллокации на пути каждой неудачной chain-попытки; credentials копируются зря дважды — тот же класс, что DT-P03).

Решение: изменить сигнатуру `singleton_key` на `&ProxyConfig` (внутренний `plain = proxy.clone()` единственный) и вызвать `singleton_key(proxy)`; сскан по слоям можно заменить предвычисленным `usize`-индексом кандидата (например, хранить в `Candidate` его singleton-эквивалентность через уже имеющийся `key` — сравнение оставить, но hoist-ить `key`-проверку в один проход с подсчётом). Public API не затронут (`mark_dead` публичный, но принимает `&ProxyConfig`).

Тест-кандидат: scoped allocation counter (как предлагалось в DT-P02/P03): `mark_dead` на 3-слойном плане — ровно 1 deep-clone ProxyConfig. Positive control: identity dedup-поведения не меняется (существующие selection-тесты). Mutation: вернуть двойной клон — счётчик ловит.

### DT-04 — Low / PERF_CANDIDATE: gate-строка в cache-пути dial.rs строится дважды при провале и всегда — вне logger-замыканий

`crates/resocks5/src/server/connect/establish_connection/dial.rs:133–139` и `166–172` (та же форма существовала и в 870caa2 — ранее покрыто P04 как «eager build»; здесь фикс-волна эти строки не тронула, что и отмечается как незакрытый остаток).

Механизм: `Vec<String>` из `print_cfg` + `join(" -> ")` строится до `connect_chain` и ещё раз внутри `Err`-плеча (shadowing) — при провале двойная работа; строится даже при выключенном/переполненном logger (адмиссия ленивая, а форматирование — нет). На gate-пути цикла (`dial.rs:223–229`) повторного билда в Err-плече нет — используется внешний `gate` (несимметричность двух путей).

Решение: считать gate-строку внутри `logger.*(|| …)` замыканий (borrowed), переиспользовать внешний билд в Err-плече cache-пути как в gate-пути. Это подмножество уже зарепорченного P04 — отдельного измерения не требует; стоит закрыть тем же патчем, что и P04.

Тест-кандидат: counting/panicking `print_cfg`-обёртка не вызывается при disabled sink; active-вывод идентичен (существующие attempt-логи). Mutation: вернуть eager build.

## 3. Вне diff — новые находки на существующем коде

### DT-05 — Low / HARDENING (B6): `http_error` — wildcard с `unreachable!` на u16-домене

`crates/resocks5-net/src/server/reply.rs:32–44`.

Механизм: `_ => unreachable!("private HTTP response status")`. Функция `pub(super)`, вызывается только из `reply_bytes` с фиксированным набором — сегодня недостижимо. Но домен — `u16`, не enum: новая площадка вызова с новым статусом паникует в проде вместо ответа клиенту (для B6 «enum I own» правило — explicit arms; здесь wildcard неизбежен, а `unreachable!` превращает будущую ошибку программиста в панику на сетевом пути).

Решение: маппить неизвестный статус в 502 (`_ => http_error(502)`-style или `match` c fallback), оставив `debug_assert!` на программный инвариант. Полстроки, не срочно.

Тест-кандидат: при расширении набора статусов тест «каждый статус из reply_bytes отвечает валидной строкой» (сейчас весь набор перечислен литерально — regression-пин не нужен до расширения).

### DT-06 — Low / HARDENING (совместимость): unpadded base64 и таб-разделитель в Basic отклоняются 407

`crates/resocks5-net/src/server/mod.rs:642–651,653–665`.

Механизм: scheme/token разделяются одним `' '` (`splitn(2, ' ')` + trim — два пробела переживает, tab нет: `Basic\t<tok>` → scheme целиком с табом → «unsupported scheme»); `general_purpose::STANDARD` требует padding — `Basic dXNlcjpwYXNz` (без `=`) → «base64 decode failed» → 407. RFC 7617 допускает расхождения реализаций; большинство клиентов шлют padded и SP. Для permissive-режима это единственное место, где синтаксически «почти» корректные кредиты отклоняются.

Решение (если совместимость нужна): `STANDARD` + повторная попытка с `STANDARD_NO_PAD`, или base64-simd «no-pad tolerant» конфиг; tab как BWS в разделителе. Не делать без реального клиента — поломок не заявлено.

Тест-кандидат (если принято): вектор `Basic\tdXNlcjpwYXNz` и unpadded-токен → 200-путь; negative — мусорный токен остаётся 407.

### DT-07 — Low / VERIFIED_STATIC (B29): restore-карта собирается `collect()` — дубликаты ключей схлопываются last-wins молча

`crates/resocks5/src/server/health/mod.rs:165–169`.

Механизм: `HashMap<(String,u8,String), &HealthEntry>` из `file.upstreams` — при дубле `(upstream, gate, group)` в файле (руками поправленный/повреждённый ktav; snapshot сам дубли не создаёт: rotator dedup (V06) + групповые имена уникальны) выживает последний, первый молча теряется. Survivor identity не load-bearing (обе записи равноправны) — потому Low, не дефект.

Решение: при желании — `Vec` + `last()`-поиск или `entry().or_insert()` с логом о дубликате; минимально — оставить как есть (поведение совпадает с документированным «old last-record-wins»).

Тест-кандидат: file с дублем ключа → обе записи идентичны по эффекту restore (pin текущего last-wins) либо warn-лог (если выбрано решение).

### DT-08 — Low / HARDENING: входные target-грамматики мягче конфиг-валидации: '@', '/', '%' в SOCKS DOMAINNAME и permissive HTTP доходят до DNS/upstream

`crates/resocks5-net/src/connect/util/host_port.rs:34–57`; `server/mod.rs:411–445` (SOCKS), `590–612` (permissive HTTP); контраст — `types/validate.rs:188–203`.

Механизм: `HostPort::parse` проверяет только форму host:port; символы `@`/`/`/`%`/произвольные байты (кроме CTL/whitespace в SOCKS) в домене проходят. Strict-HTTP их отвергает (V13), SOCKS и permissive HTTP — нет: `CONNECT u@h:80`, SOCKS DOMAINNAME `u@h` или `%%%` уходят в resolve как есть. Чужого интерпретатора userinfo/пути в下游 нет (dial использует строку как домен), так что это не обход — только мусорные DNS-запросы и отказы upstream. Несимметрия с `validate_node` (конфиг-хост forbidden '@','/') — вопрос консистентности, не безопасности.

Решение: при желании — RFC 1123 label-грамматика для inbound DOMAINNAME (как в strict authority), или просто документировать свободу домена как намеренную. Статус HARDENING, отказов/обходов не установлено.

Тест-кандидат (если принято): SOCKS target `u@h:80` → REP 4 + `ServerError::Protocol`; positive — легитимные домены/IPv6 без изменений.

## 4. TEST_GAP — границы без тестов (конкретные кандидаты)

- DT-01 corpus: `Host: h:0` / `Host: h:99999` / `Host: [::1]:0` в `server/tests/strict_http.rs` (главный кандидат, см. DT-01).
- `ChainStage::encode/decode` вокруг сентинела: `Hop(usize::MAX-1)` → Target — недостижимо практически, но один unit на `decode(encode(Hop(n))) == Hop(n)` для крайних n_pin зафиксировал бы контракт кодировки (сейчас краевые тесты идут через dial-интеграцию).
- StickyCache generation-wrap: `next_generation.wrapping_add` — при 2^64 touches дубликат `(Instant, generation)` мог бы оставить несинхронный recency-хвост; практическая недостижимость делает тест избыточным — достаточно комментария-инварианта (уже частично есть: «Break ties between touches»).
- `parse_proxy_str("*#comment")`: маркеры до `#` не дают comment-ветку (строка уходит в BadHostPort) — поведение разумное, но не запинено тестом; один assert зафиксировал бы выбор.
- `restore()` с дублем ключа (DT-07) — см. выше.
- `Credentials::into_parts` при `is_utf8()==false`: lossy-String уходит вызывающему, raw wipe уже покрыт (`raw_credentials.rs`); отсутствует тест «после take_username `username_bytes()==None`» — тривиальный пин порядка вызовов.

## 5. Снятые подозрения (проверено — не дефекты)

- `ChainKey` Eq/Hash: поля идентичны, `nodes().len()` + пер-нодовые поля — контракт цел (fixed в прошлом аудите, не регрессировал).
- `ProxyConfig::new` bracket-strip: `remove(0)`/`pop` — одноразово, длина ≤ host; `"[a"` без закрывающей — остаётся как есть, DNS-отказ позже (допустимо).
- `Prefixed::poll_read` при `buf.remaining()==0` → `Ready(Ok(()))` с 0 байт — стандартный контракт ReadBuf, callers tokio интерпретируют по filled-delta.
- `http()` header scan: `scan_from = len-3` до extend — делиметр `\r\n\r\n` через границу чанков не теряется, повторного полного rescan нет.
- `ByteLines` + строгий validate: пустая строка внутри header_lines недостижима (первый `\r\n\r\n` завершает headers).
- `phase()` при прошлом deadline — отказ до poll (`budget.is_zero()`), tokio-Instant монотонный.
- `restore`: `Quarantined` с истёкшим остатком → Probation, unknown state → skip, `left` saturating — согласовано с `Cell::restore`.
- `run_saver` `biased` select + notify-permit: stop между раундами не теряется; in-flight раунд завершается, повторной записи после stop нет.
- `weighted_index/weighted_keys`: `u=0 → +inf key`, NaN/≤0/inf — неэлегибл, fallback на rposition; `order_keys` — total_cmp+index (полный порядок, нестабильность sort безопасна).
- `RatingPolicy::validate`: NaN/поднормали/переполнение k() перекрыты (включая derived-проверки) — конфиг-плавающие не доходят до selection как NaN.
- `mark_dead` с дублированным вызовом того же proxy — double-decrement исключён (`dead.insert` false → early return).
- dial.rs `candidates[report.index]` — индексы `proxies`/`candidates` синхронны, Arc-заморозка до callback.
- `allowed_clients`: fail-closed, `explicit > 8` до вычитания (underflow-защита в коде и в тестах), hex-группы через `is_ascii_hexdigit` до `from_str_radix` (отсекает `+1`), zip по равным массивам.
- `run_user_command`: byte-length лимиты (не chars), `':'` в имени отвергнут, commit под lock против свежего disk-состояния, Debug без хешей.
- `handshake_over_stream`: длина uname/passwd/domain ≤255 до `as u8`; `read_exact`/`write_all` везде; reply-parsing без panic на усечённых ответах.

## 6. Топ приоритетных

1. **DT-01** (Low, VERIFIED_STATIC): range-check порта в strict `Host` — единственное содержательное расхождение фикс-волны с её же контрактом; закрывается парой строк + двумя corpus-строками.
2. **DT-02** (Low, PLAUSIBLE, V02-остаток): in-flight blocking write после `finish` — ack в комментарии уже есть, довести до handshake/generation-решения при следующем касании health-писателя.
3. **DT-03** (Low, PERF_CANDIDATE): двойной deep-clone в `mark_dead` — тривиальный сигнатурный фикс, убрать лишние копии credentials на пути провалов.
4. **DT-04** (Low, PERF_CANDIDATE): двойной eager gate-string — закрыть вместе с P04.
5. **DT-05/DT-06/DT-08** (Low, HARDENING): точечные усиления по мере касания файлов; самостоятельной срочности нет.
