# Верификация третьего раунда фиксов — сводный отчёт двух ревью — 2026-11-05

## Ревизия и метод

Diff-база: `c0246c3..HEAD`, HEAD `af69681`. Коммиты раунда: `2dd1621` (фиксы + регрессионные тесты), `af69681` (правка тестов после CI), `2fe2ace` (CI-only, YAML).

Два агента `@ox` (Opus 5.5, high), оба read-only, без cargo/прогонов:

- **glm-verify-fixes.md** — верификация механизмов всех фиксов по пунктам glm-раунда (`docs/reviews/2026-11-05-glm/`), проверка fix-кода на новые дефекты по категориям rust-intel;
- **glm-verify-tests.md** — регрессионные тесты: наличие, мутационная чувствительность (revert-фикса → красный тест), качество оракулов (§D1/D1a), CI-заявления.

Основной сеанс дополнительно перепроверил: H4 (NOT_FIXED — подтверждено чтением `rotator/mod.rs:90–117`), PLAUSIBLE-находку про `Instant::now() + handshake_timeout` (механизм подтверждён, `connect_socks5_proxy.rs:77`).

**Прогоны не выполнялись** (только CI), код не менялся, commit/push не выполнялись. Добавленные файлы — отчёты этого каталога.

### Статусы фиксов

**VERIFIED** (механизм подтверждён чтением) / **PARTIAL** / **NOT_FIXED** / **REGRESSION** (новый дефект в fix-коде).
### Статусы тестов

**TEST_OK** (мутация ловится) / **TEST_WEAK** / **TEST_MISSING** / **PLAUSIBLE**.

## 1. Главный вывод

Третий раунд закрыл **19 из 21** проверявшихся пунктов glm-раунда (VERIFIED, REGRESSION нет). Два исключения: **H4 — полностью не раскрыт** (doc≠код `same_upstream` остался как был), **CC-09 — частично** (API введён, прод-путь не переключён). Покрытие регрессионными тестами — **все VERIFIED-фиксы имеют тесты с ловлей мутаций**, кроме трёх зон слабости (§3). CI-заявления раунда подтверждены.

## 2. Матрица верификации (пункт → фикс → тест)

| Пункт glm | Фикс | Тест | Ключевые места |
|---|---|---|---|
| H1/CC-01 health `finish`/lock (Med) | VERIFIED — orphan-запись держит Arc-клок до реального конца blocking-write; dirty baseline; duplicate/ambiguous restore | TEST_OK — writer_tests.rs:375,433,470,508,568,607(+контроль :659),689,717,758 | health/mod.rs:346,560–580,390–402; run_saver:796–806 |
| H2/CC-02 `try_lease` overflow | VERIFIED — FAR-fallback | TEST_OK — quarantine.rs:548 | quarantine.rs:154–159,287 |
| H3/CC-03 probe double-trip | VERIFIED — generation claim + atomic `quarantine_now_unless_tripped` + destination-unreachable только для tested gate | TEST_OK — rating/mod.rs:792; probe_tests.rs:381; race :397 (8 потоков+barrier); probes_tests.rs:176,282,356,424 | rating/mod.rs:178–252,392–406; rotator/probe.rs:188; probes.rs:57–80,240–310 |
| H4/CC-04 `same_upstream` doc≠код | **NOT_FIXED** | TEST_WEAK — мутация не ловится | rotator/mod.rs:90–117 — без изменений, см. §3 |
| H5/DT-01 strict Host порт | VERIFIED — контракт doc-side: `Host: *DIGIT` per RFC 9110 (диапазон не обязателен), authority держит 1..=65535 | TEST_OK — strict_http tests: reject :139–151, accept :213–228, e2e :263 | strict_http.rs:73–100,163–172 |
| H6/API-02/03/06 raw creds + wipe + zeroize | VERIFIED — consume-форма без клонов, wipe отклонённых буферов, `zeroize` включён | TEST_OK (байты/лимиты/wipe через witness-Drop; zeroize-ряд в CI) / TEST_WEAK для «без клонов» — см. §3 | server/mod.rs:298–318,381,392; credentials.rs:111–116; resocks5/Cargo.toml:20; raw_credentials.rs:51–480,525,565,626 |
| H8/TQ-05 hedged drain-паника + source | VERIFIED — panic пойман в drain, `HedgeError::source` реализован | TEST_OK — hedged_extra_tests.rs:130 + negative control :208; :244 | hedged.rs:212–227,125–129,355 |
| CC-09 `GateLevels::new` debug_assert | **PARTIAL** — `try_new` есть, но startup.rs:385 по-прежнему `new` (безопасно по построению `group_gate_levels`, но инвариант не enforced в проде) | TEST_OK юнит (chain/mod.rs:497) / TEST_MISSING прод | chain/mod.rs:53–64; validate.rs:12,240–249 (MAX_CHAIN_NODES/ChainTooLong — VERIFIED); proxy_config.rs:163–197,363 (flat Debug — VERIFIED) |
| DT-05 `http_error` unreachable! | VERIFIED — fallback-ветка | TEST_OK — tests/credentials.rs:686 | reply.rs:47–49 |
| SEC-03 timing-enumeration | VERIFIED (на заявленном уровне) — equalised rejection step | TEST_OK — verify_tests.rs:37,49,61 (hmac-счётчик seam) | verify.rs:44–47,153–162 |
| SEC-04/CC-08 sentinel `.lock` | VERIFIED — symlink-защита, bound на рост; TOCTOU stat→open задокументирован (осознанный остаток) | TEST_OK — users_file/tests.rs:390 (symlink), :437 (pid/рост) | lock.rs:61–97,63–66 |
| SEC-05 Argon2 negative-контроли | VERIFIED — v19-only verify + позитивные контролы | TEST_OK — verify_tests.rs:77,95,108; реверт pre-check неуловим (belt-and-suspenders) | verify.rs:228–241 |
| Argon2 m=19456 | VERIFIED | TEST_OK — params.rs:41 (контракт-пин OWASP) | params.rs:15–17 |
| TQ-06 tunnel half-close | VERIFIED — recovery сохраняет сессию, оба вызывающих под бюджетом | TEST_OK — recovery_halfclose_tests.rs (http :93/:188/:268, socks5 :93/:187/:266) | recovery.rs:78–149 |
| R3 progress-aware relay | VERIFIED | TEST_OK — forward_tunnel_progress_tests.rs:30,84 (paused); progress.rs:352/:384 counterfactual pair, :416 | forward_tunnel.rs:139–161,206–241 |
| dial budget reserve | VERIFIED | TEST_OK — budget_tests.rs:107,135,195,242 | dial.rs:44–49,120–127 |
| network bounds + accept deadline | VERIFIED | TEST_OK — network_config.rs:432,479,508; run_server.rs:385 | network_config.rs:285–339; run_server.rs:40–47,66,188 |
| CC-10/GA-05 probe-логи/detached | VERIFIED | TEST_OK — probes.rs:499, probes_tests.rs:424 | route.rs:59–73; probes.rs:161–222 |
| Socks5Greeting → upstream-down | VERIFIED (+ контр-тест) | TEST_OK — error/tests.rs:146,194; dial/tests.rs:314 | error/mod.rs:44–54; connect_socks5_proxy.rs:65–97; classify.rs:69 |
| API-01 грамматики parse/validate | VERIFIED (doc-side + пин-тесты) | TEST_OK | parse_proxy_str.rs:49–58; host_port.rs:34–38; validate.rs:207–214 |
| TQ-03/CI feature_unification | VERIFIED — job с реальными `cargo check/build --locked`, не echo | TEST_OK | ci.yml:302–319 |
| TQ-04 timeout-minutes | VERIFIED — все содержательные джобы ci.yml; остаток: release.yml и `changes` без таймаутов | TEST_OK | ci.yml; release.yml |
| TQ-08 classifier self-test | VERIFIED — 10 кейсов, безусловно в structure | TEST_OK | changed-areas.sh:70–226; ci.yml:159 |
| hedged no-launch-after-win | VERIFIED | TEST_OK — вероятностный catch 2⁻¹², задокументирован | hedged_extra_tests.rs:68 |

## 3. Нераскрытое

### H4/CC-04 — NOT_FIXED (перепроверено основным сеансом на `af69681`)

`crates/resocks5-net/src/session/rotator/mod.rs:90–117` не изменены: док `same_upstream` по-прежнему утверждает «`gate` is deliberately excluded — … so rating a gate-composite still lands on the plain upstream's slot», а код сравнивает `gate_level` (:102) и включает его в `upstream_hash` (:115). Противоречие осталось: gate-composite получает отдельный слот рейтинга, вопреки доку. Теста, ловящего мутацию «gate_level в eq», нет. Требуется решение, какая сторона — контракт: либо убрать `gate_level` из eq/hash (и тогда док прав), либо переписать док и добавить тест identity plain↔gate-composite.

### CC-09 — PARTIAL

`GateLevels::try_new` введён и покрыт юнит-тестом (chain/mod.rs:497), но прод-путь `startup.rs:385` по-прежнему вызывает `new`. Сейчас безопасно по построению (`group_gate_levels` не порождает дубликатов), но инвариант не enforced: будущий код, собирающий уровни из конфига напрямую, молча примет дубликаты в release. Переключить прод на `try_new` (или добавить тест, пинящий построение).

## 4. Слабости тестов

1. **raw «без клонов»** (H6): реверс к `clone` поведенчески невидим; запинена только wipe-половина. Остаток признаётся; при желании — детерминированный счётчик аллокаций (только на same-allocator CI, §E6).
2. **hedged no-launch-after-win**: вероятностный catch 2⁻¹² (12 прогонов против tokio random-ready) — задокументировано, приемлемо, но не детерминировано.
3. **Хрупкие места** (не false-red сейчас, но на загруженном runner'е): wall-clock `elapsed<2s` в probe_tests.rs:146 (запас 1.8×), `elapsed<3s` в RST-тестах, `settle()`=8 yield в 3 negative-пинах health/tests.rs (риск пропуска мутации, не ложной красноты).
4. **af69681** — третий раунд подряд потребовал правки тестов после CI (8 точечных правок); каждая замена улучшила оракул (readable() вместо RST-гонки, ack вместо yield, `_at`-время). Тренд положительный, но шумный.

## 5. Новые замечания (ниже порога дефекта)

- **[CONFIRMED mechanism, Low]** `connect_socks5_proxy.rs:77`: `tokio::time::Instant::now() + handshake_timeout` — unchecked add; SDK-вызов с `Duration::MAX` → паника. Тот же класс, что чинился в соседних местах (V12/H2). Перепроверено основным сеансом. Лечение: checked/saturating, как в `deadline()`.
- health `unchanged`-быстрый путь: re-trip с дедлайном в пределах `every` может пропустить запись — устаревший дедлайн до смены state (health/mod.rs:166–172); окно узкое.
- probes.rs:210–290 — применённая нон-триппящая неудача логируется как «stale» (косметика логов).
- quarantine.rs:154–159 — FAR-fallback=100 лет у края `Instant` даёт `unwrap_or(now)`-угол (конфиг-путь закрыт validate, чисто теоретический).
- lock.rs:63–66 — TOCTOU stat→open задокументирован как осознанный (sentinel в каталоге, контролируемом владельцем).

## 6. Что осталось сделать

1. **H4**: решить сторону контракта `same_upstream`/`upstream_hash` (gate_level in или out), поправить док или код, добавить mutation-тест identity plain↔gate-composite.
2. **CC-09**: переключить `startup.rs:385` на `try_new` (или пин-тест на построение).
3. **Low**: saturating deadline в `connect_socks5_proxy.rs:77`.
4. Опционально: таймауты для release.yml и `changes`-джобы; тест на health `unchanged`-окно.

## 7. Ограничения

Статическая верификация механизмов и оракулов: без выполнения тестов (CI — `af69681` зелёный по сообщению коммита, но прогоны здесь не воспроизводились), без измерений, без полной RFC-сверки (RFC 9110 Host-грамматика принята по заявлению фикса). Статусы отражают чтение кода на `af69681`.
