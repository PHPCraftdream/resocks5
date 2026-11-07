# Аудит security/unsafe (rust-intel) — resocks5, 2026-11-05

Ревизия: HEAD `6237994` (содержательные фиксы после базы `870caa2`: `dfe3606`, `2c548e3`, `b4ab336`, `b7eab13`).

Метод: только чтение (Read/Grep/Glob, read-only git: log/diff/show). Никаких cargo/скриптов/приложения/тестов; код, конфиги, зависимости и Cargo.lock не менялись; worktree не создавались. Единственная запись — этот отчёт. Модули rust-intel: `security.md` (B12, B24, C2), `unsafe-and-ffi.md` (B5, B7, B18, B18a, B25, B25a). Это статическая проверка механизмов, не сертификат безопасности.

Задача: (а) проверить фиксы прошлых findings V01–V18, относящиеся к теме security/unsafe (V13, V14, V15, частично V02/V16) — встали ли и не сломали ли соседнее; (б) найти новое. Исправленное (SEC-01 Argon2-параметры, SEC-02 zeroize-scope) повторно не репортится.

## Findings

### SEC-01 — Low / VERIFIED_STATIC (триггер внешний, механизм из исходников): `eprintln!` под `claim_lock` в blocking-потоке

Место: `crates/resocks5/src/auth/state/claim.rs:226-239` (вывод на :235), guard взят на :164.

Механизм: ветка `ClaimPersist::Failed` вызывает `eprintln!` внутри closure `spawn_blocking`, пока удерживается `claim_lock` (std `Mutex`, guard живёт до конца `claim_commit`). `eprintln!` — блокирующий `write()` в stderr; при нечитающем/заполненном stderr-пайпе (supervisor без drain, служба с закрытым дескриптором) запись навсегда блокирует поток вместе с mutex. Последствия: все init-claims процесса стоят (unclaimed-аккаунты не могут залогиниться); обычные verify по committed-hash и cache-hit не затронуты — `claim_lock` берёт только claim-путь. `persist_claim` к этому моменту уже вернулся (users-file lock освобождён), так что зона — только процессные claims.

Тот же кодовая база признаёт режим отказа реальным и именно ради него перевела shutdown-диагностику health на неблокирующий канал логгера: `crates/resocks5/src/server/health/mod.rs:260-263` («a full stderr pipe must not stall the exit») и `crates/resocks5/src/server/bootstrap/log_drain.rs:129-136`. Auth-путь этим рево́рком не покрыт.

Сценарий отказа: stderr перестаёт принимать байты при живом процессе → первый неудачный persist claim-а навсегда держит `claim_lock` → init-claim DoS до рестарта; сообщение об ошибке при этом тоже теряется.

Направление решения: завести `Arc<Logger>` в `AuthState` (health уже так делает) и слать через `proxy_failure`; либо печатать после `drop(_claim_guard)`, ограничив окно удержания mutex.

Тест-кандидат: R7-04 seam уже есть (`claim_probe_emit`) — добавить сценарий «stderr-стоп»: подменить writer нельзя без расширения seam, поэтому минимальный тест — assertion, что `claim_commit` не держит `claim_lock` в момент вывода (emit «before_report»/«after_report» вокруг печати, тест ждёт оба события при заблокированном внешнем sink). Positive control: успешный claim при читаемом sink. Mutation: вернуть печать под mutex → тест зависает на after_report.

### SEC-02 — Low / PLAUSIBLE: abort-ветка `HealthSaver::finish` отпускает cross-process lock, пока blocking-запись ещё бежит

Места: `crates/resocks5/src/server/health/mod.rs:300-308` (abort+return), `:452-462` (`save_offloaded`), `:417-424` (`reclaim_own_temp`), `:429-438` (`remove_stale_temp`), `:346-357` (lock).

Механизм: `run_saver` выполняет каждую запись через `spawn_blocking`; `task.abort()` отменяет future, но НЕ запущенный blocking-closure — JoinHandle брошен, closure доигрывает. В abort-ветке `finish` (`timeout(FINISH_BUDGET)` истёк) происходит `return`, и `lock` (cross-process UsersFileLock на health-файл) освобождается, пока «сбежавшая» запись ещё может выполнить `reclaim_own_temp` + `write_atomic` на фиксированном `<health>.tmp`. Следующий инстанс (новый владелец lock) делает `remove_stale_temp` — удаляет чужой in-flight temp (потерянная запись старого поколения), либо сбежавший `reclaim_own_temp` удаляет temp нового владельца между его `create_new` и commit (потерянная запись нового; на Windows FILE_SHARE_DELETE делает удаление открытым файла возможным, после чего сбежавший writer может опубликовать снимок устаревшего поколения).

Границы: commit атомарен — порчи самого файла нет; обе стороны теряют максимум одну запись; путь требует редкой комбинации (abort по бюджету + немедленный старт второго инстанса), поэтому Low. Комментарий в коде признаёт потерю снимка, но не гонку temp-поколений — это остаточный край нового протокола single-owner из `b7eab13` (регрессия к V02-классу «uncancelled blocking write escapes its owner», сама V02 закрыта).

Направление решения: в abort-ветке дождаться JoinHandle блокирующей записи (бюджет тот же) либо хранить «generation token» в пути temp; никогда не выполнять `reclaim_own_temp` для temp-а, который мог создать другой писатель.

Тест-кандидат: writer_tests уже умеют блокировать writer барьером — сценарий: save_offloaded с барьером, `finish` по бюджету → abort, затем `start()` нового saver-а; assertion: temp нового не удалён сбежавшим (подменить remove через test seam), счётчик удалений. Positive control: нормальный finish без abort. Mutation: убрать reclaim/убрать ожидание.

### SEC-03 — Low / HARDENING: timing-enumeration имён пользователей в verify-пути

Место: `crates/resocks5/src/auth/state/verify.rs:29-36`.

Механизм: `verify_async` отвечает `false` мгновенно для неизвестного/выключенного имени (:30-32), а для существующего включённого считает HMAC и либо cache-hit (наносекунды), либо Argon2id ~15 ms (:41-56). Время ответа различает «пользователь существует и включён» от «нет» — сетевой enumeration-оракал по таймингу. Документированная гарантия («the disabled-vs-unknown distinction never leaks to the client», verify.rs:146-149) соблюдается для значения ответа, но не для его стоимости. Прошлый аудит это не репортил (SEC-01 там был про Argon2-параметры).

Сценарий: удалённый клиент перебирает имена, сортируя по latency → список валидных имён до подбора паролей.

Направление: для неизвестного/выключенного имени прогонять decoy-verify — фиксированный PHC в коде (не из файла) с теми же production-параметрами — прежде чем ответить `false`; стоимость ответа перестаёт зависеть от существования имени.

Тест-кандидат: unit-тест, что для неизвестного имени вызывается decoy-путь (счётчик вызовов Argon2-инстанса через test seam ≥ 1) и ответ по-прежнему `false`. Positive control: известное имя с верным паролем — true. Mutation: убрать decoy-вызов.

### SEC-04 — Low / HARDENING: sentinel lock-файла открывается с symlink-following `create(true)`

Место: `crates/resocks5/src/config/users/users_file/lock.rs:45-51` (открытие), `:56-59` (запись PID).

Механизм: `<users>.lock` создаётся/открывается `OpenOptions::create(true)` — финальный symlink следует за собой. Локальный актор с правом записи в каталог конфигурации может заранее подсадить `<users>.lock` как symlink на чужой файл: contenders разойдутся по inode-ам и cross-process исключение (users-file lock между сервером и CLI) молча пропадёт — два init-claim/persist идут параллельно (lost-update защита деградирует до «как повезёт» с atomic-записью). Граница угрозы: такой актор и так может переписать `users.ktav` целиком, так что это defense-in-depth для доверенного каталога, не пробой границы привилегий — потому HARDENING, не bug. Попутный nit: sentinel никогда не truncate-ится, каждая выдача lock дописывает строку PID — вечный рост на ~6 байт/выдачу при многолетнем аптайме (штатно symlink-нет, файл используется всеми, диагностический).

Направление: зафиксировать допущение «каталог конфигурации доверенный, symlink на sentinel недопустим» в doc-комментарии модуля (сейчас заявлен только «not file existence»), опционально — проверка `symlink_metadata` на первом создании; для роста — писать PID по смещению 0 (`seek`), файл всё равно диагностический.

Тест-кандидат (POSIX-only, юнит): sentinel-путь → `symlink_metadata`-проверка в `acquire_with_timeout` отвергает symlink (Err вместо Ok). Positive control: обычный файл принимается. Mutation: убрать проверку.

### SEC-05 — TEST_GAP / Low: verify-путь не имеет negative-контролей на чужеродные PHC-варианты

Место: `crates/resocks5/src/auth/state/verify.rs:191-198` (`argon2_verify`), файлы `crates/resocks5/src/auth/state/tests/claim_tests.rs` (позитивные и rejection-тесты claim-путей есть: wrong password, DiskHashChanged, user removed — проверены чтением).

Механизм: `argon2_verify` парсит PHC из файла и верифицирует тем, что записано в самом PHC (алгоритм, версия, параметры) — `Argon2::verify_password` в argon2 0.5 сверяет algorithm/version с инстансом (Argon2id/v19) и отклоняет чужие, но использует параметры ИЗ СТРОКИ. Это fail-closed для argon2i/v16 (verify → Err → false), но значит, что SEC-01-политика (m=5120,t=2) соблюдается только при СОЗДАНИИ хеша: externally-отредактированный PHC с m=8,t=1 примется. Эскалации нет — компрометировавший файл актор может просто подставить хеш известного ему пароля с сильными параметрами (равная мощность), файл owner-controlled по threat-model. Пробел — отсутствие тестов, фиксирующих эти контракты.

Тест-кандидат (по одному assertion, без сети): (1) users-файл с `$argon2i$v=16$...` → `verify` == false; (2) обрезанный PHC (нет полей params) → false; (3) PHC с валидным, но слабым params (m=8,t=1,p=1) от того же пароля → возвращает true — pin текущего self-describing контракта документирующим тестом; при введении policy-floor на verify тест мутационно сломается. Mutation-цель: убрать сверку algorithm/version в библиотеке (upstream) — тест (1) ловит.

## Новые изменения (diff 870caa2..HEAD) — findings именно на diff

- SEC-02 — единственный in-scope дефект в новом коде (health writer/lock/temp из `b7eab13`, abort-ветка; регрессия-край к V02).
- Остальное новое в моей зоне — проверено чистым:
  - `crates/resocks5-net/src/server/strict_http.rs:21-47,57-76,108-148,176-178,191-205` — V13/V14-фиксы + Host grammar из `b7eab13`: authority-грамматика до auth (`/`, `@`, userinfo, path, query отклоняются; bare IPv6 отклоняется; port 1..=65535, ≤5 цифр), CTL/NUL/DEL в field-value отклоняются, HTAB/obs-text сохранены, duplicate Host/Proxy-Authorization отклоняются, obs-fold отклоняется. Ответы — статические байты (`server/reply.rs:5-67`), данные запроса на wire не отражаются; diagnostic-строки ошибок формируются через `{:?}` (экранирование управляющих байтов) — CRLF-инъекции в wire и логи нет. Тесты: `crates/resocks5-net/src/server/tests/strict_http.rs:140-147` (Host-negative: `bad/path`, `user@host`, `bad%zz`, пустой порт, незакрытая скобка, `::1` без скобок), :94/:367 (authority path), :38/:61-72 (duplicate/missing/empty Host).
  - `crates/resocks5-net/src/server/mod.rs:732-748` — V15-фикс `discard_wiped`: `username_raw` zeroize-ится до `take()` при `take_username` (под feature; без feature — plain take). В месте с `username`-String-полем wipe при Drop остаётся на месте.
  - `crates/resocks5/src/server/health/mod.rs` — single-owner lock, own-temp reclaim, offload, stop-protocol, baseline-before-probes, group-keyed restore: встали, соседнее (users-temp) не задето (`reclaim_own_temp` удаляет только `<health>.tmp`, комментарий :415-416 подтверждает). Файл создаётся через общий `write_atomic` → unix 0600 / Windows owner-only DACL (SDDL `D:P(A;;FA;;;OW)`) с первого создания — проверено кодом `platform_windows.rs:145-222` и тестом `test_support.rs::assert_owner_only_dacl`.
  - `crates/resocks5-net/src/session/rating/quarantine.rs` — V16-фикс `duration_for` (цикл с saturating_mul, break по cap/насыщению — O(min(trips,64)), u32::MAX безопасен) и `deadline()` (checked_add → FAR=100y fallback → `unwrap_or(now)` недостижим практически: требует `now > Instant::max - 100y`). Тесты :288-330, :447-519 покрывают trips 21/22/23, u32::MAX, Duration::MAX.
  - `crates/resocks5-net/src/connect/proxy_connect/hedged.rs` — V03/V12: `handshake_slot: tokio Mutex<()>` эксклюзивный admission, win публикуется до освобождения слота; `hedge_deadline` через checked_add, `None` → `pending()` (никогда не паникует). Слот держится не дольше connect-timeout.
  - `crates/resocks5/src/server/connect/establish_connection/route.rs` — V18-половина: probe через `pool.reserve_permit`, capacity → defer, не «down». Мутационный тест в файле.
  - `crates/resocks5-net/src/session/rotator/probe.rs:210` `panic!("synthetic task failure")` — тестовый, `drain_checks` переживает панику задачи и репортит остальные результаты (тест :200-222).
- Классификатор CI (`.github/scripts/changed-areas.sh`, +5 строк) — вне моей зоны, не проверялся глубоко.

## Регрессия-проверка фиксов моей темы (V-ссылки)

| V-id | Фикс | Статус проверки |
|---|---|---|
| V13 | strict authority grammar (`strict_http.rs:108-148`) | ВСТАЛ. Соседнее не сломано: non-strict путь сохранён (:559-570 — validate только под флагом), HTAB/obs-text положительные сохранены в тестах. |
| V14 | CTL byte check (`strict_http.rs:176-178`) | ВСТАЛ. CR/LF между headers — разделители, не value-bytes; NUL/DEL/прочие C0 в значении отклоняются. |
| V15 | wipe raw username (`server/mod.rs:732-748`) | ВСТАЛ (`2c548e3` поправил witness-тест на in-place zeroize: `Vec::zeroize` также обнуляет length). |
| V02 (частично) | health: offload, lock, own-temp, stop-protocol (`health/mod.rs:254-313,452-462`) | ВСТАЛ. Один остаточный край — SEC-02 (abort-путь). users-файл recovery-политика не тронута (что и требовалось). |
| V16 | quarantine back-off до max (`quarantine.rs`) | ВСТАЛ, tests exact 21/22/23/u32::MAX. |
| SEC-01(стар.) | Argon2 params | Не менялись (`params.rs:10-12` m=5120,t=2,p=1) — повторно не репортится. |
| SEC-02(стар.) | zeroize scope | Частичный фикс V15 встал; общий parser-buffer scope остаётся прежним решением — не репортится. |

## Категории rust-intel — покрытие по коду

- **B5/B18a**: `rg unsafe` по репо — 17 блоков, все в `crates/resocks5/src/config/users/users_file/` (`platform_windows.rs`, `platform_unix.rs` flock, `test_support.rs`, тестовый). Подтверждено: transmute/from_raw_parts/get_unchecked/mem::uninitialized — нет; ручных `unsafe impl Send/Sync` — нет; raw-pointer wrappers/PhantomData-решений — нет. Каждый блок несёт `// SAFETY:` с именованными инвариантами (владение SD → `LocalFree` как документированный deallocator; errno захвачен ДО `LocalFree` — `platform_windows.rs:203-211`, образцовая дисциплина B25a). `Overlapped`/`SecurityAttributes` `#[repr(C)]` зеркала совпадают с Win32 раскладкой (32 байта на 64-бит, offsets 0/8/16/20/24; 20 на 32-бит). `read_unaligned` в test_support — test-only, корректно.
- **B7**: все аллокации от сетевого входа ограничены: SOCKS nmethods≤255, UNAME/PASSWD≤255, DOMAINNAME≤255; HTTP header — жёсткий cap 16 KiB (+1023 макс. перелёт на одном read, `server/mod.rs:519-539`), base64-decode ≤ ~12 KiB из capped-заголовка; chunk-скан `\r\n\r\n` с overlap-коррекцией (`scan_from = len-3`) корректен. Count×size через небезопасные произведения нет. Decompression/archive — нет. B7-чисто.
- **B12**: crypto-инвентарь: **Argon2id** v19 m=5120 KiB, t=2, p=1 (argon2 0.5.x) — соленье `getrandom::getrandom` 16 байт на каждый хеш, fail-closed при ошибке энтропии (`compute_hash.rs:11-15`); параметры — прежний осознанный компромисс (SEC-01 прошлый аудит). **HMAC-SHA256** (hmac 0.12 + sha2 0.10): ключ — 32 байта getrandom на процесс, не персистится (`state/mod.rs:141-143`), separator `0x00`, сравнение cache — `subtle::ConstantTimeEq` на фиксированных 32 байтах (`verify.rs:138-142`). Custom-крипты, nonce/AEAD, SmallRng/StdRng — нет. salt-per-username/fixed — нет. Secret-поля без redacted Debug: `User` derives Debug с PHC-полем (флаг прошлых аудитов, не репортится); `Credentials`/`IncomingRequest`/`Prefixed` Debug redacted.
- **B24**: `==` на секретах нет (password никогда не сравнивается, identity через Argon2/HMAC). Decrypt/MAC-oracle нет. Различие «отклонено до Argon2» по значению ответа устранено (всегда false), по времени — SEC-03.
- **B25/B25a**: extern-блоки только kernel32/advapi32 (`extern "system"`) и flock (`extern "C"`); сигнатуры — примитивы/указатели, без Rust-типов, enum/`&str`/`bool` через границу не ходят; `LocalFree` пары — точные; экспортов `#[no_mangle]` нет; колбэков нет; panics через границу невозможны (синхронные вызовы без пользовательских callback-ов).
- **C2**: unwrap/expect в production auth/users/health-путях — на `Mutex::lock().expect("poisoned")` (poison = баг инварианта, приемлемо), `expect("hardcoded Argon2 params are valid")` (константа), `expect("HMAC accepts any key length")` (контракт). Паника blocking-closure → `unwrap_or(false)`/`Done(false)` — fail-closed (`verify.rs:55,104`). `anyhow` в бинарном крейте — допустимо. Path::join с пользовательскими сегментами нет (пути только из config). Проверено, не репортится.

## Проверено — находок нет (выборка)

- `write_atomic` (`users_file/mod.rs:99-153`): create_new temp (не следует symlink финального компонента; Windows `CREATE_NEW` тоже отвергает dangling-symlink), private mode/DACL до записи, unix chmod до sync_all, ReplaceFileW-коды 1176/1177/прочие с корректной политикой сохранения tmp.
- `wide()` (`platform_windows.rs:98-129`): NUL-чек, `std::path::absolute` нормализует `..` до verbatim-префикса, verbatim-пути не трогаются; тест :131-139. Путь <248 без `\\?\` — длинные пути просто фейлятся (безопасное направление).
- `persist_claim` (`claim.rs:285-339`): все ветки fail-closed; файл-исчезновение → Failed, не resurrect; DiskHashChanged → disk wins; повторная публикация невозможна (claim_lock сериализует единственных писателей users[idx]).
- Health restore: legacy empty-group fallback только для pre-group файлов, пароли не пишутся (`HealthEntry` — только label с username), `remaining_sec` — u64, арифметика saturating (`restore` :163-207).
- `run_saver` select biased stop-first; notify-разрешение переживает итерацию записи — финальная запись остаётся единственной (не-abort путь).
- Strict HTTP header cap: scan/collect bounded; `ByteLines` без аллокаций; non-strict duplicate Proxy-Authorization — первый выигрывает, остальные никуда не пересылаются (байпаса нет).
- `Prefixed` (`prefixed.rs`): префикс отдаётся ровно один раз, EOF только от inner; Debug без байтов префикса.
- `HostPort::parse` (`host_port.rs`): rejections покрыты тестами; percent-хосты вниз по DNS не резолвятся (безопасно).
- `TlsFragmentConfig` (`config/main/tls_fragment_config.rs`): `fragment_size=0` → `.max(1)` в библиотеке; huge delay — доверие конфиг-файла (локальный owner), не remote-вход.

## Топ приоритетных

1. **SEC-02** (Low/PLAUSIBLE, новый код `b7eab13`) — abort-ветка health-finish: сбежавшая blocking-запись vs reclaim temp следующим владельцем lock. `health/mod.rs:300-308`.
2. **SEC-01** (Low/VERIFIED_STATIC) — `eprintln!` под `claim_lock` при нечитаемом stderr → process-wide init-claim DoS. `auth/state/claim.rs:235`.
3. **SEC-03** (Low/HARDENING) — timing-enumeration имен (мгновенный отказ unknown vs ~15 ms known). `auth/state/verify.rs:30-36`.
4. **SEC-05** (TEST_GAP) — negative-контроли чужеродных/слабых PHC в verify-пути. `auth/state/verify.rs:191-198`.
5. **SEC-04** (Low/HARDENING) — symlink-following sentinel lock + вечный рост PID-строк. `users_file/lock.rs:45-59`.

Ни одного High/Medium в зоне security/unsafe на текущем HEAD не найдено; фиксы V13/V14/V15/V02/V16 подтвердились, регрессий соседнего поведения не обнаружено.
