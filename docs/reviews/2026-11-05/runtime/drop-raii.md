# Аудит Drop и RAII — 2026-11-05

Автор исследования: агент `@oh`, модуль `drop-and-raii.md`. HEAD `870caa2bfa9b6afd8594fabe4df9659bca585760`; приоритет `c927e71..HEAD`. Основной сеанс сохраняет ответ агента, которому запрещена запись отчётов Markdown. Только статический аудит, без исполнения или изменений продукта. Severity ниже — оценка агента; финальная проверка и дедупликация в сводке.

## DROP-01 — Abort saver не сериализует финальный save

P2, High; новый код. `crates/resocks5/src/server/bootstrap/startup.rs:525–527`; `crates/resocks5/src/server/health/mod.rs:284–295`; `crates/resocks5/src/config/users/users_file/mod.rs:99–153`.

Saver получает snapshot A, создаёт общий temp и выполняет синхронный write/fsync. Shutdown abort только запрашивает отмену, синхронный участок продолжается. save_now(snapshot B) получает AlreadyExists, saver публикует A. Штатный shutdown оставляет старый health.

Решение: один writer, stop/final-snapshot/ack протокол; abort+await перед финальным save устраняет гонку, но не зависший I/O (DROP-02). Тест: barrier после temp создания, сменить health, shutdown; не допускать второго writer и проверить B. Mutation убрать join/сериализацию.

## DROP-02 — Синхронный health save обходит bounded teardown

P2, High, новый код. `health/mod.rs:263–265,292`; `startup.rs:527–534`; `config/users/users_file/mod.rs:139–144`; `server/bootstrap/runtime.rs:55–57` (все под `crates/resocks5/src/`).

После tunnel drain root block_on вызывает синхронный save_now. Зависший write/sync/commit не даёт дойти до log drain/runtime shutdown timeout; eprintln error path тоже синхронен. Timeout вокруг синхронного save не помогает.

Решение: isolated single writer, bounded ожидание final save, явная политика потери последнего snapshot; не запускать второй writer после timeout. Тест: controllable writer blocked до release, shutdown возвращается до release; затем освободить свой worker. Positive fast writer сохраняет финал. Mutation вернуть inline save.

## DROP-03 — Orphan health temp блокирует последующие saves

P2, High, новое применение старого helper. `crates/resocks5/src/server/health/mod.rs:258–259,292–303`; `crates/resocks5/src/config/users/users_file/mod.rs:101,108–128`; `docs/REFERENCE.md:269–274`.

Crash после создания resocks5.health.ktav.tmp до commit оставляет файл. Фиксированное имя/create_new намеренно сохраняет recovery-файл. После рестарта все retries/final save получают AlreadyExists; health lifecycle recovery нет. Потеря изменений может продолжаться неограниченно, не только последний save interval.

Решение: отдельная health temp policy — уникальный owned temp+atomic replace либо recovery под надёжной блокировкой. Не удалять users recovery temp: у него иной контракт неопределённого commit outcome.

Тест: target старый/отсутствующий + orphan temp; saver должен сохранить новое состояние без ручной очистки. Mutation фиксированный create_new без recovery.

## DROP-04 — Глубокие SDK chains рекурсивно уничтожаются

P2, High; representation pre-existing, chain API новый. `crates/resocks5-net/src/types/proxy_config.rs:58,119–122`; `types/chain.rs:12–22`; `session/rotator/mod.rs:192–197,410–419`.

Длинная unique цепочка обходится итеративно, но последний root Arc запускает recursive drop каждого gate. Sticky eviction может вызвать это под mutex. SDK depth не ограничен; CLI u8 ranks не доказывают remote arbitrary-depth attack.

Решение: iterative unique suffix teardown через извлечение gate, корректный shared suffix; builder-only limit недостаточен при public gate. Тест: isolated small-stack child drop + shared-tail positive control; mutation recursive drop.

## DROP-05 — Diagnostic Drop может double-panic

P3, High, HEAD test-only. `crates/resocks5-net/src/connect/tls/test_trace.rs:323–327`.

Во время unwind Diag::drop вызывает eprintln; при неработающем реальном stderr/--nocapture возможна вторая panic и abort test process. Обычный capture снижает достижимость, не доказывает безопасность.

Решение: best-effort non-panicking writer с ignored io::Result. Тест: error writer в diagnostic emission helper во время внешнего unwind, child failing stderr scenario. Mutation expect/eprintln возвращает abort. Это не production failure.

## DROP-06 — Concurrent forget оставляет orphan refill task

P2, High, pre-existing. `crates/resocks5-net/src/session/pool/proxy_pool/mod.rs:386–397,423–450,518–521,539–541`.

T1 публикует queue A до handle; T2 forget удаляет её без handle. T1 регистрирует A; новый spawn B заменяет handle A, detach без abort. Pool Drop abort-ит только B, task A живёт со своими queue/semaphore/sockets.

Решение: общая lifecycle serialization публикации/регистрации/forget, фиксированный порядок locks. Тест: barriers между публикацией/регистрацией, forget/recreate/drop при живом runtime, обе generations освобождаются; mutation убрать serialization. Отличается от документированного нового cap budget после forget.

## DROP-07 — take_username выбрасывает raw identity без wipe

P3, High, новый код. `crates/resocks5-net/src/server/mod.rs:157–160,735–752`; SDK `README.md:82–85`.

При raw non-UTF8 username request владеет lossy String и raw Vec. take_username возвращает только String и устанавливает username_raw=None, обычный Vec drop; feature-gated request Drop уже не видит raw allocation. Это не передача raw caller и не затрагивает password этим путём.

Решение: feature-gated wipe raw до None, сохранить once-only transfer. Тест: bounded instrumentation перед deallocation, raw username zeroed, retained credentials независимы; не читать freed memory. Mutation удалить wipe.

## Не defects сами по себе

Намеренный hedge loser drain, documented checkout_unguarded/новый cap после forget, auth permits в noncancellable closure, bounded log-drain loss policy, close owning file после unlock error, socket RAII без обещания полного TLS close. Edition остаётся 2021, миграции нет.

## Inventory, perf и limits

Custom credentials/request/pool/file-lock destructors прочитаны; конкретный escaping destructor panic найден в test diagnostic. Production process exit/abort/ManuallyDrop/mem::forget в тематическом поиске не найдены; crash-owner test exit намеренный, stdout flush явный. DB transactions нет.

Неизмеренные кандидаты: освобождать вытесненные chain Arc вне sticky mutex; отделять abort request от подтверждённого lifecycle completion. Не применять forget к resource owners ради скорости exit.

Resolved Tokio1.54.1, rustls0.23.46, tokio-rustls0.26.4, DashMap6.1.0, crossbeam-queue0.3.12, zeroize1.8.2, ktav0.8.0. Dependency sources вне checkout не читались, runtime reproduction/mutations/measurements отсутствуют. Нет доказательства отсутствия остальных lifecycle defects.
