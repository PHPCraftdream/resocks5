# Аудит unsafe, FFI и ресурсных границ — 2026-11-05

Автор исследования: агент `@oh`, `unsafe-and-ffi.md`. HEAD `870caa2bfa9b6afd8594fabe4df9659bca585760`, приоритет `c927e71..HEAD`. Сохранено основным сеансом из ответа агента: его окружение запретило запись Markdown. Никаких прогонов/измерений, продукт не менялся. Подтверждённой UB в собственных FFI агент не нашёл; это не заключение о полной безопасности.

## UFFI-01 — Неограниченная SDK chain depth и рекурсивные Drop/Debug

Medium, High для механизма; порог stack overflow не измерен. Представление pre-existing, новые chain APIs расширяют использование.

Места: `crates/resocks5-net/src/types/proxy_config.rs:58,119–148,161–172`; `crates/resocks5-net/src/types/chain.rs:12–22`; `crates/resocks5-net/src/types/validate.rs:219–225`.

`gate: Option<Arc<ProxyConfig>>` рекурсивно владеет хвостом. chain/with_gate не ограничивают число узлов, validate проверяет поля, но не depth. Итеративное конструирование, nodes и outermost не делают Drop/Debug итеративными. Конкретный кандидат: 100000 узлов без дополнительных владельцев промежуточных Arc, затем drop на small-stack thread. Последний Arc каждого узла рекурсивно уничтожает следующий и освобождает allocation после возврата; Debug рекурсивно форматирует gate. Число 100000 — вход-кандидат, не измеренный порог.

Влияние: аварийное завершение SDK consumer, если он строит чрезмерно глубокий маршрут из недоверенного списка. Удалённая атака на штатный CLI не доказана: ranked CLI ограничен u8 gate levels (255+exit). Публичное изменяемое gate и SDK builders этим пределом не связаны. Вложенные HTTPS hops также дают вложенные TLS stream layers; конечный dial timeout не ограничивает синхронный Drop/Debug.

Предложение: итеративно уничтожать уникальный хвост через take gate/Arc::try_unwrap, прекращая на shared хвосте; Debug итеративный/усечённый. Отдельный конечный hop budget до создания tunnel/TLS layers/permits. Только builder/dial validation недостаточна при public gate и самостоятельном drop/debug. Unsafe не требуется.

Тест-кандидат: child process, глубокая цепочка, small-stack thread, drop и bounded Debug; MAX_NODES и MAX_NODES+1 отказ до I/O. Mutations: вернуть recursive Drop/Debug или убрать depth admission — отдельные assertions.

## UFFI-02 — Example читает ответ в неограниченный Vec

Low, High, example-only. Новый `crates/resocks5-net/examples/dial_chain_over.rs:31–37`; аналогичный pre-existing `examples/connect_through_proxy.rs:49–53` и SDK README.

После dial total_timeout завершён, peer бесконечно передаёт chunks без EOF; read_to_end накапливает Vec до OOM или бесконечно ждёт. Production relay с bounded copy buffers этим не затронут.

Предложение: если требуется только число bytes, фиксированный read buffer + count, конечные size/time budgets. Если body нужен — take(MAX+1) и явный overflow отказ; timeout сам по себе не ограничивает память.

Тест: peer передаёт MAX+1 и остаётся открыт; helper отказывает без EOF. MAX+EOF принимается. Mutation: удалить budget либо проверять после read_to_end.

## UFFI-03 — Rustdoc custom poll_flush busy-loop при Ok(0)

Low, High; опубликованный пример, не production ProgressReportingWriter. `crates/resocks5-net/src/session/progress.rs:83–98`.

При непустом pending inner poll_write возвращает Ready(Ok(0)); drain(..0) не меняет буфер, report_confirmed(0) не прогрессирует, while повторяет poll без yield. Внешний timeout синхронный loop не прервёт. Собственный write_progress_bounded ноль корректно обрабатывает.

Предложение: written==0 → WriteZero до drain. Тест: stub возвращает Ok(0) первый раз и panic на втором; один poll_flush должен вернуть Ready(Err(WriteZero)). Mutation: удалить нулевую ветку, тест падает на втором poll без зависания.

## Red-tier inventory unsafe/FFI

Агент нашёл 17 unsafe blocks: 10 production, 7 Windows test support.

- `crates/resocks5/src/config/users/users_file/platform_unix.rs:13–35`: два flock, живой borrowed fd, scalar ABI, immediate last_os_error.
- `crates/resocks5/src/config/users/users_file/platform_windows.rs:51–95`: extern system, 8 unsafe blocks; wide strings живы, NUL отвергается, SD освобождается LocalFree, HANDLE передаётся одному File.
- `platform_windows.rs:202–221`: CreateFileW error захвачен до LocalFree.
- `test_support.rs:47–52`: LocalDescriptor владеет allocation, один LocalFree, no generic variance/PhantomData obligation, без manual Send/Sync.
- `test_support.rs:105–123`: read_unaligned в byte arrays, type/size ACE проверены, descriptor остаётся живым.
- ABI mirrors Overlapped/SecurityAttributes/AclSizeInformation repr(C); видимой ошибки не найдено, size/align/offset regression assertions не найдены.
- Miri job не найден: verification gap, не UB. OS FFI требует изоляции/mocks, не простого запуска под Miri.
- SAFETY comments описывают память/ownership, но precise foreign ownership/thread contract references в основном отсутствуют. Запрет использования Windows APIs на blocking threads не установлен.
- Собственных unsafe impl Send/Sync, static mut, transmute, MaybeUninit, get_unchecked, set_len, slice::from_raw_parts, exported C entry points, no_mangle, callback trampolines, staticlib/cdylib не найдено.

## Проверенные границы

Prefixed (`server/prefixed.rs:64–114`) использует safe projection с S:Unpin, pos ограничен фактически скопированными bytes. OverStream (`connect/dial/chain.rs:234–294`) использует Mutex<S>::get_mut эксклюзивно; unsafe workaround отсутствует. UpstreamStream/AnyUpstream/writers используют Pin::new при Unpin. connect_chain (`chain_pool.rs:68–89`) прикрепляет permits к owning base stream до wrapping; ошибки уничтожают owner. dial_chain_over документирует, что drop cloned/shared handle не гарантирует закрытие общего транспорта.

Wire-bound allocations: SOCKS u8 lengths≤255, skip bound domain≤257; inbound HTTP header 16384 с bounded 1024-byte overread; upstream ResponseHead heap 4096 и общий бюджет informational responses; recovery≤16KiB, локальные arrays 4096; TLS walker checked additions/clipped ranges, не выделяет весь attacker-declared payload заранее. Больших опасных stack arrays в просмотренных product paths нет.

## Versions и limits

Root lock: ring 0.17.14, rustls 0.23.46, tokio-rustls 0.26.4, Tokio 1.54.1, socket2 0.6.5, libc 0.2.189, zeroize 1.8.2. ring/cc и native deps входят в trusted base. Fixture lock отличается (rustls 0.23.45, Tokio 1.53.1).

FFI workspace прочитана статически; registry sources/native implementation/system headers не исследовались. Target layouts, stack thresholds, nested TLS costs не измерялись. Наличие тестов не означает их запуск/успех. Все тесты выше — проекты будущих проверок.
