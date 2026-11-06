# PERF208 — credentials (candidate 1)

## Итог

Принят финальный runner `target/perf208/credentials-proof-final`: `accepted=true`, 0,25 с при бюджете 15 с. В stdout: credentials 22, raw credentials 15, I/O failures 11, framing 20, SDK 20, app 8; всего **96 исполнений**. Из 121 парного сценария parent-before → proof-final изменились только две Basic строки; остальные 119 идентичны. Ранее принятый `credentials-verified` совпадает с proof-final по всем 121 строкам: добавленные observer/harness и guard не изменили измерения и не добавили PERF208 rows.

| Сценарий | alloc | dealloc | запрошено байт |
|---|---:|---:|---:|
| `wire/http/basic/retain` до → после | 11 → 10 | 7 → 6 | 6094 → 6084 |
| `wire/http/basic/plain` до → после | 8 → 7 | 7 → 6 | 6075 → 6065 |

Полные before/after counters и метаданные сборочного графа — в [`../results/credentials.json`](../results/credentials.json). Baseline — parent paired `before`, а не ранний эксперимент. Ранее отклонённый первоначальный вариант имел +16 B регрессии; его исторические результаты сохранены отдельно и не используются как baseline.

## Изменение и причины

В успешном HTTP Basic пути `String::from_utf8(decoded)` преобразует принадлежащий `Vec<u8>` буфер в `String` без копии; существовавший `text.to_owned()` для сохранения всего decoded token был transient и заменён перемещением `text` в `Credentials`. Нет изменений API, `Arc` или `Cow`. Реализации getters и `take` не аллоцируют; это утверждение по коду, не отдельное измерение.

Контроль +16 B: регрессию owning `FromUtf8Error` устранило именно `.map_err(|error| error.utf8_error())` перед потенциальным `.await`: ошибка больше не владеет исходным буфером. Наблюдавшийся рост Box allocation исчез. Точный размер/layout future не измерялся и диагноз точного layout не заявляется.

`duplicate` сохраняется намеренно; копируются следующие данные:

| Вариант | Дублируемые поля | Зачем нужен отдельный владелец |
|---|---|---|
| UTF-8 | username и password (`String`) — 2 копии | независимая жизнь callback-владельца, retention и request identity |
| raw | username, password и обе raw byte-векторы — 4 копии | те же независимые владельцы при сохранении исходных байтов |
| Basic | username, password и whole decoded `basic_payload` — 3 копии | callback и retention имеют независимые lifetime/drop |

Request identity управляется отдельно через `take_username`/`set_identity`: её передача не требует клонировать request или Credentials. Реализация находится в `crates/resocks5-net/src/server/credentials.rs:66-75`; поля — `:7-12`, identity API — в `crates/resocks5-net/src/server/mod.rs`.

В успешном Basic пути decoded `String` теперь становится частью `Credentials`, и при callback/error/cancel drop может очистить её через `Drop` (если включён `zeroize`). Observer компилируется только под `cfg(all(test, zeroize))`: это TLS function pointer без новых layout-полей и без heap-аллокации в неактивном режиме; уведомление происходит после фактического `Drop` wipe. Наблюдатель фиксирует lifecycle, не читает освобождённую память; осмотр freed memory не проводился. Два lifecycle-теста проверяют реальный callback `c` в pending и retention случаях независимо. Защита относится к успешной ветви: malformed UTF-8 и отсутствующий `:` завершаются до создания `Credentials`.

Unit-путь `CLEARTEXT_SERVER=true` под `cfg(test)` разрешает Basic для тестирования; это не normal policy/default. Обычный запуск без cleartext не выполнялся.

## Тесты и ограничения приёмки

В финальном runner выбраны SDK 20, app 8, credentials 22, raw credentials 15, I/O failures 11, framing 20; суммарно 96. PERF guard проверяет оба full-accept пароля длиной 22/118: decoded payload delta — 96 B; `requested_bytes` delta — 192 B для plain и 384 B для retain; allocation counts неизменны. Новых PERF208 rows нет; всего 121. Контролируемый результат согласуется с объяснением устранённой копии, но сам по себе не доказывает конкретный layout будущего. Проверки lifecycle используют callback `c` и actual Drop; не делается утверждение о compile-time non-Clone guard.

Negative controls ожидаемо отвергнуты: `credentials-negative-copy/status.json` — `accepted=false`, SDK exit 101, delta 288 != 192; `credentials-negative-wipe/status.json` — `accepted=false`, check exit 101, lifecycle `[false,false]` вместо `[true,true]`. После controls продукт восстановлен, финальный runner принят. Clippy `target/perf208/credentials-proof-clippy.txt` завершился с exit 0 (наблюдение orchestrator).

Parent-before и proof-final парные counters сверены программно по ключам: 121/121; ровно две ожидаемые Basic строки изменились, остальные 119 идентичны. Proof-final и prior accepted `credentials-verified` также равны по всем 121 строкам. Нормализованные dependency graphs сравнены независимо для SDK и app: package ID без локального пути → `package@version`, target name, kind, sorted features. SDK: 89 до/после, SHA-256 обоих `a0dd10907eb632cec95ba2081adb97193fba1bba28e40df5ed26183a60702a08`, set diff 0. App: 129 до/после, SHA-256 обоих `3117075e57c1ce907bb084b5fd15986f361d8ac8ef84904696126bf30061a598`, set diff 0. Хэш вычислен как SHA-256 UTF-8 компактного JSON нормализованного отсортированного списка объектов `{package_id,target,kind,features}` с сортировкой ключей; local package ID — `package@version` (имя из basename manifest path), registry ID — `package@version`; kind/features отсортированы. Локальные/private пути не включены.

## Отдельный world: zeroize-off

Проверен отдельно, не является A/B-сравнением и не заменяет 121 default-world counters: `target/perf208/credentials-zeroize-off/status.json` — `accepted=true`, 0,25 с при бюджете 15 с; stdout: SDK 20, app 8, четыре checks 18/12/11/20, всего **89 исполнений**. SDK manifest `target/perf208/credentials-zeroize-off-sdk-build.json` завершился exit 0. SDK features фактического артефакта: `pool,rating,rotator,serde,test-instrumentation,tls` (без `secure-auth` и `zeroize`); app — неизменённый default manifest. Guard скомпилирован и прошёл, observer и lifecycle tests gated-out без `zeroize`.

SDK build command: `RUSTFLAGS=-Dwarnings CARGO_INCREMENTAL=0 cargo test --locked -j2 -p resocks5-net --lib --no-default-features --features pool,tls,serde,rating,rotator,test-instrumentation --no-run --message-format=json`. Runner использовал те же четыре SDK checks и default app с общей deadline 15 с. Этот результат — отдельная feature-world проверка, не сопоставлять её allocation counters с основным default-world before/after.

Команды воспроизведения из корня worktree (stdout/build manifests — под `target/perf208`). Перед каждым повтором выберите новый, ещё не существующий каталог `--output`: runner намеренно отклоняет повторное использование каталога результатов.

```sh
RUSTFLAGS='-D warnings' CARGO_INCREMENTAL=0 cargo test --locked -j2 -p resocks5-net --lib --features zeroize,test-instrumentation --no-run --message-format=json > target/perf208/credentials-proof-final-sdk-build.json
RUSTFLAGS='-D warnings' CARGO_INCREMENTAL=0 cargo test --locked -j2 -p resocks5 --bin resocks5 --features test-instrumentation --no-run --message-format=json > target/perf208/credentials-proof-final-app-build.json
python tests/perf208/run.py --sdk target/perf208/credentials-proof-final-sdk-build.json --app target/perf208/credentials-proof-final-app-build.json --output target/perf208/credentials-proof-final --check sdk:server::tests::credentials:: --check sdk:server::tests::raw_credentials:: --check sdk:server::tests::io_failures:: --check sdk:server::tests::framing::
RUSTFLAGS='-D warnings' CARGO_INCREMENTAL=0 cargo clippy --locked -j2 -p resocks5-net --all-targets --features zeroize,test-instrumentation -- -D warnings
```

Runner использует общий deadline 15 с. Финальный default-world результат: `target/perf208/credentials-proof-final/status.json`, elapsed 0,25 с; Clippy artifact: `target/perf208/credentials-proof-clippy.txt` (exit 0, orchestrator). Компилятор/host copies здесь не зафиксированы отдельно; сведения environment в JSON относятся к сохранённым artifacts, не являются независимым воспроизведением версии compiler/host. Команды выше приведены для воспроизведения; при обновлении документов cargo/tests не запускались. Очистка всех копий секретов, созданных компилятором или host-кодом, не доказана; observer проверяет только живые поля Credentials после wipe, без чтения freed memory.
