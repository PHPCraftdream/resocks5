# Аудит dependencies, features и повторных вычислений — 2026-11-05

Автор: агент `@oh`, модуль `deps-macros-ergonomics.md`. HEAD `870caa2bfa9b6afd8594fabe4df9659bca585760`, диапазон `c927e71..HEAD`. Отчёт сохранён основным сеансом из сообщения агента: агенту запрещена запись Markdown. Только статическое исследование; никакие прогоны, изменения продукта, scans или измерения не выполнялись. Окончательная верификация/дедупликация — в сводке.

## DF-01 — Нет обязательного yanked dependency gate

P2 по оценке агента, High, существующий policy gap. `deny.toml:5–7`; `.github/workflows/ci.yml:309–334`.

Обязательный cargo deny проверяет licenses/bans/sources, advisories отдельным continue-on-error job. Явный yanked=deny отсутствует. Locked build может продолжать собирать уже yanked версию; отсутствие обязательного gate не доказывает, что текущий pin yanked/уязвим.

Предложение: явный deny и обязательный отказ, при намеренно информационных advisories — отдельный yanked gate. Цена: upstream yank блокирует выпуск. Тест: policy fixture с известным yanked pin, nonzero именно по yank; mutation удалить deny/обязательность.

## DF-02 — Publish token доступен verification build в cache-producing job

P2, High для границы, exploitability условна. `.github/workflows/release.yml:192–230`.

Rust-cache включён; dry-run без токена проверяет пакет. Следующий cargo publish --locked получает CARGO_REGISTRY_TOKEN и не имеет --no-verify, значит verification может снова запускать build scripts/proc macros с этим environment. Cache post-step может сохранить их outputs; manual dispatch на default branch расширяет cache visibility для PR. Фактическая утечка/содержимое dependency sources/кешей не проверены.

Предложение: secret-free verification и upload без build verification после проверки тех же неизменяемых bytes либо отдельный upload job без cache. Просто отключить verification без предварительной проверки нельзя.

Тест-кандидат: отдельный fixture с несекретным canary, build script отмечает только факт его присутствия; доказать, что token-bearing этап не запускает build code и не кеширует canary. Mutation: вернуть verification в upload.

## DF-03 — strict_http принимает path/userinfo в CONNECT authority

P2, High, новый код. `crates/resocks5-net/src/server/strict_http.rs:49–85`; `crates/resocks5-net/src/connect/util/host_port.rs:45–55`; `crates/resocks5-net/src/server/mod.rs:558–610`.

При strict=true/anonymous разрешены `CONNECT example.com/path:443 HTTP/1.1` с Host example.com, а также user@example.com:443. Validator проверяет непустой host/no colon, не грамматику authority; HostPort также пропускает. Public accept возвращает IncomingRequest для invalid authority. SSRF/request smuggling не доказаны.

Предложение: грамматика CONNECT authority — исключить userinfo/path/query/fragment/invalid bytes и escapes, сохранить bracketed IPv6/explicit port. Typed parser — отдельное решение после dependency review, без silently normalizing URL parser.

Тест-кандидат через accept: /,@,?,#,invalid percent escapes→400/Protocol/auth closure не вызвана; valid reg-name/IPv4/bracketed IPv6, ports 1/65535 приняты. Mutation убрать host grammar check.

## DF-04 — strict_http не проверяет controls неизвестных header values

P2, High, новый код. `crates/resocks5-net/src/server/strict_http.rs:90–119`; `crates/resocks5-net/src/server/mod.rs:540–567`.

В strict CONNECT `X-Note: a\x00b` (реальный NUL byte) проходит: проверяются names и отдельные Host/Auth properties, неизвестные values игнорируются. RFC validation нарушена, пересылка неизвестного header и эксплуатация не доказаны.

Предложение: byte validation каждого value до semantic handling: NUL/запрещённые controls/голые CRLF отвергать, HTAB/obs-text сохранить. is_ascii слишком строго.

Тест-кандидат: NUL/0x01/DEL/embedded CRLF→400 без auth вызова; HTAB/obs-text positive controls. Mutation убрать value validation.

## DF-05 — Повторная материализация выбранной chain и allocation в Hash

P3 performance-кандидат; High для операций, влияние не измерено. `crates/resocks5-net/src/session/chain/mod.rs:82–85,144–147,251–261`; `crates/resocks5-net/src/types/chain.rs:12–22,89–103`; `crates/resocks5/src/server/connect/establish_connection/dial.rs:110,200`.

current_pick/resolve строят linked ProxyConfig для ChainKey, clone-ят host/user/password каждого hop и создают Arc. Затем app pick.config повторяет материализацию O(h) строк/allocations. ChainKey::hash дополнительно вызывает nodes() с временным Vec<&ProxyConfig>.

Предложение: внутренний read-only app path использует уже существующий pick.key().exit() под Arc, а public config()->ProxyConfig сохраняет семантику независимой копии. Hash обходит links напрямую; length при необходимости отдельным проходом. Sharing/Arc::get_mut tradeoff нельзя молча переносить на public API.

Тест-кандидат: chain identity/order/credentials/levels для 1/2/многих hops; focused allocation/clone counter не допускает повторную материализацию после выбора; Hash не выделяет nodes Vec. Mutation вернуть pick.config/Vec hashing. Измеренных speedup нет.

## Dependency inventory

Root resolved: Tokio 1.54.1; tokio-macros 2.7.2; rustls 0.23.46; tokio-rustls 0.26.4; rustls-webpki 0.103.16; webpki-roots 0.26.11→1.0.11; zeroize 1.8.2; serde 1.0.228; socket2 0.6.5; DashMap 6.1.0; crossbeam-queue 0.3.12; regex 1.11.1; ktav 0.8.0; rpassword 7.5.1.

Изменения pins: Tokio 1.53.1→1.54.1, webpki 0.103.15→0.103.16, roots 1.0.7→1.0.11. Zeroize стал direct optional SDK dependency, раньше уже был transitive.

Внешние packages имеют crates.io/checksums; git dependencies/patch overrides не найдены. Workspace path dependency tracked, но lock не фиксирует mutable contents. Unknown registry/git запрещены deny.toml. Checksums/имена не аттестуют published bytes. Внешние advisories/yanked status/dependency sources не проверялись.

## Features, MSRV и coverage

Resolver 2 у root и fixture. Features pool/tls/serde/rating/rotator/test-instrumentation/zeroize/default; rotator→rating, instrumentation→rotator, serde без pool documented no-op. Server/chain dial доступны lean, pool APIs gated. TLS parameter placeholder/reexport публичны. Private fields/take позволяют feature-gated Drop credentials без move-public-fields break.

make_tls_connector документирует global provider resolution/panic; explicit provider API есть. Unexpected cfg warnings становятся CI errors. Feature matrix не полный powerset. Fixture unification excluded из root и не запускается собственным manifest в workflow — gap, не доказанный compile failure. Direct-minimum lane нет.

MSRV 1.88/edition2021, CI 1.88.0 workspace/all-targets/locked Ubuntu+Windows, Docker1.88. Очевидного нового std API выше1.88 агент не нашёл; full MSRV всех resolutions/features не доказан, dependency manifests вне repo не читались, zeroize-only/all features отдельным MSRV не проверяются.

RegexSet и TLS connector создаются startup, не per-request. Runtime regex recompile не найден. Cache recency/TTL реальны. ACL grammar не CIDR — отсутствие ipnet само по себе не дефект. Users writer имеет locking/atomic replacement, собственный helper не основание требовать storage dependency. Собственных proc macros/network build.rs/Deref-псевдонаследования не найдено.

Дополнительный неизмеренный кандидат: chain log formatting заранее вне lazy logger, при cached failure повторяется.

## Limits

DF-01 — policy hardening, не найденный yanked pin. DF-02 — условная секрет/cache граница, не доказанная утечка. DF-03/04 требуют окончательной проверки strict contract. Feature builds, advisory scans, package verification и performance tests не выполнялись. Отсутствие findings в части поверхности не доказывает общую безопасность.
