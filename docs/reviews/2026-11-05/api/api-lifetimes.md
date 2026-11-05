# Аудит lifetimes и public API — 2026-11-05

Исследователь агент `@oh`, `lifetimes-and-api.md`. HEAD `870caa2bfa9b6afd8594fabe4df9659bca585760`; c927e71..HEAD и v0.4.1..HEAD. Сохранено основным сеансом из ответа: агенту запрещена запись Markdown. Только статический просмотр, без прогонов/изменений. Новых dangling references/lifetime laundering/source semver break после v0.4.1 агент не подтвердил; это не механическая semver проверка.

## API-L01 — take_username освобождает raw identity без zeroize

P2/High. `crates/resocks5-net/src/server/mod.rs:157–160,732–752`.

zeroize+raw=true, invalid UTF8 username u\xff, retain=false. Request хранит lossy String и exact Vec. take_username отдаёт String и sets raw=None, обычный dealloc raw; future Drop wipe не видит буфера. Raw не передан caller, поэтому это конкретный lifecycle gap, не remote leak/password disclosure.

Предложение feature-gated raw wipe до None, same return/once-only/retained independence. Тест owned pre-dealloc observer, не freed-memory read; существующий raw_credentials:354 проверяет исчезновение API, не memory wipe. Mutation убрать wipe.

## API-L02 — Default SOCKS auth лишний username clone

P3/High, perf механизм без latency измерений. `crates/resocks5-net/src/server/mod.rs:374–379`; app использует default `handle_client.rs:120–137`.

from_utf8 owns username, identity clone нужен, второй username.clone в Credentials не нужен, original потом не используется. Baseline v0.4.1 moved original. Предложение move после identity clone. Тест scoped allocation event, mutation вернуть clone. API/retention менять не требуется.

## API-L03 — HedgeError не exposes last через Error::source

P3/High diagnostic limitation, не data loss/Rust Error requirement violation. `crates/resocks5-net/src/connect/proxy_connect/hedged.rs:103–117`.

last содержит ConnectError, но empty impl Error даёт None, Display только generic. Generic reporter не видит io source, downcast+public last всё ещё возможны. Решение source=last.as_ref, сохранить Display/fields. Тест None и Some ConnectError::Io→ConnectError→io::Error; mutation вернуть None.

## Design candidates, не текущие breaks

- API-C01: `credentials.rs:41–92`, `server/mod.rs:157–169`: into_parts/take_username возвращают lossy Strings, разные invalid UTF8 bytes могут coalesce. Byte accessors/raw-mode docs предупреждают, ошибочный consumer не найден. Явно документировать extraction lossiness; owned exact-byte method только при необходимости, не менять return existing API. Тест два invalid usernames distinct via proposed bytes method, mutation text bytes.
- API-C02: `types/validate.rs:28–58`, `session/rotator/probe.rs:16–40`, `error/mod.rs:150–229`: enum non_exhaustive не резервирует fields существующего variant. Полный external field pattern разрешён, новое поле сломает его. Для unreleased variants возможен variant-level атрибут; для released добавление атрибута тоже breaking, не patch hardening.
- API-C03: Hedged/HedgeError/Hop/Quarantined fully public fields без атрибута фиксируют shape. Это будущая совместимость, не уже произошедший break. Принять shape либо менять на допустимой breaking boundary.

## Ownership и allocations

HostPort — deliberate borrowed view; parse_proxy_str owned. nodes/chain_nodes — borrowed Vec, не allocation-free iterator. ChainKey owns Arc; ChainPlan/Pick owned, borrowed input не сохраняется в долгоживущий cache. IncomingRequest owns target/identity/prefix/credentials, не borrow stream/options. Credentials owned closure-friendly. Prefixed<S> допускает owning или &mut S, скрытого static нет. dial_chain_over Send+Unpin+static обусловлен erased owned AnyUpstream. Hedge callback static обусловлен detached drain, нельзя просто убрать bound.

Chain construction clone-ит String credentials и создаёт links, не только refcounts; Hash nodes Vec; pick.config reconstructs. Retention intentional separate copies; raw valid from_utf8 clone устраним через into_bytes error. Prefixed construction moves Vec; into_parts drain сдвигает остаток, backing memory удерживается до drop. OverStream Mutex<S>::get_mut даёт Sync для Send transport, contended lock на poll нет.

## Red inventory и public commitments

Public AsyncReadWrite открыт (`connect/util/any_upstream.rs:27–80`). Box<T> blanket impl уже baseline, fundamental Box не покрывает T для coherence. Generic TlsStream/ProgressReportingWriter wrapper impl не universal blanket. Новый универсальный impl по AsyncRead+Write пересечётся с existing; narrowing bounds/sealing тоже breaking. Сам existing open trait не баг.

New validation/server/chain types корректно reexport/nameable, TLS placeholder public lean/TLS. reachable-but-unnameable новых типов не найдено. Error payload owned, Send witnesses существуют для основных ошибок/futures. Accept сознательно допускает local-only closures без безусловного Send. Дополнительные witnesses ServerError/HedgeError/AttemptReport полезны, препятствий по fields не найдено, compile не выполнялся.

Non_exhaustive защищает многие errors/options/result enums; exhaustive ProxyProtocol/RatingError/RotatorError/ClientHelloMatch/SendProgress означают commitment. Fully public HostPort/FragmentSpec/AssembledHandshake/PoolConfig/RatingPolicy/AtCapacity и result structs тоже. Private-field Credentials/Request/Options/Prefixed/ChainError/Pick/Plan не требуют атрибута только ради добавления private field; auto traits остаются contract.

## Compatibility conclusions

v0.4.1..HEAD: old paths сохранены reexport, Reply уже non_exhaustive, private fields не ломают old struct literals, новые modes opt-in, dial не вызывает validate скрыто. Source-level break не подтверждён. Диапазон c927e71..HEAD пересекает0.3→0.4, нельзя считать каждую разницу недопустимым patch. ProbeEvent reason добавлен до0.4.0, опубликованный patch break не доказан. gate_level добавлен к non_exhaustive ProxyConfig; semantics inconsistent public gate flags — отдельный contract вопрос.

## Limits

Workspace SDK published, app publish=false; binary pub не приравнивались к library API. Lock прочитан, unreleased добавляет edge к уже pinned zeroize1.8.2. Docs/exports/manifests/feature fixture просмотрены, registry sources не читались; semver checker/compile/tests не запускались. Аудит публичной формы не заменяет protocol/security/concurrency findings соседних модулей.
