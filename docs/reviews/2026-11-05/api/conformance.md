# Аудит семантики и документированных гарантий — 2026-11-05

Автор: агент `@oh`, `semantics-and-conformance.md`. HEAD `870caa2bfa9b6afd8594fabe4df9659bca585760`; диапазон c927e71..HEAD. Основной сеанс сохраняет полученный текст: окружение агента запрещает запись Markdown. Только чтение, поиск/read-only git и read-only WebFetch выдержек RFC; тесты/сборки/скрипты/приложения не запускались. Severity/trace ниже агентские до сводной проверки.

## Claims checklist

Сначала прочитаны root/SDK/app README, REFERENCE, ARCHITECTURE: один порт SOCKS5 CONNECT/HTTP CONNECT/no anonymous direct fallback; абсолютный client deadline; HTTPS TLS+CONNECT общий budget; descending gate ranks+exit; общий attempts budget; независимые health states/password-free persistence; no duplicate CONNECT hedge; strict RFC9112 до auth; exact-once pipeline/Prefixed order/half-close; startup snapshots/init claim/IP-before-password.

## Findings

### CONF-01 — Parallel CONNECT у уже запущенных hedge candidates

P2/High. `crates/resocks5-net/src/connect/proxy_connect/hedged.rs:145–165,301–305`; SDK README397–405.

A TCP pending→hedge B→A handshake pending→B TCP ready/won false→B handshake. handshaking stops new launches, не admission уже launched. Target получает два connections, не доказан duplicate app payload. Предложение exclusive handshake transition+winner recheck. Тест controlled TCP completions, second no CONNECT до first failure. Mutation удалить admission.

### CONF-02 — Sticky chain обходит quarantine gates

P2/High. `crates/resocks5/src/server/connect/establish_connection/dial.rs:75–125`; `crates/resocks5-net/src/session/chain/mod.rs:49–85`; ARCHITECTURE179–188.

Cached G1→E, G1 quarantined, G2 healthy, E healthy. Exit get_linked eligibility проверяет E, identity-only resolve G1, app dials G1. Предложение app checks all hops; resolve оставить identity-only (`selection_tests.rs:162–176`). Тест no TCP G1, healthy route, recovery. Mutation убрать gate eligibility.

### CONF-03 — Health restore direct-probes внутренних gates

P2/High. `crates/resocks5/src/server/bootstrap/startup.rs:465–477`; `server/health/mod.rs:231–248`; `crates/resocks5-net/src/session/rotator/probe.rs:42–47`; REFERENCE415–418.

All rotators passed health start, ordinary due probes direct TCP. Probation G1 reachable only via G3 falsely down; direct traffic may reveal server IP contrary topology. Предложение restore отдельно, topology-aware dispatch internal ranks. Тест direct count0/outer CONNECT seen. Mutation обычные probes по всем.

### CONF-04 — Capacity/prefix failure штрафует внутренний gate

P2/High. `crates/resocks5/src/server/connect/establish_connection/probes.rs:76–109`; root README433–436.

connect_chain(...).is_ok уничтожает typed/stage error; occupied outer G3 produces AtCapacity→hard failure tested G1. Предложение stage-aware classification, inconclusive capacity/prefix не штрафует G1. Тест filled permits/no trips/no connect tested node; mutation бинарный bool outcome.

### CONF-05 — Health snapshot сливает независимые routing groups

P2/High. `crates/resocks5/src/server/health/mod.rs:96–108,136–161`; REFERENCE251–252,411–413.

Snapshot emits states всех rotators, restore HashMap key=(upstream_label,gate) без group. Один endpoint в v6/v4 arrays с opposite health/trips collides; last-wins state применяется обоим. Password variants также coalesce. Предложение stable group/slot discriminator для независимого runtime state, password не писать; old ambiguous records policy явно. Тест runtime snapshot→save/load→restore opposite states в обоих порядках, credential variants отдельно. Mutation удалить group key. Existing KTAV struct roundtrip (`health/tests.rs:106–116`) runtime inverse не доказывает.

### CONF-06 — Strict accepts malformed field values/Host NUL

P2/High. `crates/resocks5-net/src/server/strict_http.rs:90–118`; SDK README193–200.

CONNECT example.com:443 HTTP/1.1 + Host containing sole NUL проходит nonempty check, может вызвать auth. RFC9110 §5.5 требует reject/replace CRLFNUL, здесь neither; замена sole NUL на SP дала бы empty Host, forbidden собственным contract. Предложение generic field-value/Host grammar validation. Тест NUL-only/inside/embedded CRLF→400/0auth, unused valid obs-text positive. Mutation убрать byte checks.

### CONF-07 — Ungated dial_chain total timeout неверный stage

P2/High. `crates/resocks5-net/src/connect/dial/chain.rs:135–148,303–323`.

TCP connected, greeting seen, handshake hangs, total<handshake. Progress остался Connect из initialization, single-node dial_inner не обновляет. Wrong stage Connect вместо Target. Решение progress update/shared runner preserving result variants. Тест distinct TCP vs handshake total deadlines, mutation remove update.

### CONF-08 — Queued sticky fallback candidates не учтены в общем budget

P2/High механизма, сценарий требует независимой проверки достижимости. `crates/resocks5/src/server/connect/establish_connection/dial.rs:75–87,188–199,301–320`.

max_attempts3, оба exit rotators имеют ordinary sticky T. Они queued без увеличения attempts. Две gated attempts fail, chain loop резервирует только один fallback slot. Уже queued две ordinary затем целиком connect_hedged: всего4 routes при cap3. Предложение общий расходуемый counter/ограничить весь fallback slice остатком, включая sticky. Тест two cached routes+two chain failures, wire attempts≤3. Mutation не учитывать queued routes/не clamp fallback.

## Doc drift

DOC-01 P3/High: ARCHITECTURE90–92 not quarantined/never excluded против собственного165–188 default quarantine. Ограничить утверждение soft sand layer+all-down exception. Не отдельный wire bug.

DOC-02 P3/High: ARCHITECTURE350–352 immediate password updates/in-flight неверно, actual `auth/state/mod.rs:35–38`/REFERENCE59–64 startup snapshot. Не auth bypass корректного snapshot contract.

## Inventory и limits

SOCKS states/method/auth/CONNECT/ATYP1/3/4, unsupported CMD REP7/ATYP REP8, terminal errors/flush прослежены. Default UTF8 restriction/inbound RSV leniency документированы. Ingress16KiB/pipeline, egress frame/order/auth/boundary, chain outer-first/permits, deadlines, half-close, Prefixed/pipeline ownership/cancel terminal просмотрены. Low-level helpers/reply caller-owned deadlines не скрытый F3 leak. Disabled idle/lifetime documented mode, не автоматический DoS finding.

Init claim persist-then-publish/IP-before-verify/owned blocking guards правильны в просмотренных paths. KTAV не positional binary format, ordinal corpus rule не применялся механически. Property-based inverse gaps не равны новым bugs; особенно нужен runtime health inverse.

Read-only WebFetch дал сокращённые RFC1928/1929/9112/9110§5.5 выдержки, не полную нормативную сверку. Full CONNECT/Host grammar, BND.ADDR/PORT, RFC7617/TLS не полностью независимы. Full RFC conformance не заявляется. Wire stubs не independent interoperability proof. Никакие тесты/mutations не запускались.
