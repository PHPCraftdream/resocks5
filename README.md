# resocks5

[![CI](https://github.com/PHPCraftdream/resocks5/actions/workflows/ci.yml/badge.svg)](https://github.com/PHPCraftdream/resocks5/actions/workflows/ci.yml)
[![MSRV: 1.88](https://img.shields.io/badge/MSRV-1.88-dea584.svg)](#install)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A SOCKS5 **and** HTTP-CONNECT proxy server that spreads incoming client
connections across a pool of upstream proxies — with per-client
authentication, per-target upstream stickiness, a self-recovering
sand-rating rotator that demotes failing upstreams without ever
excluding them, and TLS fragmentation for DPI evasion.

The listener auto-detects SOCKS5 vs HTTP CONNECT per connection, so a single
port serves both kinds of client.

> **Status:** working and in daily use by the author; pre-1.0. The CLI and
> config format are stable in practice; the [`resocks5-net`](crates/resocks5-net)
> library API may still change before a 1.0 release.

## Quick demo

```bash
# 1. first run — creates the three .ktav config files in the CWD, then exits
resocks5

# 2. add one upstream: edit resocks5.proxy_list.ktav and put it in the
#    socks5_v4 list (replace the empty `socks5_v4: []` line — don't add a
#    second one; ktav rejects duplicate keys):
#        socks5_v4: [ user:pass@198.51.100.7:1080 ]
# then add one client user (interactive, no-echo password prompt):
resocks5 users add alice

# 3. start the proxy (listens on 127.0.0.1:20082 by default)
resocks5

# 4. SOCKS5 and HTTP CONNECT share the same port — either works:
curl --socks5-hostname 127.0.0.1:20082 https://ifconfig.me   # → 198.51.100.7
curl -x http://127.0.0.1:20082           https://ifconfig.me   # → 198.51.100.7
```

The returned IP is the **upstream's**, not yours — that's the whole point. Add
more entries to `resocks5.proxy_list.ktav` and resocks5 rotates across them,
demoting any that fail via the sand-rating model instead of dropping them.

## Contents

- [Quick demo](#quick-demo)
- [Features](#features)
- [Why resocks5](#why-resocks5)
- [Install](#install)
- [Quick start](#quick-start)
- [Самостоятельный прокси без upstream](#самостоятельный-прокси-без-upstream)
- [Подробная справка и все возможности](#подробная-справка-и-все-возможности)
- [Полный справочник полей и команд](docs/REFERENCE.md)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Список допуска клиентов по IP (allowed_clients)](#список-допуска-клиентов-по-ip-allowed_clients)
- [Use as a library](#use-as-a-library)
- [User management](#user-management)
- [Repository layout](#repository-layout)
- [License](#license)

## Features

- **SOCKS5 + HTTP CONNECT** front end, auto-detected per connection.
- **Upstream protocols:** SOCKS5, HTTP, and HTTPS (TLS-wrapped CONNECT) proxies.
- **Rotation + stickiness:** weighted-random selection across the pool,
  with a per-target cache so a given destination keeps using the upstream
  that last worked.
- **Gates (proxy chaining):** route through a gate proxy to a second proxy
  before reaching the target.
- **Sand-rating soft-weight rotator:** each upstream has a per-failure
  sand accumulator that decays exponentially over time. Upstream selection
  is weighted-random with weight `exp(-k · sand)` — failing upstreams are
  picked less often but never excluded, and recover automatically as their
  sand drains. When every upstream is bad the weights equalise, so a
  full outage degrades to uniform random selection instead of locking out.
- **Per-upstream concurrency cap** to respect a provider's per-account/per-IP
  connection quota.
- **Optional pre-warmed TCP pool** to cut connection latency.
- **TLS fragmentation:** splits the ClientHello across TCP segments to defeat
  SNI-based DPI blocking.
- **Authentication:** Argon2id password hashing, with an optional
  init-on-first-login mode.
- **Safety rails:** idle/lifetime tunnel timeouts, TCP keepalive, a
  max-concurrent-clients cap, and regex-based banned-target patterns.
- **Configurable logging** by category, with optional non-blocking file output.

## Why resocks5

resocks5 exists for one reason the established rotating-proxy tools don't
lean into: **graceful degradation under upstream churn**.

Most proxies either pin a single upstream (no rotation) or use a hard
circuit-breaker that quarantines a failed upstream for a fixed window. That's
fragile on small pools — one quarantine cascades into the next — and it's
weaponizable: an attacker who can trip failures can lock you out of your own
pool.

resocks5's **sand-rating** model takes the opposite stance. A failed upstream
is *demoted*, never excluded: its selection weight decays toward (but never
reaches) zero and recovers on its own as the sand drains. A full outage
degrades to uniform random selection instead of a lockout, and a recovering
upstream is probed for free because its weight never hits zero.

### How it compares

| | resocks5 | 3proxy | gost | glider |
|---|---|---|---|---|
| Language | Rust (rustls / `ring`) | C | Go | Go |
| Front end | SOCKS5 + HTTP CONNECT (auto) | many | many | many |
| Rotation model | sand-rating soft-weight, self-recovering | round-robin / parent | chaining-first | failover |
| Per-target stickiness | yes | — | — | — |
| Auth | Argon2id + HMAC verify-cache | basic | basic | basic |
| TLS ClientHello fragmentation | yes | no | no | no |
| Single-port dual-protocol | yes | — | — | — |

**Where resocks5 wins**

- **Rotation that never locks you out** — the sand-rating model's whole
  reason to exist.
- **TLS fragmentation** for per-segment, SNI-based DPI, built in.
- **Rust + rustls** — memory-safe; no `cmake` needed (`ring` compiles
  bundled C sources, but the C compiler in any standard Rust build
  environment — MSVC Build Tools, gcc, or clang — covers it).

**Where the others still win**

- **Protocol breadth** — gost in particular speaks far more wire protocols
  (shadowsocks, trojan, …) and is a better fit if you need those.
- **Footprint** — 3proxy is a hand-tuned C binary and uses less memory under
  extreme connection counts.
- **Operational maturity** — 3proxy has two decades of production use.

If you need a tunnelling swiss-army knife or a specific exotic protocol, reach
for gost. If you need the smallest possible binary on a constrained box, 3proxy.
If your problem is "I have a pool of flaky upstream proxies and I want traffic
to keep flowing when they misbehave," that's the case resocks5 is built for.

> The table characterises each project's *design focus*, not its absolute
> capabilities — verify against the current version before committing.

## Install

### Последний релиз: Linux, macOS и Windows

Установщики скачивают **последний стабильный GitHub Release**, а не собирают
код из `main`. Rust и C-компилятор для этого не нужны. Тег определяется один
раз; архив и `sha256sums.txt` загружаются из одного релиза, SHA-256 проверяется
до установки. Проверка защищает от повреждения загрузки, но не заменяет
доверие к издателю релиза.

| ОС | Архитектура | Установщик | Каталог по умолчанию |
|----|-------------|------------|---------------------|
| Linux (любой дистрибутив, glibc и musl/Alpine) | x86_64, arm64 | `sh` | `~/.local/bin` |
| macOS | Intel x86_64, Apple Silicon arm64 | `sh` | `~/.local/bin` |
| Windows | x86_64 | PowerShell 5.1+ | `%LOCALAPPDATA%\resocks5\bin` |

Linux-архивы — полностью статические (musl), без зависимостей от системных
библиотек; Windows-бинарник собран со статическим CRT и не требует
Visual C++ Redistributable. Статические Linux-архивы и arm64 выпускаются
начиная с релиза после 0.3.0; в 0.3.0 и ранее был только glibc-архив x86_64
(установщик сам выберет подходящий архив релиза, на musl/Alpine старый релиз
не поддерживается).

Для остальных платформ (Windows ARM64) нативные архивы пока не выпускаются:
установщик завершится с ошибкой, без попытки собрать проект.

**Linux / macOS** — нужны `curl`, `tar` и `sha256sum` либо `shasum`:

```sh
(
  set -eu
  installer_dir=$(mktemp -d)
  trap 'rm -rf -- "$installer_dir"' 0
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
    https://raw.githubusercontent.com/PHPCraftdream/resocks5/main/.github/scripts/install.sh \
    -o "$installer_dir/install.sh"
  sh "$installer_dir/install.sh"
)

# Для текущего терминала; для постоянной настройки добавьте в ~/.profile
# или файл конфигурации своего shell:
export PATH="$HOME/.local/bin:$PATH"
resocks5 --version
```

**Windows** — выполните в PowerShell, права администратора не нужны:

```powershell
$installerDir = Join-Path ([IO.Path]::GetTempPath()) ("resocks5-script-" + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $installerDir
try {
    $script = Join-Path $installerDir 'install.ps1'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/PHPCraftdream/resocks5/main/.github/scripts/install.ps1' -OutFile $script -ErrorAction Stop
    powershell -NoProfile -ExecutionPolicy Bypass -File $script
    if ($LASTEXITCODE -ne 0) { throw 'Установка не выполнена.' }
}
finally {
    Remove-Item -LiteralPath $installerDir -Recurse -Force
}

# Для текущего терминала:
$env:Path = "$env:LOCALAPPDATA\resocks5\bin;$env:Path"
resocks5 --version
```

Для постоянной настройки Windows добавьте `%LOCALAPPDATA%\resocks5\bin`
в пользовательскую переменную `Path` через параметры среды и откройте новый
терминал. `-ExecutionPolicy Bypass` действует только для запущенного процесса,
системная политика не меняется. Обе команды выполняют скрипт из этого
репозитория; перед запуском можно просмотреть скачанный файл.

Другой каталог можно передать как `sh install.sh /путь/к/bin` либо
`powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -InstallDir 'D:\apps\resocks5'`.
Установщики не меняют `PATH`, не запускают сервер и не трогают конфиги.
Повторный запуск обновляет только бинарник, **останавливать работающий
`resocks5` не требуется**. Установщик не перезапускает процесс: существующий
сервер продолжает работать на старой версии, новые запуски используют новую.

- **Linux/macOS:** новый файл атомарно переименовывается поверх старого.
  Старый inode остаётся доступен работающему процессу; ОС освобождает его
  после завершения процесса. Резервные имена не создаются.
- **Windows:** старый файл переименовывается в `.resocks5-old-<GUID>.exe`,
  затем новый получает имя `resocks5.exe`. При ошибке второго шага установщик
  пытается восстановить прежнее имя. Каждая успешная установка удаляет
  неиспользуемые старые копии; занятые процессами, заблокированные или
  недоступные файлы сохраняются с предупреждением. После завершения старого
  процесса его копия будет удалена при следующей успешной установке.
  Удаляются только резервные имена этого установщика, не произвольные `.exe`.
  Файл `.resocks5-install.lock` предотвращает одновременное изменение каталога
  несколькими установщиками; само наличие файла не означает активную блокировку.

### Откуда берутся настройки после установки

`resocks5` читает и создаёт `resocks5.main.ktav`, `resocks5.proxy_list.ktav`
и `resocks5.users.ktav` **в текущем рабочем каталоге запуска**, а не рядом
с установленным бинарником. Это относится и к `resocks5 users …`.
Каталог должен быть доступен для записи; установка в `PATH` это правило
не меняет. Например, на Linux/macOS:

```sh
mkdir -p my-proxy
cd my-proxy
resocks5
```

На Windows в PowerShell:

```powershell
$null = New-Item -ItemType Directory -Path 'my-proxy' -Force
Set-Location 'my-proxy'
resocks5
```

Запуски из разных каталогов используют независимые наборы настроек.
Первый запуск создаёт отсутствующие файлы в выбранном каталоге; для работы
затем настройте upstream-прокси или direct-пользователей, как описано ниже.

### Сборка из исходников

Requires a recent stable Rust toolchain. The dependency tree (rustls 0.23,
rpassword 7) sets the floor at **Rust 1.88+**, declared as `rust-version` in
every crate and enforced by the `msrv` job in CI. The crate uses the `ring`
crypto provider, which compiles bundled C sources as part of the build, so
a C compiler must be available — as it already is on any system set up to
build Rust — but no `cmake` is needed.

```bash
# Build from a checkout:
cargo build --release
# → target/release/resocks5[.exe]

# …or install the binary onto your PATH from a checkout:
cargo install --path crates/resocks5
# …or straight from git:
cargo install --git https://github.com/PHPCraftdream/resocks5 resocks5
```

Prebuilt binaries are attached to each
[GitHub Release](https://github.com/PHPCraftdream/resocks5/releases); the
binary is not published on crates.io (only the `resocks5-net` library is).

### Run with Docker

A multi-arch image (`linux/amd64`, `linux/arm64`) is published to ghcr.io on
every release tag:

```bash
# Prepare a writable bind-mount directory on Linux; the image runs as UID 65532.
mkdir -p "$PWD/resocks5-config"
sudo chown 65532:65532 resocks5-config
# First run creates the three config files, then exits; it does NOT start a usable proxy.
docker run --rm \
  -v "$PWD/resocks5-config:/etc/resocks5" \
  ghcr.io/phpcraftdream/resocks5:latest

# Edit resocks5.main.ktav in the mounted host directory before starting:
# set listen_host: 0.0.0.0 and auth.allow_anonymous: false.
# Add at least one upstream to resocks5.proxy_list.ktav by replacing its
# existing `socks5_v4: []` line; do not add a duplicate key.
# Example: socks5_v4: [ user:pass@198.51.100.7:1080 ]
# The generated files are owned by UID 65532; on Linux use an elevated editor
# or choose host permissions that let your user edit them.
# Add a client user (interactive password prompt):
docker run --rm -it \
  -v "$PWD/resocks5-config:/etc/resocks5" \
  ghcr.io/phpcraftdream/resocks5:latest users add alice

# Start with host access restricted to localhost by default.
docker run --rm -p 127.0.0.1:20082:20082 \
  -v "$PWD/resocks5-config:/etc/resocks5" \
  ghcr.io/phpcraftdream/resocks5:latest

# …or build it yourself and use resocks5 instead of the image name above:
docker build -t resocks5 .
```

The mounted config directory must be writable by UID 65532. On Linux, prepare
it as shown above; permissions depend on the host platform (`chown` is
Linux-specific, and Docker Desktop bind mounts generally work). The generated
files are owned by UID 65532, so on Linux use an elevated editor or choose host
permissions that let your user edit them. The image is distroless, so it has no
shell; edit the bind-mounted config files on the host. Keep the host port bound
to `127.0.0.1` unless remote access is intended and secured.

## Quick start

```bash
# 1. The first run creates the three config files in the working directory,
#    then exits telling you that no upstream proxies are configured yet.
resocks5

# 2. Add at least one upstream to resocks5.proxy_list.ktav by editing the
#    existing socks5_v4 line (replace `socks5_v4: []` in place — ktav rejects
#    duplicate keys, so don't append a second socks5_v4):
#       socks5_v4: [ user:pass@198.51.100.7:1080 ]

# 3. (Optional) add a client user. Anonymous access is enabled by default;
#    see below for requiring credentials before exposing the listener.
resocks5 users add alice

# 4. Start the proxy. It listens on 127.0.0.1:20082 by default.
resocks5

# 5. Point your SOCKS5 / HTTP-proxy client at 127.0.0.1:20082.
```

Before exposing the listener beyond localhost, configure users and edit the
existing `auth` block in `resocks5.main.ktav`:

```text
auth: { allow_anonymous: false }
```

Restart the server after applying these settings. Adding users alone leaves
anonymous access enabled when `allow_anonymous` is `true`. Apply both settings
before changing `listen_host` to a public interface.

## Самостоятельный прокси без upstream

`resocks5` может сам обслуживать SOCKS5 и HTTP CONNECT, подключаясь к цели
с IP сервера. Это **настройка аккаунта `direct: true`**, не глобальный режим
и не автоматический fallback при отказе upstream.

В рабочем каталоге экземпляра создайте пользователя и включите direct:

```sh
resocks5 users add alice
resocks5 users direct alice
resocks5
```

В `resocks5.main.ktav` задайте `auth: { allow_anonymous: false }`, чтобы
требовать пароль. Все шесть upstream-массивов могут оставаться пустыми:
достаточно одного включённого direct-пользователя. После изменения аккаунта
или конфигов перезапустите сервер. Вернуть аккаунт к upstream-маршрутизации:
`resocks5 users pool alice`.

Anonymous direct-доступ не получает. Цель видит IP сервера, DNS разрешается
сервером; IP-фильтры, banned_patterns, таймауты и лимиты продолжают действовать.
Подробности и команды клиентов: [полный справочник](docs/REFERENCE.md).

## Подробная справка и все возможности

```sh
resocks5 -h                         # краткая справка
resocks5 --help                     # полный встроенный справочник
resocks5 config                     # тот же справочник без запуска сервера
resocks5 users --help               # управление аккаунтами
resocks5 users add-init --help      # первый вход задаёт пароль: ограничения и риски
resocks5 users direct --help        # самостоятельный proxy по аккаунту
```

**[docs/REFERENCE.md](docs/REFERENCE.md)** — единый полный справочник,
встроенный в бинарник: все команды, все поля трёх конфигов, типы, defaults,
особые значения, примеры, ограничения и диагностика. `--help` и `config`
работают без интернета; `config` не читает и не создаёт конфиги.

| Возможность | Настройка / управление |
|-------------|------------------------|
| SOCKS5 и HTTP CONNECT на одном порту | `listen_host`, `port`; TCP CONNECT, без SOCKS5 UDP/BIND и обычного HTTP forward GET |
| Самостоятельный прокси | `users direct/pool`, `users[].direct`; только именные enabled-аккаунты |
| Пароли, disabled, первый вход | `users add/add-init/set-password/enable/disable/remove/list`, `auth.allow_anonymous` |
| Допуск IP клиента | `allowed_clients`, `users[].allowed_clients`: пересечение правил, loopback и маски |
| Запрет целей | `banned_patterns`: regex по `host:port`, не автоматическая фильтрация DNS-адресов |
| Upstream SOCKS5/HTTP/HTTPS | Шесть массивов в proxy_list, credentials, IPv6 и `*`-gates |
| Ротация и привязка цели | Sand-rating и ограниченный sticky cache, не жёсткий circuit breaker |
| Предварительные TCP-соединения | `pool.enabled`, `spare_per_proxy`, `max_session_age_sec`; не путать с pool-аккаунтом |
| Защита от зависаний и перегрузки | Все `network.*`: connect/handshake/client/tunnel deadlines, idle, keepalive и лимиты |
| SNI / Host recovery | `network.recover_host_from_payload`: pool + буквальный IPv4, возможен ранний ответ CONNECT |
| ClientHello fragmentation | `tls_fragment.*`: дробление первого распознанного ClientHello, без обещания обхода DPI |
| Журналирование | Все `log.*`, `file_log.*`; файл append, без автоматической ротации |
| Установка и обновление | Последний GitHub Release, SHA-256, Windows rename/cleanup и Unix atomic rename |
| Отдельные экземпляры | Конфиги из cwd, снимок на старте, перезапуск для применения изменений |
| Контейнер и остановка | Docker amd64/arm64, UID 65532, writable volume; Ctrl+C/SIGTERM и bounded drain |
| Безопасность и диагностика | Не открывать anonymous наружу; входной TCP не шифрует пароль; см. [SECURITY.md](SECURITY.md) |

Настройки, допустимые значения и практические ограничения каждой строки
раскрыты в справочнике, а устройство реализации — в [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## How it works

For each accepted connection:

1. **Protocol detect** — the first bytes decide SOCKS5 vs HTTP CONNECT.
2. **Authenticate** — credentials are checked against the user table (Argon2id).
   Anonymous clients are accepted only when `auth.allow_anonymous` is `true`.
3. **Pick an upstream** — if this target was reached before, reuse the sticky
   upstream that last worked; otherwise draw one with sand-rating's
   weighted-random order. IPv6 targets prefer the IPv6 upstream set.
4. **Connect** — open the tunnel through the upstream (optionally via a gate,
   optionally over a pre-warmed TCP socket). The per-upstream semaphore caps
   concurrent connections; real connect/handshake failures add sand to that
   upstream so subsequent draws prefer healthier peers (capacity-rejects
   don't count — that's our own load, not the upstream's fault).
5. **Tunnel** — forward bytes both ways until either side closes, with idle and
   lifetime timeouts. If the first client write is a TLS ClientHello and
   fragmentation is enabled, it is split across TCP segments.

## Configuration

Configuration lives in three [KTAV](https://github.com/ktav-lang/rust) files in
the working directory, all auto-created on first launch:

| File | Purpose |
|------|---------|
| `resocks5.main.ktav` | server settings: port, auth, logging, pool, network/sand-rating, TLS fragmentation, banned patterns, `allowed_clients` |
| `resocks5.proxy_list.ktav` | upstream proxies, grouped by transport and IP family |
| `resocks5.users.ktav` | Пользователи: пароли и флаги — через `resocks5 users …`; `allowed_clients` — вручную при остановленном сервере |

Print the **full field reference** — every option, its default, and behaviour
notes — with:

```bash
resocks5 config
```

> **Security:** these files hold secrets — the auth salt, upstream proxy
> credentials, and Argon2 user hashes. They are git-ignored; never commit them.

### Upstream proxy list

In `resocks5.proxy_list.ktav`, list upstreams in arrays per transport and IP
family. Each entry is `[*]user:pass@host:port` (credentials optional); a
leading `*` marks a **gate**.

```text
socks5_v4: [
  alice:s3cret@198.51.100.7:1080
  *gateuser:gatepass@203.0.113.9:1080
]
http_v4:  [ user:pass@198.51.100.20:8080 ]
https_v4: [ user:pass@198.51.100.30:443 ]
## …and the corresponding *_v6 arrays for IPv6 upstreams.
```

## Список допуска клиентов по IP (allowed_clients)

Глобальная строка `allowed_clients` в `resocks5.main.ktav` (по умолчанию
`"*"` — все) ограничивает, с каких IP клиентов вообще можно подключаться.
Проверка выполняется по **реальному TCP-адресу пира** до чтения любых
байтов протокола; отклонённому пиру соединение закрывается без ответа.
Невалидное правило валит старт сервера (fail-closed), включая правила,
прикреплённые к disabled- и дублирующимся пользователям. Изменения
требуют рестарта: правило компилируется один раз в снапшот на старте.

Каждый пользователь в `resocks5.users.ktav` может нести опциональную
строку `allowed_clients`. Итоговая проверка — **И глобального правила,
и правила пользователя** (поле пользователя добавляет ограничение только
если задано); элементы внутри одного списка — альтернативы **ИЛИ**.
Фильтр пользователя выполняется **до проверки пароля**, поэтому
отклонённый IP получает обычный отказ аутентификации (SOCKS5 `[1,1]` /
HTTP 407) без работы Argon2, без попадания в HMAC-кеш и без записи
init-claim на диск. К anonymous-клиентам он не применяется вообще
(они подчиняются только глобальному правилу); direct-пользователи
подчиняются ему как все.

Поддерживаемые формы (через запятую; элементы обрезаются по пробелам):

- точный IP: `127.0.0.1`, `::1`, `2001:db8::1` — только стандартный
  синтаксис std;
- `loopback` — `127.0.0.0/8` и `::1` (не любой адрес интерфейса и не
  замена аутентификации);
- wildcard `*` — весь список (`*`) или ровно один октет IPv4-маски
  (ровно 4 октета): `192.168.*.*`, либо ровно одна hex-группа
  IPv6-маски (ровно 8 групп): `2001:db8:*:*:*:*:*:*`. `::` может
  встречаться один раз и означает **только** нулевые группы:
  `2001:db8::*` — это `2001:db8:0:0:0:0:0:*`, а не /64.

При проверке IPv6-маской IPv4-адрес рассматривается как
`::ffff:a.b.c.d`; совместимые с IPv4 адреса (`::a.b.c.d` без ffff) не
разворачиваются. Пример: маска `::ffff:7f00:*` совпадает с `127.0.0.1`
и `127.0.255.255`, но НЕ с `127.1.0.1`. Отвергаемые формы — имена
хостов, CIDR, порты, частичные звёзды (`1*.2.3.4`), пустые элементы
(`a,,b`) — делают всю строку невалидной.

Альтернативные значения KTAV — выберите одно, заменив существующий ключ.
Строки пишутся без кавычек: кавычки станут частью значения, а не снимутся.

```text
allowed_clients: *
allowed_clients: 127.0.0.1,::1
allowed_clients: loopback
allowed_clients: 192.168.*.*
allowed_clients: 2001:db8:*:*:*:*:*:*
```

Пир — это фактический адрес TCP-источника, как его видит сервер: за NAT
или обратным прокси пиром будет адрес прокси — `X-Forwarded-For`
НЕ учитывается.

## Use as a library

The networking core is published as a separate crate,
[`resocks5-net`](crates/resocks5-net) — inbound smart-port framing, upstream
connectors, the TCP pool, sand-rating, rotation and TLS fragmentation. Credential
storage, logging and routing policy stay in the host application.
Add it from crates.io (the inbound `server` module needs 0.3 or newer), or as a
git dependency to follow unreleased changes:

```toml
[dependencies]
resocks5-net = "0.3"
# resocks5-net = { git = "https://github.com/PHPCraftdream/resocks5" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

Connect to a target through an upstream proxy and drive any protocol over the
returned stream:

```rust
use std::time::Duration;

use resocks5_net::connect::{connect_proxy, parse_proxy_str};
use resocks5_net::pool::{PoolConfig, ProxyPool};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyProtocol, IP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse upstream lines: "[*]user:pass@host:port" (credentials optional).
    let proxies = ["user:pass@198.51.100.7:1080"]
        .into_iter()
        .filter_map(|s| parse_proxy_str(s, ProxyProtocol::Socks5, IP::V4).ok())
        .collect::<Vec<_>>();

    // Weighted-random rotator (sand-rating uses defaults from RatingPolicy)
    // + a pre-connect TCP pool (left disabled here).
    let rotator = ProxyRotator::new(proxies);
    let pool = ProxyPool::new(
        PoolConfig::default(),
        Duration::from_secs(10), // upstream connect timeout
        8,                       // max concurrent connections per upstream
    );

    // Pick an upstream and tunnel to the target through it. The returned
    // stream is AsyncRead + AsyncWrite.
    let upstream = rotator.get_next();
    let mut stream = connect_proxy(
        "example.com:80",
        &upstream,
        &pool,
        Duration::from_secs(10), // handshake timeout
        None,                    // TLS connector — Some(..) only for HTTPS upstreams
    )
    .await?;

    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        .await?;
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await?;
    println!("received {} bytes", body.len());
    Ok(())
}
```

The library entry point is [`resocks5_net`](crates/resocks5-net/src/lib.rs);
the top-level modules include `server`, `connect`, `error`, `progress`, `pool`,
`rating`, `rotator`, and `types`.

### Embed a SOCKS5 + HTTP CONNECT listener

The unconditional `resocks5_net::server` module works without default features:

```rust
let options = resocks5_net::server::ServerOptions::new(accept_deadline, false, true);
let mut req = resocks5_net::server::accept(&mut client, &options, move |credentials| async move {
    host_auth.verify_async(credentials.username(), credentials.password()).await
}).await?;
// Host-owned destination policy and real egress connection happen here.
// Only after egress is ready:
req.reply(&mut client, resocks5_net::server::Reply::Established).await?;
let prefix = req.take_pipeline(); // send exactly once before relaying unread bytes
```

The snippet's stream, deadline, authentication state and egress are supplied by the
host, not fabricated by the parser. See the [complete API contracts and usage](crates/resocks5-net/README.md#inbound-server-api)
and the [finite local-egress example](crates/resocks5-net/examples/serve_local.rs).
The example requires a separately running local echo target, actually dials it,
and accepts two clients on one smart port; it sends success only after that dial.

`accept` returns an unresolved destination, verified username (`None` for anonymous)
and owned pipeline bytes. It bounds detection/auth/framing with one absolute Tokio
deadline; the application anchors this at listener acceptance before task spawning.
HTTP headers are byte-parsed, accept unused obs-text, and have a delimiter-inclusive
16KiB cap independent of tunneled payload size. On cancellation/error discard the
stream; admitted authentication persistence can still finish. Routing, gates,
SNI/Host recovery, logs and egress/tunnel budgets remain host-owned. After early
recovery success, failure closes the tunnel instead of sending a second reply.
External authentication and Tor egress can use the same closure-based API; the Tor
proxy [tor-socks5](https://github.com/PHPCraftdream/tor-socks5) embeds its listener
this way.

## User management

```bash
resocks5 users add <name>            # add a user (interactive password)
resocks5 users add-init <name>       # claim-on-first-login placeholder
resocks5 users set-password <name>   # change a password
resocks5 users list                  # list users (never hashes)
resocks5 users enable  <name>
resocks5 users disable <name>
resocks5 users remove  <name> [--yes]
resocks5 users direct  <name>       # bypass upstream pool
resocks5 users pool    <name>       # route through upstream pool (default)
```

Anonymous access defaults to `auth.allow_anonymous: true`, including when users
are configured. Set it to `false` to require credentials. Restart the server
after changing users or authentication settings to apply the new snapshot.
Passwords are only ever read from an interactive, no-echo prompt — never from
a command-line flag — so they don't leak into shell history.

## Repository layout

This is a Cargo workspace with two crates:

| Crate | Role |
|-------|------|
| [`resocks5-net`](crates/resocks5-net) | Reusable proxy networking toolkit — SOCKS5/HTTP/HTTPS upstream connectors, a pre-connect TCP pool, a sand-rating soft-weight rotator with exponential decay, and TLS ClientHello fragmentation. |
| [`resocks5`](crates/resocks5) | The CLI proxy server binary — wires `resocks5-net` together with KTAV configuration, Argon2 user auth, logging, and the SOCKS5/HTTP listener. |

```bash
cargo test --workspace      # run the test suite
cargo clippy --workspace --all-targets
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
