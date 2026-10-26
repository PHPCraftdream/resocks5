use clap::Parser;

use crate::cli::print_config_docs::DOCS;
use crate::cli::Command;

#[derive(Debug, Parser)]
#[command(
    name = "resocks5",
    about = "SOCKS5 и HTTP CONNECT: direct-прокси по аккаунту или ротация upstream.",
    long_about = "\
Прокси-сервер SOCKS5 и HTTP CONNECT на одном TCP-порту.
Именованный direct-аккаунт подключается к цели от IP этого сервера;
остальные клиенты используют SOCKS5/HTTP/HTTPS upstream, gates и sand-rating.

Без аргументов запускается сервер. Настройки и аккаунты читаются из
resocks5.main.ktav, resocks5.proxy_list.ktav и resocks5.users.ktav в текущем
каталоге запуска, независимо от расположения бинарника. Нужен upstream
либо хотя бы один включённый direct-пользователь.

Есть auth, каскадные IP-фильтры, banned_patterns, таймауты и лимиты,
TCP keepalive, pre-connect pool, recovery SNI/Host, TLS fragmentation и логи.
Подробности всех команд, полей, defaults, ограничений и эксплуатации — ниже.",
    version,
    after_help = "\
ПРИМЕРЫ:
  resocks5                           запуск из текущего каталога
  resocks5 config                    полный справочник без запуска сервера
  resocks5 users add alice            создать аккаунт, запросить пароль
  resocks5 users direct alice         самостоятельный прокси без upstream
  resocks5 users pool alice           вернуть аккаунт в upstream-режим
  resocks5 users --help               все операции с аккаунтами

--help показывает полный справочник, -h — краткую справку.
Наличие пользователей не отключает anonymous: задайте auth.allow_anonymous=false.
После изменения конфигов/аккаунтов нужен перезапуск. Паролей в CLI-флагах нет.",
    after_long_help = DOCS
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}
