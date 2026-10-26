use clap::Subcommand;

use crate::cli::UserAction;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Аккаунты: add/add-init/list/set-password/remove/enable/disable/direct/pool.
    ///
    /// Работает только с resocks5.users.ktav в текущем каталоге, не запускает
    /// listener и не требует корректного main/proxy_list. Новые аккаунты
    /// включены, используют pool и не имеют дополнительного IP-фильтра.
    /// Работающий сервер применит изменения после перезапуска.
    Users {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Полный справочник: все функции, настройки, defaults и примеры.
    ///
    /// Печатает встроенный docs/REFERENCE.md без чтения конфигов,
    /// создания файлов, запуска сервера и доступа к интернету.
    /// Тот же справочник доступен через resocks5 --help.
    Config,
}
