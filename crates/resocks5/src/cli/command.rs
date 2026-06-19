use clap::Subcommand;

use crate::cli::UserAction;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// User management: add / list / set-password / remove / enable / disable.
    Users {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Print the full configuration-file reference (every field of
    /// `resocks5.main.ktav`, `resocks5.proxy_list.ktav`,
    /// `resocks5.users.ktav` with defaults and behaviour notes).
    Config,
}
