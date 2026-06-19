//! Command-line interface. The bare binary still runs the server (the
//! historic behaviour); subcommands gate user management.
//!
//! Passwords are NEVER taken as CLI flags — only via interactive prompt
//! (with terminal echo disabled) so they don't leak into shell history,
//! `ps` output, or process-listing tools.

pub mod app;
pub mod command;
pub mod print_config_docs;
pub mod run_user_command;
pub mod user_action;

pub use app::Cli;
pub use command::Command;
pub use print_config_docs::print_config_docs;
pub use run_user_command::run_user_command;
pub use user_action::UserAction;
