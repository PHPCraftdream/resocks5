mod auth;
mod cli;
mod config;
mod http_proxy;
mod logger;
mod server;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    match args.command {
        Some(cli::Command::Users { action }) => cli::run_user_command(action),
        Some(cli::Command::Config) => {
            cli::print_config_docs();
            Ok(())
        }
        None => server::bootstrap::run_server(),
    }
}
