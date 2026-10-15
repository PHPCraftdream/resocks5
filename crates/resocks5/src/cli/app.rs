use clap::Parser;

use crate::cli::Command;

#[derive(Debug, Parser)]
#[command(
    name = "resocks5",
    about = "SOCKS5 proxy rotator with optional user authentication.",
    long_about = "\
SOCKS5 proxy rotator. Accepts SOCKS5 and HTTP CONNECT client connections and
balances them across SOCKS5, HTTP, and HTTPS upstream proxies (IPv4/IPv6), with
optional per-client username/password authentication.

Configuration lives in three files in the current directory, all auto-
created on first launch with sensible defaults:

  resocks5.main.ktav        server settings (listener, auth, log, pool)
  resocks5.proxy_list.ktav  upstream proxies in `socks5_v4`, `socks5_v6`,
                            `http_v4`, `http_v6`, `https_v4`, and `https_v6`
                            arrays. Each entry is a `[*]user:pass@host:port`
                            line; `*` marks a gate.
  resocks5.users.ktav       client users (managed by `resocks5 users …`,
                            do not edit by hand).

Run with no arguments to start the server. Use `resocks5 users …` for
user management.",
    version,
    after_help = "\
EXAMPLES:
  resocks5                              start the server (current dir)
  resocks5 config                       print full configuration reference
  resocks5 users add alice              prompt for password, add user
  resocks5 users list                   show configured users
  resocks5 users disable alice          temporarily reject alice
  resocks5 users set-password alice     change alice's password
  resocks5 users remove alice           delete alice
  resocks5 users --help                 details on the user subcommands

Authentication is controlled by `auth.allow_anonymous` (default: `true`);
when false, an empty user list rejects all clients.
Passwords are NEVER taken via command-line flags — only via interactive
prompt with no terminal echo, so they don't end up in shell history.

For the full configuration-file reference (every field of
resocks5.main.ktav, proxy_list.ktav, users.ktav with defaults and
behaviour notes), run `resocks5 config`."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}
