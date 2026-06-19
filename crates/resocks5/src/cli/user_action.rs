use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum UserAction {
    /// Add a new user. Password is read interactively (no echo).
    Add {
        /// Username. Will be rejected if it already exists.
        name: String,
    },
    /// Add a new user with a placeholder hash. The first client that
    /// connects with this username claims the account by submitting
    /// the password — it is then hashed (Argon2id), written into
    /// `resocks5.users.ktav`, and from that point on the account
    /// behaves as a normally-managed user.
    ///
    /// Use only when you control the timing of the first login —
    /// anyone who knows the username and beats the legitimate user to
    /// the first connection claims it instead.
    AddInit {
        /// Username. Will be rejected if it already exists.
        name: String,
    },
    /// Change an existing user's password. Read interactively.
    SetPassword { name: String },
    /// Remove a user from the list.
    Remove {
        name: String,
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// List configured users (names, enabled flag — never the hashes).
    List,
    /// Mark a user as enabled.
    Enable { name: String },
    /// Mark a user as disabled — auth attempts will fail without revealing
    /// disabled vs unknown.
    Disable { name: String },
    /// Mark a user as direct (bypass-pool): traffic goes from this server's IP.
    Direct { name: String },
    /// Mark a user as pool-routed (default): traffic flows through configured upstream proxies.
    Pool { name: String },
}
