//! Per-event-type logging with format-deferred macros. Each log call
//! site reads its category flag from `LogConfig` (loaded from
//! `resocks5.main.ktav`) and only formats the message + sends it on the
//! channel when the flag is true.
//!
//! The methods take `impl FnOnce() -> String` so the closure isn't
//! evaluated when the flag is off — no `format!()` allocation, no
//! channel send. On a hot path this saves ~200 ns per skipped log.

pub mod e_log;
pub mod log;
pub mod log_config;

pub use e_log::ELog;
pub use log::Logger;
pub use log_config::LogConfig;
