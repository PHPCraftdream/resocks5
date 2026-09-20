mod log_drain;
mod runtime;
mod startup;

#[cfg(test)]
mod tests;

pub(crate) use runtime::run_server;

// In scope so `use super::*` in tests.rs resolves exactly as it did
// when this code lived at the crate root.
#[cfg(test)]
use log_drain::*;
#[cfg(test)]
use runtime::*;
#[cfg(test)]
use startup::*;
