//! Load → mutate → save harness. Promoted to [`mw_core::state::with_config`] so
//! the daemon shares one implementation; re-exported here for the CLI's
//! existing `crate::store::with_config` call sites.

pub use mw_core::state::with_config;
