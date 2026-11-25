//! A sans-I/O syncer state machine.

#![allow(dead_code)]

mod config;
mod time;

pub use config::{Limits, LimitsBuilder, PeerConfig};
pub use time::SyncInstant;
