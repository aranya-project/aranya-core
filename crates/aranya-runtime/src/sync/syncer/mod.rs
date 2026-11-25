//! A sans-I/O syncer state machine.

#![allow(dead_code)]

mod config;
mod schedule;
#[cfg(test)]
mod schedule_tests;
mod slots;
mod time;

pub use config::{Limits, LimitsBuilder, PeerConfig};
pub use slots::{FixedSlots, HeapSlots, OutOfSlots, SyncSlot, SyncSlots};
pub use time::SyncInstant;
