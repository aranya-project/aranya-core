#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![deny(
    clippy::arithmetic_side_effects,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

mod client;
mod command;
pub mod engine;
pub mod model;
mod prior;
pub mod protocol;
pub mod quic_syncer;
pub mod storage;
pub mod sync;

pub use crate::{
    client::*, command::*, engine::*, prior::Prior, storage::*, sync::*, vm_policy::*,
};

#[cfg(test)]
mod tests;
mod vm_policy;
