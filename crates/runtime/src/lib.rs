//! The Aranya runtime.
//!
//! # Overview
//!
//! The runtime crate is the starting point for integrating with Aranya.
//!
//! The runtime provides a higher level interface to:
//! 1. An [`Engine`] responsible for enforcing a [`Policy`] on graph [`Command`]s.
//! 2. A [`StorageProvider`] responsible for providing a storage mechanism for graph commands.
//! 3. A [`sync`] interface responsible for syncing graph state between peers.
//!
//! # Usage
//!
//! Refer to provided demo/quickstart code for an example of how to use the runtime crate.
//! The `quic_syncer.rs` module provides a good example of syncing via QUIC.
//!
//! # Example
//!
//! Start by initializing a client with desired [`Engine`] and [`StorageProvider`]
//! ```ignore
//! let client = ClientState::new(engine, storage)
//! ```
//!
//! Initialize graph for the client with:
//! ```ignore
//! client.new_graph(...)
//! ```
//!
//! Start listening for incoming sync requests with:
//! ```ignore
//! sync::run_syncer(...)
//! ```
//!
//! To initiate a sync with another peer, construct a [`SyncRequester`]
//! and send the sync request to the peer via the Aranya transport:
//! ```ignore
//! SyncRequester::new(...)
//! sync::sync(...)
//! ```

#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![deny(
    clippy::arithmetic_side_effects,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

mod client;
pub mod command;
pub mod engine;
pub mod metrics;
mod prior;
pub mod protocol;
pub mod storage;
pub mod sync;

pub use crate::{
    client::*, command::*, engine::*, prior::Prior, storage::*, sync::*, vm_policy::*,
};

pub mod vm_policy;
