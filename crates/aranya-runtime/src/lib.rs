//! The Aranya runtime.
//!
//! # Overview
//!
//! The runtime crate is the starting point for integrating with Aranya.
//!
//! The runtime provides a higher level interface to:
//! 1. An [`PolicyStore`] responsible for storing [`Policy`]s evaluated on graph [`Command`]s.
//! 2. A [`StorageProvider`] responsible for providing a storage mechanism for graph commands.
//! 3. A [`sync`] interface responsible for syncing graph state between peers.
//!
//! # Usage
//!
//! Refer to provided demo/quickstart code for an example of how to use the runtime crate.
//! The `aranya-tcp-syncer` crate provides a good example of syncing via TCP.
//!
//! # Example
//!
//! Start by initializing a client with desired [`PolicyStore`] and [`StorageProvider`]
//! ```ignore
//! let client = ClientState::new(policy_store, storage)
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
//! To sync with other peers, register them with a [`Syncer`] and drive it
//! from your transport: send what [`Syncer::next_outbound`] produces, hand
//! replies to [`Syncer::handle_reply`] and peers' requests to
//! [`Syncer::handle_incoming`]:
//! ```ignore
//! syncer.add_peer(peer, graph_id, PeerConfig::periodic(interval), now)?;
//! while let Some(outbound) = syncer.next_outbound(now, &mut cx, &mut buf)? { ... }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

extern crate alloc;

mod client;
pub mod command;
pub mod metrics;
pub mod policy;
mod prior;
pub mod storage;
pub mod sync;
pub mod testing;
pub(crate) mod util;
pub mod vm_policy;

pub use crate::{
    client::*,
    command::*,
    policy::*,
    prior::Prior,
    storage::*,
    sync::*,
    vm_policy::{
        AttributeError, FfiCallable, VmAction, VmEffect, VmEffectData, VmFactCursor, VmPolicy,
        VmPolicyError,
    },
};
