//! Stable public API for the Aranya runtime.
//!
//! This crate provides a curated, stable interface to the Aranya runtime.
//! Types exported from this crate follow semver and will not introduce
//! breaking changes without a major version bump.
//!
//! # Modules
//!
//! - [`storage`] — storage providers and I/O plumbing for the graph.
//! - [`policy`] — VM-backed policy execution (actions, effects, FFI).
//! - [`sync`] — peer-to-peer sync protocol for replicating graph state.
//!
//! The crate root exposes the [`ClientState`] facade and the fundamental
//! types that cut across every module (graph/command identity, sinks,
//! traversal buffers, and [`Transaction`]/[`Session`] handles).

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

mod client;

#[doc(inline)]
pub use aranya_runtime::{
    Address, ClientError, ClientState, CmdId, Command, GraphId, Session, Sink, Transaction,
    TraversalBuffer, TraversalBuffers,
};
#[doc(inline)]
pub use client::VmPolicyStore;

pub mod storage {
    //! Storage providers and low-level I/O for the graph.
    //!
    //! [`LinearStorageProvider`] is the stock append-only storage backend
    //! used by [`crate::ClientState`]; construct one with
    //! [`LinearStorageProvider::new`]. It is parameterized over an
    //! [`IoManager`] implementation — the user-swappable piece that owns
    //! how bytes are actually persisted. [`FileManager`] is the file-backed
    //! reference [`IoManager`] (available under the `libc` feature); custom
    //! backends implement [`IoManager`] (and the associated [`Read`]/
    //! [`Write`] traits) to plug in alternative storage.

    #[cfg(feature = "libc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "libc")))]
    #[doc(inline)]
    pub use aranya_runtime::storage::linear::libc::FileManager;
    #[doc(inline)]
    pub use aranya_runtime::{
        StorageError,
        storage::linear::{IoManager, LinearStorage, LinearStorageProvider, Read, Write},
    };
}

pub mod policy {
    //! VM-backed policy primitives: actions, effects, and FFI callables.
    //!
    //! [`VmPolicy`] compiles and runs policy bytecode against incoming
    //! commands, emitting [`VmEffect`]s. [`VmPolicyStore`] is the
    //! single-policy store used by [`crate::ClientState`]; construct one
    //! with [`VmPolicyStore::new`].

    #[doc(inline)]
    pub use aranya_runtime::vm_policy::{
        FfiCallable, VmAction, VmEffect, VmEffectData, VmPolicy, VmPolicyError,
    };

    #[doc(inline)]
    pub use crate::VmPolicyStore;
}

pub mod sync {
    //! Peer-to-peer sync protocol for replicating graph state.
    //!
    //! A [`SyncRequester`] polls a peer; a [`SyncResponder`] serves the polled
    //! request. Messages up to [`MAX_SYNC_MESSAGE_SIZE`] bytes are exchanged
    //! as [`SyncType`] envelopes over any transport the caller provides.

    #[doc(inline)]
    pub use aranya_runtime::sync::{
        COMMAND_RESPONSE_MAX, CommandMeta, MAX_SYNC_MESSAGE_SIZE, PEER_HEAD_MAX, PeerCache,
        SubscribeResult, SyncCommand, SyncError, SyncHelloType, SyncRequestMessage, SyncRequester,
        SyncResponder, SyncResponseMessage, SyncType,
    };
}
