//! Stable public API for the Aranya runtime.
//!
//! This crate provides a curated, stable interface to the Aranya runtime.
//! Types exported from this crate follow semver and will not introduce
//! breaking changes without a major version bump.
//!
//! # Modules
//!
//! - [`crypto`] — cryptography engine and cipher suite.
//! - [`id`] — tagged cryptographic identifiers and the [`id::custom_id`] macro.
//! - [`ifgen`] — runtime surface for `policy-ifgen`-generated interfaces.
//! - [`keystore`] — device key material and keystore plumbing.
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
pub mod id;

#[doc(inline)]
pub use aranya_policy_ifgen as ifgen;
#[doc(inline)]
pub use aranya_runtime::{
    Address, BraidBuffer, ClientError, ClientState, CmdId, Command, GraphId, RuntimeBuffers,
    Session, Sink, Transaction, TraversalBuffer, TraversalBuffers,
};

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
    #[cfg(feature = "libc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "libc")))]
    #[doc(inline)]
    pub use aranya_runtime::LibcSpill;
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
    pub use crate::client::VmPolicyStore;
}

pub mod crypto {
    //! Cryptography engine and cipher suite.
    //!
    //! Most consumers should use [`DefaultEngine`] parameterized on
    //! [`DefaultCipherSuite`] and [`Rng`]:
    //!
    //! ```ignore
    //! use aranya_core::crypto::{DefaultCipherSuite, DefaultEngine, Rng};
    //!
    //! let (engine, key) =
    //!     DefaultEngine::<Rng, DefaultCipherSuite>::from_entropy(Rng);
    //! ```
    //!
    //! The returned AEAD key is the root of trust for wrapped keys and
    //! must be persisted securely.
    //!
    //! To implement a custom [`Engine`], enable the `custom-engine`
    //! feature. This exposes the low-level trait surface
    //! ([`RawSecretWrap`], [`UnwrappedKey`], [`WrappedKey`], etc.) needed
    //! to write a conforming engine. Custom engines are security-critical
    //! and should be reviewed by cryptographers.

    #[cfg(feature = "custom-engine")]
    #[cfg_attr(docsrs, doc(cfg(feature = "custom-engine")))]
    #[doc(inline)]
    pub use aranya_crypto::engine::{
        AlgId, RawSecret, RawSecretWrap, Secret, UnwrappedKey, UnwrappedSecret, WrappedKey,
        WrongKeyType,
    };
    #[doc(inline)]
    pub use aranya_crypto::{
        CipherSuite, Csprng, Engine, Random, Rng, UnwrapError, WrapError,
        default::{DefaultCipherSuite, DefaultEngine},
    };
}

pub mod keystore {
    //! Device key material and keystore plumbing.
    //!
    //! Device keys — [`IdentityKey`], [`SigningKey`], and [`EncryptionKey`] —
    //! are stored as wrapped secrets in a [`KeyStore`]. [`KeyStoreExt`] is a
    //! blanket-impl convenience trait layered over [`KeyStore`] that adds
    //! `insert_key`/`get_key`/`remove_key` using the
    //! [`Engine`](crate::crypto::Engine)-based wrap/unwrap path. [`Identified`]
    //! is the trait that ties each key to its stable [`Identified::Id`].
    //!
    //! [`MemStore`] is an in-memory [`KeyStore`] suitable for tests and
    //! short-lived sessions; enable the `memstore` feature to use it.

    #[cfg(feature = "memstore")]
    #[cfg_attr(docsrs, doc(cfg(feature = "memstore")))]
    #[doc(inline)]
    pub use aranya_crypto::keystore::memstore::MemStore;
    #[doc(inline)]
    pub use aranya_crypto::{
        DeviceId, EncryptionKey, Identified, IdentityKey, KeyStore, KeyStoreExt, SigningKey,
    };
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
