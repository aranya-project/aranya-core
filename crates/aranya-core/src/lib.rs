//! Stable public API for the Aranya runtime.
//!
//! This crate provides a curated, stable interface to the Aranya runtime.
//! Types exported from this crate follow semver and will not introduce
//! breaking changes without a major version bump.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

mod client;

#[cfg(feature = "libc")]
#[cfg_attr(docsrs, doc(cfg(feature = "libc")))]
#[doc(inline)]
pub use aranya_runtime::storage::linear::libc::FileManager;
#[doc(inline)]
pub use aranya_runtime::{
    Address, ClientError, CmdId, Command, GraphId, Session, Sink, StorageError, Transaction,
    TraversalBuffer, TraversalBuffers,
    storage::linear::{IoManager, LinearStorage, LinearStorageProvider, Read, Write},
    vm_policy::{FfiCallable, VmAction, VmEffect, VmEffectData, VmPolicy, VmPolicyError},
};
#[doc(inline)]
pub use client::{Client, ClientSession, ClientTransaction, VmPolicyStore};

pub mod sync;
