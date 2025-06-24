//! The Aranya Cryptography Engine.
//!
//! # Overview
//!
//! Instead of performing ad-hoc cryptography, Aranya's
//! cryptography is centralized inside of the *cryptography
//! engine*. The cryptographic APIs provided by the cryptography
//! engine are described in multiple documents, including the
//! [IDAM crypto] spec.
//!
//! While it's generally referred to as *the* cryptography
//! engine, it's important to note that there can be multiple
//! implementations of the cryptography engine. The cryptography
//! engine requires a particular set of primitives, but allows
//! users to choose their own algorithms.
//!
//! # Design
//!
//! As mentioned above, the cryptography engine only requires
//! certain cryptographic primitives, not algorithms. For
//! instance, it requires an AEAD with at least a 128-bit
//! security level, not AES-GCM.
//!
//! The set of algorithms is referred to as a *cipher suite*.
//! Each algorithm has an identifier that distinguishes it from
//! other algorithms implementing the same primitive. For
//! example, the identifier for AES-256-GCM is different from the
//! identifer for ChaCha20Poly1305. The identifiers for the
//! algorithms used by a particular cipher suite are referred to
//! as the cipher suite's identifier, or "suite IDs."
//!
//! Every cryptographic operation performed by the engine mixes
//! in the cipher suite's identifier for domain separation and
//! contextual binding purposes. Among other things, this helps
//! prevent cross-version attacks.
//!
// TODO: Once the idam_crypto doc gets open sourced this link should be updated. <https://github.com/aranya-project/aranya-docs/issues/17>
//! [IDAM crypto]: <https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/idam-crypto-apis/src/idam_crypto.md>

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest)), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod id;

// These crates are public dependencies.
pub use ::generic_array;
pub use ::subtle;
pub use ::typenum;

pub use crate::id::Id;
