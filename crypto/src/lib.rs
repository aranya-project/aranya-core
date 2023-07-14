//! The Aranya Cryptography Engine.
//!
//! # Overview
//!
//! Instead of performing ad-hoc cryptography, Aranya's
//! cryptography is centralized inside of the *cryptography
//! engine*. The cryptographic APIs provided by the cryptography
//! engine are described in multiple documents, including the
//! [IDAM] and [IDAM crypto] specs.
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
//! [IDAM crypto]: https://github.com/spideroak-inc/flow3-docs/blob/37bfddf39c37ae258615e8bf2617432aaf8d453a/idam_crypto.md
//! [IDAM]: https://github.com/spideroak-inc/flow3-docs/blob/8bf06fdfdb4521f96892de9eff8c7b2908413ace/src/idam.md

#![allow(unstable_name_collisions)]
#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(feature = "error_in_core", feature(error_in_core))]
#![cfg_attr(feature = "result_option_inspect", feature(result_option_inspect))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![deny(
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::unwrap_used,
    clippy::wildcard_imports,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[macro_use]
mod util;

pub mod aead;
pub mod apq;
pub mod asn1;
pub mod bearssl;
pub mod boring;
mod ciphersuite;
pub mod csprng;
mod default;
pub mod ec;
pub mod ed25519;
pub mod engine;
mod error;
mod features;
mod groupkey;
pub mod hash;
pub mod hex;
pub mod hkdf;
pub mod hmac;
pub mod hpke;
pub mod hybrid_array;
mod id;
pub mod import;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod mac;
mod misc;
pub mod signer;
pub mod test_util;
mod userkeys;
pub mod zeroize;

pub use {
    aead::{AeadError, BufferTooSmallError},
    ciphersuite::*,
    default::*,
    engine::{Engine, UnwrapError, UnwrappedKey, WrapError, WrongKeyTypeError},
    error::*,
    groupkey::*,
    hpke::HpkeError,
    id::*,
    import::{ExportError, ImportError},
    kdf::KdfError,
    kem::{EcdhError, KemError},
    mac::MacError,
    signer::SignerError,
    userkeys::*,
};
