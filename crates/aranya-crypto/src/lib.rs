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
//! [IDAM crypto]: https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/idam-crypto-apis/src/idam_crypto.md

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![cfg_attr(not(all(test, feature = "trng")), forbid(unsafe_code))]
#![warn(missing_docs)]

pub mod afc;
pub mod apq;
mod aranya;
mod ciphersuite;
pub mod default;
pub mod engine;
mod error;
mod groupkey;
pub mod id;
pub mod keystore;
mod misc;
mod policy;
pub mod test_util;
mod tests;

// Re-export `$name` without inlining it.
macro_rules! reexport {
    ($($name:ident),* $(,)?) => {
        $(
            /// # Warning
            ///
            /// This is a low-level module. You should not be
            /// using it directly unless you are implementing an
            /// engine.
            #[doc(no_inline)]
            pub use aranya_crypto_core::$name;
        )*
    }
}
reexport! {
    aead,
    asn1,
    csprng,
    ec,
    ed25519,
    hash,
    hex,
    hkdf,
    hmac,
    hpke,
    import,
    kdf,
    kem,
    keys,
    mac,
    rust,
    signer,
}

pub use aranya::*;
pub use aranya_buggy;
#[doc(no_inline)]
#[cfg(feature = "bearssl")]
#[cfg_attr(docsrs, doc(cfg(feature = "bearssl")))]
pub use aranya_crypto_core::bearssl;
pub use aranya_crypto_core::{
    aead::{BufferTooSmallError, OpenError, SealError},
    csprng::{Csprng, Random},
    generic_array,
    hpke::HpkeError,
    import::{ExportError, ImportError},
    kdf::KdfError,
    kem::{EcdhError, KemError},
    mac::MacError,
    signer::SignerError,
    subtle, typenum, zeroize,
};
#[cfg(feature = "hazmat")]
#[cfg_attr(docsrs, doc(cfg(feature = "hazmat")))]
pub use aranya_crypto_core::{dhkem_impl, hkdf_impl, hmac_impl};
pub use ciphersuite::*;
pub use default::Rng;
pub use engine::{Engine, UnwrapError, WrapError};
pub use error::*;
pub use groupkey::*;
pub use id::{Id, Identified};
pub use keystore::{KeyStore, KeyStoreExt};
pub use policy::*;
pub use siphasher;
