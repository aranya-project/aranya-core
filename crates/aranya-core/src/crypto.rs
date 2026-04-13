//! Re-exports of the cryptography engine from [`aranya_crypto`].
//!
//! The [`Engine`] trait is the contract every cryptographic engine
//! must satisfy. [`DefaultEngine`] is a reference implementation that
//! covers the vast majority of integrations; use
//! [`DefaultCryptoEngine`] when you want it paired with [`Rng`] and
//! [`DefaultCipherSuite`].
//!
//! # Stability
//!
//! These items follow `aranya-core`'s semver contract: breaking
//! changes will not be introduced without a major version bump.
//! Because [`CipherSuite`]'s associated types come from the
//! `spideroak_crypto` crate, that crate is transitively part of this
//! crate's public surface; that situation predates this module and is
//! not changed by it.

#[doc(inline)]
pub use aranya_crypto::default::{DefaultCipherSuite, DefaultEngine};
#[doc(inline)]
pub use aranya_crypto::{
    BaseId, CipherSuite, Csprng, DeviceId, Encap, EncryptionKey, EncryptionKeyId,
    EncryptionPublicKey, Engine, Identified, IdentityKey, IdentityVerifyingKey, Random, Rng,
    Signature, SigningKey, SigningKeyId, UnwrapError, VerifyingKey, WrapError,
};

/// The reference [`DefaultEngine`] parameterized with [`Rng`] and
/// [`DefaultCipherSuite`].
///
/// Equivalent to `DefaultEngine<Rng, DefaultCipherSuite>`. Start here
/// unless you have a reason to pick a different CSPRNG or cipher suite.
pub type DefaultCryptoEngine = DefaultEngine<Rng, DefaultCipherSuite>;

/// Wrapped-key storage.
pub mod keystore {
    /// File-system-backed keystore.
    ///
    /// Renamed from the upstream
    /// `aranya_crypto::keystore::fs_keystore::Store` so the
    /// unqualified facade name is unambiguous.
    #[cfg(feature = "fs-keystore")]
    #[cfg_attr(docsrs, doc(cfg(feature = "fs-keystore")))]
    #[doc(inline)]
    pub use aranya_crypto::keystore::fs_keystore::Store as FsKeyStore;
    #[cfg(feature = "memstore")]
    #[cfg_attr(docsrs, doc(cfg(feature = "memstore")))]
    #[doc(inline)]
    pub use aranya_crypto::keystore::memstore::MemStore;
    #[doc(inline)]
    pub use aranya_crypto::keystore::{
        Entry, Error, ErrorKind, KeyStore, KeyStoreExt, Occupied, Vacant,
    };
}
