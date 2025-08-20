//!  - `AEAD`: Authenticated Encryption with Additional
//!    Authenticated Data.  See [AEAD] and [RFC 5116].
//!  - `Digital signature`: See [Signature].
//!  - `encapsulate`: To encrypt cryptographic key material,
//!    typically for use with an asymmetric algorithm. See [KEM].
//!  - `HPKE`: Hybrid Public Key Encryption. See [HPKE].
//!  - `KDF`: A Key Derivation Function. See [KDF].
//!  - `KEM`: A Key Encapsulation Mechanism. See [KEM].
//!  - `seal`: Synonymous with "encrypt."
//!  - `open`: Synonymous with "decrypt."
//!
//! [AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [HPKE]: https://www.rfc-editor.org/rfc/rfc9180.html
//! [KDF]: https://en.wikipedia.org/wiki/Key_derivation_function
//! [KEM]: https://en.wikipedia.org/wiki/Key_encapsulation_mechanism
//! [RFC 5116]: https://www.rfc-editor.org/rfc/rfc5116
//! [Signature]: https://en.wikipedia.org/wiki/Digital_signature

mod ext;

use spideroak_crypto::{
    hash,
    hpke::{HpkeAead, HpkeKdf, HpkeKem},
    mac,
    oid::Identified,
    signer,
    typenum::U32,
};

pub use crate::ciphersuite::ext::{CipherSuiteExt, Oids};

/// A marker trait for AEADs.
pub trait Aead: HpkeAead + Identified {}

impl<A: HpkeAead + Identified> Aead for A {}

/// A marker trait for cryptographic hash functions.
pub trait Hash: hash::Hash + Identified {}

impl<H: hash::Hash + Identified> Hash for H {}

/// A marker trait for key derivation functions.
pub trait Kdf: HpkeKdf + Identified {}

impl<K: HpkeKdf + Identified> Kdf for K {}

/// A marker trait for key encapsulation mechanisms.
pub trait Kem: HpkeKem + Identified {}

impl<K: HpkeKem + Identified> Kem for K {}

/// A marker trait for messaged authentication codes.
pub trait Mac: mac::Mac + Identified {}

impl<M: mac::Mac + Identified> Mac for M {}

/// A marker trait for digital signatures.
pub trait Signer: signer::Signer + Identified {}

impl<S: signer::Signer + Identified> Signer for S {}

/// The cryptographic primitives used by the cryptography engine.
///
/// # Warning
///
/// It is incredibly important to fully read the documentation
/// for every single primitive as some primitives have very
/// particular requirements. For example, implementations of
/// [`Signer`] must reject non-canonical signatures. For ECDSA,
/// this might mean rejecting `-s mod N`.
///
/// While the requirements were designed to help ensure safe
/// defaults regardless of algorithm, it is still possible to
/// choose algorithms (or implementations) that severely
/// compromise the security of the engine. As such, we very
/// highly recommend that only cryptographers or experienced
/// cryptography engineers implement their own cipher suites.
///
/// Additionally, please test your implementation using the
/// `test_util` module.
pub trait CipherSuite {
    /// OIDS contains the OIDs from the algorithms in the cipher
    /// suite.
    const OIDS: Oids<Self> = Oids::new();

    /// See [`Aead`] for more information.
    type Aead: Aead;
    /// See [`Hash`] for more information.
    type Hash: Hash<DigestSize = U32>;
    /// See [`Kdf`] for more information.
    type Kdf: Kdf;
    /// See [`Kem`] for more information.
    type Kem: Kem;
    /// See [`Mac`] for more information.
    type Mac: Mac;
    /// See [`Signer`] for more information.
    type Signer: Signer;
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "bearssl")]
    mod bearssl {
        use spideroak_crypto::oid::consts::{DHKEM_P256_HKDF_SHA256, DHKEM_P521_HKDF_SHA512};

        use crate::{
            bearssl::{
                self, Aes256Gcm, HkdfSha256, HkdfSha384, HkdfSha512, HmacSha512, P256, P384, P521,
                Sha256,
            },
            kem_with_oid,
            test_util::{TestCs, test_ciphersuite},
        };

        kem_with_oid! {
            /// DHKEM(P256, HKDF-SHA256).
            #[derive(Debug)]
            struct DhKemP256HkdfSha256(bearssl::DhKemP256HkdfSha256) => DHKEM_P256_HKDF_SHA256
        }

        kem_with_oid! {
            /// DHKEM(P521, HKDF-SHA512).
            #[derive(Debug)]
            struct DhKemP521HkdfSha512(bearssl::DhKemP521HkdfSha512) => DHKEM_P521_HKDF_SHA512
        }

        test_ciphersuite!(p256, TestCs<
            Aes256Gcm,
            Sha256,
            HkdfSha256,
            DhKemP256HkdfSha256,
            HmacSha512,
            P256,
        >);
        test_ciphersuite!(p384, TestCs<
            Aes256Gcm,
            Sha256,
            HkdfSha384,
            DhKemP256HkdfSha256, // DhKemP384HkdfSha384 does not exist
            HmacSha512,
            P384,
        >);
        test_ciphersuite!(p521, TestCs<
            Aes256Gcm,
            Sha256,
            HkdfSha512,
            DhKemP521HkdfSha512,
            HmacSha512,
            P521,
        >);
    }

    mod rust {
        use spideroak_crypto::{
            oid::consts::DHKEM_P256_HKDF_SHA256,
            rust::{self, Aes256Gcm, HkdfSha256, HkdfSha384, HmacSha512, P256, P384, Sha256},
        };

        use crate::{
            kem_with_oid,
            test_util::{TestCs, test_ciphersuite},
        };

        kem_with_oid! {
            /// DHKEM(P256, HKDF-SHA256).
            #[derive(Debug)]
            struct DhKemP256HkdfSha256(rust::DhKemP256HkdfSha256) => DHKEM_P256_HKDF_SHA256
        }

        test_ciphersuite!(p256, TestCs<
            Aes256Gcm,
            Sha256,
            HkdfSha256,
            DhKemP256HkdfSha256,
            HmacSha512,
            P256,
        >);
        test_ciphersuite!(p384, TestCs<
            Aes256Gcm,
            Sha256,
            HkdfSha384,
            DhKemP256HkdfSha256, // DhKemP384HkdfSha384 does not exist
            HmacSha512,
            P384,
        >);
    }
}
