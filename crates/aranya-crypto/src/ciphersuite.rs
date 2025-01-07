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

#![forbid(unsafe_code)]

use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};

use crate::{
    aead::{Aead, AeadId, IndCca2},
    hash::{Hash, HashId},
    kdf::{Kdf, KdfId},
    kem::{Kem, KemId},
    mac::{Mac, MacId},
    signer::{Signer, SignerId},
    typenum::U64,
    Id,
};

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
    /// Uniquely identifies the [`CipherSuite`].
    const ID: Id;

    /// See [`Aead`] for more information.
    type Aead: Aead + IndCca2;
    /// See [`Hash`] for more information.
    type Hash: Hash<DigestSize = U64>;
    /// See [`Kdf`] for more information.
    type Kdf: Kdf;
    /// See [`Kem`] for more information.
    type Kem: Kem;
    /// See [`Mac`] for more information.
    type Mac: Mac<KeySize = U64, TagSize = U64>;
    /// See [`Signer`] for more information.
    type Signer: Signer;
}

/// Identifies the algorithms used by a [`CipherSuite`].
///
/// Used for domain separation and contextual binding.
#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, MaxSize)]
pub(crate) struct SuiteIds {
    pub aead: AeadId,
    pub hash: HashId,
    pub kdf: KdfId,
    pub kem: KemId,
    pub mac: MacId,
    pub signer: SignerId,
}

impl SuiteIds {
    #[allow(clippy::cast_possible_truncation)]
    pub const fn into_bytes(self) -> [u8; 6 * 2] {
        // TODO(eric): there is probably a better way of doing
        // this, like with a macro or something.
        [
            self.aead.to_u16() as u8,
            (self.aead.to_u16() >> 8) as u8,
            self.hash.to_u16() as u8,
            (self.hash.to_u16() >> 8) as u8,
            self.kdf.to_u16() as u8,
            (self.kdf.to_u16() >> 8) as u8,
            self.kem.to_u16() as u8,
            (self.kem.to_u16() >> 8) as u8,
            self.mac.to_u16() as u8,
            (self.mac.to_u16() >> 8) as u8,
            self.signer.to_u16() as u8,
            (self.signer.to_u16() >> 8) as u8,
        ]
    }

    pub const fn from_suite<S: CipherSuite>() -> Self {
        Self {
            aead: S::Aead::ID,
            hash: S::Hash::ID,
            kdf: S::Kdf::ID,
            kem: S::Kem::ID,
            mac: S::Mac::ID,
            signer: S::Signer::ID,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "bearssl")]
    mod bearssl {
        use crate::{
            bearssl::{
                Aes256Gcm, DhKemP256HkdfSha256, DhKemP521HkdfSha512, HkdfSha256, HkdfSha384,
                HkdfSha512, HmacSha512, Sha512, P256, P384, P521,
            },
            test_util::{test_ciphersuite, TestCs},
        };

        test_ciphersuite!(p256, TestCs<
            Aes256Gcm,
            Sha512,
            HkdfSha256,
            DhKemP256HkdfSha256,
            HmacSha512,
            P256,
        >);
        test_ciphersuite!(p384, TestCs<
            Aes256Gcm,
            Sha512,
            HkdfSha384,
            DhKemP256HkdfSha256, // DhKemP384HkdfSha384 does not exist
            HmacSha512,
            P384,
        >);
        test_ciphersuite!(p521, TestCs<
            Aes256Gcm,
            Sha512,
            HkdfSha512,
            DhKemP521HkdfSha512,
            HmacSha512,
            P521,
        >);
    }

    mod rust {
        use crate::{
            rust::{
                Aes256Gcm, DhKemP256HkdfSha256, HkdfSha256, HkdfSha384, HmacSha512, Sha512, P256,
                P384,
            },
            test_util::{test_ciphersuite, TestCs},
        };

        test_ciphersuite!(p256, TestCs<
            Aes256Gcm,
            Sha512,
            HkdfSha256,
            DhKemP256HkdfSha256,
            HmacSha512,
            P256,
        >);
        test_ciphersuite!(p384, TestCs<
            Aes256Gcm,
            Sha512,
            HkdfSha384,
            DhKemP256HkdfSha256, // DhKemP384HkdfSha384 does not exist
            HmacSha512,
            P384,
        >);
    }
}
