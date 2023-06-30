//! Digital Signatures.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

#![forbid(unsafe_code)]

use {
    crate::{
        asn1::EncodingError,
        import::Import,
        keys::{PublicKey, SecretKey},
    },
    cfg_if::cfg_if,
    core::{
        borrow::Borrow,
        fmt::{self, Debug},
        result::Result,
    },
    serde::{Deserialize, Serialize},
};

cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        use core::error;
    } else if #[cfg(feature = "std")] {
        use std::error;
    }
}

/// An error from a [`Signer`].
#[derive(Debug, Eq, PartialEq)]
pub enum SignerError {
    /// An unknown or internal error has occurred.
    Other(&'static str),
    /// The imported signature is invalid.
    Encoding(EncodingError),
    /// The signature could not be verified.
    Verification,
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(msg) => write!(f, "{}", msg),
            Self::Encoding(err) => write!(f, "{}", err),
            Self::Verification => write!(f, "unable to verify signature"),
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for SignerError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Other(_) => None,
            Self::Encoding(err) => Some(err),
            Self::Verification => None,
        }
    }
}

impl From<EncodingError> for SignerError {
    fn from(err: EncodingError) -> Self {
        Self::Encoding(err)
    }
}

/// Digital signature algorithm identifiers.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum SignerId {
    /// ECDSA using NIST Curve P-256.
    P256,
    /// ECDSA using NIST Curve P-384.
    P384,
    /// ECDSA using NIST Curve P-521.
    P521,
    /// EdDSA using Ed25519.
    Ed25519,
    /// EdDSA using Ed448.
    Ed448,
    /// Some other digital signature algorithm.
    Other(u16),
}

impl SignerId {
    pub(crate) const fn to_u16(self) -> u16 {
        match self {
            Self::P256 => 0x0001,
            Self::P384 => 0x0002,
            Self::P521 => 0x0003,
            Self::Ed25519 => 0x0004,
            Self::Ed448 => 0x0005,
            Self::Other(id) => id,
        }
    }
}

/// Signer is a digital signature algorithm.
///
/// # Requirements
///
/// The algorithm must:
///
/// * Have at minimum a 128-bit security level.
/// * Generate canonical signatures.
/// * Reject non-canonical signatures.
/// * Be EUF-CMA secure.
///
/// Note that rejecting non-canonical signatures implies strong
/// EUF-CMA security. However, this API's definition is
/// intentionally weaker.
///
/// Examples of algorithms that fulfill these requirements
/// include ECDSA with the three NIST prime-order curves (P-256,
/// P-384, and P521), albeit with minor modifications (like
/// rejecting s >= N/2).
pub trait Signer {
    /// Uniquely identifies the signature algorithm.
    const ID: SignerId;

    /// A private key used to create signatures.
    type SigningKey: SigningKey<Self>;
    /// A public key used verify signatures.
    type VerifyingKey: VerifyingKey<Self>;
    /// A digital signature.
    type Signature: Borrow<[u8]> + Clone + Debug + for<'a> Import<&'a [u8]>;
}

/// An asymmetric secret key used to create digital signatures.
pub trait SigningKey<T: Signer + ?Sized>: SecretKey {
    /// Returns the signature over `msg`, which must NOT be
    /// pre-hashed.
    fn sign(&self, msg: &[u8]) -> Result<T::Signature, SignerError>;

    /// Returns the public half of the key.
    fn public(&self) -> T::VerifyingKey;
}

/// An asymmetric public key used to verify digital signatures.
pub trait VerifyingKey<T: Signer + ?Sized>: PublicKey {
    /// Reports whether the signature over `msg` is valid.
    fn verify(&self, msg: &[u8], sig: &T::Signature) -> Result<(), SignerError>;
}
