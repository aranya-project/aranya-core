//! Digital Signatures.

#![forbid(unsafe_code)]

use core::{borrow::Borrow, fmt::Debug, num::NonZeroU16, result::Result};

use aranya_buggy::Bug;

use crate::{
    asn1::EncodingError,
    import::Import,
    keys::{PublicKey, SecretKey},
    AlgId,
};

/// An error from a [`Signer`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum SignerError {
    /// An unknown or internal error has occurred.
    #[error("{0}")]
    Other(&'static str),
    /// The imported signature is invalid.
    #[error(transparent)]
    Encoding(#[from] EncodingError),
    /// The signature could not be verified.
    #[error("unable to verify signature")]
    Verification,
    /// [`Signer::verify_batch`] was called with different
    /// lengths for messages, signatures, or verifying keys.
    #[error("invalid `verify_batch` lengths")]
    InvalidBatchLengths,
    /// An internal error was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
}

/// Digital signature algorithm identifiers.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, AlgId)]
pub enum SignerId {
    /// ECDSA using NIST Curve P-256.
    #[alg_id(0x0001)]
    P256,
    /// ECDSA using NIST Curve P-384.
    #[alg_id(0x0002)]
    P384,
    /// ECDSA using NIST Curve P-521.
    #[alg_id(0x0003)]
    P521,
    /// EdDSA using Ed25519.
    #[alg_id(0x0004)]
    Ed25519,
    /// EdDSA using Ed448.
    #[alg_id(0x0005)]
    Ed448,
    /// Some other digital signature algorithm.
    #[alg_id(Other)]
    Other(NonZeroU16),
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
    type Signature: Signature<Self>;

    /// Verifies all (message, signature, verifying key) tuples
    /// as a batch.
    ///
    /// For some digital signature schemes, batch verification
    /// can differ from regular signature verification. For
    /// example, see some [Ed25519 quirks][quirks]. This function
    /// MUST NOT diverge from regular signature verification.
    ///
    /// [quirks]: https://hdevalence.ca/blog/2020-10-04-its-25519am
    fn verify_batch(
        msgs: &[&[u8]],
        sigs: &[Self::Signature],
        pks: &[Self::VerifyingKey],
    ) -> Result<(), SignerError> {
        if msgs.len() != sigs.len() || sigs.len() != pks.len() {
            return Err(SignerError::InvalidBatchLengths);
        }
        for (msg, (sig, pk)) in msgs.iter().zip(sigs.iter().zip(pks)) {
            pk.verify(msg, sig)?;
        }
        Ok(())
    }
}

/// An asymmetric secret key used to create digital signatures.
pub trait SigningKey<T: Signer + ?Sized>: SecretKey {
    /// Returns the signature over `msg`, which must NOT be
    /// pre-hashed.
    fn sign(&self, msg: &[u8]) -> Result<T::Signature, SignerError>;

    /// Returns the public half of the key.
    fn public(&self) -> Result<T::VerifyingKey, PkError>;
}

/// Handles Public Key errors
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct PkError(pub(crate) &'static str);

impl PkError {
    // Exported for `aranya-crypto`. Do not use.
    #[doc(hidden)]
    pub const fn msg(&self) -> &'static str {
        self.0
    }
}

/// An asymmetric public key used to verify digital signatures.
pub trait VerifyingKey<T: Signer + ?Sized>: PublicKey {
    /// Reports whether the signature over `msg` is valid.
    fn verify(&self, msg: &[u8], sig: &T::Signature) -> Result<(), SignerError>;
}

/// A canonical digital signature.
pub trait Signature<T: Signer + ?Sized>: Clone + Debug + for<'a> Import<&'a [u8]> {
    /// The fixed-length byte encoding of the signature.
    ///
    /// This should be `[u8; N]` or similar.
    type Data: Borrow<[u8]> + Clone + Sized;

    /// Returns the byte encoding of the signature.
    fn export(&self) -> Self::Data;
}
