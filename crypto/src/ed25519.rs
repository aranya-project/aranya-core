//! Ed25519 key generation, signatures, and verification using
//! [ed25519-dalek].
//!
//! This module performs *strict* signature verification to
//! protect against [weak key forgeries][weak-key]. This means
//! that it might not be interoperable with all Ed25519
//! implementations.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.
//!
//! [ed25519-dalek]: https://github.com/dalek-cryptography/ed25519-dalek
//! [weak-key]: https://github.com/dalek-cryptography/ed25519-dalek/tree/58a967f6fb28806a21180c880bbec4fdeb907aef#weak-key-forgery-and-verify_strict

use core::fmt::{self, Debug};

use ed25519_dalek as dalek;
use subtle::{Choice, ConstantTimeEq};

use crate::{
    csprng::Csprng,
    hex::ToHex,
    import::{try_import, ExportError, Import, ImportError},
    keys::{PublicKey, RawKey, SecretKey},
    signer::{self, Signer, SignerError, SignerId},
    zeroize::{ZeroizeOnDrop, Zeroizing},
};

/// EdDSA using Ed25519.
pub struct Ed25519;

impl Signer for Ed25519 {
    const ID: SignerId = SignerId::Ed25519;

    type SigningKey = SigningKey;
    type VerifyingKey = VerifyingKey;
    type Signature = Signature;

    #[cfg_attr(docs, doc(cfg(feature = "ed25519_batch")))]
    #[cfg(feature = "ed25519_batch")]
    fn verify_batch(
        msgs: &[&[u8]],
        sigs: &[Self::Signature],
        pks: &[Self::VerifyingKey],
    ) -> Result<(), SignerError> {
        dalek::verify_batch(
            msgs,
            // SAFETY: [`Signature`] has the same layout as
            // [`dalek::Signature`].
            unsafe { core::mem::transmute(sigs) },
            // SAFETY: [`VerifyingKey`] has the same layout as
            // [`dalek::VerifyingKey`].
            unsafe { core::mem::transmute(pks) },
        )
        .map_err(|_| SignerError::Verification)
    }
}

/// An Ed25519 signing key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SigningKey(dalek::SigningKey);

impl signer::SigningKey<Ed25519> for SigningKey {
    fn sign(&self, msg: &[u8]) -> Result<Signature, SignerError> {
        let sig = dalek::Signer::sign(&self.0, msg);
        Ok(Signature(sig))
    }

    fn public(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
}

impl SecretKey for SigningKey {
    fn new<R: Csprng>(rng: &mut R) -> Self {
        let mut sk = dalek::SecretKey::default();
        rng.fill_bytes(&mut sk);
        Self(dalek::SigningKey::from_bytes(&sk))
    }

    type Data = RawKey<32>;

    #[inline]
    fn try_export_secret(&self) -> Result<Self::Data, ExportError> {
        Ok(self.0.to_bytes().into())
    }
}

impl ConstantTimeEq for SigningKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        let lhs = Zeroizing::new(self.0.to_bytes());
        let rhs = Zeroizing::new(other.0.to_bytes());
        ConstantTimeEq::ct_eq(lhs.as_ref(), rhs.as_ref())
    }
}

impl Import<&[u8; 32]> for SigningKey {
    fn import(data: &[u8; 32]) -> Result<Self, ImportError> {
        Ok(Self(dalek::SigningKey::from_bytes(data)))
    }
}

impl Import<[u8; 32]> for SigningKey {
    fn import(data: [u8; 32]) -> Result<Self, ImportError> {
        Self::import(&data)
    }
}

impl Import<RawKey<32>> for SigningKey {
    fn import(data: RawKey<32>) -> Result<Self, ImportError> {
        Self::import(Into::<[u8; 32]>::into(data))
    }
}

impl Import<&[u8]> for SigningKey {
    fn import(data: &[u8]) -> Result<Self, ImportError> {
        try_import(data)
    }
}

/// An Ed25519 signature verifying key.
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct VerifyingKey(dalek::VerifyingKey);

impl signer::VerifyingKey<Ed25519> for VerifyingKey {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), SignerError> {
        self.0
            .verify_strict(msg, &sig.0)
            .map_err(|_| SignerError::Verification)
    }
}

impl PublicKey for VerifyingKey {
    type Data = [u8; 32];

    fn export(&self) -> Self::Data {
        self.0.to_bytes()
    }
}

impl Import<&[u8; 32]> for VerifyingKey {
    fn import(data: &[u8; 32]) -> Result<Self, ImportError> {
        let pk = dalek::VerifyingKey::from_bytes(data).map_err(|_| ImportError::InvalidSyntax)?;
        Ok(Self(pk))
    }
}

impl Import<[u8; 32]> for VerifyingKey {
    fn import(data: [u8; 32]) -> Result<Self, ImportError> {
        Self::import(&data)
    }
}

impl<'a> Import<&'a [u8]> for VerifyingKey {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        try_import(data)
    }
}

impl Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.export().to_hex())
    }
}

/// An Ed25519 signature.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Signature(dalek::Signature);

impl signer::Signature<Ed25519> for Signature {
    type Data = [u8; 64];

    fn export(&self) -> Self::Data {
        self.0.to_bytes()
    }
}

impl Import<&[u8; 64]> for Signature {
    fn import(data: &[u8; 64]) -> Result<Self, ImportError> {
        Ok(Signature(dalek::Signature::from_bytes(data)))
    }
}

impl Import<[u8; 64]> for Signature {
    fn import(data: [u8; 64]) -> Result<Self, ImportError> {
        Self::import(&data)
    }
}

impl Import<&[u8]> for Signature {
    fn import(data: &[u8]) -> Result<Self, ImportError> {
        try_import(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_signer;

    test_signer!(ed25519, Ed25519, EddsaTest::Ed25519);
}
