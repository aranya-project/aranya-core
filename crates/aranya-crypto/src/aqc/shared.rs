use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::{
    csprng::{Csprng, Random},
    import::{ExportError, Import, ImportError},
    kdf::{Expand, Kdf, KdfError, Prk},
    kem::{DecapKey, Kem},
    keys::{SecretKey, SecretKeyBytes},
    signer::PkError,
    subtle::{Choice, ConstantTimeEq},
    typenum::U32,
    zeroize::{Zeroize, ZeroizeOnDrop},
    CipherSuite,
};

/// The root key material for a channel.
pub(crate) struct RootChannelKey<CS: CipherSuite>(<CS::Kem as Kem>::DecapKey);

impl<CS: CipherSuite> RootChannelKey<CS> {
    pub(super) fn new(sk: <CS::Kem as Kem>::DecapKey) -> Self {
        Self(sk)
    }

    pub(super) fn public(&self) -> Result<<CS::Kem as Kem>::EncapKey, PkError> {
        self.0.public()
    }

    pub(super) fn into_inner(self) -> <CS::Kem as Kem>::DecapKey {
        self.0
    }
}

impl<CS: CipherSuite> Clone for RootChannelKey<CS> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<CS: CipherSuite> ConstantTimeEq for RootChannelKey<CS> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<CS: CipherSuite> Random for RootChannelKey<CS> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(<<CS::Kem as Kem>::DecapKey as SecretKey>::new(rng))
    }
}

impl<CS: CipherSuite> SecretKey for RootChannelKey<CS> {
    fn new<R: Csprng>(rng: &mut R) -> Self {
        Random::random(rng)
    }

    type Size = <<CS::Kem as Kem>::DecapKey as SecretKey>::Size;

    fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
        self.0.try_export_secret()
    }
}

impl<CS: CipherSuite> ZeroizeOnDrop for RootChannelKey<CS> {
    // The only field is `DecapKey`, which is `ZeroizeOnDrop`.
}

impl<'a, CS: CipherSuite> Import<&'a [u8]> for RootChannelKey<CS> {
    fn import(key: &'a [u8]) -> Result<Self, ImportError> {
        Ok(Self(Import::import(key)?))
    }
}

/// A raw PSK.
#[derive(Serialize, Deserialize)]
pub struct RawPsk<CS> {
    // TODO(eric): support larger sizes?
    psk: [u8; 32],
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> RawPsk<CS> {
    /// Returns the raw PSK secret bytes.
    #[inline]
    pub const fn raw_secret_bytes(&self) -> &[u8] {
        &self.psk
    }
}

impl<CS: CipherSuite> Clone for RawPsk<CS> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            psk: self.psk,
            _marker: PhantomData,
        }
    }
}

impl<CS: CipherSuite> ConstantTimeEq for RawPsk<CS> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.psk.ct_eq(&other.psk)
    }
}

impl<CS: CipherSuite> ConstantTimeEq for &RawPsk<CS> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(*self, other)
    }
}

impl<CS: CipherSuite> Expand for RawPsk<CS> {
    type Size = U32;

    fn expand_multi<'a, K, I>(prk: &Prk<K::PrkSize>, info: I) -> Result<Self, KdfError>
    where
        K: Kdf,
        I: IntoIterator<Item = &'a [u8]>,
        I::IntoIter: Clone,
    {
        Ok(Self {
            psk: Expand::expand_multi::<K, _>(prk, info)?,
            _marker: PhantomData,
        })
    }
}

impl<CS: CipherSuite> Random for RawPsk<CS> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self {
            psk: Random::random(rng),
            _marker: PhantomData,
        }
    }
}

impl<CS> ZeroizeOnDrop for RawPsk<CS> {}
impl<CS> Drop for RawPsk<CS> {
    fn drop(&mut self) {
        self.psk.zeroize();
    }
}
