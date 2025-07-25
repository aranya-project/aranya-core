use core::marker::PhantomData;

use derive_where::derive_where;
use spideroak_crypto::{
    csprng::{Csprng, Random},
    hpke::{RecvCtx, SendCtx},
    import::{ExportError, Import, ImportError},
    kdf::{Expand, Kdf, KdfError, Prk},
    kem::{DecapKey, Kem},
    keys::{SecretKey, SecretKeyBytes},
    signer::PkError,
    subtle::{Choice, ConstantTimeEq},
    typenum::U32,
    zeroize::{Zeroize, ZeroizeOnDrop},
};

use crate::ciphersuite::CipherSuite;

/// The root key material for a channel.
#[derive_where(Clone)]
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

impl<CS: CipherSuite> ConstantTimeEq for RootChannelKey<CS> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<CS: CipherSuite> Random for RootChannelKey<CS> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(Random::random(rng))
    }
}

impl<CS: CipherSuite> SecretKey for RootChannelKey<CS> {
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
#[derive_where(Clone, Serialize, Deserialize)]
pub(super) struct RawPsk<CS> {
    // TODO(eric): support different sizes?
    psk: [u8; 32],
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> RawPsk<CS> {
    /// Returns the raw PSK secret bytes.
    #[inline]
    pub(super) const fn raw_secret_bytes(&self) -> &[u8] {
        &self.psk
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

pub(super) enum SendOrRecvCtx<CS: CipherSuite> {
    Send(SendCtx<CS::Kem, CS::Kdf, CS::Aead>),
    Recv(RecvCtx<CS::Kem, CS::Kdf, CS::Aead>),
}

impl<CS: CipherSuite> SendOrRecvCtx<CS> {
    pub(super) fn export<T>(&self, context: &[u8]) -> Result<T, KdfError>
    where
        T: Expand,
    {
        match self {
            SendOrRecvCtx::Send(ctx) => ctx.export(context),
            SendOrRecvCtx::Recv(ctx) => ctx.export(context),
        }
    }
}
