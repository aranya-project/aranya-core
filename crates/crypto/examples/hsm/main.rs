//! This examples demonstrates implementing an [`Engine`] backed
//! by an HSM.

use core::fmt;
use std::vec::Vec;

use buggy::{bug, Bug};
use crypto::{
    aead::{Aead, OpenError},
    csprng::Csprng,
    ed25519::{self, Ed25519},
    engine::{self, AlgId, RawSecret, RawSecretWrap, UnwrappedKey, WrongKeyType},
    import::{ExportError, Import, ImportError},
    kdf::{Kdf, Prk},
    kem::Kem,
    keys::{PublicKey, SecretKey, SecretKeyBytes},
    mac::Mac,
    rust,
    signer::{Signature, Signer, SignerError, SignerId, SigningKey, VerifyingKey},
    subtle::{Choice, ConstantTimeEq},
    zeroize::ZeroizeOnDrop,
    CipherSuite, Engine, Id, Identified, Rng, UnwrapError, WrapError,
};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};

mod hsm;

use hsm::{Hsm, HsmError, KeyId};

// Ignore this.
#[cfg(feature = "moonshot")]
#[no_mangle]
unsafe extern "C" fn OS_hardware_rand() -> u32 {
    use ::rand::RngCore;
    ::rand::rngs::OsRng.next_u32()
}

/// An HSM-backed [`Engine`].
pub struct HsmEngine(());

impl HsmEngine {
    /// Creates a new [`HsmEngine`].
    pub fn new() -> Self {
        Self(())
    }
}

impl Default for HsmEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Csprng for HsmEngine {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        Rng.fill_bytes(dst)
    }
}

impl CipherSuite for HsmEngine {
    type Aead = rust::Aes256Gcm;
    type Hash = rust::Sha512;
    type Kdf = rust::HkdfSha512;
    type Kem = rust::DhKemP256HkdfSha256;
    type Mac = rust::HmacSha512;

    // Signature creation and verification is performed inside of
    // the HSM.
    type Signer = HsmSigner;
}

impl Engine for HsmEngine {
    const ID: Id = Id::default();

    type WrappedKey = WrappedKey;
}

impl RawSecretWrap<Self> for HsmEngine {
    fn wrap_secret<T>(
        &mut self,
        id: &<T as Identified>::Id,
        secret: RawSecret<Self>,
    ) -> Result<<Self as Engine>::WrappedKey, WrapError>
    where
        T: UnwrappedKey<Self>,
    {
        let id = (*id).into();
        let alg_id = secret.alg_id();
        let plaintext: RawSecretBytes<Self> = match secret {
            RawSecret::Aead(sk) => RawSecretBytes::Aead(sk.try_export_secret()?),
            RawSecret::Decap(sk) => RawSecretBytes::Decap(sk.try_export_secret()?),
            RawSecret::Mac(sk) => RawSecretBytes::Mac(sk.try_export_secret()?),
            RawSecret::Prk(sk) => RawSecretBytes::Prk(sk),
            RawSecret::Seed(sk) => RawSecretBytes::Seed(sk),
            // Signing keys are stored inside the HSM.
            RawSecret::Signing(sk) => return Ok(WrappedKey::internal(sk.0)),
        };
        let ciphertext =
            Hsm::read().wrap_key(&id.to_string(), plaintext.as_bytes(), alg_id.name())?;
        Ok(WrappedKey::external(id, ciphertext))
    }

    fn unwrap_secret<T>(
        &self,
        key: &<Self as Engine>::WrappedKey,
    ) -> Result<RawSecret<Self>, UnwrapError>
    where
        T: UnwrappedKey<Self>,
    {
        let secret = match (T::ID, &key.0) {
            // Signing keys are stored inside the HSM.
            (AlgId::Signing(_), WrappedKeyImpl::Internal { id }) => {
                RawSecret::Signing(HsmSigningKey(*id))
            }
            // Every other key is stored outside of the HSM.
            (alg_id, WrappedKeyImpl::External { id, ciphertext }) => {
                let plaintext =
                    Hsm::read().unwrap_key(&id.to_string(), ciphertext, alg_id.name())?;
                match alg_id {
                    AlgId::Aead(_) => RawSecret::Aead(Import::<_>::import(plaintext.as_slice())?),
                    AlgId::Decap(_) => RawSecret::Decap(Import::<_>::import(plaintext.as_slice())?),
                    AlgId::Mac(_) => RawSecret::Mac(Import::<_>::import(plaintext.as_slice())?),
                    AlgId::Prk(_) => RawSecret::Prk(Prk::new(SecretKeyBytes::new(
                        Import::<_>::import(plaintext.as_slice())?,
                    ))),
                    AlgId::Seed(_) => RawSecret::Seed(Import::<_>::import(plaintext.as_slice())?),
                    AlgId::Signing(_) => {
                        bug!("`AlgId::Signing(_)` is already covered one case up");
                    }
                }
            }
            (alg_id, _) => {
                return Err(WrongKeyType {
                    got: "External",
                    expected: alg_id.name(),
                }
                .into())
            }
        };
        Ok(secret)
    }
}

/// Simplifies the code inside [`HsmEngine::unwrap`].
///
/// See [`RawSecret`].
enum RawSecretBytes<E: Engine + ?Sized> {
    Aead(SecretKeyBytes<<<E::Aead as Aead>::Key as SecretKey>::Size>),
    Decap(SecretKeyBytes<<<E::Kem as Kem>::DecapKey as SecretKey>::Size>),
    Mac(SecretKeyBytes<<<E::Mac as Mac>::Key as SecretKey>::Size>),
    Prk(Prk<<E::Kdf as Kdf>::PrkSize>),
    Seed([u8; 64]),
    // Signing is not needed since it's stored inside the HSM.
}

impl<E: Engine + ?Sized> RawSecretBytes<E> {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Aead(v) => v.as_bytes(),
            Self::Decap(v) => v.as_bytes(),
            Self::Mac(v) => v.as_bytes(),
            Self::Prk(v) => v.as_bytes(),
            Self::Seed(v) => &v[..],
        }
    }
}

impl From<HsmError> for WrapError {
    fn from(err: HsmError) -> WrapError {
        match err {
            HsmError::Bug(err) => WrapError::Bug(err),
            _ => WrapError::Bug(Bug::new("non-wrap error")),
        }
    }
}

impl From<HsmError> for UnwrapError {
    fn from(err: HsmError) -> UnwrapError {
        match err {
            HsmError::Bug(err) => UnwrapError::Bug(err),
            HsmError::Authentication => UnwrapError::Open(OpenError::Authentication),
            _ => UnwrapError::Bug(Bug::new("non-unwrap error")),
        }
    }
}

/// A key wrapped by [`HsmEngine`].
#[derive(Clone, Serialize, Deserialize)]
pub struct WrappedKey(WrappedKeyImpl);

impl WrappedKey {
    const fn internal(id: KeyId) -> Self {
        Self(WrappedKeyImpl::Internal { id })
    }

    const fn external(id: Id, ciphertext: Vec<u8>) -> Self {
        Self(WrappedKeyImpl::External { id, ciphertext })
    }
}

impl engine::WrappedKey for WrappedKey {}

impl Identified for WrappedKey {
    type Id = WrappedKeyId;

    fn id(&self) -> Self::Id {
        WrappedKeyId(self.0.id())
    }
}

#[derive(Clone, Serialize, Deserialize)]
enum WrappedKeyImpl {
    /// Stored inside the HSM.
    Internal { id: KeyId },
    /// Encrypted secret key bytes.
    External { id: Id, ciphertext: Vec<u8> },
}

impl WrappedKeyImpl {
    fn id(&self) -> KeyIdImpl {
        match self {
            Self::Internal { id } => KeyIdImpl::Internal(*id),
            Self::External { id, .. } => KeyIdImpl::External(*id),
        }
    }
}

/// Uniquely identifies a [`WrappedKey`].
#[derive(
    Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, MaxSize,
)]
pub struct WrappedKeyId(KeyIdImpl);

impl fmt::Display for WrappedKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.into_id())
    }
}

impl From<WrappedKeyId> for Id {
    #[inline]
    fn from(id: WrappedKeyId) -> Self {
        id.0.into_id()
    }
}

#[derive(
    Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, MaxSize,
)]
enum KeyIdImpl {
    Internal(KeyId),
    External(Id),
}

impl KeyIdImpl {
    fn into_id(self) -> Id {
        match self {
            Self::Internal(id) => id.into(),
            Self::External(id) => id,
        }
    }
}

impl From<HsmError> for SignerError {
    fn from(err: HsmError) -> SignerError {
        match err {
            HsmError::NotFound(_) => SignerError::Other("key not found"),
            HsmError::WrongKeyType => SignerError::Other("wrong key type"),
            HsmError::Bug(err) => SignerError::Bug(err),
            _ => SignerError::Bug(Bug::new("non-signer error")),
        }
    }
}

/// An HSM-backed [`Signer`].
pub struct HsmSigner;

impl Signer for HsmSigner {
    const ID: SignerId = <Ed25519 as Signer>::ID;

    type SigningKey = HsmSigningKey;
    type VerifyingKey = HsmVerifyingKey;
    type Signature = HsmSignature;
}

/// An HSM-backed [`SigningKey`].
#[derive(Clone)]
pub struct HsmSigningKey(
    // The actual key is stored inside the HSM, so we refer to
    // it by its ID.
    KeyId,
);

impl SigningKey<HsmSigner> for HsmSigningKey {
    fn sign(&self, msg: &[u8]) -> Result<HsmSignature, SignerError> {
        let sig = Hsm::read().signing_key(self.0, |sk| sk.sign(msg))??;
        Ok(HsmSignature(sig))
    }

    fn public(&self) -> HsmVerifyingKey {
        HsmVerifyingKey(self.0)
    }
}

impl SecretKey for HsmSigningKey {
    type Size = <ed25519::SigningKey as SecretKey>::Size;

    fn new<R: Csprng>(_rng: &mut R) -> Self {
        let key_id = Hsm::write().new_signing_key();
        Self(key_id)
    }

    #[inline]
    fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
        Err(ExportError::Opaque)
    }
}

impl ConstantTimeEq for HsmSigningKey {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(&self.0, &other.0)
    }
}

impl<'a> Import<&'a [u8]> for HsmSigningKey {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        let key_id = Hsm::write().import_signing_key(data)?;
        Ok(Self(key_id))
    }
}

impl ZeroizeOnDrop for HsmSigningKey {
    // `HsmSigningKey` does not contain any secret data.
}

/// A [`VerifyingKey`] that uses the default trait methods.
#[derive(Clone, Debug)]
pub struct HsmVerifyingKey(
    // The actual key is stored inside the HSM, so we refer to
    // it by its ID.
    KeyId,
);

impl VerifyingKey<HsmSigner> for HsmVerifyingKey {
    fn verify(&self, msg: &[u8], sig: &HsmSignature) -> Result<(), SignerError> {
        Hsm::read().verifying_key(self.0, |pk| pk.verify(msg, &sig.0))??;
        Ok(())
    }
}

impl PublicKey for HsmVerifyingKey {
    type Data = <ed25519::VerifyingKey as PublicKey>::Data;

    fn export(&self) -> Self::Data {
        Hsm::read()
            .verifying_key(self.0, |pk| pk.export())
            .expect("see issues/519")
    }
}

impl<'a> Import<&'a [u8]> for HsmVerifyingKey {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        let key_id = Hsm::write().import_verifying_key(data)?;
        Ok(Self(key_id))
    }
}

impl Eq for HsmVerifyingKey {}
impl PartialEq for HsmVerifyingKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(&self.0, &other.0)
    }
}

/// A signature produced by [`HsmSigningKey`].
#[derive(Clone, Debug)]
pub struct HsmSignature(ed25519::Signature);

impl Signature<HsmSigner> for HsmSignature {
    type Data = <ed25519::Signature as Signature<Ed25519>>::Data;

    fn export(&self) -> Self::Data {
        self.0.export()
    }
}

impl<'a> Import<&'a [u8]> for HsmSignature {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        Ok(Self(ed25519::Signature::import(data)?))
    }
}

// It's always important to test your `Engine` implementations
// against our test suite.
#[cfg(test)]
#[allow(clippy::wildcard_imports)]
mod test {
    use crypto::{test_engine, test_util::test_ciphersuite};

    use super::*;

    test_engine!(hsm_engine, || -> HsmEngine { HsmEngine::new() });
    test_ciphersuite!(hsm_ciphersuite, HsmEngine);
}