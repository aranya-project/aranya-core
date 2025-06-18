//! Default implementations.

use serde::{Deserialize, Serialize};
pub use spideroak_crypto::default::Rng;
use spideroak_crypto::{
    aead::{Aead, Nonce, Tag},
    csprng::{Csprng, Random},
    ed25519,
    generic_array::GenericArray,
    import::Import,
    kdf::{Kdf, Prk},
    kem::Kem,
    keys::{SecretKey, SecretKeyBytes},
    mac::Mac,
    oid::Identified as _,
    rust,
    signer::Signer,
    typenum::U64,
};

use crate::{
    ciphersuite::{CipherSuite, CipherSuiteExt},
    engine::{
        self, AlgId, Engine, RawSecret, RawSecretWrap, UnwrapError, UnwrappedKey, WrapError,
        WrongKeyType,
    },
    id::{Id, IdError, Identified},
};

/// The default [`CipherSuite`].
///
/// It uses the following algorithms:
///
/// - AEAD: AES-256-GCM
/// - Hash: SHA-512
/// - KDF: HKDF-SHA-512
/// - KEM: DH-KEM(P-256, HKDF-SHA-256)
/// - MAC: HMAC-SHA-512
/// - Signatures: Ed25519
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type Aead = rust::Aes256Gcm;
    type Hash = rust::Sha256;
    type Kdf = rust::HkdfSha512;
    #[cfg_attr(test, allow(unused_qualifications))]
    type Kem = __private::DhKemP256HkdfSha256;
    type Mac = rust::HmacSha512;
    type Signer = ed25519::Ed25519;
}

// Keep the raw Kem newtype out of the public API surface.
mod __private {
    use spideroak_crypto::{oid::consts::DHKEM_P256_HKDF_SHA256, rust};

    crate::kem_with_oid! {
        /// DHKEM(P256, HKDF-SHA256).
        #[derive(Debug)]
        pub struct DhKemP256HkdfSha256(rust::DhKemP256HkdfSha256) => DHKEM_P256_HKDF_SHA256
    }
}

// Expose the newtype for crate-local tests, but keep it hidden externally.
#[cfg(test)]
pub use __private::DhKemP256HkdfSha256;

/// A basic [`Engine`] implementation that wraps keys with its [`Aead`].
pub struct DefaultEngine<R: Csprng = Rng, S: CipherSuite = DefaultCipherSuite> {
    aead: S::Aead,
    rng: R,
}

impl<S: CipherSuite> Clone for DefaultEngine<Rng, S>
where
    S::Aead: Clone,
{
    fn clone(&self) -> Self {
        Self {
            aead: self.aead.clone(),
            rng: Rng,
        }
    }
}

impl<R: Csprng, S: CipherSuite> DefaultEngine<R, S> {
    /// Creates an [`Engine`] using `key`.
    pub fn new(key: &<S::Aead as Aead>::Key, rng: R) -> Self {
        Self {
            aead: S::Aead::new(key),
            rng,
        }
    }

    /// Creates an [`Engine`] using entropy from `rng` and
    /// returns it and the generated key.
    pub fn from_entropy(mut rng: R) -> (Self, <S::Aead as Aead>::Key) {
        let key = <S::Aead as Aead>::Key::random(&mut rng);
        let eng = Self::new(&key, rng);
        (eng, key)
    }
}

impl<R: Csprng, S: CipherSuite> Csprng for DefaultEngine<R, S> {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.rng.fill_bytes(dst)
    }
}

impl<R: Csprng, S: CipherSuite> Engine for DefaultEngine<R, S> {
    type CS = S;

    type WrappedKey = WrappedKey<S>;
}

impl<R: Csprng, S: CipherSuite> RawSecretWrap<Self> for DefaultEngine<R, S> {
    fn wrap_secret<T>(
        &mut self,
        id: &<T as Identified>::Id,
        secret: RawSecret<S>,
    ) -> Result<<Self as Engine>::WrappedKey, WrapError>
    where
        T: UnwrappedKey<S>,
    {
        let id = (*id).into();
        let mut tag = Tag::<S::Aead>::default();
        // TODO(eric): we should probably ensure that we do not
        // repeat nonces.
        let nonce = Nonce::<_>::random(&mut self.rng);

        let ad = S::tuple_hash(b"DefaultEngine", [T::ID.as_bytes(), id.as_bytes()]);

        let mut secret = match secret {
            RawSecret::Aead(sk) => Ciphertext::Aead(sk.try_export_secret()?.into_bytes()),
            RawSecret::Decap(sk) => Ciphertext::Decap(sk.try_export_secret()?.into_bytes()),
            RawSecret::Mac(sk) => Ciphertext::Mac(sk.try_export_secret()?.into_bytes()),
            RawSecret::Prk(sk) => Ciphertext::Prk(sk.into_bytes().into_bytes()),
            RawSecret::Seed(sk) => Ciphertext::Seed(sk.into()),
            RawSecret::Signing(sk) => Ciphertext::Signing(sk.try_export_secret()?.into_bytes()),
        };
        self.aead.seal_in_place(
            nonce.as_ref(),
            secret.as_bytes_mut(),
            &mut tag,
            ad.as_bytes(),
        )?;
        // `secret` is now encrypted.

        Ok(WrappedKey {
            id,
            nonce: nonce.into_inner(),
            ciphertext: secret,
            tag,
        })
    }

    fn unwrap_secret<T>(
        &self,
        key: &<Self as Engine>::WrappedKey,
    ) -> Result<RawSecret<S>, UnwrapError>
    where
        T: UnwrappedKey<S>,
    {
        let mut data = key.ciphertext.clone();
        let ad = S::tuple_hash(b"DefaultEngine", [T::ID.as_bytes(), key.id.as_bytes()]);

        self.aead.open_in_place(
            key.nonce.as_ref(),
            data.as_bytes_mut(),
            &key.tag,
            ad.as_bytes(),
        )?;
        // `data` has now been decrypted

        let secret = match (T::ID, &data) {
            (AlgId::Aead(_), Ciphertext::Aead(data)) => {
                RawSecret::Aead(Import::<_>::import(data.as_slice())?)
            }
            (AlgId::Decap(_), Ciphertext::Decap(data)) => {
                RawSecret::Decap(Import::<_>::import(data.as_slice())?)
            }
            (AlgId::Mac(_), Ciphertext::Mac(data)) => {
                RawSecret::Mac(Import::<_>::import(data.as_slice())?)
            }
            (AlgId::Prk(_), Ciphertext::Prk(data)) => {
                RawSecret::Prk(Prk::new(SecretKeyBytes::new(data.clone())))
            }
            (AlgId::Seed(_), Ciphertext::Seed(data)) => {
                RawSecret::Seed(Import::<_>::import(data.as_slice())?)
            }
            (AlgId::Signing(_), Ciphertext::Signing(data)) => {
                RawSecret::Signing(Import::<_>::import(data.as_slice())?)
            }
            _ => {
                return Err(WrongKeyType {
                    got: data.name(),
                    expected: T::ID.name(),
                }
                .into())
            }
        };
        Ok(secret)
    }
}

/// Encrypted [`RawSecret`] bytes.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
enum Ciphertext<CS: CipherSuite> {
    Aead(GenericArray<u8, <<CS::Aead as Aead>::Key as SecretKey>::Size>),
    Decap(GenericArray<u8, <<CS::Kem as Kem>::DecapKey as SecretKey>::Size>),
    Mac(GenericArray<u8, <<CS::Mac as Mac>::Key as SecretKey>::Size>),
    Prk(GenericArray<u8, <CS::Kdf as Kdf>::PrkSize>),
    // NB: not `[u8; 64]` because serde only supports arrays up
    // to 32 elements without additional gymnastics.
    Seed(GenericArray<u8, U64>),
    Signing(GenericArray<u8, <<CS::Signer as Signer>::SigningKey as SecretKey>::Size>),
}

impl<CS: CipherSuite> Ciphertext<CS> {
    const fn name(&self) -> &'static str {
        self.alg_id().name()
    }

    const fn alg_id(&self) -> AlgId {
        match self {
            Self::Aead(_) => AlgId::Aead(CS::Aead::OID),
            Self::Decap(_) => AlgId::Decap(CS::Kem::OID),
            Self::Mac(_) => AlgId::Mac(CS::Mac::OID),
            Self::Prk(_) => AlgId::Prk(CS::Kdf::OID),
            Self::Seed(_) => AlgId::Seed(()),
            Self::Signing(_) => AlgId::Signing(CS::Signer::OID),
        }
    }
}

impl<CS: CipherSuite> Clone for Ciphertext<CS> {
    fn clone(&self) -> Self {
        match self {
            Self::Aead(v) => Self::Aead(v.clone()),
            Self::Decap(v) => Self::Decap(v.clone()),
            Self::Mac(v) => Self::Mac(v.clone()),
            Self::Prk(v) => Self::Prk(v.clone()),
            Self::Seed(v) => Self::Seed(*v),
            Self::Signing(v) => Self::Signing(v.clone()),
        }
    }
}

impl<CS: CipherSuite> Ciphertext<CS> {
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Aead(v) => v.as_mut_slice(),
            Self::Decap(v) => v.as_mut_slice(),
            Self::Mac(v) => v.as_mut_slice(),
            Self::Prk(v) => v.as_mut_slice(),
            Self::Seed(v) => v.as_mut_slice(),
            Self::Signing(v) => v.as_mut_slice(),
        }
    }
}

/// A key wrapped by [`DefaultEngine`].
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct WrappedKey<CS: CipherSuite> {
    id: Id,
    nonce: GenericArray<u8, <CS::Aead as Aead>::NonceSize>,
    ciphertext: Ciphertext<CS>,
    tag: Tag<CS::Aead>,
}

impl<CS: CipherSuite> Clone for WrappedKey<CS> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
            tag: self.tag.clone(),
        }
    }
}

impl<CS: CipherSuite> engine::WrappedKey for WrappedKey<CS> {}

impl<CS: CipherSuite> Identified for WrappedKey<CS> {
    type Id = Id;

    fn id(&self) -> Result<Self::Id, IdError> {
        Ok(self.id)
    }
}

#[cfg(test)]
#[allow(clippy::wildcard_imports)]
mod test {
    use super::*;
    use crate::{test_engine, test_util::test_ciphersuite, Rng};

    test_engine!(
        default_engine,
        || -> DefaultEngine<Rng, DefaultCipherSuite> {
            let (eng, _) = DefaultEngine::<Rng>::from_entropy(Rng);
            eng
        }
    );

    test_ciphersuite!(default_ciphersuite, DefaultCipherSuite);
}
