//! Default implementations.

use buggy::BugExt;
use cfg_if::cfg_if;
use generic_array::GenericArray;
use postcard::experimental::max_size::MaxSize;
#[cfg(feature = "rand_core")]
use rand_core::{impls, CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use typenum::U64;

use crate::{
    aead::{Aead, Nonce, Tag},
    ciphersuite::CipherSuite,
    csprng::{Csprng, Random},
    engine::{
        self, AlgId, Engine, RawSecret, RawSecretWrap, UnwrapError, UnwrappedKey, WrapError,
        WrongKeyType,
    },
    id::{Id, Identified},
    import::Import,
    kdf::{Kdf, Prk},
    kem::Kem,
    keys::{SecretKey, SecretKeyBytes},
    mac::Mac,
    signer::Signer,
};

/// The default CSPRNG.
///
/// Certain feature flags will change the default CSPRNG:
///
/// - `moonshot`: Uses a CSPRNG specific to Project Moonshot.
/// - `std`: Uses a thread-local CSPRNG seeded from the system
/// CSPRNG.
/// - `boringssl`: Uses BoringSSL's CSPRNG.
/// - `libc`: Uses the system CSPRNG.
///
/// The `libc` flag is enabled by default.
///
/// If all of those feature flags are disabled, `Rng` invokes the
/// following routine:
///
/// ```
/// extern "C" {
///     /// Reads `len` cryptographically secure bytes into
///     /// `dst`.
///     fn crypto_getrandom(dst: *mut u8, len: usize);
/// }
/// ```
///
/// In general, `Rng` should be used directly instead of being
/// created with [`Rng::new`]. For example:
///
/// ```
/// # use crypto::csprng::Csprng;
/// use crypto::Rng;
///
/// fn foo<R: Csprng>(_rng: &mut R) {}
///
/// foo(&mut Rng);
/// ```
#[derive(Copy, Clone, Debug, Default)]
pub struct Rng;

impl Rng {
    /// Creates a default CSPRNG.
    ///
    /// In general, `Rng` should be used directly instead of
    /// being created with this method.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl Csprng for Rng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        cfg_if! {
            if #[cfg(feature = "moonshot")] {
                crate::csprng::moonshot::thread_rng().fill_bytes(dst)
            } else if #[cfg(feature = "std")] {
                // Try to use `ThreadRng` if possible.
                RngCore::fill_bytes(&mut rand::thread_rng(), dst)
            } else if #[cfg(feature = "boringssl")] {
                crate::boring::Rand.fill_bytes(dst)
            } else if #[cfg(feature = "getrandom")] {
                getrandom::getrandom(dst).expect("should not fail")
            } else {
                extern "C" {
                    fn crypto_getrandom(dst: *mut u8, len: usize);
                }
                // SAFETY: FFI call, no invariants.
                unsafe {
                    crypto_getrandom(dst.as_mut_ptr(), dst.len())
                }
            }
        }
    }
}

#[cfg(feature = "rand_core")]
impl CryptoRng for Rng {}

#[cfg(feature = "rand_core")]
impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        Csprng::fill_bytes(self, dst)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        Csprng::fill_bytes(self, dst);
        Ok(())
    }
}

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
    type Aead = crate::rust::Aes256Gcm;
    type Hash = crate::rust::Sha512;
    type Kdf = crate::rust::HkdfSha512;
    type Kem = crate::rust::DhKemP256HkdfSha256;
    type Mac = crate::rust::HmacSha512;
    type Signer = crate::ed25519::Ed25519;
}

/// A basic [`Engine`] implementation that wraps keys with
/// its [`Aead`].
///
/// # Notes
///
/// It's mostly useful for tests as its [`Engine::ID`]
/// constant is all zeros and the user must store the root
/// encryption key somewhere.
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
        let key = <S::Aead as Aead>::Key::new(&mut rng);
        let eng = Self::new(&key, rng);
        (eng, key)
    }
}

impl<R: Csprng, S: CipherSuite> Csprng for DefaultEngine<R, S> {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.rng.fill_bytes(dst)
    }
}

impl<R: Csprng, S: CipherSuite> CipherSuite for DefaultEngine<R, S> {
    type Aead = S::Aead;
    type Hash = S::Hash;
    type Kdf = S::Kdf;
    type Kem = S::Kem;
    type Mac = S::Mac;
    type Signer = S::Signer;
}

/// Contextual binding for wrapped keys.
// TODO(eric): include a `purpose` field. The trick is that it
// has to be a fixed size so that we can use `heapless`.
#[derive(Serialize, MaxSize)]
struct AuthData {
    /// `Engine::Id`.
    eng_id: Id,
    /// `Unwrapped::ID`.
    alg_id: AlgId,
    /// `<Unwrapped as Identified>::id`.
    key_id: Id,
}

impl<R: Csprng, S: CipherSuite> Engine for DefaultEngine<R, S> {
    const ID: Id = Id::default();

    type WrappedKey = WrappedKey<Self>;
}

impl<R: Csprng, S: CipherSuite> RawSecretWrap<Self> for DefaultEngine<R, S> {
    fn wrap_secret<T>(
        &mut self,
        id: &<T as Identified>::Id,
        secret: RawSecret<Self>,
    ) -> Result<<Self as Engine>::WrappedKey, WrapError>
    where
        T: UnwrappedKey<Self>,
    {
        let id = (*id).into();
        let mut tag = Tag::<S::Aead>::default();
        // TODO(eric): we should probably ensure that we do not
        // repeat nonces.
        let nonce = Nonce::<_>::random(&mut self.rng);
        let ad = postcard::to_vec::<_, { AuthData::POSTCARD_MAX_SIZE }>(&AuthData {
            eng_id: Self::ID,
            alg_id: T::ID,
            key_id: id,
        })
        .assume("there should be enough space")?;

        let mut secret = match secret {
            RawSecret::Aead(sk) => Ciphertext::Aead(sk.try_export_secret()?.into_bytes()),
            RawSecret::Decap(sk) => Ciphertext::Decap(sk.try_export_secret()?.into_bytes()),
            RawSecret::Mac(sk) => Ciphertext::Mac(sk.try_export_secret()?.into_bytes()),
            RawSecret::Prk(sk) => Ciphertext::Prk(sk.into_bytes().into_bytes()),
            RawSecret::Seed(sk) => Ciphertext::Seed(sk.into()),
            RawSecret::Signing(sk) => Ciphertext::Signing(sk.try_export_secret()?.into_bytes()),
        };
        self.aead
            .seal_in_place(nonce.as_ref(), secret.as_bytes_mut(), &mut tag, &ad)?;
        // `secret` is now encrypted.

        Ok(WrappedKey {
            id,
            nonce,
            ciphertext: secret,
            tag,
        })
    }

    fn unwrap_secret<T>(
        &self,
        key: &<Self as Engine>::WrappedKey,
    ) -> Result<RawSecret<Self>, UnwrapError>
    where
        T: UnwrappedKey<Self>,
    {
        let mut data = key.ciphertext.clone();
        let ad = postcard::to_vec::<_, { AuthData::POSTCARD_MAX_SIZE }>(&AuthData {
            eng_id: Self::ID,
            alg_id: T::ID,
            key_id: key.id,
        })
        .assume("there should be enough space")?;

        self.aead
            .open_in_place(key.nonce.as_ref(), data.as_bytes_mut(), &key.tag, &ad)?;
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
enum Ciphertext<E: Engine + ?Sized> {
    Aead(GenericArray<u8, <<E::Aead as Aead>::Key as SecretKey>::Size>),
    Decap(GenericArray<u8, <<E::Kem as Kem>::DecapKey as SecretKey>::Size>),
    Mac(GenericArray<u8, <<E::Mac as Mac>::Key as SecretKey>::Size>),
    Prk(GenericArray<u8, <E::Kdf as Kdf>::PrkSize>),
    // NB: not `[u8; 64]` because serde only supports arrays up
    // to 32 elements without additional gymnastics.
    Seed(GenericArray<u8, U64>),
    Signing(GenericArray<u8, <<E::Signer as Signer>::SigningKey as SecretKey>::Size>),
}

impl<E: Engine + ?Sized> Ciphertext<E> {
    const fn name(&self) -> &'static str {
        self.alg_id().name()
    }

    const fn alg_id(&self) -> AlgId {
        match self {
            Self::Aead(_) => AlgId::Aead(<E::Aead as Aead>::ID),
            Self::Decap(_) => AlgId::Decap(<E::Kem as Kem>::ID),
            Self::Mac(_) => AlgId::Mac(<E::Mac as Mac>::ID),
            Self::Prk(_) => AlgId::Prk(<E::Kdf as Kdf>::ID),
            Self::Seed(_) => AlgId::Seed(()),
            Self::Signing(_) => AlgId::Signing(<E::Signer as Signer>::ID),
        }
    }
}

impl<E: Engine + ?Sized> Clone for Ciphertext<E> {
    fn clone(&self) -> Self {
        match self {
            Self::Aead(v) => Self::Aead(v.clone()),
            Self::Decap(v) => Self::Decap(v.clone()),
            Self::Mac(v) => Self::Mac(*v),
            Self::Prk(v) => Self::Prk(v.clone()),
            Self::Seed(v) => Self::Seed(*v),
            Self::Signing(v) => Self::Signing(v.clone()),
        }
    }
}

impl<E: Engine + ?Sized> Ciphertext<E> {
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
pub struct WrappedKey<E: Engine + ?Sized> {
    id: Id,
    nonce: Nonce<<E::Aead as Aead>::NonceSize>,
    ciphertext: Ciphertext<E>,
    tag: Tag<E::Aead>,
}

impl<E: Engine + ?Sized> Clone for WrappedKey<E> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
            tag: self.tag.clone(),
        }
    }
}

impl<E: Engine + ?Sized> engine::WrappedKey for WrappedKey<E> {}

impl<E: Engine + ?Sized> Identified for WrappedKey<E> {
    type Id = Id;

    fn id(&self) -> Self::Id {
        self.id
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
            let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
            eng
        }
    );

    test_ciphersuite!(default_ciphersuite, DefaultCipherSuite);
}
