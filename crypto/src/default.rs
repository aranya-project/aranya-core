#![forbid(unsafe_code)]

use cfg_if::cfg_if;

use crate::{ciphersuite::CipherSuite, csprng::Csprng};

/// The default CSPRNG.
///
/// By default, `Rng` uses [`getrandom`] which uses
/// a system-specific CSPRNG. If `getrandom` does not support the
/// current target, it can be overridden with
/// [`register_custom_getrandom`][crate::csprng::getrandom::register_custom_getrandom].
///
/// Certain feature flags will change the default CSPRNG:
///
/// - `moonshot`: Uses a CSPRNG specific to Project Moonshot.
/// - `std`: Uses a thread-local CSPRNG.
/// - `boringssl`: Uses BoringSSL's CSPRNG.
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
pub struct Rng;

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

impl Rng {
    /// Creates a default CSPRNG.
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
                rand::thread_rng().fill_bytes(dst)
            } else if #[cfg(feature = "boringssl")] {
                crate::boring::Rand.fill_bytes(dst)
            } else {
                getrandom::getrandom(dst).expect("should not fail")
            }
        }
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

#[cfg(feature = "alloc")]
#[cfg_attr(docs, doc(cfg(feature = "alloc")))]
mod default_engine {
    extern crate alloc;

    #[allow(clippy::wildcard_imports)]
    use {
        crate::{
            aead::{Aead, AeadError},
            ciphersuite::CipherSuite,
            csprng::Csprng,
            engine::{
                Engine, KeyType, SecretData, UnwrapError, UnwrappedKey, WrapError, WrappedKey,
            },
            id::Id,
            import::Import,
            keys::SecretKey,
            zeroize::Zeroizing,
            DefaultCipherSuite,
        },
        alloc::{vec, vec::Vec},
        serde::{Deserialize, Serialize},
    };

    impl KeyType {
        fn to_vec(self) -> heapless::Vec<u8, 4> {
            // All of the "*Id" types are `u16`, which is at most
            // three bytes on the wire. Since `KeyType` is an
            // enum it's prefixed with a `u32`, which is at most
            // five bytes on the wire. However, we only have
            // ~five variants, so we know that the `u32` encodes
            // as a single byte on the wire. Being exact makes it
            // more likely that we catch bugs in our tests.
            //
            // Ideally, we'd just use something like Postcard's
            // experimental `MaxSize` feature. But when we used
            // that feature with APS it prevented us from
            // building a `no_std` staticlib. So, perhaps try it
            // in the future.
            postcard::to_vec(&self).expect("bug: should not fail")
        }
    }

    /// A basic [`Engine`] implementation that wraps keys with its
    /// [`Aead`].
    ///
    /// # Notes
    ///
    /// It's mostly useful for tests as its [`Engine::ID`] constant
    /// is all zeros and the user must store the root encryption key
    /// somewhere.
    pub struct DefaultEngine<R: Csprng, S: CipherSuite = DefaultCipherSuite> {
        aead: S::Aead,
        rng: R,
    }

    impl<R: Csprng, S: CipherSuite> DefaultEngine<R, S> {
        const NONCE_SIZE: usize = S::Aead::NONCE_SIZE;
        const OVERHEAD: usize = Self::NONCE_SIZE + S::Aead::OVERHEAD;

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

    impl<R: Csprng, S: CipherSuite> Engine for DefaultEngine<R, S> {
        const ID: Id = Id::default();

        type WrappedKey = DefaultWrappedKey;

        fn wrap<T>(&mut self, key: T) -> Result<Self::WrappedKey, WrapError>
        where
            T: Into<UnwrappedKey<Self>>,
        {
            let key = key.into();
            let secret = SecretData::from_unwrapped(&key)?;
            let kt = key.id();

            // TODO(eric): if we pre-allocate `plaintext` we can
            // encrypt in-place and avoid creating a second buffer.
            let mut dst = vec![0u8; secret.as_ref().len() + Self::OVERHEAD];
            let (nonce, out) = dst.split_at_mut(Self::NONCE_SIZE);
            self.rng.fill_bytes(nonce);
            self.aead
                .seal(out, nonce, secret.as_ref(), kt.to_vec().as_slice())?;

            Ok(DefaultWrappedKey::new(kt, dst))
        }

        fn unwrap(&self, key: &Self::WrappedKey) -> Result<UnwrappedKey<Self>, UnwrapError> {
            let DefaultWrappedKey { kt, ciphertext } = key;

            if ciphertext.len() < Self::OVERHEAD {
                // Cannot authenticate the wrapped key if it clearly
                // does not contain both the nonce and tag.
                return Err(UnwrapError::Aead(AeadError::Authentication));
            }
            let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len() - Self::OVERHEAD]);
            let (nonce, ciphertext) = ciphertext.split_at(Self::NONCE_SIZE);
            self.aead
                .open(&mut plaintext, nonce, ciphertext, kt.to_vec().as_slice())?;

            Ok(UnwrappedKey::import((*kt, &plaintext))?)
        }
    }

    /// The default implementation of [`WrappedKey`].
    #[derive(Serialize, Deserialize, Debug)]
    pub struct DefaultWrappedKey {
        /// The type of the wrapped key.
        pub kt: KeyType,
        /// The encrypted, authenticated secret.
        pub ciphertext: Vec<u8>,
    }

    impl DefaultWrappedKey {
        /// Creates a wrapped key.
        pub fn new(kt: KeyType, ciphertext: Vec<u8>) -> Self {
            Self { kt, ciphertext }
        }
    }

    impl WrappedKey for DefaultWrappedKey {
        type Output = Vec<u8>;
        type Error = postcard::Error;

        fn id(&self) -> KeyType {
            self.kt
        }

        fn encode(&self) -> Result<Self::Output, Self::Error> {
            postcard::to_allocvec(self)
        }

        fn decode(data: &[u8]) -> Result<Self, Self::Error> {
            postcard::from_bytes(data)
        }
    }

    #[cfg(test)]
    mod test {
        use crate::{test_engine, DefaultCipherSuite, DefaultEngine, Rng};

        test_engine!(
            default_engine,
            || -> DefaultEngine<Rng, DefaultCipherSuite> {
                let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
                eng
            }
        );
    }
}
#[cfg(feature = "alloc")]
pub use default_engine::*;

#[cfg(test)]
#[allow(clippy::wildcard_imports)]
mod test {
    use super::*;
    use crate::test_util::test_ciphersuite;

    test_ciphersuite!(default_ciphersuite, DefaultCipherSuite);
}
