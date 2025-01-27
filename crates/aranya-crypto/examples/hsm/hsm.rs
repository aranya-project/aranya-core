#![allow(clippy::arithmetic_side_effects)]

use std::{
    collections::btree_map::{BTreeMap, Entry},
    sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use aranya_crypto::{
    aead::{Aead, Nonce},
    csprng::Random,
    custom_id,
    ed25519::{SigningKey, VerifyingKey},
    hash::tuple_hash,
    import::{Import, ImportError},
    keys::{PublicKey, SecretKey},
    rust::{Aes256Gcm, Sha512},
    signer::PkError,
    Rng,
};
use buggy::{Bug, BugExt};
use serde::{Deserialize, Serialize};

/// An error returned by [`Hsm`].
#[derive(Debug, thiserror::Error)]
pub enum HsmError {
    /// Unable to authenticate the wrapped key.
    #[error("unable to authenticate")]
    Authentication,
    /// The key was not found.
    #[error("key not found: {0}")]
    NotFound(KeyId),
    /// Wrong key type.
    #[error("wrong key type")]
    WrongKeyType,
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
    /// The Public Key is invalid.
    #[error(transparent)]
    PkError(#[from] PkError),
}

/// A pretend hardware security module.
pub(crate) struct Hsm {
    /// Used for key wrapping.
    aead: Aes256Gcm,
    /// All keys stored in the HSM.
    keys: BTreeMap<KeyId, HsmKey>,
}

impl Hsm {
    /// Returns a connection to the HSM.
    fn get() -> &'static RwLock<Hsm> {
        static HSM: OnceLock<RwLock<Hsm>> = OnceLock::new();
        HSM.get_or_init(|| {
            RwLock::new(Self {
                aead: Aes256Gcm::new(&Random::random(&mut Rng)),
                keys: Default::default(),
            })
        })
    }

    /// Returns a read-only connection to the HSM.
    pub fn read() -> RwLockReadGuard<'static, Hsm> {
        Self::get().read().expect("poisoned")
    }

    /// Returns a read-write connection to the HSM.
    pub fn write() -> RwLockWriteGuard<'static, Hsm> {
        Self::get().write().expect("poisoned")
    }
}

// Key wrapping impl.
impl Hsm {
    /// Encrypts and authenticates the `key` identified by
    /// `alias`.
    pub fn wrap_key(&self, alias: &str, key: &[u8], context: &str) -> Result<Vec<u8>, HsmError> {
        // The dst buffer passed to `Aead::seal` should be at
        // least as long as the input, plus the `Aead`'s
        // overhead (auth tag, etc).
        let mut ciphertext = vec![0u8; key.len() + <Aes256Gcm as Aead>::OVERHEAD];

        // A random nonce is fine for this example. In practice,
        // you would probably want to ensure that you never
        // repeat nonces.
        let nonce = Nonce::<_>::random(&mut Rng);

        // Bind the ciphertext to the (alias, context) tuple.
        let ad = postcard::to_allocvec(&AuthData { alias, context })
            .assume("should be able to encode `AuthData`")?;

        self.aead
            .seal(&mut ciphertext, &nonce, key, &ad)
            .assume("`Aes256Gcm::seal` should never fail")?;

        let wrapped = postcard::to_allocvec(&WrappedKey {
            nonce,
            ciphertext: &ciphertext,
        })
        .assume("should be able to encode `WrappedKey`")?;
        Ok(wrapped)
    }

    /// Decrypts and authenticates the `key` identified by
    /// `alias`.
    pub fn unwrap_key(
        &self,
        alias: &str,
        wrapped: &[u8],
        context: &str,
    ) -> Result<Vec<u8>, HsmError> {
        let WrappedKey { nonce, ciphertext } =
            postcard::from_bytes(wrapped).map_err(|_| HsmError::Authentication)?;

        // The ciphertext is bound to the (alias, context) tuple.
        let ad = postcard::to_allocvec(&AuthData { alias, context })
            .assume("should be able to encode `AuthData`")?;

        // The dst buffer passed to `Aead::open` should be at
        // least as long as the input less the `Aead`'s overhead
        // (auth tag, etc).
        let mut plaintext = vec![0u8; ciphertext.len() - <Aes256Gcm as Aead>::OVERHEAD];

        self.aead
            .open(&mut plaintext, &nonce, ciphertext, &ad)
            .map_err(|_| HsmError::Authentication)?;

        Ok(plaintext)
    }
}

/// The structure of a key wrapped by the HSM.
#[derive(Serialize, Deserialize)]
struct WrappedKey<'a> {
    nonce: Nonce<<Aes256Gcm as Aead>::NonceSize>,
    #[serde(borrow)]
    ciphertext: &'a [u8],
}

/// The structure of the additional authenticated data used when
/// wrapping keys.
#[derive(Serialize, Deserialize)]
struct AuthData<'a> {
    #[serde(borrow)]
    alias: &'a str,
    #[serde(borrow)]
    context: &'a str,
}

// Signer impl.
impl Hsm {
    fn signer_key_id(pk: &VerifyingKey) -> KeyId {
        let id = tuple_hash::<Sha512, _>(["HSM-v1".as_bytes(), "Ed25519".as_bytes(), &pk.export()])
            .into_array()
            .into();
        KeyId(id)
    }

    /// Creates a new `SigningKey`.
    pub fn new_signing_key(&mut self) -> KeyId {
        let sk = SigningKey::new(&mut Rng);
        let id = Self::signer_key_id(&SigningKey::public(&sk));
        self.keys.insert(id, HsmKey::Signing(sk));
        id
    }

    /// Imports a `SigningKey`.
    pub fn import_signing_key(&mut self, data: &[u8]) -> Result<KeyId, ImportError> {
        let sk = SigningKey::import(data)?;
        let id = Self::signer_key_id(&SigningKey::public(&sk));
        self.keys.insert(id, HsmKey::Signing(sk));
        Ok(id)
    }

    /// Imports a `VerifyingKey`.
    pub fn import_verifying_key(&mut self, data: &[u8]) -> Result<KeyId, ImportError> {
        let pk = VerifyingKey::import(data)?;
        let id = Self::signer_key_id(&pk);
        if let Entry::Vacant(v) = self.keys.entry(id) {
            v.insert(HsmKey::Verifying(pk));
        }
        Ok(id)
    }

    /// Invokes `f` with a `SigningKey`.
    pub fn signing_key<F, R>(&self, id: KeyId, f: F) -> Result<R, HsmError>
    where
        F: FnOnce(&SigningKey) -> R,
    {
        match self.load_key(id)? {
            HsmKey::Signing(ref sk) => Ok(f(sk)),
            _ => Err(HsmError::WrongKeyType),
        }
    }

    /// Invokes `f` with a `VerifyingKey`.
    pub fn verifying_key<F, R>(&self, id: KeyId, f: F) -> Result<R, HsmError>
    where
        F: FnOnce(&VerifyingKey) -> R,
    {
        match self.load_key(id)? {
            HsmKey::Signing(sk) => Ok(f(&SigningKey::public(sk))),
            HsmKey::Verifying(pk) => Ok(f(pk)),
        }
    }

    fn load_key(&self, id: KeyId) -> Result<&HsmKey, HsmError> {
        self.keys.get(&id).ok_or(HsmError::NotFound(id))
    }
}

enum HsmKey {
    Signing(SigningKey),
    Verifying(VerifyingKey),
}

custom_id! {
    /// Uniquely identifies an HSM key
    pub struct KeyId;
}
