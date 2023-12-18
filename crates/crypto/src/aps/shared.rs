use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    aead::{Aead, KeyData, Nonce, Tag},
    aranya::{Encap, EncryptionKey, EncryptionPublicKey},
    engine::Engine,
    error::Error,
    hpke::{Hpke, Mode},
    import::{ExportError, Import, ImportError},
    kem::Kem,
    keys::{SecretKey, SecretKeyBytes},
    util::Ciphertext,
};

/// A channel author's encapsulated secret.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub(super) struct AuthorEncap<E: Engine + ?Sized> {
    /// The encapsulation needed to decrypt `ciphertext`.
    encap: Encap<E>,
    /// The encrypted ephemeral key, `skE`.
    #[allow(clippy::type_complexity)]
    ciphertext: Ciphertext<
        GenericArray<u8, <<E::Kem as Kem>::DecapKey as SecretKey>::Size>,
        GenericArray<u8, <E::Aead as Aead>::Overhead>,
    >,
}

/// A channel peer's encapsulated secret.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct PeerEncap<E: Engine + ?Sized>(Encap<E>);

impl<E: Engine + ?Sized> PeerEncap<E> {
    /// Creates a peer's encapsulation deterministically using
    /// `ephemeral_sk`.
    pub fn new(
        author_sk: &EncryptionKey<E>,
        peer_pk: &EncryptionPublicKey<E>,
        info: &[u8],
        ephemeral_sk: EphemeralDecapKey<E>,
    ) -> Result<Self, Error> {
        let (encap, _) = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_send_deterministically(
            Mode::Auth(&author_sk.0),
            &peer_pk.0,
            info,
            // TODO(eric): should HPKE take a ref?
            ephemeral_sk.into_inner(),
        )?;
        Ok(Self(Encap(encap)))
    }

    /// Encodes itself as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns itself from its byte encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        Ok(Self(Encap::from_bytes(data)?))
    }

    pub fn as_inner(&self) -> &<E::Kem as Kem>::Encap {
        self.0.as_inner()
    }
}

/// An ephemeral decapsulation (secret) key.
pub(super) struct EphemeralDecapKey<E: Engine + ?Sized>(<E::Kem as Kem>::DecapKey);

impl<E: Engine + ?Sized> EphemeralDecapKey<E> {
    /// Creates a random ephemeral decapsulation key.
    pub fn new(eng: &mut E) -> Self {
        Self(<<E::Kem as Kem>::DecapKey as SecretKey>::new(eng))
    }

    /// Encrypts the ephemeral secret key to itself (`sk`).
    pub fn seal(
        self,
        eng: &mut E,
        sk: &EncryptionKey<E>,
        info: &[u8],
    ) -> Result<AuthorEncap<E>, Error> {
        let (encap, mut ctx) = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_send(
            eng,
            Mode::Auth(&sk.0),
            &sk.public().0,
            info,
        )?;
        let (ciphertext, overhead) = {
            let mut secret = self.try_export_secret()?;
            let mut tag = Tag::<E::Aead>::default();
            ctx.seal_in_place(secret.as_bytes_mut(), &mut tag, info)?;
            (secret.into_bytes(), tag)
        };
        Ok(AuthorEncap {
            encap: Encap(encap),
            ciphertext: Ciphertext {
                ciphertext,
                overhead,
            },
        })
    }

    /// Decrypts the ephemeral secret key that we encrypted to
    /// ourself.
    pub fn open(encap: AuthorEncap<E>, sk: &EncryptionKey<E>, info: &[u8]) -> Result<Self, Error> {
        let mut ctx = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_recv(
            Mode::Auth(&sk.public().0),
            &encap.encap.0,
            &sk.0,
            info,
        )?;
        let Ciphertext {
            mut ciphertext,
            overhead,
        } = encap.ciphertext;
        ctx.open_in_place(&mut ciphertext, &overhead, info)?;
        let ephemeral_sk = <E::Kem as Kem>::DecapKey::import(&ciphertext)?;
        Ok(EphemeralDecapKey(ephemeral_sk))
    }

    pub fn into_inner(self) -> <E::Kem as Kem>::DecapKey {
        self.0
    }

    pub fn try_export_secret(
        &self,
    ) -> Result<SecretKeyBytes<<<E::Kem as Kem>::DecapKey as SecretKey>::Size>, ExportError> {
        self.0.try_export_secret()
    }
}

impl<E: Engine + ?Sized> Clone for EphemeralDecapKey<E> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// A raw (key, nonce) tuple.
pub struct RawKey<E: Engine + ?Sized> {
    /// The key data.
    pub key: KeyData<E::Aead>,
    /// The base nonce.
    pub base_nonce: Nonce<<E::Aead as Aead>::NonceSize>,
}

impl<E: Engine + ?Sized> ConstantTimeEq for RawKey<E> {
    fn ct_eq(&self, other: &Self) -> Choice {
        let key = self.key.ct_eq(&other.key);
        let nonce = self.base_nonce.ct_eq(&other.base_nonce);
        key | nonce
    }
}

impl<E: Engine + ?Sized> ConstantTimeEq for &RawKey<E> {
    fn ct_eq(&self, other: &Self) -> Choice {
        (*self).ct_eq(other)
    }
}
