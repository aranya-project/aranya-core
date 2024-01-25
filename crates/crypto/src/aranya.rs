//! This file contains the various user keys.

#![forbid(unsafe_code)]

use core::{borrow::Borrow, fmt, marker::PhantomData, ops::Add, result::Result};

use generic_array::{ArrayLength, GenericArray};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use typenum::{operator_aliases::Sum, U64};

use crate::{
    aead::Aead,
    ciphersuite::SuiteIds,
    csprng::Csprng,
    engine::{unwrapped, Engine},
    error::Error,
    groupkey::GroupKey,
    hash::tuple_hash,
    hpke::{Hpke, Mode},
    id::Id,
    import::{Import, ImportError},
    kem::{DecapKey, Kem},
    keys::{PublicKey, SecretKey},
    misc::{ciphertext, key_misc, SigData},
    signer::{self, Signer, SigningKey as SigningKey_, VerifyingKey as VerifyingKey_},
};

/// A signature created by a signing key.
#[derive(Clone, Debug)]
pub struct Signature<E: Engine + ?Sized>(pub(crate) <E::Signer as Signer>::Signature);

impl<E: Engine + ?Sized> Signature<E> {
    /// Returns the raw signature.
    ///
    /// Should only be used in situations where contextual data
    /// is being merged in. E.g., [`Id::from_sig`]. Otherwise,
    /// use [`Serialize`].
    pub(crate) fn raw_sig(&self) -> SigData<E> {
        signer::Signature::export(&self.0)
    }

    /// Encodes itself as bytes.
    pub fn to_bytes(&self) -> impl Borrow<[u8]> {
        self.raw_sig()
    }

    /// Returns itself from its byte encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        let sig = <E::Signer as Signer>::Signature::import(data)?;
        Ok(Self(sig))
    }
}

impl<E: Engine + ?Sized> Serialize for Signature<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.to_bytes().borrow())
    }
}

impl<'de, E: Engine + ?Sized> Deserialize<'de> for Signature<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor<E: ?Sized>(PhantomData<E>);
        impl<'de, G: Engine + ?Sized> de::Visitor<'de> for SigVisitor<G> {
            type Value = Signature<G>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a signature")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Signature::<G>::from_bytes(v).map_err(de::Error::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Signature::<G>::from_bytes(v).map_err(de::Error::custom)
            }
        }
        let sig = deserializer.deserialize_bytes(SigVisitor::<E>(PhantomData))?;
        Ok(sig)
    }
}

/// The private half of [`IdentityKey`].
pub struct IdentityKey<E: Engine + ?Sized>(<E::Signer as Signer>::SigningKey);

key_misc!(IdentityKey, IdentityVerifyingKey, UserId);

impl<E: Engine + ?Sized> IdentityKey<E> {
    /// Creates an `IdentityKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <E::Signer as Signer>::SigningKey::new(rng);
        IdentityKey(sk)
    }

    /// Creates a signature over `msg` bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "moonshot")))]
    /// # {
    /// use crypto::{
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     IdentityKey,
    ///     Rng,
    /// };
    ///
    /// let sk = IdentityKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng);
    ///
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// const CONTEXT: &str = "doc test";
    /// let sig = sk.sign(MESSAGE, CONTEXT)
    ///     .expect("should not fail");
    ///
    /// sk.public().verify(MESSAGE, CONTEXT, &sig)
    ///     .expect("should not fail");
    ///
    /// sk.public().verify(MESSAGE, "wrong context", &sig)
    ///     .expect_err("should fail");
    ///
    /// let wrong_sig = sk.sign(b"different", "signature")
    ///     .expect("should not fail");
    /// sk.public().verify(MESSAGE, CONTEXT, &wrong_sig)
    ///     .expect_err("should fail");
    /// # }
    /// ```
    pub fn sign(&self, msg: &[u8], context: &'static str) -> Result<Signature<E>, Error> {
        // digest = H(
        //     "IdentityKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = tuple_hash::<E::Hash, _>([
            "IdentityKey".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            self.id().as_bytes(),
            context.as_bytes(),
            msg,
        ]);
        let sig = self.0.sign(&sum)?;
        Ok(Signature(sig))
    }
}

unwrapped! {
    name: IdentityKey;
    type: Signing;
    into: |key: Self| { key.0 };
    from: |key| { Self(key) };
}

/// The public half of [`IdentityKey`].
pub struct IdentityVerifyingKey<E: Engine + ?Sized>(<E::Signer as Signer>::VerifyingKey);

impl<E: Engine + ?Sized> IdentityVerifyingKey<E> {
    /// Verifies the signature allegedly created over `msg` and
    /// bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    pub fn verify(
        &self,
        msg: &[u8],
        context: &'static str,
        sig: &Signature<E>,
    ) -> Result<(), Error> {
        // digest = H(
        //     "IdentityKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = tuple_hash::<E::Hash, _>([
            "IdentityKey".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            self.id().as_bytes(),
            context.as_bytes(),
            msg,
        ]);
        Ok(self.0.verify(&sum, &sig.0)?)
    }
}

/// The private half of [`SigningKey`].
pub struct SigningKey<E: Engine + ?Sized>(<E::Signer as Signer>::SigningKey);

key_misc!(SigningKey, VerifyingKey, SigningKeyId);

impl<E: Engine + ?Sized> SigningKey<E> {
    /// Creates a `SigningKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <E::Signer as Signer>::SigningKey::new(rng);
        SigningKey(sk)
    }

    /// Creates a signature over `msg` bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "moonshot")))]
    /// # {
    /// use crypto::{
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     Rng,
    ///     SigningKey,
    /// };
    ///
    /// let sk = SigningKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng);
    ///
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// const CONTEXT: &str = "doc test";
    /// let sig = sk.sign(MESSAGE, CONTEXT)
    ///     .expect("should not fail");
    ///
    /// sk.public().verify(MESSAGE, CONTEXT, &sig)
    ///     .expect("should not fail");
    ///
    /// sk.public().verify(MESSAGE, "wrong context", &sig)
    ///     .expect_err("should fail");
    ///
    /// let wrong_sig = sk.sign(b"different", "signature")
    ///     .expect("should not fail");
    /// sk.public().verify(MESSAGE, CONTEXT, &wrong_sig)
    ///     .expect_err("should fail");
    /// # }
    /// ```
    pub fn sign(&self, msg: &[u8], context: &'static str) -> Result<Signature<E>, Error> {
        // digest = H(
        //     "SigningKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = tuple_hash::<E::Hash, _>([
            "SigningKey".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            self.id().as_bytes(),
            context.as_bytes(),
            msg,
        ]);
        let sig = self.0.sign(&sum)?;
        Ok(Signature(sig))
    }
}

unwrapped! {
    name: SigningKey;
    type: Signing;
    into: |key: Self| { key.0 };
    from: |key| { Self(key) };
}

/// The public half of [`SigningKey`].
pub struct VerifyingKey<E: Engine + ?Sized>(<E::Signer as Signer>::VerifyingKey);

impl<E: Engine + ?Sized> VerifyingKey<E> {
    /// Verifies the signature allegedly created over `msg` and
    /// bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    pub fn verify(
        &self,
        msg: &[u8],
        context: &'static str,
        sig: &Signature<E>,
    ) -> Result<(), Error> {
        // digest = H(
        //     "SigningKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = tuple_hash::<E::Hash, _>([
            "SigningKey".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            self.id().as_bytes(),
            context.as_bytes(),
            msg,
        ]);
        Ok(self.0.verify(&sum, &sig.0)?)
    }
}

/// The private half of [`EncryptionKey`].
pub struct EncryptionKey<E: Engine + ?Sized>(pub(crate) <E::Kem as Kem>::DecapKey);

key_misc!(EncryptionKey, EncryptionPublicKey, EncryptionKeyId);

impl<E: Engine + ?Sized> EncryptionKey<E> {
    /// Creates a user's `EncryptionKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <E::Kem as Kem>::DecapKey::new(rng);
        EncryptionKey(sk)
    }

    /// Decrypts and authenticates a [`GroupKey`] received from
    /// a peer.
    pub fn open_group_key(
        &self,
        enc: &Encap<E>,
        ciphertext: &EncryptedGroupKey<E>,
        group: Id,
    ) -> Result<GroupKey<E>, Error>
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        // info = H(
        //     "GroupKey",
        //     suite_id,
        //     engine_id,
        //     group,
        // )
        let info = tuple_hash::<E::Hash, _>([
            "GroupKey".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            E::ID.as_bytes(),
            group.as_bytes(),
        ]);
        let mut ctx =
            Hpke::<E::Kem, E::Kdf, E::Aead>::setup_recv(Mode::Base, &enc.0, &self.0, &info)?;
        let mut seed = [0u8; 64];
        ctx.open(&mut seed, ciphertext.as_bytes(), &info)?;
        Ok(GroupKey::from_seed(seed))
    }
}

unwrapped! {
    name: EncryptionKey;
    type: Decap;
    into: |key: Self| { key.0 };
    from: |key| { Self(key) };
}

/// The public half of [`EncryptionKey`].
pub struct EncryptionPublicKey<E: Engine + ?Sized>(pub(crate) <E::Kem as Kem>::EncapKey);

impl<E: Engine + ?Sized> EncryptionPublicKey<E> {
    /// Encrypts and authenticates the [`GroupKey`] such that it
    /// can only be decrypted by the holder of the private half
    /// of the [`EncryptionPublicKey`].
    pub fn seal_group_key<R: Csprng>(
        &self,
        rng: &mut R,
        key: &GroupKey<E>,
        group: Id,
    ) -> Result<(Encap<E>, EncryptedGroupKey<E>), Error>
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        // info = H(
        //     "GroupKey",
        //     suite_id,
        //     engine_id,
        //     group,
        // )
        let info = tuple_hash::<E::Hash, _>([
            "GroupKey".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            E::ID.as_bytes(),
            group.as_bytes(),
        ]);
        let (enc, mut ctx) =
            Hpke::<E::Kem, E::Kdf, E::Aead>::setup_send(rng, Mode::Base, &self.0, &info)?;
        let mut dst = GenericArray::default();
        ctx.seal(&mut dst, key.raw_seed(), &info)?;
        Ok((Encap(enc), EncryptedGroupKey(dst)))
    }
}

/// An encapsulated symmetric key.
pub struct Encap<E: Engine + ?Sized>(pub(crate) <E::Kem as Kem>::Encap);

impl<E: Engine + ?Sized> Encap<E> {
    /// Encodes itself as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.borrow()
    }

    /// Returns itself from its byte encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        let enc = <E::Kem as Kem>::Encap::import(data)?;
        Ok(Self(enc))
    }

    pub(crate) fn as_inner(&self) -> &<E::Kem as Kem>::Encap {
        &self.0
    }
}

impl<E> Serialize for Encap<E>
where
    E: Engine + ?Sized,
{
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(self.as_bytes())
    }
}

impl<'de, E> Deserialize<'de> for Encap<E>
where
    E: Engine + ?Sized,
{
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EncapVisitor<G>(PhantomData<G>);
        impl<'de, G> de::Visitor<'de> for EncapVisitor<G>
        where
            G: Engine + ?Sized,
        {
            type Value = Encap<G>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a valid encapsulation")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Encap::<G>::from_bytes(v).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Encap::<G>::from_bytes(v).map_err(E::custom)
            }
        }
        d.deserialize_bytes(EncapVisitor(PhantomData))
    }
}

ciphertext!(EncryptedGroupKey, U64, "An encrypted [`GroupKey`].");
