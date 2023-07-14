//! This file contains the various user keys.

#![forbid(unsafe_code)]

use {
    crate::{
        aead::Aead,
        ciphersuite::SuiteIds,
        csprng::Csprng,
        engine::Engine,
        error::Error,
        groupkey::GroupKey,
        hash::tuple_hash,
        hpke::{Hpke, Mode},
        hybrid_array::{
            typenum::{operator_aliases::Sum, U64},
            ArraySize, ByteArray,
        },
        id::Id,
        import::{ExportError, Import, ImportError},
        kem::{DecapKey, Kem},
        keys::{PublicKey, SecretKey},
        misc::{
            key_misc, DecapKeyData, ExportedData, ExportedDataType, SerdeBorrowedSig,
            SerdeOwnedSig, SigData, SigningKeyData,
        },
        signer::{self, Signer, SigningKey as SigningKey_, VerifyingKey as VerifyingKey_},
        zeroize::ZeroizeOnDrop,
    },
    core::{borrow::Borrow, ops::Add, result::Result},
    serde::{de, Deserialize, Deserializer, Serialize, Serializer},
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
}

impl<E: Engine + ?Sized> Serialize for Signature<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ExportedData::<SerdeBorrowedSig<'_, E::Signer>>::from_sig::<E>(
            &self.0,
            ExportedDataType::Signature,
        )
        .serialize(serializer)
    }
}

impl<'de, E: Engine + ?Sized> Deserialize<'de> for Signature<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = ExportedData::<SerdeOwnedSig<E::Signer>>::deserialize(deserializer)?;
        if !data.valid_context::<E>(ExportedDataType::Signature) {
            Err(de::Error::custom(ImportError::InvalidContext))
        } else {
            Ok(Self(data.data.0))
        }
    }
}

/// The private half of [`IdentityKey`].
#[derive(ZeroizeOnDrop)]
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
    /// # #[cfg(feature = "alloc")]
    /// # {
    /// use crypto::{
    ///     DefaultCipherSuite,
    ///     DefaultEngine,
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

    // Utility routines for other modules.

    pub(crate) fn import(data: &[u8]) -> Result<Self, ImportError> {
        let sk = <E::Signer as Signer>::SigningKey::import(data)?;
        Ok(Self(sk))
    }
    pub(crate) fn try_export_secret(&self) -> Result<SigningKeyData<E>, ExportError> {
        self.0.try_export_secret()
    }
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
#[derive(ZeroizeOnDrop)]
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
    /// # #[cfg(feature = "alloc")]
    /// # {
    /// use crypto::{
    ///     DefaultCipherSuite,
    ///     DefaultEngine,
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

    // Utility routines for other modules.

    pub(crate) fn import(data: &[u8]) -> Result<Self, ImportError> {
        let sk = <E::Signer as Signer>::SigningKey::import(data)?;
        Ok(Self(sk))
    }
    pub(crate) fn try_export_secret(&self) -> Result<SigningKeyData<E>, ExportError> {
        self.0.try_export_secret()
    }
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
#[derive(ZeroizeOnDrop)]
pub struct EncryptionKey<E: Engine + ?Sized>(<E::Kem as Kem>::DecapKey);

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
        enc: &<E::Kem as Kem>::Encap,
        ciphertext: &EncryptedGroupKey<E>,
        group: Id,
    ) -> Result<GroupKey<E>, Error>
    where
        <E::Aead as Aead>::TagSize: Add<U64>,
        Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize,
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
        let mut ctx = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_recv(Mode::Base, enc, &self.0, &info)?;
        let mut seed = [0u8; 64];
        ctx.open(&mut seed, ciphertext.as_bytes(), &info)?;
        Ok(GroupKey::from_seed(seed))
    }

    // Utility routines for other modules.

    pub(crate) fn import(data: &[u8]) -> Result<Self, ImportError> {
        let sk = <E::Kem as Kem>::DecapKey::import(data)?;
        Ok(Self(sk))
    }
    pub(crate) fn try_export_secret(&self) -> Result<DecapKeyData<E>, ExportError> {
        self.0.try_export_secret()
    }
}

/// The public half of [`EncryptionKey`].
pub struct EncryptionPublicKey<E: Engine + ?Sized>(<E::Kem as Kem>::EncapKey);

impl<E: Engine + ?Sized> EncryptionPublicKey<E> {
    /// Encrypts and authenticates the [`GroupKey`] such that it
    /// can only be decrypted by the holder of the private half
    /// of the [`EncryptionPublicKey`].
    pub fn seal_group_key<R: Csprng>(
        &self,
        rng: &mut R,
        key: &GroupKey<E>,
        group: Id,
    ) -> Result<(<E::Kem as Kem>::Encap, EncryptedGroupKey<E>), Error>
    where
        <E::Aead as Aead>::TagSize: Add<U64>,
        Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize,
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
        let mut dst = ByteArray::default();
        ctx.seal(&mut dst, key.raw_seed(), &info)?;
        Ok((enc, EncryptedGroupKey(dst)))
    }
}

/// An encrypted [`GroupKey`].
pub struct EncryptedGroupKey<E: Engine + ?Sized>(ByteArray<Sum<<E::Aead as Aead>::TagSize, U64>>)
where
    <E::Aead as Aead>::TagSize: Add<U64>,
    Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize;

impl<E: Engine + ?Sized> EncryptedGroupKey<E>
where
    <E::Aead as Aead>::TagSize: Add<U64>,
    Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize,
{
    /// Reutrns itself as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}
