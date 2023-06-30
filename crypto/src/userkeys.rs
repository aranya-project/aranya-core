//! This file contains the various user keys.

#![forbid(unsafe_code)]

use {
    crate::{
        aead::Aead,
        ciphersuite::{CipherSuite, SuiteIds},
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
        signer::{Signer, SigningKey as SigningKey_, VerifyingKey as VerifyingKey_},
        zeroize::ZeroizeOnDrop,
    },
    core::{
        borrow::Borrow,
        fmt::{self, Debug, Display},
        ops::Add,
        result::Result,
    },
    serde::{Deserialize, Serialize},
};

// These are shorthand for lots::of::turbo::fish.
type SigningKeyData<E> = <<<E as CipherSuite>::Signer as Signer>::SigningKey as SecretKey>::Data;
type VerifyingKeyData<E> =
    <<<E as CipherSuite>::Signer as Signer>::VerifyingKey as PublicKey>::Data;
type DecapKeyData<E> = <<<E as CipherSuite>::Kem as Kem>::DecapKey as SecretKey>::Data;
type EncapKeyData<E> = <<<E as CipherSuite>::Kem as Kem>::EncapKey as PublicKey>::Data;

macro_rules! key_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Copy, Clone, Eq, PartialEq)]
        pub struct $name(Id);

        impl AsRef<[u8]> for $name {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl From<Id> for $name {
            #[inline]
            fn from(id: Id) -> Self {
                Self(id)
            }
        }

        impl From<$name> for Id {
            #[inline]
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Display::fmt(&self.0, f)
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), " {}"), self.0)
            }
        }
    };
}

macro_rules! key_misc {
    ($name:ident) => {
        impl<E: Engine + ?Sized> Clone for $name<E> {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl<E: Engine + ?Sized> Display for $name<E> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.id())
            }
        }

        impl<E: Engine + ?Sized> Debug for $name<E> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), " {}"), self.id())
            }
        }
    };
}

/// A signature created by an [`IdentityKey`] or by
/// a [`SigningKey`].
#[derive(Clone, Debug)]
pub struct Signature<E: Engine + ?Sized>(<E::Signer as Signer>::Signature);

impl<E: Engine + ?Sized> Signature<E> {
    /// Returns the byte representation of the signature.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.borrow()
    }
}

/// The private half of [`IdentityKey`].
#[derive(ZeroizeOnDrop)]
pub struct IdentityKey<E: Engine + ?Sized>(<E::Signer as Signer>::SigningKey);

impl<E: Engine + ?Sized> IdentityKey<E> {
    /// Creates an `IdentityKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <E::Signer as Signer>::SigningKey::new(rng);
        IdentityKey(sk)
    }

    /// Uniquely identifies the `IdentityKey`.
    ///
    /// Two keys with the same ID are the same key.
    #[inline]
    pub fn id(&self) -> UserId {
        self.public().id()
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
            self.0.public().export().borrow(),
            context.as_bytes(),
            msg,
        ]);
        let sig = self.0.sign(&sum)?;
        Ok(Signature(sig))
    }

    /// Returns the public half of the key.
    #[inline]
    pub fn public(&self) -> IdentityVerifyingKey<E> {
        IdentityVerifyingKey(self.0.public())
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
key_misc!(IdentityKey);
key_id!(UserId, "Uniquely identifies an [`IdentityKey`].");

/// The public half of [`IdentityKey`].
pub struct IdentityVerifyingKey<E: Engine + ?Sized>(<E::Signer as Signer>::VerifyingKey);

impl<E: Engine + ?Sized> IdentityVerifyingKey<E> {
    /// Uniquely identifies the `IdentityKey`.
    ///
    /// Two keys with the same ID are the same key.
    #[inline]
    pub fn id(&self) -> UserId {
        UserId(Id::new::<E>(self.0.export().borrow(), b"IdentityKey"))
    }

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
            self.0.export().borrow(),
            context.as_bytes(),
            msg,
        ]);
        Ok(self.0.verify(&sum, &sig.0)?)
    }

    /// Returns its exported representation.
    pub fn export(&self) -> ExportedKey<impl Borrow<[u8]>> {
        ExportedKey::from_data::<E>(self.0.export())
    }
}
key_misc!(IdentityVerifyingKey);

impl<E: Engine + ?Sized> Import<&ExportedKey<VerifyingKeyData<E>>> for IdentityVerifyingKey<E> {
    fn import(key: &ExportedKey<VerifyingKeyData<E>>) -> Result<Self, ImportError> {
        if !valid_context::<E>(key) {
            Err(ImportError::InvalidContext)
        } else {
            let pk = <E::Signer as Signer>::VerifyingKey::import(key.data.borrow())?;
            Ok(Self(pk))
        }
    }
}

/// The private half of [`SigningKey`].
#[derive(ZeroizeOnDrop)]
pub struct SigningKey<E: Engine + ?Sized>(<E::Signer as Signer>::SigningKey);

impl<E: Engine + ?Sized> SigningKey<E> {
    /// Creates a `SigningKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <E::Signer as Signer>::SigningKey::new(rng);
        SigningKey(sk)
    }

    /// Uniquely identifies the `SigningKey`.
    ///
    /// Two keys with the same ID are the same key.
    #[inline]
    pub fn id(&self) -> SigningKeyId {
        self.public().id()
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
            self.0.public().export().borrow(),
            context.as_bytes(),
            msg,
        ]);
        let sig = self.0.sign(&sum)?;
        Ok(Signature(sig))
    }

    /// Returns the public half of the key.
    #[inline]
    pub fn public(&self) -> VerifyingKey<E> {
        VerifyingKey(self.0.public())
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
key_misc!(SigningKey);
key_id!(SigningKeyId, "Uniquely identifies a [`SigningKey`].");

/// The public half of [`SigningKey`].
pub struct VerifyingKey<E: Engine + ?Sized>(<E::Signer as Signer>::VerifyingKey);

impl<E: Engine + ?Sized> VerifyingKey<E> {
    /// Uniquely identifies the `SigningKey`.
    ///
    /// Two keys with the same ID are the same key.
    #[inline]
    pub fn id(&self) -> SigningKeyId {
        SigningKeyId(Id::new::<E>(self.0.export().borrow(), b"SigningKey"))
    }

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
            self.0.export().borrow(),
            context.as_bytes(),
            msg,
        ]);
        Ok(self.0.verify(&sum, &sig.0)?)
    }

    /// Returns the byte encoding of the public key.
    pub fn export(&self) -> ExportedKey<impl Borrow<[u8]>> {
        ExportedKey::from_data::<E>(self.0.export())
    }
}
key_misc!(VerifyingKey);

impl<E: Engine + ?Sized> Import<&ExportedKey<VerifyingKeyData<E>>> for VerifyingKey<E> {
    fn import(key: &ExportedKey<VerifyingKeyData<E>>) -> Result<Self, ImportError> {
        if !valid_context::<E>(key) {
            Err(ImportError::InvalidContext)
        } else {
            let pk = <E::Signer as Signer>::VerifyingKey::import(key.data.borrow())?;
            Ok(Self(pk))
        }
    }
}

/// The private half of [`EncryptionKey`].
#[derive(ZeroizeOnDrop)]
pub struct EncryptionKey<E: Engine + ?Sized>(<E::Kem as Kem>::DecapKey);

impl<E: Engine + ?Sized> EncryptionKey<E> {
    /// Creates a user's `EncryptionKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <E::Kem as Kem>::DecapKey::new(rng);
        EncryptionKey(sk)
    }

    /// Uniquely identifies the `EncryptionKey`.
    ///
    /// Two keys with the same ID are the same key.
    #[inline]
    pub fn id(&self) -> EncryptionKeyId {
        self.public().id()
    }

    /// Decrypts and authenticates a [`GroupKey`] received from
    /// a peer using the `local` secret key.
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
        let mut ctx =
            Hpke::<E::Kem, E::Kdf, E::Aead>::setup_recv(&Mode::Base, enc, &self.0, &info)?;
        let mut seed = [0u8; 64];
        ctx.open(&mut seed, ciphertext.as_bytes(), &info)?;
        Ok(GroupKey::from_seed(seed))
    }

    /// Returns the public half of the key.
    pub fn public(&self) -> EncryptionPublicKey<E> {
        EncryptionPublicKey(self.0.public())
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
key_misc!(EncryptionKey);
key_id!(EncryptionKeyId, "Uniquely identifies a [`EncryptionKey`].");

/// The public half of [`EncryptionKey`].
pub struct EncryptionPublicKey<E: Engine + ?Sized>(<E::Kem as Kem>::EncapKey);

impl<E: Engine + ?Sized> EncryptionPublicKey<E> {
    /// Uniquely identifies the `EncryptionKey`.
    ///
    /// Two keys with the same ID are the same key.
    #[inline]
    pub fn id(&self) -> EncryptionKeyId {
        EncryptionKeyId(Id::new::<E>(self.0.export().borrow(), b"EncryptionKey"))
    }

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
            Hpke::<E::Kem, E::Kdf, E::Aead>::setup_send(rng, &Mode::Base, &self.0, &info)?;
        let mut dst = ByteArray::default();
        ctx.seal(&mut dst, key.raw_seed(), &info)?;
        Ok((enc, EncryptedGroupKey(dst)))
    }

    /// Returns its exported representation.
    pub fn export(&self) -> ExportedKey<impl Borrow<[u8]>> {
        ExportedKey::from_data::<E>(self.0.export())
    }
}
key_misc!(EncryptionPublicKey);

impl<E: Engine + ?Sized> Import<&ExportedKey<EncapKeyData<E>>> for EncryptionPublicKey<E> {
    fn import(key: &ExportedKey<EncapKeyData<E>>) -> Result<Self, ImportError> {
        if !valid_context::<E>(key) {
            Err(ImportError::InvalidContext)
        } else {
            let pk = <E::Kem as Kem>::EncapKey::import(key.data.borrow())?;
            Ok(Self(pk))
        }
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

/// An exported public key.
#[derive(Serialize, Deserialize)]
pub struct ExportedKey<D: Borrow<[u8]>> {
    eng_id: Id,
    suite_id: SuiteIds,
    pub(crate) data: D,
}

impl<D: Borrow<[u8]>> ExportedKey<D> {
    fn from_data<E: Engine + ?Sized>(data: D) -> Self {
        Self {
            eng_id: E::ID,
            suite_id: SuiteIds::from_suite::<E>(),
            data,
        }
    }
}

fn valid_context<E: Engine + ?Sized>(key: &ExportedKey<impl Borrow<[u8]>>) -> bool {
    key.eng_id == E::ID && key.suite_id == SuiteIds::from_suite::<E>()
}
