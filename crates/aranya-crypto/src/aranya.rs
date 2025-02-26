//! This file contains the various user keys.

#![forbid(unsafe_code)]

use core::{borrow::Borrow, fmt, marker::PhantomData, result::Result};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    aead::Tag,
    ciphersuite::SuiteIds,
    csprng::Csprng,
    engine::unwrapped,
    error::Error,
    groupkey::{EncryptedGroupKey, GroupKey},
    hash::tuple_hash,
    hpke::{Hpke, Mode},
    id::Id,
    import::{Import, ImportError},
    kem::{DecapKey, Kem},
    keys::{PublicKey, SecretKey},
    misc::{key_misc, SigData},
    policy::{self, Cmd, CmdId},
    signer::{self, Signer, SigningKey as SigningKey_, VerifyingKey as VerifyingKey_},
    CipherSuite,
};

/// A signature created by a signing key.
pub struct Signature<CS: CipherSuite>(pub(crate) <CS::Signer as Signer>::Signature);

impl<CS: CipherSuite> Signature<CS> {
    /// Returns the raw signature.
    ///
    /// Should only be used in situations where contextual data
    /// is being merged in. Otherwise, use [`Serialize`].
    pub(crate) fn raw_sig(&self) -> SigData<CS> {
        signer::Signature::export(&self.0)
    }

    /// Encodes itself as bytes.
    pub fn to_bytes(&self) -> impl Borrow<[u8]> {
        self.raw_sig()
    }

    /// Returns itself from its byte encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        let sig = <CS::Signer as Signer>::Signature::import(data)?;
        Ok(Self(sig))
    }
}

impl<CS: CipherSuite> fmt::Debug for Signature<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature").field(&self.0).finish()
    }
}

impl<CS: CipherSuite> Clone for Signature<CS> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<CS: CipherSuite> Serialize for Signature<CS> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.to_bytes().borrow())
    }
}

impl<'de, CS: CipherSuite> Deserialize<'de> for Signature<CS> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor<CS>(PhantomData<CS>);
        impl<'de, G: CipherSuite> de::Visitor<'de> for SigVisitor<G> {
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
        let sig = deserializer.deserialize_bytes(SigVisitor::<CS>(PhantomData))?;
        Ok(sig)
    }
}

/// The private half of [`IdentityKey`].
pub struct IdentityKey<CS: CipherSuite>(<CS::Signer as Signer>::SigningKey);

key_misc!(IdentityKey, IdentityVerifyingKey, UserId);

impl<CS: CipherSuite> IdentityKey<CS> {
    /// Creates an `IdentityKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <CS::Signer as Signer>::SigningKey::new(rng);
        IdentityKey(sk)
    }

    /// Creates a signature over `msg` bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
    /// # {
    /// use aranya_crypto::{
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     IdentityKey,
    ///     Rng,
    /// };
    ///
    /// let sk = IdentityKey::<DefaultCipherSuite>::new(&mut Rng);
    ///
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// const CONTEXT: &[u8] = b"doc test";
    /// let sig = sk.sign(MESSAGE, CONTEXT)
    ///     .expect("should not fail");
    ///
    /// sk.public().expect("identity key should be valid").verify(MESSAGE, CONTEXT, &sig)
    ///     .expect("should not fail");
    ///
    /// sk.public().expect("identity key should be valid").verify(MESSAGE, b"wrong context", &sig)
    ///     .expect_err("should fail");
    ///
    /// let wrong_sig = sk.sign(b"different", b"signature")
    ///     .expect("should not fail");
    /// sk.public().expect("identity key should be valid").verify(MESSAGE, CONTEXT, &wrong_sig)
    ///     .expect_err("should fail");
    /// # }
    /// ```
    pub fn sign(&self, msg: &[u8], context: &[u8]) -> Result<Signature<CS>, Error> {
        // digest = H(
        //     "IdentityKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = tuple_hash::<CS::Hash, _>([
            "IdentityKey".as_bytes(),
            &SuiteIds::from_suite::<CS>().into_bytes(),
            self.id()?.as_bytes(),
            context,
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
pub struct IdentityVerifyingKey<CS: CipherSuite>(<CS::Signer as Signer>::VerifyingKey);

impl<CS: CipherSuite> IdentityVerifyingKey<CS> {
    /// Verifies the signature allegedly created over `msg` and
    /// bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    pub fn verify(&self, msg: &[u8], context: &[u8], sig: &Signature<CS>) -> Result<(), Error> {
        // digest = H(
        //     "IdentityKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = tuple_hash::<CS::Hash, _>([
            "IdentityKey".as_bytes(),
            &SuiteIds::from_suite::<CS>().into_bytes(),
            self.id()?.as_bytes(),
            context,
            msg,
        ]);
        Ok(self.0.verify(&sum, &sig.0)?)
    }
}

/// The private half of [`SigningKey`].
pub struct SigningKey<CS: CipherSuite>(<CS::Signer as Signer>::SigningKey);

key_misc!(SigningKey, VerifyingKey, SigningKeyId);

impl<CS: CipherSuite> SigningKey<CS> {
    /// Creates a `SigningKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <CS::Signer as Signer>::SigningKey::new(rng);
        SigningKey(sk)
    }

    /// Creates a signature over `msg` bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
    /// # {
    /// use aranya_crypto::{
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     Rng,
    ///     SigningKey,
    /// };
    ///
    /// let sk = SigningKey::<DefaultCipherSuite>::new(&mut Rng);
    ///
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// const CONTEXT: &[u8] = b"doc test";
    /// let sig = sk.sign(MESSAGE, CONTEXT)
    ///     .expect("should not fail");
    ///
    /// sk.public().expect("signing key should be valid").verify(MESSAGE, CONTEXT, &sig)
    ///     .expect("should not fail");
    ///
    /// sk.public().expect("signing key should be valid").verify(MESSAGE, b"wrong context", &sig)
    ///     .expect_err("should fail");
    ///
    /// let wrong_sig = sk.sign(b"different", b"signature")
    ///     .expect("should not fail");
    /// sk.public().expect("signing key should be valid").verify(MESSAGE, CONTEXT, &wrong_sig)
    ///     .expect_err("should fail");
    /// # }
    /// ```
    pub fn sign(&self, msg: &[u8], context: &[u8]) -> Result<Signature<CS>, Error> {
        // digest = H(
        //     "SigningKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = tuple_hash::<CS::Hash, _>([
            "SigningKey".as_bytes(),
            &SuiteIds::from_suite::<CS>().into_bytes(),
            self.id()?.as_bytes(),
            context,
            msg,
        ]);
        let sig = self.0.sign(&sum)?;
        Ok(Signature(sig))
    }

    /// Creates a signature over a named policy command.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
    /// # {
    /// use aranya_crypto::{
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     Cmd,
    ///     Id,
    ///     Rng,
    ///     SigningKey,
    /// };
    ///
    /// let sk = SigningKey::<DefaultCipherSuite>::new(&mut Rng);
    ///
    /// let data = b"... some command data ...";
    /// let name = "AddUser";
    /// let parent_id = &Id::random(&mut Rng);
    ///
    /// let good_cmd = Cmd { data, name, parent_id };
    /// let (sig, _) = sk.sign_cmd(good_cmd)
    ///     .expect("should not fail");
    /// sk.public().expect("signing key should be valid").verify_cmd(good_cmd, &sig)
    ///     .expect("should not fail");
    ///
    /// let wrong_name_cmd = Cmd {
    ///     data,
    ///     name: "wrong name",
    ///     parent_id,
    /// };
    /// sk.public().expect("signing key should be valid").verify_cmd(wrong_name_cmd, &sig)
    ///     .expect_err("should fail");
    ///
    /// let wrong_id_cmd = Cmd {
    ///     data,
    ///     name,
    ///     parent_id: &Id::random(&mut Rng),
    /// };
    /// sk.public().expect("signing key should be valid").verify_cmd(wrong_id_cmd, &sig)
    ///     .expect_err("should fail");
    ///
    /// let wrong_sig_cmd = Cmd {
    ///     data: b"different",
    ///     name: "signature",
    ///     parent_id: &Id::random(&mut Rng),
    /// };
    /// let (wrong_sig, _) = sk.sign_cmd(wrong_sig_cmd)
    ///     .expect("should not fail");
    /// sk.public().expect("signing key should be valid").verify_cmd(good_cmd, &wrong_sig)
    ///     .expect_err("should fail");
    /// # }
    /// ```
    pub fn sign_cmd(&self, cmd: Cmd<'_>) -> Result<(Signature<CS>, CmdId), Error> {
        let digest = cmd.digest::<CS>(self.id()?);
        let sig = Signature(self.0.sign(&digest)?);
        let id = policy::cmd_id(&digest, &sig);
        Ok((sig, id))
    }
}

unwrapped! {
    name: SigningKey;
    type: Signing;
    into: |key: Self| { key.0 };
    from: |key| { Self(key) };
}

/// The public half of [`SigningKey`].
pub struct VerifyingKey<CS: CipherSuite>(<CS::Signer as Signer>::VerifyingKey);

impl<CS: CipherSuite> VerifyingKey<CS> {
    /// Verifies the signature allegedly created over `msg` and
    /// bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    pub fn verify(&self, msg: &[u8], context: &[u8], sig: &Signature<CS>) -> Result<(), Error> {
        // digest = H(
        //     "SigningKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = tuple_hash::<CS::Hash, _>([
            "SigningKey".as_bytes(),
            &SuiteIds::from_suite::<CS>().into_bytes(),
            self.id()?.as_bytes(),
            context,
            msg,
        ]);
        Ok(self.0.verify(&sum, &sig.0)?)
    }

    /// Verifies the signature allegedly created over a policy
    /// command and returns its ID.
    pub fn verify_cmd(&self, cmd: Cmd<'_>, sig: &Signature<CS>) -> Result<CmdId, Error> {
        let digest = cmd.digest::<CS>(self.id()?);
        self.0.verify(&digest, &sig.0)?;
        let id = policy::cmd_id(&digest, sig);
        Ok(id)
    }
}

/// The private half of [`EncryptionKey`].
pub struct EncryptionKey<CS: CipherSuite>(pub(crate) <CS::Kem as Kem>::DecapKey);

key_misc!(EncryptionKey, EncryptionPublicKey, EncryptionKeyId);

impl<CS: CipherSuite> EncryptionKey<CS> {
    /// Creates a user's `EncryptionKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <CS::Kem as Kem>::DecapKey::new(rng);
        EncryptionKey(sk)
    }

    /// Decrypts and authenticates a [`GroupKey`] received from
    /// a peer.
    pub fn open_group_key(
        &self,
        enc: &Encap<CS>,
        ciphertext: EncryptedGroupKey<CS>,
        group: Id,
    ) -> Result<GroupKey<CS>, Error> {
        let EncryptedGroupKey {
            mut ciphertext,
            tag,
        } = ciphertext;

        // info = H(
        //     "GroupKey",
        //     suite_id,
        //     engine_id,
        //     group,
        // )
        let info = tuple_hash::<CS::Hash, _>([
            "GroupKey".as_bytes(),
            &SuiteIds::from_suite::<CS>().into_bytes(),
            group.as_bytes(),
        ]);
        let mut ctx =
            Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_recv(Mode::Base, &enc.0, &self.0, &info)?;
        ctx.open_in_place(&mut ciphertext, &tag, &info)?;
        Ok(GroupKey::from_seed(ciphertext.into()))
    }
}

unwrapped! {
    name: EncryptionKey;
    type: Decap;
    into: |key: Self| { key.0 };
    from: |key| { Self(key) };
}

/// The public half of [`EncryptionKey`].
pub struct EncryptionPublicKey<CS: CipherSuite>(pub(crate) <CS::Kem as Kem>::EncapKey);

impl<CS: CipherSuite> EncryptionPublicKey<CS> {
    /// Encrypts and authenticates the [`GroupKey`] such that it
    /// can only be decrypted by the holder of the private half
    /// of the [`EncryptionPublicKey`].
    pub fn seal_group_key<R: Csprng>(
        &self,
        rng: &mut R,
        key: &GroupKey<CS>,
        group: Id,
    ) -> Result<(Encap<CS>, EncryptedGroupKey<CS>), Error> {
        // info = H(
        //     "GroupKey",
        //     suite_id,
        //     engine_id,
        //     group,
        // )
        let info = tuple_hash::<CS::Hash, _>([
            "GroupKey".as_bytes(),
            &SuiteIds::from_suite::<CS>().into_bytes(),
            group.as_bytes(),
        ]);
        let (enc, mut ctx) =
            Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send(rng, Mode::Base, &self.0, &info)?;
        let mut ciphertext = (*key.raw_seed()).into();
        let mut tag = Tag::<CS::Aead>::default();
        ctx.seal_in_place(&mut ciphertext, &mut tag, &info)?;
        Ok((Encap(enc), EncryptedGroupKey { ciphertext, tag }))
    }
}

/// An encapsulated symmetric key.
pub struct Encap<CS: CipherSuite>(pub(crate) <CS::Kem as Kem>::Encap);

impl<CS: CipherSuite> Encap<CS> {
    /// Encodes itself as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.borrow()
    }

    /// Returns itself from its byte encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        let enc = <CS::Kem as Kem>::Encap::import(data)?;
        Ok(Self(enc))
    }

    pub(crate) fn as_inner(&self) -> &<CS::Kem as Kem>::Encap {
        &self.0
    }
}

impl<CS> Serialize for Encap<CS>
where
    CS: CipherSuite,
{
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(self.as_bytes())
    }
}

impl<'de, CS> Deserialize<'de> for Encap<CS>
where
    CS: CipherSuite,
{
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EncapVisitor<G: ?Sized>(PhantomData<G>);
        impl<'de, G> de::Visitor<'de> for EncapVisitor<G>
        where
            G: CipherSuite,
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
