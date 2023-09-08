//! Cryptography code for [APQ].
//!
//! [APQ]: https://github.com/spideroak-inc/apq

#![forbid(unsafe_code)]

use {
    crate::{
        aead::{Aead, AeadError, BufferTooSmallError, KeyData},
        aranya::{Encap, Signature},
        ciphersuite::SuiteIds,
        csprng::Csprng,
        engine::Engine,
        error::Error,
        hash::tuple_hash,
        hpke::{Hpke, Mode},
        hybrid_array::{
            typenum::{operator_aliases::Sum, U64},
            ArraySize, ByteArray,
        },
        id::{custom_id, Id},
        import::{ExportError, Import, ImportError, InvalidSizeError},
        kdf::{Kdf, KdfError},
        kem::{DecapKey, Kem},
        keys::{PublicKey, SecretKey},
        mac::Mac,
        misc::{key_misc, DecapKeyData, SigningKeyData},
        signer::{Signer, SigningKey as SigningKey_, VerifyingKey as VerifyingKey_},
        zeroize::{Zeroize, ZeroizeOnDrop},
    },
    core::{
        borrow::{Borrow, BorrowMut},
        ops::Add,
        result::Result,
    },
};

/// A sender's identity.
pub struct Sender<E: Engine + ?Sized> {
    /// The sender's public key.
    pub enc_key: SenderPublicKey<E>,
    /// The sender's verifying key.
    pub sign_key: SenderVerifyingKey<E>,
}

/// The current APQ version.
#[derive(Copy, Clone, Debug, Default)]
#[repr(transparent)]
pub struct Version(pub u32);

impl Version {
    const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// The APQ topic being used.
#[derive(Copy, Clone, Debug, Default)]
#[repr(transparent)]
pub struct Topic(pub u32);

impl Topic {
    const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

custom_id!(TopicKeyId, "Uniquely identifies a [`TopicKey`].");

/// A [symmetric key] used to encrypt queue messages for
/// a particular topic.
///
/// [symmetric key]: https://github.com/spideroak-inc/apq/blob/spec/design.md#topickey
pub struct TopicKey<E: Engine + ?Sized> {
    // TopicKey is quite similar to GroupKey. However, unlike
    // GroupKey, we do not compute the key from the seed each
    // time we encrypt some data. Instead, we compute the key
    // when creating a TopicKey.
    //
    // We do this because APQ has a higher throughput than
    // Aranya, so recomputing the key each time could be too
    // expensive.
    //
    // The downside is that we still have to keep the seed in
    // memory alongside the key in case we need to send the seed
    // to a receiver. So, each TopicKey ends up being ~twice as
    // large and we have to handle two pieces of key material.
    key: <E::Aead as Aead>::Key,
    seed: [u8; 64],
}

impl<E: Engine + ?Sized> ZeroizeOnDrop for TopicKey<E> {}
impl<E: Engine + ?Sized> Drop for TopicKey<E> {
    fn drop(&mut self) {
        self.seed.zeroize()
    }
}

impl<E: Engine + ?Sized> Clone for TopicKey<E> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            seed: self.seed,
        }
    }
}

impl<E: Engine + ?Sized> TopicKey<E> {
    /// Creates a new, random `TopicKey`.
    pub fn new<R: Csprng>(rng: &mut R, version: Version, topic: Topic) -> Result<Self, Error> {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed, version, topic)
    }

    /// Uniquely identifies the [`TopicKey`].
    ///
    /// Two keys with the same ID are the same key.
    #[inline]
    pub fn id(&self) -> TopicKeyId {
        // ID = MAC(
        //     key=TopicKey,
        //     message="TopicKeyId-v1" || suite_id,
        //     outputBytes=64,
        // )
        let mut h = E::Mac::new(&self.seed.into());
        h.update(b"TopicKeyId-v1");
        h.update(&SuiteIds::from_suite::<E>().into_bytes());
        TopicKeyId(h.tag().into())
    }

    /// The size in bytes of the overhead added to plaintexts
    /// when encrypted.
    pub const OVERHEAD: usize = E::Aead::NONCE_SIZE + E::Aead::TAG_SIZE;

    /// Returns the size in bytes of the overhead added to
    /// plaintexts when encrypted.
    ///
    /// Same as [`OVERHEAD`][Self::OVERHEAD].
    pub const fn overhead(&self) -> usize {
        Self::OVERHEAD
    }

    /// Encrypts and authenticates `plaintext`.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least [`overhead`][Self::overhead] bytes longer
    /// than `plaintext.len()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "moonshot")))]
    /// # {
    /// use crypto::{
    ///     apq::{
    ///         Sender,
    ///         SenderSecretKey,
    ///         SenderSigningKey,
    ///         Topic,
    ///         TopicKey,
    ///         Version,
    ///     },
    ///     DefaultCipherSuite,
    ///     DefaultEngine,
    ///     Id,
    ///     Rng,
    ///     UserId,
    /// };
    ///
    /// const VERSION: Version = Version(1);
    /// const TOPIC: Topic = Topic(4);
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// let ident = Sender {
    ///     enc_key: SenderSecretKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng)
    ///         .public(),
    ///     sign_key: SenderSigningKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng)
    ///         .public(),
    /// };
    ///
    /// let key = TopicKey::new(&mut Rng, VERSION, TOPIC)
    ///     .expect("should not fail");
    ///
    /// let ciphertext = {
    ///     let mut dst = vec![0u8; MESSAGE.len() + key.overhead()];
    ///     key.seal_message(
    ///         &mut Rng,
    ///         &mut dst,
    ///         MESSAGE,
    ///         VERSION,
    ///         TOPIC,
    ///         &ident,
    ///     ).expect("should not fail");
    ///     dst
    /// };
    /// let plaintext = {
    ///     let mut dst = vec![0u8; ciphertext.len() - key.overhead()];
    ///     key.open_message(
    ///         &mut dst,
    ///         &ciphertext,
    ///         VERSION,
    ///         TOPIC,
    ///         &ident,
    ///     ).expect("should not fail");
    ///     dst
    /// };
    /// assert_eq!(&plaintext, MESSAGE);
    /// # }
    /// ```
    pub fn seal_message<R: Csprng>(
        &self,
        rng: &mut R,
        dst: &mut [u8],
        plaintext: &[u8],
        version: Version,
        topic: Topic,
        ident: &Sender<E>,
    ) -> Result<(), Error> {
        if dst.len() < self.overhead() {
            // Not enough room in `dst`.
            return Err(Error::Aead(AeadError::BufferTooSmall(BufferTooSmallError(
                Some(self.overhead() + plaintext.len()),
            ))));
        }
        // ad = concat(
        //     i2osp(version, 4),
        //     i2osp(topic, 4),
        //     suite_id,
        //     hash(pk(SenderKey)),
        //     hash(pk(SenderSigningKey)),
        // )
        let ad = tuple_hash::<E::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.to_be_bytes()[..],
            &SuiteIds::from_suite::<E>().into_bytes(),
            ident.enc_key.id().as_bytes(),
            ident.sign_key.id().as_bytes(),
        ]);
        let (nonce, out) = dst.split_at_mut(E::Aead::NONCE_SIZE);
        rng.fill_bytes(nonce);
        Ok(E::Aead::new(&self.key).seal(out, nonce, plaintext, &ad)?)
    }

    /// Decrypts and authenticates `ciphertext`.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// be at least as long as the original plaintext (i.e.,
    /// `ciphertext.len()` - [`overhead`][Self::overhead] bytes
    /// long).
    pub fn open_message(
        &self,
        dst: &mut [u8],
        ciphertext: &[u8],
        version: Version,
        topic: Topic,
        ident: &Sender<E>,
    ) -> Result<(), Error> {
        if ciphertext.len() < self.overhead() {
            // Can't find the nonce and/or tag, so it's obviously
            // invalid.
            return Err(AeadError::Authentication.into());
        }
        let (nonce, ciphertext) = ciphertext.split_at(E::Aead::NONCE_SIZE);
        // ad = concat(
        //     i2osp(version, 4),
        //     i2osp(topic, 4),
        //     suite_id,
        //     hash(pk(SenderSigningKey)),
        // )
        let ad = tuple_hash::<E::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.to_be_bytes()[..],
            &SuiteIds::from_suite::<E>().into_bytes(),
            ident.enc_key.id().as_bytes(),
            ident.sign_key.id().as_bytes(),
        ]);
        Ok(E::Aead::new(&self.key).open(dst, nonce, ciphertext, &ad)?)
    }

    fn from_seed(seed: [u8; 64], version: Version, topic: Topic) -> Result<Self, Error> {
        let key = Self::derive_key(&seed, version, topic)?;
        Ok(Self { key, seed })
    }

    /// Derives a key for [`Self::open`] and [`Self::seal`].
    ///
    /// See <https://github.com/spideroak-inc/apq/blob/spec/design.md#topickey-generation>
    fn derive_key(
        seed: &[u8; 64],
        version: Version,
        topic: Topic,
    ) -> Result<<E::Aead as Aead>::Key, Error> {
        // prk = LabeledExtract({0}^512, seed, "topic_key_prk")
        let prk = Self::labeled_extract(&[], b"topic_key_prk", seed);
        // info = concat(
        //     i2osp(version, 4),
        //     i2osp(topic, 4),
        // )
        // key = LabeledExpand(prk, "topic_key_key", info, L)
        let key = Self::labeled_expand::<KeyData<E::Aead>, 13>(
            &prk,
            b"topic_key_key",
            &((u64::from(version.0) << 32) | u64::from(topic.0)).to_be_bytes(),
        )?;
        Ok(<<E::Aead as Aead>::Key as Import<_>>::import(key.borrow())?)
    }

    fn labeled_extract<const N: usize>(
        salt: &[u8],
        label: &[u8; N],
        ikm: &[u8; 64],
    ) -> <E::Kdf as Kdf>::Prk {
        let labeled_ikm = [
            "APQ-v1".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            label,
            ikm,
        ];
        E::Kdf::extract_multi(&labeled_ikm, salt)
    }

    fn labeled_expand<T: Borrow<[u8]> + BorrowMut<[u8]> + Default, const N: usize>(
        prk: &<E::Kdf as Kdf>::Prk,
        label: &[u8; N],
        info: &[u8],
    ) -> Result<T, KdfError> {
        let mut out = T::default();
        // We know all possible enumerations of `T` and they all
        // must have a length <= 2^16 - 1.
        assert!(out.borrow().len() <= (u16::MAX as usize));
        let labeled_info = [
            &(out.borrow().len() as u16).to_be_bytes(),
            "APQ-v1".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            label,
            info,
        ];
        E::Kdf::expand_multi(out.borrow_mut(), prk, &labeled_info)?;
        Ok(out)
    }
}

/// An encrypted [`TopicKey`].
pub struct EncryptedTopicKey<E: Engine + ?Sized>(ByteArray<Sum<<E::Aead as Aead>::TagSize, U64>>)
where
    <E::Aead as Aead>::TagSize: Add<U64>,
    Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize;

impl<E: Engine + ?Sized> EncryptedTopicKey<E>
where
    <E::Aead as Aead>::TagSize: Add<U64>,
    Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize,
{
    const SIZE: usize = 64 + E::Aead::TAG_SIZE;

    /// Reutrns itself as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Returns itself from its byte encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, InvalidSizeError> {
        let v = data.try_into().map_err(|_| InvalidSizeError {
            got: data.len(),
            want: Self::SIZE..Self::SIZE,
        })?;
        Ok(Self(v))
    }
}

/// The private half of a [SenderSigningKey].
///
/// [SenderSigningKey]: https://github.com/spideroak-inc/apq/blob/spec/design.md#sendersigningkey
#[derive(ZeroizeOnDrop)]
pub struct SenderSigningKey<E: Engine + ?Sized>(<E::Signer as Signer>::SigningKey);

key_misc!(SenderSigningKey, SenderVerifyingKey, SenderSigningKeyId);

impl<E: Engine + ?Sized> SenderSigningKey<E> {
    /// Creates a `SenderSigningKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <E::Signer as Signer>::SigningKey::new(rng);
        SenderSigningKey(sk)
    }

    /// Creates a signature over an encoded record.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "moonshot")))]
    /// # {
    /// use crypto::{
    ///     apq::{SenderSigningKey, Topic, Version},
    ///     DefaultCipherSuite,
    ///     DefaultEngine,
    ///     Rng,
    /// };
    ///
    /// const VERSION: Version = Version(1);
    /// const TOPIC: Topic = Topic(4);
    /// const RECORD: &[u8] = b"an encoded record";
    /// const RECORD_NAME: &str = "MessageRecord";
    ///
    /// let sk = SenderSigningKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng);
    ///
    /// let sig = sk.sign(VERSION, TOPIC, RECORD, RECORD_NAME)
    ///     .expect("should not fail");
    ///
    /// sk.public().verify(VERSION, TOPIC, RECORD, RECORD_NAME, &sig)
    ///     .expect("should not fail");
    ///
    /// sk.public().verify(Version(VERSION.0 + 1), TOPIC, RECORD, RECORD_NAME, &sig)
    ///     .expect_err("should fail: wrong version");
    ///
    /// sk.public().verify(VERSION, Topic(TOPIC.0 + 1), RECORD, RECORD_NAME, &sig)
    ///     .expect_err("should fail: wrong topic");
    ///
    /// sk.public().verify(VERSION, TOPIC, b"wrong", RECORD_NAME, &sig)
    ///     .expect_err("should fail: wrong record");
    ///
    /// sk.public().verify(VERSION, TOPIC, RECORD, "SomeRecord", &sig)
    ///     .expect_err("should fail: wrong record name");
    ///
    /// let wrong_sig = sk.sign(Version(VERSION.0 + 1), Topic(TOPIC.0 + 1), b"foo", "bar")
    ///     .expect("should not fail");
    /// sk.public().verify(VERSION, TOPIC, RECORD, RECORD_NAME, &wrong_sig)
    ///     .expect_err("should fail: wrong signature");
    /// # }
    /// ```
    pub fn sign(
        &self,
        version: Version,
        topic: Topic,
        record: &[u8],
        record_name: &'static str,
    ) -> Result<Signature<E>, Error> {
        // message = concat(
        //     RecordName(record),
        //     i2osp(version, 4),
        //     i2osp(topic, 4),
        //     suite_id,
        //     pk(SenderSigningKey),
        //     context,
        //     encode(record),
        // )
        let msg = tuple_hash::<E::Hash, _>([
            record_name.as_bytes(),
            &version.to_be_bytes(),
            &topic.to_be_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            self.public().id().as_bytes(),
            record,
        ]);
        let sig = self.0.sign(&msg)?;
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

/// The public half of a [SenderSigningKey].
///
/// [SenderSigningKey]: https://github.com/spideroak-inc/apq/blob/spec/design.md#sendersigningkey
pub struct SenderVerifyingKey<E: Engine + ?Sized>(<E::Signer as Signer>::VerifyingKey);

impl<E: Engine + ?Sized> SenderVerifyingKey<E> {
    /// Verifies the signature allegedly created over an encoded
    /// record.
    pub fn verify(
        &self,
        version: Version,
        topic: Topic,
        record: &[u8],
        record_name: &'static str,
        sig: &Signature<E>,
    ) -> Result<(), Error> {
        // message = concat(
        //     RecordName(record),
        //     i2osp(version, 4),
        //     i2osp(topic, 4),
        //     suite_id,
        //     pk(SenderSigningKey),
        //     context,
        //     encode(record),
        // )
        let msg = tuple_hash::<E::Hash, _>([
            record_name.as_bytes(),
            &version.to_be_bytes(),
            &topic.to_be_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            self.id().as_bytes(),
            record,
        ]);
        Ok(self.0.verify(&msg, &sig.0)?)
    }
}

/// The private half of a [SenderKey].
///
/// [SenderKey]: https://github.com/spideroak-inc/apq/blob/spec/design.md#senderkey
#[derive(ZeroizeOnDrop)]
pub struct SenderSecretKey<E: Engine + ?Sized>(<E::Kem as Kem>::DecapKey);

key_misc!(SenderSecretKey, SenderPublicKey, SenderKeyId);

impl<E: Engine + ?Sized> SenderSecretKey<E> {
    /// Creates a `SenderSecretKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <E::Kem as Kem>::DecapKey::new(rng);
        SenderSecretKey(sk)
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

/// The public half of a [SenderKey].
///
/// [SenderKey]: https://github.com/spideroak-inc/apq/blob/spec/design.md#senderkey
pub struct SenderPublicKey<E: Engine + ?Sized>(<E::Kem as Kem>::EncapKey);

/// The private half of a [ReceiverKey].
///
/// [ReceiverKey]: https://github.com/spideroak-inc/apq/blob/spec/design.md#receiverkey
#[derive(ZeroizeOnDrop)]
pub struct ReceiverSecretKey<E: Engine + ?Sized>(<E::Kem as Kem>::DecapKey);

key_misc!(ReceiverSecretKey, ReceiverPublicKey, ReceiverKeyId);

impl<E: Engine + ?Sized> ReceiverSecretKey<E> {
    /// Creates a `ReceiverSecretKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <E::Kem as Kem>::DecapKey::new(rng);
        ReceiverSecretKey(sk)
    }

    /// Decrypts and authenticates a [`TopicKey`] received from
    /// a peer.
    pub fn open_topic_key(
        &self,
        version: Version,
        topic: Topic,
        pk: &SenderPublicKey<E>,
        enc: &Encap<E>,
        ciphertext: &EncryptedTopicKey<E>,
    ) -> Result<TopicKey<E>, Error>
    where
        <E::Aead as Aead>::TagSize: Add<U64>,
        Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize,
    {
        // ad = concat(
        //     i2osp(version, 4),
        //     i2osp(topic, 4),
        //     suite_id,
        //     "TopicKeyRotation",
        // )
        let ad = tuple_hash::<E::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.to_be_bytes()[..],
            &SuiteIds::from_suite::<E>().into_bytes(),
            b"TopicKeyRotation",
        ]);
        // ciphertext = HPKE_OneShotOpen(
        //     mode=mode_auth,
        //     skR=sk(ReceiverKey),
        //     pkS=pk(SenderEncKey),
        //     info="TopicKeyRotation",
        //     enc=enc,
        //     ciphertext=ciphertext,
        //     ad=ad,
        // )
        let mut ctx =
            Hpke::<E::Kem, E::Kdf, E::Aead>::setup_recv(Mode::Auth(&pk.0), &enc.0, &self.0, &ad)?;
        let mut seed = [0u8; 64];
        ctx.open(&mut seed, ciphertext.as_bytes(), &ad)?;
        TopicKey::from_seed(seed, version, topic)
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

/// The public half of a [ReceiverKey].
///
/// [ReceiverKey]: https://github.com/spideroak-inc/apq/blob/spec/design.md#receiverkey
pub struct ReceiverPublicKey<E: Engine + ?Sized>(<E::Kem as Kem>::EncapKey);

impl<E: Engine + ?Sized> ReceiverPublicKey<E> {
    /// Encrypts and authenticates the [`TopicKey`] such that it
    /// can only be decrypted by the holder of the private half
    /// of the [`ReceiverPublicKey`].
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "moonshot")))]
    /// # {
    /// use crypto::{
    ///     apq::{
    ///         ReceiverSecretKey,
    ///         SenderSecretKey,
    ///         Topic,
    ///         TopicKey,
    ///         Version,
    ///     },
    ///     DefaultCipherSuite,
    ///     DefaultEngine,
    ///     Id,
    ///     Rng,
    ///     UserId,
    /// };
    ///
    /// const VERSION: Version = Version(1);
    /// const TOPIC: Topic = Topic(4);
    ///
    /// let send_sk = SenderSecretKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng);
    /// let send_pk = send_sk.public();
    /// let recv_sk = ReceiverSecretKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng);
    /// let recv_pk = recv_sk.public();
    ///
    /// let key = TopicKey::new(&mut Rng, VERSION, TOPIC)
    ///     .expect("should not fail");
    ///
    /// // The sender encrypts...
    /// let (enc, mut ciphertext) = recv_pk.seal_topic_key(
    ///     &mut Rng,
    ///     VERSION,
    ///     TOPIC,
    ///     &send_sk,
    ///     &key,
    /// ).expect("should not fail");
    /// // ...and the receiver decrypts.
    /// let got = recv_sk.open_topic_key(
    ///     VERSION,
    ///     TOPIC,
    ///     &send_pk,
    ///     &enc,
    ///     &ciphertext,
    /// ).expect("should not fail");
    /// assert_eq!(got.id(), key.id());
    ///
    /// // Wrong version.
    /// recv_sk.open_topic_key(
    ///     Version(VERSION.0 + 1),
    ///     TOPIC,
    ///     &send_pk,
    ///     &enc,
    ///     &ciphertext,
    /// ).err().expect("should fail: wrong version");
    ///
    /// // Wrong topic.
    /// recv_sk.open_topic_key(
    ///     VERSION,
    ///     Topic(TOPIC.0 + 1),
    ///     &send_pk,
    ///     &enc,
    ///     &ciphertext,
    /// ).err().expect("should fail: wrong topic");
    /// # }
    /// ```
    pub fn seal_topic_key<R: Csprng>(
        &self,
        rng: &mut R,
        version: Version,
        topic: Topic,
        sk: &SenderSecretKey<E>,
        key: &TopicKey<E>,
    ) -> Result<(Encap<E>, EncryptedTopicKey<E>), Error>
    where
        <E::Aead as Aead>::TagSize: Add<U64>,
        Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize,
    {
        // ad = concat(
        //     i2osp(version, 4),
        //     i2osp(topic, 4),
        //     suite_id,
        //     "TopicKeyRotation",
        // )
        let ad = tuple_hash::<E::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.to_be_bytes()[..],
            &SuiteIds::from_suite::<E>().into_bytes(),
            b"TopicKeyRotation",
        ]);
        // (enc, ciphertext) = HPKE_OneShotSeal(
        //     mode=mode_auth,
        //     pkR=pk(ReceiverKey),
        //     skS=sk(SenderKey),
        //     info=ad,
        //     plaintext=seed,
        //     ad=ad,
        // )
        let (enc, mut ctx) =
            Hpke::<E::Kem, E::Kdf, E::Aead>::setup_send(rng, Mode::Auth(&sk.0), &self.0, &ad)?;
        let mut dst = ByteArray::default();
        ctx.seal(&mut dst, &key.seed, &ad)?;
        Ok((Encap(enc), EncryptedTopicKey(dst)))
    }
}
