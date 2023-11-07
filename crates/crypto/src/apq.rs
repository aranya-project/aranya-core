//! Cryptography code for [APQ].
//!
//! [APQ]: https://git.spideroak-inc.com/spideroak-inc/apq

#![forbid(unsafe_code)]

use core::{
    borrow::{Borrow, BorrowMut},
    fmt,
    ops::Add,
    result::Result,
};

use generic_array::{ArrayLength, GenericArray};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use siphasher::sip128::SipHasher24;
use typenum::{Sum, U64};

use crate::{
    aead::{Aead, BufferTooSmallError, KeyData, OpenError, SealError},
    aranya::{Encap, Signature},
    ciphersuite::SuiteIds,
    csprng::Csprng,
    engine::Engine,
    error::Error,
    hash::tuple_hash,
    hex::ToHex,
    hpke::{Hpke, Mode},
    id::custom_id,
    import::{ExportError, Import, ImportError},
    kdf::{Kdf, KdfError},
    kem::{DecapKey, Kem},
    keys::{PublicKey, SecretKey},
    mac::Mac,
    misc::{ciphertext, key_misc, DecapKeyData, SigningKeyData},
    signer::{Signer, SigningKey as SigningKey_, VerifyingKey as VerifyingKey_},
    zeroize::{Zeroize, ZeroizeOnDrop},
};

/// A sender's identity.
pub struct Sender<'a, E: Engine + ?Sized> {
    /// The sender's public key.
    pub enc_key: &'a SenderPublicKey<E>,
    /// The sender's verifying key.
    pub sign_key: &'a SenderVerifyingKey<E>,
}

/// The current APQ version.
#[derive(Copy, Clone, Debug, Default)]
pub struct Version(u32);

impl Version {
    /// Creates a new version.
    pub const fn new(version: u32) -> Self {
        Self(version)
    }

    /// Returns the version as a `u32`.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// The APQ topic being used.
#[derive(
    Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, MaxSize,
)]
pub struct Topic([u8; 16]);

impl Topic {
    /// Creates a new topic.
    pub fn new<T: AsRef<[u8]>>(topic: T) -> Self {
        let d = SipHasher24::new().hash(topic.as_ref());
        Self(d.as_bytes())
    }

    /// Converts itself into its byte representation.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Converts itself into its byte representation.
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl AsRef<[u8]> for Topic {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl From<[u8; 16]> for Topic {
    fn from(val: [u8; 16]) -> Self {
        Self(val)
    }
}

impl From<Topic> for [u8; 16] {
    fn from(topic: Topic) -> [u8; 16] {
        topic.0
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

custom_id!(TopicKeyId, "Uniquely identifies a [`TopicKey`].");

/// A [symmetric key] used to encrypt queue messages for
/// a particular topic.
///
/// [symmetric key]: https://git.spideroak-inc.com/spideroak-inc/apq/blob/spec/design.md#topickey
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
    pub fn new<R: Csprng>(rng: &mut R, version: Version, topic: &Topic) -> Result<Self, Error> {
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
    pub const OVERHEAD: usize = E::Aead::NONCE_SIZE + E::Aead::OVERHEAD;

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
    /// const VERSION: Version = Version::new(1);
    /// let topic = Topic::new("SomeTopic");
    /// const MESSAGE: &[u8] = b"hello, world!";
    ///
    /// let ident = Sender {
    ///     enc_key: &SenderSecretKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng)
    ///         .public(),
    ///     sign_key: &SenderSigningKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng)
    ///         .public(),
    /// };
    ///
    /// let key = TopicKey::new(&mut Rng, VERSION, &topic)
    ///     .expect("should not fail");
    ///
    /// let ciphertext = {
    ///     let mut dst = vec![0u8; MESSAGE.len() + key.overhead()];
    ///     key.seal_message(
    ///         &mut Rng,
    ///         &mut dst,
    ///         MESSAGE,
    ///         VERSION,
    ///         &topic,
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
    ///         &topic,
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
        topic: &Topic,
        ident: &Sender<'_, E>,
    ) -> Result<(), Error> {
        if dst.len() < self.overhead() {
            // Not enough room in `dst`.
            return Err(Error::Seal(SealError::BufferTooSmall(BufferTooSmallError(
                Some(self.overhead() + plaintext.len()),
            ))));
        }
        // ad = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     hash(pk(SenderKey)),
        //     hash(pk(SenderSigningKey)),
        // )
        let ad = tuple_hash::<E::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.as_bytes()[..],
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
        topic: &Topic,
        ident: &Sender<'_, E>,
    ) -> Result<(), Error> {
        if ciphertext.len() < self.overhead() {
            // Can't find the nonce and/or tag, so it's obviously
            // invalid.
            return Err(OpenError::Authentication.into());
        }
        let (nonce, ciphertext) = ciphertext.split_at(E::Aead::NONCE_SIZE);
        // ad = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     hash(pk(SenderSigningKey)),
        // )
        let ad = tuple_hash::<E::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.as_bytes()[..],
            &SuiteIds::from_suite::<E>().into_bytes(),
            ident.enc_key.id().as_bytes(),
            ident.sign_key.id().as_bytes(),
        ]);
        Ok(E::Aead::new(&self.key).open(dst, nonce, ciphertext, &ad)?)
    }

    fn from_seed(seed: [u8; 64], version: Version, topic: &Topic) -> Result<Self, Error> {
        let key = Self::derive_key(&seed, version, topic)?;
        Ok(Self { key, seed })
    }

    /// Derives a key for [`Self::open`] and [`Self::seal`].
    ///
    /// See <https://git.spideroak-inc.com/spideroak-inc/apq/blob/spec/design.md#topickey-generation>
    fn derive_key(
        seed: &[u8; 64],
        version: Version,
        topic: &Topic,
    ) -> Result<<E::Aead as Aead>::Key, Error> {
        // prk = LabeledExtract({0}^512, seed, "topic_key_prk")
        let prk = Self::labeled_extract(&[], b"topic_key_prk", seed);
        // info = concat(
        //     i2osp(version, 4),
        //     topic,
        // )
        // key = LabeledExpand(prk, "topic_key_key", info, L)
        let key =
            Self::labeled_expand::<KeyData<E::Aead>, 13>(&prk, b"topic_key_key", version, topic)?;
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
        version: Version,
        topic: &Topic,
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
            &version.to_be_bytes(),
            &topic.as_bytes()[..],
        ];
        E::Kdf::expand_multi(out.borrow_mut(), prk, &labeled_info)?;
        Ok(out)
    }
}

ciphertext!(EncryptedTopicKey, U64, "An encrypted [`TopicKey`].");

/// The private half of a [SenderSigningKey].
///
/// [SenderSigningKey]: https://git.spideroak-inc.com/spideroak-inc/apq/blob/spec/design.md#sendersigningkey
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
    /// const VERSION: Version = Version::new(1);
    /// let topic = Topic::new("SomeTopic");
    /// const RECORD: &[u8] = b"an encoded record";
    ///
    /// let sk = SenderSigningKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng);
    ///
    /// let sig = sk.sign(VERSION, &topic, RECORD)
    ///     .expect("should not fail");
    ///
    /// sk.public().verify(VERSION, &topic, RECORD, &sig)
    ///     .expect("should not fail");
    ///
    /// sk.public().verify(Version::new(2), &topic, RECORD, &sig)
    ///     .expect_err("should fail: wrong version");
    ///
    /// sk.public().verify(VERSION, &Topic::new("WrongTopic"), RECORD, &sig)
    ///     .expect_err("should fail: wrong topic");
    ///
    /// sk.public().verify(VERSION, &topic, b"wrong", &sig)
    ///     .expect_err("should fail: wrong record");
    ///
    /// let wrong_sig = sk
    ///     .sign(
    ///         Version::new(2),
    ///         &Topic::new("AnotherTopic"),
    ///         b"encoded record",
    ///     )
    ///     .expect("should not fail");
    /// sk.public().verify(VERSION, &topic, RECORD, &wrong_sig)
    ///     .expect_err("should fail: wrong signature");
    /// # }
    /// ```
    pub fn sign(
        &self,
        version: Version,
        topic: &Topic,
        record: &[u8],
    ) -> Result<Signature<E>, Error> {
        // message = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     pk(SenderSigningKey),
        //     encode(record),
        // )
        let msg = tuple_hash::<E::Hash, _>([
            &version.to_be_bytes(),
            &topic.as_bytes()[..],
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
/// [SenderSigningKey]: https://git.spideroak-inc.com/spideroak-inc/apq/blob/spec/design.md#sendersigningkey
pub struct SenderVerifyingKey<E: Engine + ?Sized>(<E::Signer as Signer>::VerifyingKey);

impl<E: Engine + ?Sized> SenderVerifyingKey<E> {
    /// Verifies the signature allegedly created over an encoded
    /// record.
    pub fn verify(
        &self,
        version: Version,
        topic: &Topic,
        record: &[u8],
        sig: &Signature<E>,
    ) -> Result<(), Error> {
        // message = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     pk(SenderSigningKey),
        //     context,
        //     encode(record),
        // )
        let msg = tuple_hash::<E::Hash, _>([
            &version.to_be_bytes(),
            &topic.as_bytes()[..],
            &SuiteIds::from_suite::<E>().into_bytes(),
            self.id().as_bytes(),
            record,
        ]);
        Ok(self.0.verify(&msg, &sig.0)?)
    }
}

/// The private half of a [SenderKey].
///
/// [SenderKey]: https://git.spideroak-inc.com/spideroak-inc/apq/blob/spec/design.md#senderkey
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
/// [SenderKey]: https://git.spideroak-inc.com/spideroak-inc/apq/blob/spec/design.md#senderkey
pub struct SenderPublicKey<E: Engine + ?Sized>(<E::Kem as Kem>::EncapKey);

/// The private half of a [ReceiverKey].
///
/// [ReceiverKey]: https://git.spideroak-inc.com/spideroak-inc/apq/blob/spec/design.md#receiverkey
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
        topic: &Topic,
        pk: &SenderPublicKey<E>,
        enc: &Encap<E>,
        ciphertext: &EncryptedTopicKey<E>,
    ) -> Result<TopicKey<E>, Error>
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        // ad = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     "TopicKeyRotation",
        // )
        let ad = tuple_hash::<E::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.as_bytes()[..],
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
/// [ReceiverKey]: https://git.spideroak-inc.com/spideroak-inc/apq/blob/spec/design.md#receiverkey
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
    /// const VERSION: Version = Version::new(1);
    /// let topic = Topic::new("SomeTopic");
    ///
    /// let send_sk = SenderSecretKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng);
    /// let send_pk = send_sk.public();
    /// let recv_sk = ReceiverSecretKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng);
    /// let recv_pk = recv_sk.public();
    ///
    /// let key = TopicKey::new(&mut Rng, VERSION, &topic)
    ///     .expect("should not fail");
    ///
    /// // The sender encrypts...
    /// let (enc, mut ciphertext) = recv_pk.seal_topic_key(
    ///     &mut Rng,
    ///     VERSION,
    ///     &topic,
    ///     &send_sk,
    ///     &key,
    /// ).expect("should not fail");
    /// // ...and the receiver decrypts.
    /// let got = recv_sk.open_topic_key(
    ///     VERSION,
    ///     &topic,
    ///     &send_pk,
    ///     &enc,
    ///     &ciphertext,
    /// ).expect("should not fail");
    /// assert_eq!(got.id(), key.id());
    ///
    /// // Wrong version.
    /// recv_sk.open_topic_key(
    ///     Version::new(2),
    ///     &topic,
    ///     &send_pk,
    ///     &enc,
    ///     &ciphertext,
    /// ).err().expect("should fail: wrong version");
    ///
    /// // Wrong topic.
    /// recv_sk.open_topic_key(
    ///     VERSION,
    ///     &Topic::new("WrongTopic"),
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
        topic: &Topic,
        sk: &SenderSecretKey<E>,
        key: &TopicKey<E>,
    ) -> Result<(Encap<E>, EncryptedTopicKey<E>), Error>
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        // ad = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     "TopicKeyRotation",
        // )
        let ad = tuple_hash::<E::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.as_bytes()[..],
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
        let mut dst = GenericArray::default();
        ctx.seal(&mut dst, &key.seed, &ad)?;
        Ok((Encap(enc), EncryptedTopicKey(dst)))
    }
}
