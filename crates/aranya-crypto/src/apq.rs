//! Cryptography code for [APQ].
//!
//! [APQ]: https://git.spideroak-inc.com/spideroak-inc/apq

#![forbid(unsafe_code)]

use core::{borrow::Borrow, fmt, ops::Add, result::Result};

use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use siphasher::sip128::SipHasher24;

use crate::{
    aead::{Aead, BufferTooSmallError, KeyData, OpenError, SealError},
    aranya::{Encap, Signature},
    ciphersuite::SuiteIds,
    csprng::{Csprng, Random},
    engine::unwrapped,
    error::Error,
    generic_array::{ArrayLength, GenericArray},
    hash::tuple_hash,
    hex::ToHex,
    hmac::Hmac,
    hpke::{Hpke, Mode},
    id::custom_id,
    import::{Import, ImportError},
    kdf::Context,
    kem::{DecapKey, Kem},
    keys::{PublicKey, SecretKey},
    misc::{ciphertext, key_misc},
    signer::{Signer, SigningKey as SigningKey_, VerifyingKey as VerifyingKey_},
    typenum::{Sum, U64},
    zeroize::{Zeroize, ZeroizeOnDrop},
    CipherSuite,
};

/// A sender's identity.
pub struct Sender<'a, CS: CipherSuite> {
    /// The sender's public key.
    pub enc_key: &'a SenderPublicKey<CS>,
    /// The sender's verifying key.
    pub sign_key: &'a SenderVerifyingKey<CS>,
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

custom_id! {
    /// Uniquely identifies a [`TopicKey`].
    pub struct TopicKeyId;
}

/// A [symmetric key] used to encrypt queue messages for
/// a particular topic.
///
/// [symmetric key]: https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/main/src/apq.md#topickey
pub struct TopicKey<CS: CipherSuite> {
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
    key: <CS::Aead as Aead>::Key,
    seed: [u8; 64],
}

impl<CS: CipherSuite> ZeroizeOnDrop for TopicKey<CS> {}
impl<CS: CipherSuite> Drop for TopicKey<CS> {
    fn drop(&mut self) {
        self.seed.zeroize()
    }
}

impl<CS: CipherSuite> Clone for TopicKey<CS> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            seed: self.seed,
        }
    }
}

impl<CS: CipherSuite> TopicKey<CS> {
    /// Creates a new, random `TopicKey`.
    pub fn new<R: Csprng>(rng: &mut R, version: Version, topic: &Topic) -> Result<Self, Error> {
        Self::from_seed(Random::random(rng), version, topic)
    }

    /// Uniquely identifies the [`TopicKey`].
    ///
    /// Two keys with the same ID are the same key.
    #[inline]
    pub fn id(&self) -> TopicKeyId {
        // ID = HMAC(
        //     key=TopicKey,
        //     message="TopicKeyId-v1" || suite_id,
        //     outputBytes=64,
        // )
        let mut h = Hmac::<CS::Hash>::new(&self.seed);
        h.update(b"TopicKeyId-v1");
        h.update(&SuiteIds::from_suite::<CS>().into_bytes());
        TopicKeyId(h.tag().into_array().into())
    }

    /// The size in bytes of the overhead added to plaintexts
    /// when encrypted.
    pub const OVERHEAD: usize = CS::Aead::NONCE_SIZE + CS::Aead::OVERHEAD;

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
    /// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
    /// # {
    /// use aranya_crypto::{
    ///     apq::{
    ///         Sender,
    ///         SenderSecretKey,
    ///         SenderSigningKey,
    ///         Topic,
    ///         TopicKey,
    ///         Version,
    ///     },
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     Id,
    ///     Rng,
    ///     DeviceId,
    /// };
    ///
    /// const VERSION: Version = Version::new(1);
    /// let topic = Topic::new("SomeTopic");
    /// const MESSAGE: &[u8] = b"hello, world!";
    ///
    /// let ident = Sender {
    ///     enc_key: &SenderSecretKey::<DefaultCipherSuite>::new(&mut Rng)
    ///         .public().expect("sender encryption key should be valid"),
    ///     sign_key: &SenderSigningKey::<DefaultCipherSuite>::new(&mut Rng)
    ///         .public().expect("sender signing key should be valid"),
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
        ident: &Sender<'_, CS>,
    ) -> Result<(), Error> {
        if dst.len() < self.overhead() {
            // Not enough room in `dst`.
            return Err(Error::Seal(SealError::BufferTooSmall(BufferTooSmallError(
                self.overhead().checked_add(plaintext.len()),
            ))));
        }
        // ad = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     hash(pk(SenderKey)),
        //     hash(pk(SenderSigningKey)),
        // )
        let ad = tuple_hash::<CS::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.as_bytes()[..],
            &SuiteIds::from_suite::<CS>().into_bytes(),
            ident.enc_key.id()?.as_bytes(),
            ident.sign_key.id()?.as_bytes(),
        ]);
        let (nonce, out) = dst.split_at_mut(CS::Aead::NONCE_SIZE);
        rng.fill_bytes(nonce);
        Ok(CS::Aead::new(&self.key).seal(out, nonce, plaintext, &ad)?)
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
        ident: &Sender<'_, CS>,
    ) -> Result<(), Error> {
        if ciphertext.len() < self.overhead() {
            // Can't find the nonce and/or tag, so it's obviously
            // invalid.
            return Err(OpenError::Authentication.into());
        }
        let (nonce, ciphertext) = ciphertext.split_at(CS::Aead::NONCE_SIZE);
        // ad = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     hash(pk(SenderSigningKey)),
        // )
        let ad = tuple_hash::<CS::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.as_bytes()[..],
            &SuiteIds::from_suite::<CS>().into_bytes(),
            ident.enc_key.id()?.as_bytes(),
            ident.sign_key.id()?.as_bytes(),
        ]);
        Ok(CS::Aead::new(&self.key).open(dst, nonce, ciphertext, &ad)?)
    }

    fn from_seed(seed: [u8; 64], version: Version, topic: &Topic) -> Result<Self, Error> {
        let key = Self::derive_key(&seed, version, topic)?;
        Ok(Self { key, seed })
    }

    const KDF_CTX: Context = Context {
        domain: "APQ-v1",
        suite_ids: &SuiteIds::from_suite::<CS>().into_bytes(),
    };

    /// Derives a key for [`Self::open`] and [`Self::seal`].
    ///
    /// See <https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/main/src/apq.md#topickey-generation>
    fn derive_key(
        seed: &[u8; 64],
        version: Version,
        topic: &Topic,
    ) -> Result<<CS::Aead as Aead>::Key, Error> {
        // prk = LabeledExtract({0}^512, seed, "topic_key_prk")
        let prk = Self::KDF_CTX.labeled_extract::<CS::Kdf>(&[], "topic_key_prk", seed);
        // info = concat(
        //     i2osp(version, 4),
        //     topic,
        // )
        // key = LabeledExpand(prk, "topic_key_key", info, L)
        let key = Self::KDF_CTX.labeled_expand::<CS::Kdf, KeyData<CS::Aead>>(
            &prk,
            "topic_key_key",
            &[&version.to_be_bytes(), &topic.as_bytes()[..]],
        )?;

        Ok(<<CS::Aead as Aead>::Key as Import<_>>::import(
            key.as_bytes(),
        )?)
    }
}

ciphertext!(EncryptedTopicKey, U64, "An encrypted [`TopicKey`].");

/// The private half of a [SenderSigningKey].
///
/// [SenderSigningKey]: https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/main/src/apq.md#sendersigningkey
pub struct SenderSigningKey<CS: CipherSuite>(<CS::Signer as Signer>::SigningKey);

key_misc!(SenderSigningKey, SenderVerifyingKey, SenderSigningKeyId);

impl<CS: CipherSuite> SenderSigningKey<CS> {
    /// Creates a `SenderSigningKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <CS::Signer as Signer>::SigningKey::new(rng);
        SenderSigningKey(sk)
    }

    /// Creates a signature over an encoded record.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
    /// # {
    /// use aranya_crypto::{
    ///     apq::{SenderSigningKey, Topic, Version},
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     Rng,
    /// };
    ///
    /// const VERSION: Version = Version::new(1);
    /// let topic = Topic::new("SomeTopic");
    /// const RECORD: &[u8] = b"an encoded record";
    ///
    /// let sk = SenderSigningKey::<DefaultCipherSuite>::new(&mut Rng);
    ///
    /// let sig = sk.sign(VERSION, &topic, RECORD)
    ///     .expect("should not fail");
    ///
    /// sk.public().expect("sender signing key should be valid").verify(VERSION, &topic, RECORD, &sig)
    ///     .expect("should not fail");
    ///
    /// sk.public().expect("sender signing key should be valid").verify(Version::new(2), &topic, RECORD, &sig)
    ///     .expect_err("should fail: wrong version");
    ///
    /// sk.public().expect("sender signing key should be valid").verify(VERSION, &Topic::new("WrongTopic"), RECORD, &sig)
    ///     .expect_err("should fail: wrong topic");
    ///
    /// sk.public().expect("sender signing key should be valid").verify(VERSION, &topic, b"wrong", &sig)
    ///     .expect_err("should fail: wrong record");
    ///
    /// let wrong_sig = sk
    ///     .sign(
    ///         Version::new(2),
    ///         &Topic::new("AnotherTopic"),
    ///         b"encoded record",
    ///     )
    ///     .expect("should not fail");
    /// sk.public().expect("sender signing key should be valid").verify(VERSION, &topic, RECORD, &wrong_sig)
    ///     .expect_err("should fail: wrong signature");
    /// # }
    /// ```
    pub fn sign(
        &self,
        version: Version,
        topic: &Topic,
        record: &[u8],
    ) -> Result<Signature<CS>, Error> {
        // message = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     pk(SenderSigningKey),
        //     encode(record),
        // )
        let msg = tuple_hash::<CS::Hash, _>([
            &version.to_be_bytes(),
            &topic.as_bytes()[..],
            &SuiteIds::from_suite::<CS>().into_bytes(),
            self.public()?.id()?.as_bytes(),
            record,
        ]);
        let sig = self.0.sign(&msg)?;
        Ok(Signature(sig))
    }
}

unwrapped! {
    name: SenderSigningKey;
    type: Signing;
    into: |key: Self| { key.0 };
    from: |key| { Self(key) };
}

/// The public half of a [SenderSigningKey].
///
/// [SenderSigningKey]: https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/main/src/apq.md#sendersigningkey
pub struct SenderVerifyingKey<CS: CipherSuite>(<CS::Signer as Signer>::VerifyingKey);

impl<CS: CipherSuite> SenderVerifyingKey<CS> {
    /// Verifies the signature allegedly created over an encoded
    /// record.
    pub fn verify(
        &self,
        version: Version,
        topic: &Topic,
        record: &[u8],
        sig: &Signature<CS>,
    ) -> Result<(), Error> {
        // message = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     pk(SenderSigningKey),
        //     context,
        //     encode(record),
        // )
        let msg = tuple_hash::<CS::Hash, _>([
            &version.to_be_bytes(),
            &topic.as_bytes()[..],
            &SuiteIds::from_suite::<CS>().into_bytes(),
            self.id()?.as_bytes(),
            record,
        ]);
        Ok(self.0.verify(&msg, &sig.0)?)
    }
}

/// The private half of a [SenderKey].
///
/// [SenderKey]: https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/main/src/apq.md#senderkey
pub struct SenderSecretKey<CS: CipherSuite>(<CS::Kem as Kem>::DecapKey);

key_misc!(SenderSecretKey, SenderPublicKey, SenderKeyId);

impl<CS: CipherSuite> SenderSecretKey<CS> {
    /// Creates a `SenderSecretKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <CS::Kem as Kem>::DecapKey::new(rng);
        SenderSecretKey(sk)
    }
}

unwrapped! {
    name: SenderSecretKey;
    type: Decap;
    into: |key: Self| { key.0 };
    from: |key| { Self(key) };
}

/// The public half of a [SenderKey].
///
/// [SenderKey]: https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/main/src/apq.md#senderkey
pub struct SenderPublicKey<CS: CipherSuite>(<CS::Kem as Kem>::EncapKey);

/// The private half of a [ReceiverKey].
///
/// [ReceiverKey]: https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/main/src/apq.md#receiverkey
pub struct ReceiverSecretKey<CS: CipherSuite>(<CS::Kem as Kem>::DecapKey);

key_misc!(ReceiverSecretKey, ReceiverPublicKey, ReceiverKeyId);

impl<CS: CipherSuite> ReceiverSecretKey<CS> {
    /// Creates a `ReceiverSecretKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> Self {
        let sk = <CS::Kem as Kem>::DecapKey::new(rng);
        ReceiverSecretKey(sk)
    }

    /// Decrypts and authenticates a [`TopicKey`] received from
    /// a peer.
    pub fn open_topic_key(
        &self,
        version: Version,
        topic: &Topic,
        pk: &SenderPublicKey<CS>,
        enc: &Encap<CS>,
        ciphertext: &EncryptedTopicKey<CS>,
    ) -> Result<TopicKey<CS>, Error>
    where
        <CS::Aead as Aead>::Overhead: Add<U64>,
        Sum<<CS::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        // ad = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     "TopicKeyRotation",
        // )
        let ad = tuple_hash::<CS::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.as_bytes()[..],
            &SuiteIds::from_suite::<CS>().into_bytes(),
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
        let mut ctx = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_recv(
            Mode::Auth(&pk.0),
            &enc.0,
            &self.0,
            &ad,
        )?;
        let mut seed = [0u8; 64];
        ctx.open(&mut seed, ciphertext.as_bytes(), &ad)?;
        TopicKey::from_seed(seed, version, topic)
    }
}

unwrapped! {
    name: ReceiverSecretKey;
    type: Decap;
    into: |key: Self| { key.0 };
    from: |key| { Self(key) };
}

/// The public half of a [ReceiverKey].
///
/// [ReceiverKey]: https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/main/src/apq.md#receiverkey
pub struct ReceiverPublicKey<CS: CipherSuite>(<CS::Kem as Kem>::EncapKey);

impl<CS: CipherSuite> ReceiverPublicKey<CS> {
    /// Encrypts and authenticates the [`TopicKey`] such that it
    /// can only be decrypted by the holder of the private half
    /// of the [`ReceiverPublicKey`].
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
    /// # {
    /// use aranya_crypto::{
    ///     apq::{
    ///         ReceiverSecretKey,
    ///         SenderSecretKey,
    ///         Topic,
    ///         TopicKey,
    ///         Version,
    ///     },
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     Id,
    ///     Rng,
    ///     DeviceId,
    /// };
    ///
    /// const VERSION: Version = Version::new(1);
    /// let topic = Topic::new("SomeTopic");
    ///
    /// let send_sk = SenderSecretKey::<DefaultCipherSuite>::new(&mut Rng);
    /// let send_pk = send_sk.public().expect("sender public key should be valid");
    /// let recv_sk = ReceiverSecretKey::<DefaultCipherSuite>::new(&mut Rng);
    /// let recv_pk = recv_sk.public().expect("receiver public key should be valid");
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
        sk: &SenderSecretKey<CS>,
        key: &TopicKey<CS>,
    ) -> Result<(Encap<CS>, EncryptedTopicKey<CS>), Error>
    where
        <CS::Aead as Aead>::Overhead: Add<U64>,
        Sum<<CS::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        // ad = concat(
        //     i2osp(version, 4),
        //     topic,
        //     suite_id,
        //     "TopicKeyRotation",
        // )
        let ad = tuple_hash::<CS::Hash, _>([
            &version.to_be_bytes()[..],
            &topic.as_bytes()[..],
            &SuiteIds::from_suite::<CS>().into_bytes(),
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
            Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send(rng, Mode::Auth(&sk.0), &self.0, &ad)?;
        let mut dst = GenericArray::default();
        ctx.seal(&mut dst, &key.seed, &ad)?;
        Ok((Encap(enc), EncryptedTopicKey(dst)))
    }
}
