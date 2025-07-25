use core::cell::OnceCell;

use buggy::BugExt;
use derive_where::derive_where;
use spideroak_crypto::{csprng::Random, import::ImportError, kem::Kem};
use zerocopy::{
    ByteEq, Immutable, IntoBytes, KnownLayout, Unaligned,
    byteorder::{BE, U32},
};

use crate::{
    afc::{
        keys::{OpenKey, SealKey, Seq},
        shared::{RawOpenKey, RawSealKey, RootChannelKey},
    },
    aranya::{DeviceId, Encap, EncryptionKey, EncryptionPublicKey},
    ciphersuite::CipherSuite,
    engine::{Engine, unwrapped},
    error::Error,
    hpke::{self, Mode},
    id::{Id, IdError, custom_id},
    misc::sk_misc,
};

/// Contextual information for a bidirectional AFC channel.
///
/// In a bidirectional channel, both devices can encrypt and
/// decrypt messages.
///
/// ```rust
/// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
/// # {
/// use {
///     core::borrow::{Borrow, BorrowMut},
///     aranya_crypto::{
///         afc::{
///             AuthData,
///             BidiAuthorSecret,
///             BidiChannel,
///             BidiKeys,
///             BidiPeerEncap,
///             BidiSecrets,
///             OpenKey,
///             SealKey,
///         },
///         CipherSuite,
///         Csprng,
///         default::{
///             DefaultCipherSuite,
///             DefaultEngine,
///         },
///         Engine,
///         Id,
///         IdentityKey,
///         EncryptionKey,
///         Rng,
///     }
/// };
///
/// struct Keys<CS: CipherSuite> {
///     seal: SealKey<CS>,
///     open: OpenKey<CS>,
/// }
///
/// impl<CS: CipherSuite> Keys<CS> {
///     fn from_author(
///         ch: &BidiChannel<'_, CS>,
///         secret: BidiAuthorSecret<CS>,
///     ) -> Self {
///         let keys = BidiKeys::from_author_secret(ch, secret)
///             .expect("should be able to create author keys");
///         let (seal, open) = keys.into_keys()
///             .expect("should be able to convert `BidiKeys`");
///         Self { seal, open }
///     }
///
///     fn from_peer(
///         ch: &BidiChannel<'_, CS>,
///         encap: BidiPeerEncap<CS>,
///     ) -> Self {
///         let keys = BidiKeys::from_peer_encap(ch, encap)
///             .expect("should be able to decapsulate peer keys");
///         let (seal, open) = keys.into_keys()
///             .expect("should be able to convert `BidiKeys`");
///         Self { seal, open }
///     }
/// }
///
/// type E = DefaultEngine<Rng, DefaultCipherSuite>;
/// let (mut eng, _) = E::from_entropy(Rng);
///
/// let parent_cmd_id = Id::random(&mut eng);
/// let label = 42u32;
///
/// let device1_sk = EncryptionKey::<<E as Engine>::CS>::new(&mut eng);
/// let device1_id = IdentityKey::<<E as Engine>::CS>::new(&mut eng).id().expect("device1 ID should be valid");
///
/// let device2_sk = EncryptionKey::<<E as Engine>::CS>::new(&mut eng);
/// let device2_id = IdentityKey::<<E as Engine>::CS>::new(&mut eng).id().expect("device2 ID should be valid");
///
/// // device1 creates the channel keys and sends the encapsulation
/// // to device2...
/// let device1_ch = BidiChannel {
///     parent_cmd_id,
///     our_sk: &device1_sk,
///     our_id: device1_id,
///     their_pk: &device2_sk.public().expect("receiver encryption public key should be valid"),
///     their_id: device2_id,
///     label,
/// };
/// let BidiSecrets { author, peer } = BidiSecrets::new(&mut eng, &device1_ch)
///     .expect("unable to create `BidiSecrets`");
/// let mut device1 = Keys::from_author(&device1_ch, author);
///
/// // ...and device2 decrypts the encapsulation to discover the
/// // channel keys.
/// let device2_ch = BidiChannel {
///     parent_cmd_id,
///     our_sk: &device2_sk,
///     our_id: device2_id,
///     their_pk: &device1_sk.public().expect("receiver encryption public key should be valid"),
///     their_id: device1_id,
///     label,
/// };
/// let mut device2 = Keys::from_peer(&device2_ch, peer);
///
/// fn test<CS: CipherSuite>(a: &mut Keys<CS>, b: &Keys<CS>) {
///     const GOLDEN: &[u8] = b"hello, world!";
///     const ADDITIONAL_DATA: &[u8] = b"authenticated, but not encrypted data";
///
///     let version = 4;
///     let label = 1234;
///     let (ciphertext, seq) = {
///         let mut dst = vec![0u8; GOLDEN.len() + SealKey::<CS>::OVERHEAD];
///         let ad = AuthData { version, label };
///         let seq = a.seal.seal(&mut dst, GOLDEN, &ad)
///             .expect("should be able to encrypt plaintext");
///         (dst, seq)
///     };
///     let plaintext = {
///         let mut dst = vec![0u8; ciphertext.len()];
///         let ad = AuthData { version, label };
///         b.open.open(&mut dst, &ciphertext, &ad, seq)
///             .expect("should be able to decrypt ciphertext");
///         dst.truncate(ciphertext.len() - OpenKey::<CS>::OVERHEAD);
///         dst
///     };
///     assert_eq!(&plaintext, GOLDEN);
/// }
/// test(&mut device1, &device2); // device1 -> device2
/// test(&mut device2, &device1); // device2 -> device1
/// # }
/// ```
pub struct BidiChannel<'a, CS: CipherSuite> {
    /// The ID of the parent command.
    pub parent_cmd_id: Id,
    /// Our secret encryption key.
    pub our_sk: &'a EncryptionKey<CS>,
    /// Our DeviceID.
    pub our_id: DeviceId,
    /// Their public encryption key.
    pub their_pk: &'a EncryptionPublicKey<CS>,
    /// Their DeviceID.
    pub their_id: DeviceId,
    /// The policy label applied to the channel.
    pub label: u32,
}

impl<CS: CipherSuite> BidiChannel<'_, CS> {
    /// The author's `info` parameter.
    pub(crate) const fn author_info(&self) -> Info {
        // info = concat(
        //     "AfcBidiKeys-v1",
        //     parent_cmd_id,
        //     their_id,
        //     our_id,
        //     i2osp(label, 4),
        // )
        Info {
            domain: *b"AfcBidiKeys-v1",
            parent_cmd_id: self.parent_cmd_id,
            their_id: self.their_id,
            our_id: self.our_id,
            label: U32::new(self.label),
        }
    }

    /// The peer's `info` parameter.
    pub(crate) const fn peer_info(&self) -> Info {
        // Same as the author's info, except that we're computing
        // it from the peer's perspective, so `our_id` and
        // `their_id` are reversed.
        Info {
            domain: *b"AfcBidiKeys-v1",
            parent_cmd_id: self.parent_cmd_id,
            their_id: self.our_id,
            our_id: self.their_id,
            label: U32::new(self.label),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, ByteEq, Immutable, IntoBytes, KnownLayout, Unaligned)]
pub(crate) struct Info {
    domain: [u8; 14],
    parent_cmd_id: Id,
    their_id: DeviceId,
    our_id: DeviceId,
    label: U32<BE>,
}

/// A bidirectional channel author's secret.
pub struct BidiAuthorSecret<CS: CipherSuite> {
    sk: RootChannelKey<CS>,
    id: OnceCell<Result<BidiAuthorSecretId, IdError>>,
}

sk_misc!(
    BidiAuthorSecret,
    BidiAuthorSecretId,
    "AFC Bidi Author Secret"
);

unwrapped! {
    name: BidiAuthorSecret;
    type: Decap;
    into: |key: Self| { key.sk.into_inner() };
    from: |key| { Self { sk: RootChannelKey::new(key), id: OnceCell::new() } };
}

/// A bidirectional channel peer's encapsulated secret.
///
/// This should be freely shared with the channel peer.
#[derive_where(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BidiPeerEncap<CS: CipherSuite> {
    encap: Encap<CS>,
    #[serde(skip)]
    id: OnceCell<BidiChannelId>,
}

impl<CS: CipherSuite> BidiPeerEncap<CS> {
    /// Uniquely identifies the bidirectional channel.
    #[inline]
    pub fn id(&self) -> BidiChannelId {
        *self
            .id
            .get_or_init(|| BidiChannelId(Id::new::<CS>(self.as_bytes(), b"BidiChannelId")))
    }

    /// Encodes itself as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.encap.as_bytes()
    }

    /// Returns itself from its byte encoding.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        Ok(Self {
            encap: Encap::from_bytes(data)?,
            id: OnceCell::new(),
        })
    }

    fn as_inner(&self) -> &<CS::Kem as Kem>::Encap {
        self.encap.as_inner()
    }
}

custom_id! {
    /// Uniquely identifies a bidirectional channel.
    pub struct BidiChannelId;
}

/// The secrets for a bidirectional channel.
pub struct BidiSecrets<CS: CipherSuite> {
    /// The author's secret.
    pub author: BidiAuthorSecret<CS>,
    /// The peer's encapsulated secret.
    pub peer: BidiPeerEncap<CS>,
}

impl<CS: CipherSuite> BidiSecrets<CS> {
    /// Creates a new set of encapsulated secrets for the
    /// bidirectional channel.
    pub fn new<E: Engine<CS = CS>>(eng: &mut E, ch: &BidiChannel<'_, CS>) -> Result<Self, Error> {
        // Only the channel author calls this function.
        let author_id = ch.our_id;
        let author_sk = ch.our_sk;
        let peer_id = ch.their_id;
        let peer_pk = ch.their_pk;

        if author_id == peer_id {
            return Err(Error::same_device_id());
        }

        let root_sk = RootChannelKey::random(eng);
        let peer = {
            let (enc, _) = hpke::setup_send_deterministically::<CS>(
                Mode::Auth(&author_sk.sk),
                &peer_pk.pk,
                [ch.author_info().as_bytes()],
                // TODO(eric): should HPKE take a ref?
                root_sk.clone().into_inner(),
            )?;
            BidiPeerEncap {
                encap: Encap(enc),
                id: OnceCell::new(),
            }
        };
        let author = BidiAuthorSecret {
            sk: root_sk,
            id: OnceCell::new(),
        };

        Ok(BidiSecrets { author, peer })
    }

    /// Uniquely identifies the bidirectional channel.
    #[inline]
    pub fn id(&self) -> BidiChannelId {
        self.peer.id()
    }
}

/// Bidirectional channel encryption keys.
pub struct BidiKeys<CS: CipherSuite> {
    seal: RawSealKey<CS>,
    open: RawOpenKey<CS>,
}

impl<CS: CipherSuite> BidiKeys<CS> {
    /// Creates the channel author's bidirectional channel keys.
    pub fn from_author_secret(
        ch: &BidiChannel<'_, CS>,
        secret: BidiAuthorSecret<CS>,
    ) -> Result<Self, Error> {
        // Only the channel author calls this function.
        let author_id = ch.our_id;
        let author_sk = ch.our_sk;
        let peer_id = ch.their_id;
        let peer_pk = ch.their_pk;

        if author_id == peer_id {
            return Err(Error::same_device_id());
        }

        let (_, ctx) = hpke::setup_send_deterministically::<CS>(
            Mode::Auth(&author_sk.sk),
            &peer_pk.pk,
            [ch.author_info().as_bytes()],
            secret.sk.into_inner(),
        )?;

        // See section 9.8 of RFC 9180.
        let open = RawOpenKey {
            key: ctx.export(b"bidi response key")?,
            base_nonce: ctx.export(b"bidi response base_nonce")?,
        };
        let seal = {
            // `SendCtx` only gets rid of the raw key after the
            // first call to `seal`, etc., so it should still
            // exist at this point.
            let (key, base_nonce) = ctx
                .into_raw_parts()
                .assume("`SendCtx` should still contain the raw key")?;
            RawSealKey { key, base_nonce }
        };
        Ok(Self { seal, open })
    }

    /// Decapsulates the encapsulated channel keys received from
    /// the channel author and creates the peer's channel keys.
    pub fn from_peer_encap(
        ch: &BidiChannel<'_, CS>,
        enc: BidiPeerEncap<CS>,
    ) -> Result<Self, Error> {
        // Only the channel peer calls this function.
        let peer_id = ch.our_id;
        let peer_sk = ch.our_sk;
        let author_id = ch.their_id;
        let author_pk = ch.their_pk;

        if author_id == peer_id {
            return Err(Error::same_device_id());
        }

        let ctx = hpke::setup_recv::<CS>(
            Mode::Auth(&author_pk.pk),
            enc.as_inner(),
            &peer_sk.sk,
            [ch.peer_info().as_bytes()],
        )?;

        // See section 9.8 of RFC 9180.
        let seal = RawSealKey {
            key: ctx.export(b"bidi response key")?,
            base_nonce: ctx.export(b"bidi response base_nonce")?,
        };
        let open = {
            // `Recv` only gets rid of the raw key after the
            // first call to `open`, etc., so it should still
            // exist at this point.
            let (key, base_nonce) = ctx
                .into_raw_parts()
                .assume("`RecvCtx` should still contain the raw key")?;
            RawOpenKey { key, base_nonce }
        };
        Ok(Self { seal, open })
    }

    /// Returns the channel keys.
    pub fn into_keys(self) -> Result<(SealKey<CS>, OpenKey<CS>), Error> {
        let seal = SealKey::from_raw(&self.seal, Seq::ZERO)?;
        let open = OpenKey::from_raw(&self.open)?;
        Ok((seal, open))
    }

    /// Returns the raw channel keys.
    pub fn into_raw_keys(self) -> (RawSealKey<CS>, RawOpenKey<CS>) {
        (self.seal, self.open)
    }

    /// Returns the raw channel keys.
    #[cfg(any(test, feature = "test_util"))]
    pub(crate) fn as_raw_keys(&self) -> (&RawSealKey<CS>, &RawOpenKey<CS>) {
        (&self.seal, &self.open)
    }
}

#[cfg(any(test, feature = "test_util"))]
impl<CS: CipherSuite> BidiKeys<CS> {
    pub(crate) fn seal_key(&self) -> &RawSealKey<CS> {
        &self.seal
    }

    pub(crate) fn open_key(&self) -> &RawOpenKey<CS> {
        &self.open
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aranya::{EncryptionKey, IdentityKey},
        default::{DefaultCipherSuite, DefaultEngine, Rng},
        id::Id,
    };

    #[test]
    fn test_info_positive() {
        type E = DefaultEngine<Rng>;
        type CS = DefaultCipherSuite;
        let (mut eng, _) = E::from_entropy(Rng);
        let parent_cmd_id = Id::random(&mut eng);
        let sk1 = EncryptionKey::<CS>::new(&mut eng);
        let sk2 = EncryptionKey::<CS>::new(&mut eng);
        let label = 123;
        let ch1 = BidiChannel {
            parent_cmd_id,
            our_sk: &sk1,
            our_id: IdentityKey::<CS>::new(&mut eng)
                .id()
                .expect("sender ID should be valid"),
            their_pk: &sk2
                .public()
                .expect("receiver encryption public key should be valid"),
            their_id: IdentityKey::<CS>::new(&mut eng)
                .id()
                .expect("receiver ID should be valid"),
            label,
        };
        let ch2 = BidiChannel {
            parent_cmd_id,
            our_sk: &sk2,
            our_id: ch1.their_id,
            their_pk: &sk1
                .public()
                .expect("receiver encryption public key should be valid"),
            their_id: ch1.our_id,
            label,
        };
        assert_eq!(ch1.author_info(), ch2.peer_info());
        assert_eq!(ch1.peer_info(), ch2.author_info());
    }

    #[test]
    fn test_info_negative() {
        type E = DefaultEngine<Rng>;
        type CS = DefaultCipherSuite;
        let (mut eng, _) = E::from_entropy(Rng);

        let sk1 = EncryptionKey::<CS>::new(&mut eng);
        let device1_id = IdentityKey::<CS>::new(&mut eng)
            .id()
            .expect("device1 ID should be valid");

        let sk2 = EncryptionKey::<CS>::new(&mut eng);
        let device2_id = IdentityKey::<CS>::new(&mut eng)
            .id()
            .expect("device2 Id should be valid");

        let label = 123;

        let cases = [
            (
                "different parent_cmd_id",
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk1,
                    our_id: device1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device2_id,
                    label,
                },
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk2,
                    our_id: device2_id,
                    their_pk: &sk1
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device1_id,
                    label,
                },
            ),
            (
                "different our_id",
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk1,
                    our_id: device1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device2_id,
                    label,
                },
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk2,
                    our_id: IdentityKey::<CS>::new(&mut eng)
                        .id()
                        .expect("sender ID should be valid"),
                    their_pk: &sk1
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device1_id,
                    label,
                },
            ),
            (
                "different their_id",
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk1,
                    our_id: device1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device2_id,
                    label,
                },
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk2,
                    our_id: device2_id,
                    their_pk: &sk1
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: IdentityKey::<CS>::new(&mut eng)
                        .id()
                        .expect("receiver ID should be valid"),
                    label,
                },
            ),
            (
                "different label",
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk1,
                    our_id: device1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device2_id,
                    label: 123,
                },
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk2,
                    our_id: device2_id,
                    their_pk: &sk1
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device1_id,
                    label: 456,
                },
            ),
        ];
        for (name, ch1, ch2) in cases {
            assert_ne!(ch1.author_info(), ch2.peer_info(), "test failed: {name}");
            assert_ne!(ch1.peer_info(), ch2.author_info(), "test failed: {name}");
        }
    }

    /// Golden test for [`BidiAuthorSecret`] IDs.
    #[test]
    fn test_bidi_author_secret_id() {
        use spideroak_crypto::{ed25519::Ed25519, import::Import, kem::Kem, rust};

        use crate::{afc::shared::RootChannelKey, default::DhKemP256HkdfSha256, test_util::TestCs};

        type CS = TestCs<
            rust::Aes256Gcm,
            rust::Sha256,
            rust::HkdfSha512,
            DhKemP256HkdfSha256,
            rust::HmacSha512,
            Ed25519,
        >;

        let tests = [(
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20,
            ],
            "ARjYRYoDMcoQmVFY9BMLFJggmLLiH48bMvRkWSxwvjZ4",
        )];

        for (i, (key_bytes, expected_id)) in tests.iter().enumerate() {
            let sk = <<CS as CipherSuite>::Kem as Kem>::DecapKey::import(key_bytes)
                .expect("should import decap key");
            let root_key = RootChannelKey::<CS>::new(sk);
            let bidi_author_secret = BidiAuthorSecret {
                sk: root_key,
                id: OnceCell::new(),
            };

            let got_id = bidi_author_secret.id().expect("should compute ID");
            let expected =
                BidiAuthorSecretId::decode(expected_id).expect("should decode expected ID");

            assert_eq!(got_id, expected, "test case #{i}");
        }
    }
}
