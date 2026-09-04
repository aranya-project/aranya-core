use core::{cell::OnceCell, iter};

use buggy::BugExt as _;
use derive_where::derive_where;
use spideroak_crypto::{csprng::Random as _, import::ImportError, kem::Kem};
use zerocopy::{ByteEq, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    CmdId,
    afc::{
        keys::{OpenKey, SealKey, Seq},
        shared::{RawOpenKey, RawSealKey, RootChannelKey},
    },
    aranya::{DeviceId, Encap, EncryptionKey, EncryptionPublicKey},
    ciphersuite::CipherSuite,
    engine::{Engine, unwrapped},
    error::Error,
    hpke::{self, Mode},
    id::{IdError, IdExt as _, custom_id},
    misc::sk_misc,
    policy::LabelId,
};

/// Contextual information for a unidirectional AFC channel.
///
/// In a unidirectional channel, one device is permitted to encrypt
/// messages and one device is permitted to receive decrypt
/// messages.
///
/// ```rust
/// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
/// # {
/// use core::borrow::{Borrow, BorrowMut};
///
/// use aranya_crypto::{
///     BaseId, CipherSuite, Csprng, EncryptionKey, Engine, IdentityKey, Rng,
///     afc::{
///         AuthData, OpenKey, SealKey, UniAuthorSecret, UniChannel, UniOpenKey, UniPeerEncap,
///         UniSealKey, UniSecrets,
///     },
///     default::{DefaultCipherSuite, DefaultEngine},
///     id::IdExt as _,
///     policy::{CmdId, LabelId},
/// };
///
/// fn key_from_author<CS: CipherSuite>(
///     ch: &UniChannel<'_, CS>,
///     secret: UniAuthorSecret<CS>,
/// ) -> SealKey<CS> {
///     let key = UniSealKey::from_author_secret(ch, secret)
///         .expect("should be able to decapsulate author secret");
///     key.into_key().expect("should be able to create `SealKey`")
/// }
///
/// fn key_from_peer<CS: CipherSuite>(
///     ch: &UniChannel<'_, CS>,
///     encap: UniPeerEncap<CS>,
/// ) -> OpenKey<CS> {
///     let key =
///         UniOpenKey::from_peer_encap(ch, encap).expect("should be able to decapsulate peer key");
///     key.into_key().expect("should be able to create `OpenKey`")
/// }
///
/// type E = DefaultEngine<Rng, DefaultCipherSuite>;
/// let (eng, _) = E::from_entropy(Rng);
/// let parent_cmd_id = CmdId::random(&eng);
/// let label_id = LabelId::random(&eng);
/// // The channel author's current epoch, read from the graph.
/// let epoch = 0;
///
/// let device1_sk = EncryptionKey::<<E as Engine>::CS>::new(&eng);
/// let device1_id = IdentityKey::<<E as Engine>::CS>::new(&eng)
///     .id()
///     .expect("device1 ID should be valid");
///
/// let device2_sk = EncryptionKey::<<E as Engine>::CS>::new(&eng);
/// let device2_id = IdentityKey::<<E as Engine>::CS>::new(&eng)
///     .id()
///     .expect("device2 ID should be valid");
///
/// // device1 creates the channel keys and sends the encapsulation
/// // to device2...
/// let device1_ch = UniChannel {
///     parent_cmd_id,
///     our_sk: &device1_sk,
///     their_pk: &device2_sk
///         .public()
///         .expect("receiver encryption key should be valid"),
///     seal_id: device1_id,
///     open_id: device2_id,
///     label_id,
///     epoch,
/// };
/// let UniSecrets { author, peer } =
///     UniSecrets::new(&eng, &device1_ch).expect("unable to create `UniSecrets`");
/// let mut device1 = key_from_author(&device1_ch, author);
///
/// // ...and device2 decrypts the encapsulation to discover the
/// // channel keys.
/// let device2_ch = UniChannel {
///     parent_cmd_id,
///     our_sk: &device2_sk,
///     their_pk: &device1_sk
///         .public()
///         .expect("receiver encryption key should be valid"),
///     seal_id: device1_id,
///     open_id: device2_id,
///     label_id,
///     epoch,
/// };
/// let device2 = key_from_peer(&device2_ch, peer);
///
/// fn test<CS: CipherSuite>(seal: &mut SealKey<CS>, open: &OpenKey<CS>) {
///     const GOLDEN: &[u8] = b"hello, world!";
///     const ADDITIONAL_DATA: &[u8] = b"authenticated, but not encrypted data";
///
///     let version = 4;
///     type E = DefaultEngine<Rng, DefaultCipherSuite>;
///     let label_id = LabelId::random(Rng);
///
///     let (ciphertext, seq) = {
///         let mut dst = vec![0u8; GOLDEN.len() + SealKey::<CS>::OVERHEAD];
///         let ad = AuthData { version, label_id };
///         let seq = seal
///             .seal(&mut dst, GOLDEN, &ad)
///             .expect("should be able to encrypt plaintext");
///         (dst, seq)
///     };
///     let plaintext = {
///         let mut dst = vec![0u8; ciphertext.len()];
///         let ad = AuthData { version, label_id };
///         open.open(&mut dst, &ciphertext, &ad, seq)
///             .expect("should be able to decrypt ciphertext");
///         dst.truncate(ciphertext.len() - OpenKey::<CS>::OVERHEAD);
///         dst
///     };
///     assert_eq!(&plaintext, GOLDEN);
/// }
/// test(&mut device1, &device2); // device1 -> device2
///
/// # }
/// ```
pub struct UniChannel<'a, CS: CipherSuite> {
    /// The ID of the parent command.
    pub parent_cmd_id: CmdId,
    /// Our secret encryption key.
    pub our_sk: &'a EncryptionKey<CS>,
    /// Their public encryption key.
    pub their_pk: &'a EncryptionPublicKey<CS>,
    /// The device that is permitted to encrypt messages.
    pub seal_id: DeviceId,
    /// The device that is permitted to decrypt messages.
    pub open_id: DeviceId,
    /// The policy label applied to the channel.
    pub label_id: LabelId,
    /// The channel author's epoch at creation time.
    pub epoch: u64,
}

impl<CS: CipherSuite> UniChannel<'_, CS> {
    pub(crate) const fn info(&self) -> Info {
        // info = concat(
        //     "AfcUniKey-v2",
        //     parent_cmd_id,
        //     seal_id,
        //     open_id,
        //     label_id,
        //     i2osp(epoch, 8),
        // )
        Info {
            domain: *b"AfcUniKey-v2",
            parent_cmd_id: self.parent_cmd_id,
            seal_id: self.seal_id,
            open_id: self.open_id,
            label_id: self.label_id,
            epoch: self.epoch.to_be_bytes(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, ByteEq, Immutable, IntoBytes, KnownLayout, Unaligned)]
pub(crate) struct Info {
    domain: [u8; 12],
    parent_cmd_id: CmdId,
    seal_id: DeviceId,
    open_id: DeviceId,
    label_id: LabelId,
    /// Big-endian `u64`.
    epoch: [u8; 8],
}

/// A unirectional channel author's secret.
pub struct UniAuthorSecret<CS: CipherSuite> {
    sk: RootChannelKey<CS>,
    id: OnceCell<Result<UniAuthorSecretId, IdError>>,
}

sk_misc!(UniAuthorSecret, UniAuthorSecretId, "AFC Uni Author Secret");

unwrapped! {
    name: UniAuthorSecret;
    type: Decap;
    into: |key: Self| { key.sk.into_inner() };
    from: |key| { Self { sk: RootChannelKey::new(key), id: OnceCell::new() } };
}

/// A unirectional channel peer's encapsulated secret.
///
/// This should be freely shared with the channel peer.
#[derive_where(Serialize, Deserialize)]
#[serde(transparent)]
pub struct UniPeerEncap<CS: CipherSuite> {
    encap: Encap<CS>,
    #[serde(skip)]
    id: OnceCell<UniChannelId>,
}

impl<CS: CipherSuite> UniPeerEncap<CS> {
    /// Uniquely identifies the unirectional channel.
    #[inline]
    pub fn id(&self) -> UniChannelId {
        *self.id.get_or_init(|| {
            UniChannelId::new::<CS>(b"UniChannelId-v1", iter::once(self.as_bytes()))
        })
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
    /// Uniquely identifies a unidirectional channel.
    pub struct UniChannelId;
}

/// The secrets for a unirectional channel.
pub struct UniSecrets<CS: CipherSuite> {
    /// The author's secret.
    pub author: UniAuthorSecret<CS>,
    /// The peer's encapsulation.
    pub peer: UniPeerEncap<CS>,
}

impl<CS: CipherSuite> UniSecrets<CS> {
    /// Creates a new set of encapsulated secrets for the
    /// unidirectional channel.
    pub fn new<E: Engine<CS = CS>>(eng: &E, ch: &UniChannel<'_, CS>) -> Result<Self, Error> {
        // Only the channel author calls this function.
        let author_sk = ch.our_sk;
        let peer_pk = ch.their_pk;

        if ch.seal_id == ch.open_id {
            return Err(Error::same_device_id());
        }

        let root_sk = RootChannelKey::random(eng);
        let peer = {
            let (enc, _) = hpke::setup_send_deterministically::<CS>(
                Mode::Auth(&author_sk.sk),
                &peer_pk.pk,
                [ch.info().as_bytes()],
                // TODO(eric): should HPKE take a ref?
                root_sk.clone().into_inner(),
            )?;
            UniPeerEncap {
                encap: Encap(enc),
                id: OnceCell::new(),
            }
        };
        let author = UniAuthorSecret {
            sk: root_sk,
            id: OnceCell::new(),
        };

        Ok(Self { author, peer })
    }

    /// Uniquely identifies the unirectional channel.
    #[inline]
    pub fn id(&self) -> UniChannelId {
        self.peer.id()
    }
}

macro_rules! uni_key {
    ($name:ident, $inner:ident, $doc:expr $(,)?) => {
        #[doc = $doc]
        pub struct $name<CS: CipherSuite>($inner<CS>);

        impl<CS: CipherSuite> $name<CS> {
            /// Creates the channel author's unidirectional
            /// channel key.
            pub fn from_author_secret(
                ch: &UniChannel<'_, CS>,
                secret: UniAuthorSecret<CS>,
            ) -> Result<Self, Error> {
                // Only the channel author calls this function.
                let author_sk = ch.our_sk;
                let peer_pk = ch.their_pk;

                if ch.seal_id == ch.open_id {
                    return Err(Error::same_device_id());
                }

                let (_, ctx) = hpke::setup_send_deterministically::<CS>(
                    Mode::Auth(&author_sk.sk),
                    &peer_pk.pk,
                    [ch.info().as_bytes()],
                    secret.sk.into_inner(),
                )?;
                let key = {
                    // `SendCtx` only gets rid of the raw key
                    // after the first call to `seal`, etc., so
                    // it should still exist at this point.
                    let (key, base_nonce) = ctx
                        .into_raw_parts()
                        .assume("`SendCtx` should still contain the raw key")?;
                    $inner { key, base_nonce }
                };
                Ok(Self(key))
            }

            /// Decrypts and authenticates an encapsulated key
            /// received from a peer.
            pub fn from_peer_encap(
                ch: &UniChannel<'_, CS>,
                enc: UniPeerEncap<CS>,
            ) -> Result<Self, Error> {
                // Only the channel peer calls this function.
                let peer_sk = ch.our_sk;
                let author_pk = ch.their_pk;

                if ch.seal_id == ch.open_id {
                    return Err(Error::same_device_id());
                }

                let ctx = hpke::setup_recv::<CS>(
                    Mode::Auth(&author_pk.pk),
                    enc.as_inner(),
                    &peer_sk.sk,
                    [ch.info().as_bytes()],
                )?;
                let key = {
                    // `Recv` only gets rid of the raw key after
                    // the first call to `open`, etc., so it
                    // should still exist at this point.
                    let (key, base_nonce) = ctx
                        .into_raw_parts()
                        .assume("`RecvCtx` should still contain the raw key")?;
                    $inner { key, base_nonce }
                };
                Ok(Self(key))
            }

            /// Returns the raw key material.
            pub fn into_raw_key(self) -> $inner<CS> {
                self.0
            }

            /// Returns the raw key material.
            #[cfg(any(test, feature = "test_util"))]
            pub(crate) fn as_raw_key(&self) -> &$inner<CS> {
                &self.0
            }
        }
    };
}
uni_key!(
    UniSealKey,
    RawSealKey,
    "A unidirectional channel encryption key.",
);

impl<CS: CipherSuite> UniSealKey<CS> {
    /// Returns the channel key.
    pub fn into_key(self) -> Result<SealKey<CS>, Error> {
        let seal = SealKey::from_raw(&self.0, Seq::ZERO)?;
        Ok(seal)
    }
}

uni_key!(
    UniOpenKey,
    RawOpenKey,
    "A unidirectional channel decryption key.",
);

impl<CS: CipherSuite> UniOpenKey<CS> {
    /// Returns the channel key.
    pub fn into_key(self) -> Result<OpenKey<CS>, Error> {
        let open = OpenKey::from_raw(&self.0)?;
        Ok(open)
    }
}

#[cfg(test)]
mod tests {
    use spideroak_crypto::{ed25519::Ed25519, import::Import as _, kem::Kem, rust};

    use super::*;
    use crate::{
        Rng,
        afc::{AuthData, shared::RootChannelKey},
        default::DhKemP256HkdfSha256,
        test_util::TestCs,
    };

    type CS = TestCs<
        rust::Aes256Gcm,
        rust::Sha256,
        rust::HkdfSha512,
        DhKemP256HkdfSha256,
        rust::HmacSha512,
        Ed25519,
    >;

    /// Golden test for [`UniAuthorSecret`] IDs.
    #[test]
    fn test_uni_author_secret_id() {
        let tests = [(
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20,
            ],
            "8QFfLfKymtXHa9MJWhJcKvwYWXtsmuCK3Bsf2tCxpdK1",
        )];

        for (i, (key_bytes, expected_id)) in tests.iter().enumerate() {
            let sk = <<CS as CipherSuite>::Kem as Kem>::DecapKey::import(key_bytes)
                .expect("should import decap key");
            let root_key = RootChannelKey::<CS>::new(sk);
            let uni_author_secret = UniAuthorSecret {
                sk: root_key,
                id: OnceCell::new(),
            };

            let got_id = uni_author_secret.id().expect("should compute ID");
            let expected =
                UniAuthorSecretId::decode(expected_id).expect("should decode expected ID");

            assert_eq!(got_id, expected, "test case #{i}");
        }
    }

    /// Golden test for the [`Info`] byte layout.
    #[test]
    fn test_uni_info_layout() {
        let parent_cmd_id = CmdId::from([0x11; 32]);
        let seal_id = DeviceId::from([0x22; 32]);
        let open_id = DeviceId::from([0x33; 32]);
        let label_id = LabelId::from([0x44; 32]);
        let epoch = 0x0102_0304_0506_0708u64;

        let sk = EncryptionKey::<CS>::new(Rng);
        let pk = sk.public().expect("public key should be valid");
        let ch = UniChannel {
            parent_cmd_id,
            our_sk: &sk,
            their_pk: &pk,
            seal_id,
            open_id,
            label_id,
            epoch,
        };
        let info = ch.info();
        let got = info.as_bytes();

        let mut want = Vec::<u8>::new();
        want.extend_from_slice(b"AfcUniKey-v2");
        want.extend_from_slice(&[0x11; 32]);
        want.extend_from_slice(&[0x22; 32]);
        want.extend_from_slice(&[0x33; 32]);
        want.extend_from_slice(&[0x44; 32]);
        want.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        assert_eq!(got.len(), 148);
        assert_eq!(got, &want[..]);
    }

    /// Keys derived with the same epoch interoperate; keys
    /// derived with different epochs do not.
    #[test]
    fn test_uni_epoch_binding() {
        let eng = crate::default::DefaultEngine::<Rng, CS>::from_entropy(Rng).0;
        let author_sk = EncryptionKey::<CS>::new(&eng);
        let peer_sk = EncryptionKey::<CS>::new(&eng);
        let author_pk = author_sk.public().expect("public key should be valid");
        let peer_pk = peer_sk.public().expect("public key should be valid");

        let parent_cmd_id = CmdId::random(&eng);
        let seal_id = DeviceId::random(&eng);
        let open_id = DeviceId::random(&eng);
        let label_id = LabelId::random(&eng);
        const EPOCH: u64 = 7;

        let author_ch = UniChannel {
            parent_cmd_id,
            our_sk: &author_sk,
            their_pk: &peer_pk,
            seal_id,
            open_id,
            label_id,
            epoch: EPOCH,
        };
        let UniSecrets { author, peer } =
            UniSecrets::new(&eng, &author_ch).expect("should create secrets");
        let mut seal = UniSealKey::from_author_secret(&author_ch, author)
            .expect("should derive seal key")
            .into_key()
            .expect("should convert seal key");

        const GOLDEN: &[u8] = b"hello, world!";
        let ad = AuthData {
            version: 1,
            label_id,
        };
        let mut ciphertext = vec![0u8; GOLDEN.len() + SealKey::<CS>::OVERHEAD];
        let seq = seal
            .seal(&mut ciphertext, GOLDEN, &ad)
            .expect("should seal");

        let open_with = |epoch: u64| {
            let peer_ch = UniChannel {
                parent_cmd_id,
                our_sk: &peer_sk,
                their_pk: &author_pk,
                seal_id,
                open_id,
                label_id,
                epoch,
            };
            let open = UniOpenKey::from_peer_encap(
                &peer_ch,
                UniPeerEncap::from_bytes(peer.as_bytes()).expect("should decode encap"),
            )
            .expect("should derive open key")
            .into_key()
            .expect("should convert open key");
            let mut plaintext = vec![0u8; ciphertext.len()];
            open.open(&mut plaintext, &ciphertext, &ad, seq).map(|()| {
                plaintext.truncate(ciphertext.len() - OpenKey::<CS>::OVERHEAD);
                plaintext
            })
        };

        // Same epoch: round trip.
        let plaintext = open_with(EPOCH).expect("same epoch should open");
        assert_eq!(&plaintext[..], GOLDEN);

        // Different epoch: authentication failure.
        open_with(EPOCH + 1).expect_err("different epoch should not open");
        open_with(0).expect_err("different epoch should not open");
    }
}
