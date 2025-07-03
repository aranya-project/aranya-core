use core::{cell::OnceCell, fmt};

use derive_where::derive_where;
use serde::{Deserialize, Serialize};
use spideroak_crypto::{
    csprng::Random,
    import::ImportError,
    kem::Kem,
    subtle::{Choice, ConstantTimeEq},
};
use zerocopy::{
    byteorder::{BE, U16},
    ByteEq, Immutable, IntoBytes, KnownLayout, Unaligned,
};

use crate::{
    aqc::shared::{RawPsk, RootChannelKey, SendOrRecvCtx},
    aranya::{DeviceId, Encap, EncryptionKey, EncryptionPublicKey},
    ciphersuite::CipherSuite,
    engine::{unwrapped, Engine},
    error::Error,
    hpke::{self, Mode},
    id::{custom_id, BaseId, IdError, IdExt as _},
    misc::sk_misc,
    tls::CipherSuiteId,
};

/// Contextual information for a bidirectional AQC channel.
///
/// In a bidirectional channel, both devices can encrypt and
/// decrypt messages.
///
/// ```rust
/// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
/// # {
/// use aranya_crypto::{
///     aqc::{
///         BidiAuthorSecret,
///         BidiChannel,
///         BidiPeerEncap,
///         BidiPsk,
///         BidiSecrets,
///         BidiSecret,
///         CipherSuiteId,
///     },
///     id::IdExt as _,
///     CipherSuite,
///     Csprng,
///     default::{
///         DefaultCipherSuite,
///         DefaultEngine,
///     },
///     Engine,
///     BaseId,
///     IdentityKey,
///     EncryptionKey,
///     Rng,
///     subtle::ConstantTimeEq,
/// };
///
/// type E = DefaultEngine<Rng, DefaultCipherSuite>;
/// let (mut eng, _) = E::from_entropy(Rng);
///
/// let parent_cmd_id = BaseId::random(&mut eng);
/// let label = BaseId::random(&mut eng);
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
///     psk_length_in_bytes: 32,
///     parent_cmd_id,
///     our_sk: &device1_sk,
///     our_id: device1_id,
///     their_pk: &device2_sk.public().expect("receiver encryption public key should be valid"),
///     their_id: device2_id,
///     label,
/// };
/// let BidiSecrets { author, peer } = BidiSecrets::new(&mut eng, &device1_ch)
///     .expect("unable to create `BidiSecrets`");
/// let device1_psk = BidiSecret::from_author_secret(&device1_ch, author)
///     .expect("unable to derive `BidiSecret` from author secrets")
///     .generate_psk(CipherSuiteId::TlsAes128GcmSha256)
///     .expect("unable to generate `BidiPsk`");
///
/// // ...and device2 decrypts the encapsulation to discover the
/// // channel keys.
/// let device2_ch = BidiChannel {
///     psk_length_in_bytes: 32,
///     parent_cmd_id,
///     our_sk: &device2_sk,
///     our_id: device2_id,
///     their_pk: &device1_sk.public()
///         .expect("receiver encryption public key should be valid"),
///     their_id: device1_id,
///     label,
/// };
/// let device2_psk = BidiSecret::from_peer_encap(&device2_ch, peer)
///     .expect("unable to derive `BidiSecret` from peer encap")
///     .generate_psk(CipherSuiteId::TlsAes128GcmSha256)
///     .expect("unable to generate `BidiPsk`");
///
/// assert_eq!(device1_psk.identity(), device2_psk.identity());
/// assert!(bool::from(device1_psk.raw_secret_bytes().ct_eq(device2_psk.raw_secret_bytes())));
/// # }
/// ```
pub struct BidiChannel<'a, CS: CipherSuite> {
    /// The size in bytes of the PSK.
    ///
    /// Per the AQC specification this must be at least 32. This
    /// implementation restricts it to exactly 32. This
    /// restriction may be lifted in the future.
    pub psk_length_in_bytes: u16,
    /// The ID of the parent command.
    pub parent_cmd_id: BaseId,
    /// Our secret encryption key.
    pub our_sk: &'a EncryptionKey<CS>,
    /// Our DeviceID.
    pub our_id: DeviceId,
    /// Their public encryption key.
    pub their_pk: &'a EncryptionPublicKey<CS>,
    /// Their DeviceID.
    pub their_id: DeviceId,
    /// The policy label applied to the channel.
    pub label: BaseId,
}

impl<CS: CipherSuite> BidiChannel<'_, CS> {
    /// The author's `info` parameter.
    pub(crate) const fn author_info(&self) -> Info {
        // info = concat(
        //     "AqcBidiPsk-v1",
        //     iso2p(psk_length_in_bytes, 2),
        //     parent_cmd_id,
        //     author_id,
        //     peer_id,
        //     label_id,
        // )
        Info {
            domain: *b"AqcBidiPsk-v1",
            psk_length_in_bytes: U16::new(self.psk_length_in_bytes),
            parent_cmd_id: self.parent_cmd_id,
            seal_id: self.our_id,
            open_id: self.their_id,
            label: self.label,
        }
    }

    /// The peer's `info` parameter.
    pub(crate) const fn peer_info(&self) -> Info {
        // Same as the author's info, except that we're computing
        // it from the peer's perspective, so `our_id` and
        // `their_id` are reversed.
        Info {
            domain: *b"AqcBidiPsk-v1",
            psk_length_in_bytes: U16::new(self.psk_length_in_bytes),
            parent_cmd_id: self.parent_cmd_id,
            seal_id: self.their_id,
            open_id: self.our_id,
            label: self.label,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, ByteEq, Immutable, IntoBytes, KnownLayout, Unaligned)]
pub(crate) struct Info {
    /// Always "AqcBidiPsk-v1".
    domain: [u8; 13],
    psk_length_in_bytes: U16<BE>,
    parent_cmd_id: BaseId,
    seal_id: DeviceId,
    open_id: DeviceId,
    label: BaseId,
}

/// A bidirectional channel author's secret.
pub struct BidiAuthorSecret<CS: CipherSuite> {
    sk: RootChannelKey<CS>,
    id: OnceCell<Result<BidiAuthorSecretId, IdError>>,
}

sk_misc!(
    BidiAuthorSecret,
    BidiAuthorSecretId,
    "AQC Bidi Author Secret"
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
            .get_or_init(|| BidiChannelId::new::<CS>(self.as_bytes(), b"AqcBidiChannelId"))
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
    #[derive(Immutable, IntoBytes, KnownLayout, Unaligned)]
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
    ///
    /// This is used by the channel author.
    pub fn new<E: Engine<CS = CS>>(eng: &mut E, ch: &BidiChannel<'_, CS>) -> Result<Self, Error> {
        if ch.psk_length_in_bytes != 32 {
            return Err(Error::invalid_psk_length());
        }

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
    ///
    /// This is the same thing as [`BidiPeerEncap::id`].
    #[inline]
    pub fn id(&self) -> BidiChannelId {
        self.peer.id()
    }
}

/// The shared bidirectional channel secret used by both the
/// channel author and channel peer to derive individual PSKs.
#[derive_where(Debug)]
pub struct BidiSecret<CS: CipherSuite> {
    id: BidiChannelId,
    #[derive_where(skip(Debug))]
    ctx: SendOrRecvCtx<CS>,
}

impl<CS: CipherSuite> BidiSecret<CS> {
    /// Creates the bidirectional channel secret from the channel
    /// author's secret.
    pub fn from_author_secret(
        ch: &BidiChannel<'_, CS>,
        secret: BidiAuthorSecret<CS>,
    ) -> Result<Self, Error> {
        if ch.psk_length_in_bytes != 32 {
            return Err(Error::invalid_psk_length());
        }

        // Only the channel author calls this function.
        let author_id = ch.our_id;
        let author_sk = ch.our_sk;
        let peer_id = ch.their_id;
        let peer_pk = ch.their_pk;

        if author_id == peer_id {
            return Err(Error::same_device_id());
        }

        let (enc, ctx) = hpke::setup_send_deterministically::<CS>(
            Mode::Auth(&author_sk.sk),
            &peer_pk.pk,
            [ch.author_info().as_bytes()],
            secret.sk.into_inner(),
        )?;

        Ok(Self {
            id: BidiPeerEncap::<CS> {
                encap: Encap(enc),
                id: OnceCell::new(),
            }
            .id(),
            ctx: SendOrRecvCtx::Send(ctx),
        })
    }

    /// Decapsulates the encapsulated channel keys received from
    /// the channel author and returns the bidirectional channel
    /// secret.
    pub fn from_peer_encap(
        ch: &BidiChannel<'_, CS>,
        enc: BidiPeerEncap<CS>,
    ) -> Result<Self, Error> {
        if ch.psk_length_in_bytes != 32 {
            return Err(Error::invalid_psk_length());
        }

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

        let id = enc.id();

        Ok(Self {
            id,
            ctx: SendOrRecvCtx::Recv(ctx),
        })
    }

    /// Returns the bidirectional channel ID.
    pub fn id(&self) -> &BidiChannelId {
        &self.id
    }

    /// Generates a PSK for the cipher suite.
    ///
    /// This method is deterministic over the `BidiSecret` and
    /// cipher suite: calling it with the same `BidiSecret` and
    /// cipher suite will generate the same PSK.
    pub fn generate_psk(&self, suite: CipherSuiteId) -> Result<BidiPsk<CS>, Error> {
        // See section 9.8 of RFC 9180.
        let context = PskCtx {
            prefix: *b"aqc bidi psk",
            channel_id: self.id,
            suite,
        };
        Ok(BidiPsk {
            id: BidiPskId { id: self.id, suite },
            psk: self.ctx.export(context.as_bytes())?,
        })
    }
}

/// The context used when generating a [`BidiPsk`].
#[repr(C)]
#[derive(Copy, Clone, Debug, Immutable, IntoBytes, KnownLayout)]
struct PskCtx {
    prefix: [u8; 12],
    channel_id: BidiChannelId,
    suite: CipherSuiteId,
}

/// A PSK for a bidirectional channel.
#[derive_where(Debug)]
pub struct BidiPsk<CS> {
    id: BidiPskId,
    #[derive_where(skip(Debug))]
    psk: RawPsk<CS>,
}

impl<CS: CipherSuite> BidiPsk<CS> {
    /// Returns the PSK identity.
    ///
    /// See [RFC 8446] section 4.2.11 for more information about
    /// PSKs.
    ///
    /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
    pub fn identity(&self) -> &BidiPskId {
        &self.id
    }

    /// Returns the raw PSK secret.
    ///
    /// See [RFC 8446] section 4.2.11 for more information about
    /// PSKs.
    ///
    /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
    pub fn raw_secret_bytes(&self) -> &[u8] {
        self.psk.raw_secret_bytes()
    }
}

/// Uniquely identifies a [`BidiPsk`].
#[derive(Copy, Clone, Debug, ByteEq, Immutable, IntoBytes, KnownLayout, Serialize, Deserialize)]
pub struct BidiPskId {
    id: BidiChannelId,
    suite: CipherSuiteId,
}

impl BidiPskId {
    /// Returns the AQC channel ID.
    pub const fn channel_id(&self) -> &BidiChannelId {
        &self.id
    }

    /// Returns the TLS 1.3 cipher suite ID.
    pub const fn cipher_suite(&self) -> CipherSuiteId {
        self.suite
    }

    /// Converts the ID to its byte encoding.
    pub const fn as_bytes(&self) -> &[u8; 34] {
        zerocopy::transmute_ref!(self)
    }
}

impl ConstantTimeEq for BidiPskId {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl From<(BidiChannelId, CipherSuiteId)> for BidiPskId {
    #[inline]
    fn from((id, suite): (BidiChannelId, CipherSuiteId)) -> Self {
        Self { id, suite }
    }
}

impl fmt::Display for BidiPskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { id, suite } = self;
        write!(f, "BidiPSK-{id}-{suite}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aranya::{EncryptionKey, IdentityKey},
        default::{DefaultCipherSuite, DefaultEngine, Rng},
        id::BaseId,
    };

    #[test]
    fn test_info_positive() {
        type E = DefaultEngine<Rng>;
        type CS = DefaultCipherSuite;
        let (mut eng, _) = E::from_entropy(Rng);
        let parent_cmd_id = BaseId::random(&mut eng);
        let sk1 = EncryptionKey::<CS>::new(&mut eng);
        let sk2 = EncryptionKey::<CS>::new(&mut eng);
        let label = BaseId::random(&mut eng);
        let ch1 = BidiChannel {
            psk_length_in_bytes: 32,
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
            psk_length_in_bytes: 32,
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

        let parent_cmd_id = BaseId::random(&mut eng);
        let label = BaseId::random(&mut eng);

        let cases = [
            (
                "different parent_cmd_id",
                BidiChannel {
                    psk_length_in_bytes: 32,
                    parent_cmd_id: BaseId::random(&mut eng),
                    our_sk: &sk1,
                    our_id: device1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device2_id,
                    label,
                },
                BidiChannel {
                    psk_length_in_bytes: 32,
                    parent_cmd_id: BaseId::random(&mut eng),
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
                    parent_cmd_id,
                    psk_length_in_bytes: 32,
                    our_sk: &sk1,
                    our_id: device1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device2_id,
                    label,
                },
                BidiChannel {
                    parent_cmd_id,
                    psk_length_in_bytes: 32,
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
                    parent_cmd_id,
                    psk_length_in_bytes: 32,
                    our_sk: &sk1,
                    our_id: device1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device2_id,
                    label,
                },
                BidiChannel {
                    parent_cmd_id,
                    psk_length_in_bytes: 32,
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
                    parent_cmd_id,
                    psk_length_in_bytes: 32,
                    our_sk: &sk1,
                    our_id: device1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device2_id,
                    label: BaseId::random(&mut eng),
                },
                BidiChannel {
                    parent_cmd_id,
                    psk_length_in_bytes: 32,
                    our_sk: &sk2,
                    our_id: device2_id,
                    their_pk: &sk1
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: device1_id,
                    label: BaseId::random(&mut eng),
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

        use crate::{aqc::shared::RootChannelKey, default::DhKemP256HkdfSha256, test_util::TestCs};

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
            "Efo3AYjbWpxHmFqMZyGQY3dD9s9UGKMGjSJvPb8fVzr8",
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
