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
    engine::unwrapped,
    error::Error,
    hpke::{self, Mode},
    id::{custom_id, Id, IdError},
    misc::sk_misc,
    tls::CipherSuiteId,
    Engine,
};

/// Contextual information for a unidirectional AQC channel.
///
/// In a unidirectional channel, one device is permitted to encrypt
/// messages and one device is permitted to receive decrypt
/// messages.
///
/// ```rust
/// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
/// # {
/// use aranya_crypto::{
///     aqc::{
///         CipherSuiteId,
///         UniAuthorSecret,
///         UniChannel,
///         UniRecvPsk,
///         UniPeerEncap,
///         UniSendPsk,
///         UniSecrets,
///         UniSecret,
///     },
///     CipherSuite,
///     Csprng,
///     default::{
///         DefaultCipherSuite,
///         DefaultEngine,
///     },
///     Engine,
///     Id,
///     IdentityKey,
///     EncryptionKey,
///     Rng,
///     subtle::ConstantTimeEq as _,
/// };
///
/// type E = DefaultEngine<Rng, DefaultCipherSuite>;
/// let (mut eng, _) = E::from_entropy(Rng);
///
/// let parent_cmd_id = Id::random(&mut eng);
/// let label = Id::random(&mut eng);
///
/// let device1_sk = EncryptionKey::<<E as Engine>::CS>::new(&mut eng);
/// let device1_id = IdentityKey::<<E as Engine>::CS>::new(&mut eng).id().expect("device1 ID should be valid");
///
/// let device2_sk = EncryptionKey::<<E as Engine>::CS>::new(&mut eng);
/// let device2_id = IdentityKey::<<E as Engine>::CS>::new(&mut eng).id().expect("device2 ID should be valid");
///
/// // device1 creates the channel keys and sends the encapsulation
/// // to device2...
/// let device1_ch = UniChannel {
///     psk_length_in_bytes: 32,
///     parent_cmd_id,
///     our_sk: &device1_sk,
///     their_pk: &device2_sk.public().expect("receiver encryption key should be valid"),
///     seal_id: device1_id,
///     open_id: device2_id,
///     label,
/// };
/// let UniSecrets { author, peer } = UniSecrets::new(&mut eng, &device1_ch)
///     .expect("unable to create `UniSecrets`");
/// let device1_psk = UniSecret::from_author_secret(&device1_ch, author)
///     .expect("unable to derive `UniSecret` from author secrets")
///     .generate_send_only_psk(CipherSuiteId::TlsAes128GcmSha256)
///     .expect("unable to generate `UniSendPsk`");
///
/// // ...and device2 decrypts the encapsulation to discover the
/// // channel keys.
/// let device2_ch = UniChannel {
///     psk_length_in_bytes: 32,
///     parent_cmd_id,
///     our_sk: &device2_sk,
///     their_pk: &device1_sk.public().expect("receiver encryption key should be valid"),
///     seal_id: device1_id,
///     open_id: device2_id,
///     label,
/// };
/// let device2_psk = UniSecret::from_peer_encap(&device2_ch, peer)
///     .expect("unable to derive `UniRecvPsk` from peer encap")
///     .generate_recv_only_psk(CipherSuiteId::TlsAes128GcmSha256)
///     .expect("unable to generate `UniRecvPsk`");
///
/// assert_eq!(device1_psk.identity(), device2_psk.identity());
/// assert!(bool::from(device1_psk.raw_secret_bytes().ct_eq(device2_psk.raw_secret_bytes())));
/// # }
/// ```
#[derive_where(Debug)]
pub struct UniChannel<'a, CS: CipherSuite> {
    /// The size in bytes of the PSK.
    ///
    /// Per the AQC specification this must be at least 32. This
    /// implementation restricts it to exactly 32. This
    /// restriction may be lifted in the future.
    pub psk_length_in_bytes: u16,
    /// The ID of the parent command.
    pub parent_cmd_id: Id,
    /// Our secret encryption key.
    pub our_sk: &'a EncryptionKey<CS>,
    /// Their public encryption key.
    pub their_pk: &'a EncryptionPublicKey<CS>,
    /// The device that is permitted to encrypt messages.
    pub seal_id: DeviceId,
    /// The device that is permitted to decrypt messages.
    pub open_id: DeviceId,
    /// The policy label applied to the channel.
    pub label: Id,
}

impl<CS: CipherSuite> UniChannel<'_, CS> {
    pub(crate) const fn info(&self) -> Info {
        // info = concat(
        //     "AqcUniPsk-v1",
        //     i2osp(psk_length_in_bytes, 2),
        //     parent_cmd_id,
        //     seal_id,
        //     open_id,
        //     label_id,
        // )
        Info {
            domain: *b"AqcUniPsk-v1",
            psk_length_in_bytes: U16::new(self.psk_length_in_bytes),
            parent_cmd_id: self.parent_cmd_id,
            seal_id: self.seal_id,
            open_id: self.open_id,
            label: self.label,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, ByteEq, Immutable, IntoBytes, KnownLayout, Unaligned)]
pub(crate) struct Info {
    /// Always "AqcUniPsk-v1".
    domain: [u8; 12],
    psk_length_in_bytes: U16<BE>,
    parent_cmd_id: Id,
    seal_id: DeviceId,
    open_id: DeviceId,
    label: Id,
}

/// A unirectional channel author's secret.
pub struct UniAuthorSecret<CS: CipherSuite> {
    key: RootChannelKey<CS>,
    id: OnceCell<Result<UniAuthorSecretId, IdError>>,
}

sk_misc!(UniAuthorSecret, UniAuthorSecretId);

impl<CS: CipherSuite> UniAuthorSecret<CS> {
    pub(crate) const CONTEXT: &'static str = "AQC Uni Author Secret";
}

unwrapped! {
    name: UniAuthorSecret;
    type: Decap;
    into: |key: Self| { key.key.into_inner() };
    from: |key| { Self { key: RootChannelKey::new(key), id: OnceCell::new() } };
}

/// A unirectional channel peer's encapsulated secret.
///
/// This should be freely shared with the channel peer.
#[derive_where(Debug, Serialize, Deserialize)]
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
        *self
            .id
            .get_or_init(|| UniChannelId(Id::new::<CS>(self.as_bytes(), b"AqcUniChannelId")))
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
    #[derive(Immutable, IntoBytes, KnownLayout, Unaligned)]
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
    pub fn new<E: Engine<CS = CS>>(eng: &mut E, ch: &UniChannel<'_, CS>) -> Result<Self, Error> {
        if ch.psk_length_in_bytes != 32 {
            return Err(Error::invalid_psk_length());
        }

        // Only the channel author calls this function.
        let author_sk = ch.our_sk;
        let peer_pk = ch.their_pk;

        if ch.seal_id == ch.open_id {
            return Err(Error::same_device_id());
        }

        let root_sk = RootChannelKey::random(eng);
        let peer = {
            let (enc, _) = hpke::setup_send_deterministically::<CS>(
                Mode::Auth(&author_sk.key),
                &peer_pk.0,
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
            key: root_sk,
            id: OnceCell::new(),
        };

        Ok(UniSecrets { author, peer })
    }

    /// Uniquely identifies the unirectional channel.
    #[inline]
    pub fn id(&self) -> UniChannelId {
        self.peer.id()
    }
}

/// The shared unidirectional channel secret used by both the
/// channel author and channel peer to derive individual PSKs.
#[derive_where(Debug)]
pub struct UniSecret<CS: CipherSuite> {
    id: UniChannelId,
    #[derive_where(skip(Debug))]
    ctx: SendOrRecvCtx<CS>,
}

impl<CS: CipherSuite> UniSecret<CS> {
    /// Creates the channel author's unidirectional
    /// channel key.
    pub fn from_author_secret(
        ch: &UniChannel<'_, CS>,
        secret: UniAuthorSecret<CS>,
    ) -> Result<Self, Error> {
        if ch.psk_length_in_bytes != 32 {
            return Err(Error::invalid_psk_length());
        }

        // Only the channel author calls this function.
        let author_sk = ch.our_sk;
        let peer_pk = ch.their_pk;

        if ch.seal_id == ch.open_id {
            return Err(Error::same_device_id());
        }

        let (enc, ctx) = hpke::setup_send_deterministically::<CS>(
            Mode::Auth(&author_sk.key),
            &peer_pk.0,
            [ch.info().as_bytes()],
            secret.key.into_inner(),
        )?;

        let id = UniPeerEncap::<CS> {
            encap: Encap(enc),
            id: OnceCell::new(),
        }
        .id();

        Ok(Self {
            id,
            ctx: SendOrRecvCtx::Send(ctx),
        })
    }

    /// Decrypts and authenticates an encapsulated key
    /// received from a peer.
    pub fn from_peer_encap(ch: &UniChannel<'_, CS>, enc: UniPeerEncap<CS>) -> Result<Self, Error> {
        if ch.psk_length_in_bytes != 32 {
            return Err(Error::invalid_psk_length());
        }

        // Only the channel peer calls this function.
        let peer_sk = ch.our_sk;
        let author_pk = ch.their_pk;

        if ch.seal_id == ch.open_id {
            return Err(Error::same_device_id());
        }

        let ctx = hpke::setup_recv::<CS>(
            Mode::Auth(&author_pk.0),
            enc.as_inner(),
            &peer_sk.key,
            [ch.info().as_bytes()],
        )?;

        Ok(Self {
            id: enc.id(),
            ctx: SendOrRecvCtx::Recv(ctx),
        })
    }

    /// Returns the unidirectional channel ID.
    pub fn id(&self) -> &UniChannelId {
        &self.id
    }

    /// Generates a send-only PSK for the cipher suite.
    ///
    /// This method is deterministic over the `UniSecret` and
    /// cipher suite: calling it with the same `UniSecret` and
    /// cipher suite will generate the same PSK.
    pub fn generate_send_only_psk(&self, suite: CipherSuiteId) -> Result<UniSendPsk<CS>, Error> {
        Ok(UniSendPsk {
            id: UniPskId { id: self.id, suite },
            psk: self.generate_psk(suite)?,
        })
    }

    /// Generates a receive-only PSK for the cipher suite.
    ///
    /// This method is deterministic over the `UniSecret` and
    /// cipher suite: calling it with the same `UniSecret` and
    /// cipher suite will generate the same PSK.
    pub fn generate_recv_only_psk(&self, suite: CipherSuiteId) -> Result<UniRecvPsk<CS>, Error> {
        Ok(UniRecvPsk {
            id: UniPskId { id: self.id, suite },
            psk: self.generate_psk(suite)?,
        })
    }

    fn generate_psk(&self, suite: CipherSuiteId) -> Result<RawPsk<CS>, Error> {
        // See section 9.8 of RFC 9180.
        let context = PskCtx {
            prefix: *b"aqc uni psk!",
            channel_id: self.id,
            suite,
        };
        Ok(self.ctx.export(context.as_bytes())?)
    }
}

/// The context used when generating a [`UniSendPsk`] or
/// [`UniRecvPsk`].
#[repr(C)]
#[derive(Copy, Clone, Debug, Immutable, IntoBytes, KnownLayout)]
struct PskCtx {
    prefix: [u8; 12],
    channel_id: UniChannelId,
    suite: CipherSuiteId,
}

/// Uniquely identifies both a [`UniSendPsk`] and
/// a [`UniRecvPsk`].
#[derive(Copy, Clone, Debug, ByteEq, Immutable, IntoBytes, KnownLayout, Serialize, Deserialize)]
pub struct UniPskId {
    id: UniChannelId,
    suite: CipherSuiteId,
}

impl UniPskId {
    /// Returns the AQC channel ID.
    pub const fn channel_id(&self) -> &UniChannelId {
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

impl ConstantTimeEq for UniPskId {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl From<(UniChannelId, CipherSuiteId)> for UniPskId {
    #[inline]
    fn from((id, suite): (UniChannelId, CipherSuiteId)) -> Self {
        Self { id, suite }
    }
}

impl fmt::Display for UniPskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { id, suite } = self;
        write!(f, "UniPSK-{id}-{suite}")
    }
}

macro_rules! uni_psk {
    (
        $(#[$meta:meta])*
        struct $name:ident;
    ) => {
        $(#[$meta])*
        pub struct $name<CS> {
            id: UniPskId,
            psk: RawPsk<CS>,
        }

        impl<CS: CipherSuite> $name<CS> {
            /// Returns the PSK identity.
            ///
            /// See [RFC 8446] section 4.2.11 for more information about
            /// PSKs.
            ///
            /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
            pub fn identity(&self) -> &UniPskId {
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

        impl<CS: CipherSuite> fmt::Debug for $name<CS> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Avoid leaking `psk`.
                f.debug_struct(stringify!($name))
                    .field("id", &self.id)
                    .finish_non_exhaustive()
            }
        }
    };
}

uni_psk! {
    /// A PSK for a unidirectional channel where the user is
    /// sending data.
    struct UniSendPsk;
}
uni_psk! {
    /// A PSK for a unidirectional channel where the user is
    /// receiving data.
    struct UniRecvPsk;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden test for [`UniAuthorSecret`] IDs.
    #[test]
    fn test_uni_author_secret_id() {
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
            // Fixed key bytes for reproducible test
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20,
            ],
            "1S3KBvgcjZL8vdzhLrkGookzZfEL1e48jrLazNN7zSGw",
        )];

        for (i, (key_bytes, expected_id)) in tests.iter().enumerate() {
            let sk = <<CS as CipherSuite>::Kem as Kem>::DecapKey::import(key_bytes)
                .expect("should import decap key");
            let root_key: RootChannelKey<CS> = RootChannelKey::new(sk);
            let uni_author_secret: UniAuthorSecret<CS> = UniAuthorSecret {
                key: root_key,
                id: OnceCell::new(),
            };

            let got_id = uni_author_secret.id().expect("should compute ID");
            let expected =
                UniAuthorSecretId::decode(expected_id).expect("should decode expected ID");

            assert_eq!(got_id, expected, "test case #{i}");
        }
    }
}
