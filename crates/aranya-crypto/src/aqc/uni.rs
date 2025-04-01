use core::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    aqc::shared::{RawPsk, RootChannelKey},
    aranya::{DeviceId, Encap, EncryptionKey, EncryptionPublicKey},
    ciphersuite::SuiteIds,
    csprng::Random,
    engine::unwrapped,
    error::Error,
    hash::{tuple_hash, Digest, Hash},
    hpke::{Hpke, Mode},
    id::{custom_id, Id},
    import::ImportError,
    kem::Kem,
    misc::sk_misc,
    subtle::{Choice, ConstantTimeEq},
    CipherSuite, Engine,
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
///         UniAuthorSecret,
///         UniChannel,
///         UniRecvPsk,
///         UniPeerEncap,
///         UniSendPsk,
///         UniSecrets,
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
///     import::Import,
///     keys::SecretKey,
///     EncryptionKey,
///     Rng,
///     subtle::ConstantTimeEq,
/// };
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
/// let device1_psk = UniSendPsk::from_author_secret(&device1_ch, author)
///     .expect("unable to derive `UniSendPsk` from author secrets");
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
/// let device2_psk = UniRecvPsk::from_peer_encap(&device2_ch, peer)
///     .expect("unable to derive `UniRecvPsk` from peer encap");
///
/// assert_eq!(device1_psk.identity(), device2_psk.identity());
/// assert!(bool::from(device1_psk.raw_secret_bytes().ct_eq(device2_psk.raw_secret_bytes())));
/// # }
/// ```
#[derive(Debug)]
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
    pub label: u32,
}

impl<CS: CipherSuite> UniChannel<'_, CS> {
    pub(crate) fn info(&self) -> Digest<<CS::Hash as Hash>::DigestSize> {
        // info = H(
        //     "AqcUniPsk",
        //     suite_id,
        //     engine_id,
        //     i2osp(psk_length_in_bytes, 2),
        //     parent_cmd_id,
        //     seal_id,
        //     open_id,
        //     i2osp(label, 4),
        // )
        tuple_hash::<CS::Hash, _>([
            "AqcUniPsk".as_bytes(),
            &SuiteIds::from_suite::<CS>().into_bytes(),
            &self.psk_length_in_bytes.to_be_bytes(),
            self.parent_cmd_id.as_bytes(),
            self.seal_id.as_bytes(),
            self.open_id.as_bytes(),
            &self.label.to_be_bytes(),
        ])
    }
}

/// A unirectional channel author's secret.
pub struct UniAuthorSecret<CS: CipherSuite>(RootChannelKey<CS>);

sk_misc!(UniAuthorSecret, UniAuthorSecretId);

impl<CS: CipherSuite> ConstantTimeEq for UniAuthorSecret<CS> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

unwrapped! {
    name: UniAuthorSecret;
    type: Decap;
    into: |key: Self| { key.0.into_inner() };
    from: |key| { Self(RootChannelKey::new(key)) };
}

/// A unirectional channel peer's encapsulated secret.
///
/// This should be freely shared with the channel peer.
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UniPeerEncap<CS: CipherSuite>(Encap<CS>);

impl<CS: CipherSuite> UniPeerEncap<CS> {
    /// Uniquely identifies the unirectional channel.
    #[inline]
    pub fn id(&self) -> UniChannelId {
        UniChannelId(Id::new::<CS>(self.as_bytes(), b"AqcUniChannelId"))
    }

    /// Encodes itself as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns itself from its byte encoding.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        Ok(Self(Encap::from_bytes(data)?))
    }

    fn as_inner(&self) -> &<CS::Kem as Kem>::Encap {
        self.0.as_inner()
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
            let (enc, _) = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send_deterministically(
                Mode::Auth(&author_sk.0),
                &peer_pk.0,
                &ch.info(),
                // TODO(eric): should HPKE take a ref?
                root_sk.clone().into_inner(),
            )?;
            UniPeerEncap(Encap(enc))
        };
        let author = UniAuthorSecret(root_sk);

        Ok(UniSecrets { author, peer })
    }

    /// Uniquely identifies the unirectional channel.
    #[inline]
    pub fn id(&self) -> UniChannelId {
        self.peer.id()
    }
}

macro_rules! uni_key {
    ($name:ident, $doc:expr $(,)?) => {
        #[doc = $doc]
        pub struct $name<CS> {
            id: UniChannelId,
            psk: RawPsk<CS>,
        }

        impl<CS: CipherSuite> $name<CS> {
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

                let (enc, ctx) = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send_deterministically(
                    Mode::Auth(&author_sk.0),
                    &peer_pk.0,
                    &ch.info(),
                    secret.0.into_inner(),
                )?;

                let id = UniPeerEncap::<CS>(Encap(enc)).id();

                // See section 9.8 of RFC 9180.
                let psk = ctx.export(b"aqc uni psk")?;

                Ok(Self { id, psk })
            }

            /// Decrypts and authenticates an encapsulated key
            /// received from a peer.
            pub fn from_peer_encap(
                ch: &UniChannel<'_, CS>,
                enc: UniPeerEncap<CS>,
            ) -> Result<Self, Error> {
                if ch.psk_length_in_bytes != 32 {
                    return Err(Error::invalid_psk_length());
                }

                // Only the channel peer calls this function.
                let peer_sk = ch.our_sk;
                let author_pk = ch.their_pk;

                if ch.seal_id == ch.open_id {
                    return Err(Error::same_device_id());
                }

                let info = ch.info();
                let ctx = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_recv(
                    Mode::Auth(&author_pk.0),
                    enc.as_inner(),
                    &peer_sk.0,
                    &info,
                )?;

                let id = enc.id();

                // See section 9.8 of RFC 9180.
                let psk = ctx.export(b"aqc uni psk")?;

                Ok(Self { id, psk })
            }

            /// Returns the PSK identity.
            ///
            /// See [RFC 8446] section 4.2.11 for more information about
            /// PSKs.
            ///
            /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
            pub fn identity(&self) -> UniChannelId {
                self.id
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

uni_key!(
    UniSendPsk,
    "A PSK for a unidirectional channel where the user is sending data.",
);
uni_key!(
    UniRecvPsk,
    "A PSK for a unidirectional channel where the user is receiving data.",
);
