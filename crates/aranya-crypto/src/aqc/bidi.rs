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
/// let device1_psk = BidiPsk::from_author_secret(&device1_ch, author)
///     .expect("unable to derive `BidiPsk` from author secrets");
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
/// let device2_psk = BidiPsk::from_peer_encap(&device2_ch, peer)
///     .expect("unable to derive `BidiPsk` from peer encap");
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
    pub label: Id,
}

impl<CS: CipherSuite> BidiChannel<'_, CS> {
    const LABEL: &'static [u8] = b"AqcBidiPsk";

    /// The author's `info` parameter.
    pub(crate) fn author_info(&self) -> Digest<<CS::Hash as Hash>::DigestSize> {
        // info = H(
        //     "AqcBidiPsk",
        //     suite_id,
        //     iso2p(psk_length_in_bytes, 2),
        //     parent_cmd_id,
        //     author_id,
        //     peer_id,
        //     label_id,
        // )
        tuple_hash::<CS::Hash, _>([
            Self::LABEL,
            &SuiteIds::from_suite::<CS>().into_bytes(),
            &self.psk_length_in_bytes.to_be_bytes(),
            self.parent_cmd_id.as_bytes(),
            self.our_id.as_bytes(),
            self.their_id.as_bytes(),
            self.label.as_bytes(),
        ])
    }

    /// The peer's `info` parameter.
    pub(crate) fn peer_info(&self) -> Digest<<CS::Hash as Hash>::DigestSize> {
        // Same as the author's info, except that we're computing
        // it from the peer's perspective, so `our_id` and
        // `their_id` are reversed.
        tuple_hash::<CS::Hash, _>([
            Self::LABEL,
            &SuiteIds::from_suite::<CS>().into_bytes(),
            &self.psk_length_in_bytes.to_be_bytes(),
            self.parent_cmd_id.as_bytes(),
            self.their_id.as_bytes(),
            self.our_id.as_bytes(),
            self.label.as_bytes(),
        ])
    }
}

/// A bidirectional channel author's secret.
pub struct BidiAuthorSecret<CS: CipherSuite>(RootChannelKey<CS>);

sk_misc!(BidiAuthorSecret, BidiAuthorSecretId);

impl<CS: CipherSuite> ConstantTimeEq for BidiAuthorSecret<CS> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

unwrapped! {
    name: BidiAuthorSecret;
    type: Decap;
    into: |key: Self| { key.0.into_inner() };
    from: |key| { Self(RootChannelKey::new(key)) };
}

/// A bidirectional channel peer's encapsulated secret.
///
/// This should be freely shared with the channel peer.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BidiPeerEncap<CS: CipherSuite>(Encap<CS>);

impl<CS: CipherSuite> BidiPeerEncap<CS> {
    /// Uniquely identifies the bidirectional channel.
    #[inline]
    pub fn id(&self) -> BidiChannelId {
        BidiChannelId(Id::new::<CS>(self.as_bytes(), b"AqcBidiChannelId"))
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
            let (enc, _) = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send_deterministically(
                Mode::Auth(&author_sk.0),
                &peer_pk.0,
                &ch.author_info(),
                // TODO(eric): should HPKE take a ref?
                root_sk.clone().into_inner(),
            )?;
            BidiPeerEncap(Encap(enc))
        };
        let author = BidiAuthorSecret(root_sk);

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

/// A PSK for a bidirectional channel.
pub struct BidiPsk<CS> {
    id: BidiChannelId,
    psk: RawPsk<CS>,
}

impl<CS: CipherSuite> BidiPsk<CS> {
    /// Creates the bidirectional PSK from the channel author's
    /// secret.
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

        let (enc, ctx) = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send_deterministically(
            Mode::Auth(&author_sk.0),
            &peer_pk.0,
            &ch.author_info(),
            secret.0.into_inner(),
        )?;

        let id = BidiPeerEncap::<CS>(Encap(enc)).id();

        // See section 9.8 of RFC 9180.
        let psk = ctx.export(b"aqc bidi psk")?;

        Ok(Self { id, psk })
    }

    /// Decapsulates the encapsulated channel keys received from
    /// the channel author and returns the bidirectional PSK.
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

        let ctx = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_recv(
            Mode::Auth(&author_pk.0),
            enc.as_inner(),
            &peer_sk.0,
            &ch.peer_info(),
        )?;

        let id = enc.id();

        // See section 9.8 of RFC 9180.
        let psk = ctx.export(b"aqc bidi psk")?;

        Ok(Self { id, psk })
    }

    /// Returns the PSK identity.
    ///
    /// See [RFC 8446] section 4.2.11 for more information about
    /// PSKs.
    ///
    /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
    pub fn identity(&self) -> BidiChannelId {
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

impl<CS: CipherSuite> fmt::Debug for BidiPsk<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking `psk`.
        f.debug_struct("BidiPsk")
            .field("id", &self.id)
            .finish_non_exhaustive()
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
        let label = Id::random(&mut eng);
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

        let parent_cmd_id = Id::random(&mut eng);
        let label = Id::random(&mut eng);

        let cases = [
            (
                "different parent_cmd_id",
                BidiChannel {
                    psk_length_in_bytes: 32,
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
                    psk_length_in_bytes: 32,
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
                    label: Id::random(&mut eng),
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
                    label: Id::random(&mut eng),
                },
            ),
        ];
        for (name, ch1, ch2) in cases {
            assert_ne!(ch1.author_info(), ch2.peer_info(), "test failed: {name}");
            assert_ne!(ch1.peer_info(), ch2.author_info(), "test failed: {name}");
        }
    }
}
