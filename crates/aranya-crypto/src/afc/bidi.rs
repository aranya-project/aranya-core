use aranya_buggy::BugExt;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use super::{
    keys::{OpenKey, SealKey, Seq},
    shared::{RawOpenKey, RawSealKey, RootChannelKey},
};
use crate::{
    aranya::{Encap, EncryptionKey, EncryptionPublicKey, UserId},
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
    CipherSuite, Engine,
};

/// Contextual information for a bidirectional AFC channel.
///
/// In a bidirectional channel, both users can encrypt and
/// decrypt messages.
///
/// ```rust
/// # #[cfg(all(feature = "alloc", not(feature = "moonshot")))]
/// # {
/// use {
///     core::borrow::{Borrow, BorrowMut},
///     aranya_crypto::{
///         aead::{Aead, KeyData},
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
///         import::Import,
///         keys::SecretKey,
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
/// let user1_sk = EncryptionKey::<<E as Engine>::CS>::new(&mut eng);
/// let user1_id = IdentityKey::<<E as Engine>::CS>::new(&mut eng).id().expect("user1 ID should be valid");
///
/// let user2_sk = EncryptionKey::<<E as Engine>::CS>::new(&mut eng);
/// let user2_id = IdentityKey::<<E as Engine>::CS>::new(&mut eng).id().expect("user2 ID should be valid");
///
/// // user1 creates the channel keys and sends the encapsulation
/// // to user2...
/// let user1_ch = BidiChannel {
///     parent_cmd_id,
///     our_sk: &user1_sk,
///     our_id: user1_id,
///     their_pk: &user2_sk.public().expect("receiver encryption public key should be valid"),
///     their_id: user2_id,
///     label,
/// };
/// let BidiSecrets { author, peer } = BidiSecrets::new(&mut eng, &user1_ch)
///     .expect("unable to create `BidiSecrets`");
/// let mut user1 = Keys::from_author(&user1_ch, author);
///
/// // ...and user2 decrypts the encapsulation to discover the
/// // channel keys.
/// let user2_ch = BidiChannel {
///     parent_cmd_id,
///     our_sk: &user2_sk,
///     our_id: user2_id,
///     their_pk: &user1_sk.public().expect("receiver encryption public key should be valid"),
///     their_id: user1_id,
///     label,
/// };
/// let mut user2 = Keys::from_peer(&user2_ch, peer);
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
/// test(&mut user1, &user2); // user1 -> user2
/// test(&mut user2, &user1); // user2 -> user1
/// # }
/// ```
pub struct BidiChannel<'a, CS: CipherSuite> {
    /// The ID of the parent command.
    pub parent_cmd_id: Id,
    /// Our secret encryption key.
    pub our_sk: &'a EncryptionKey<CS>,
    /// Our UserID.
    pub our_id: UserId,
    /// Their public encryption key.
    pub their_pk: &'a EncryptionPublicKey<CS>,
    /// Their UserID.
    pub their_id: UserId,
    /// The policy label applied to the channel.
    pub label: u32,
}

impl<CS: CipherSuite> BidiChannel<'_, CS> {
    const LABEL: &'static [u8] = b"AfcChannelKeys";

    /// The author's `info` parameter.
    pub(crate) fn author_info(&self) -> Digest<<CS::Hash as Hash>::DigestSize> {
        // info = H(
        //     "AfcChannelKeys",
        //     suite_id,
        //     engine_id,
        //     parent_cmd_id,
        //     author_id,
        //     peer_id,
        //     i2osp(label, 4),
        // )
        tuple_hash::<CS::Hash, _>([
            Self::LABEL,
            &SuiteIds::from_suite::<CS>().into_bytes(),
            CS::ID.as_bytes(),
            self.parent_cmd_id.as_bytes(),
            self.our_id.as_bytes(),
            self.their_id.as_bytes(),
            &self.label.to_be_bytes(),
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
            CS::ID.as_bytes(),
            self.parent_cmd_id.as_bytes(),
            self.their_id.as_bytes(),
            self.our_id.as_bytes(),
            &self.label.to_be_bytes(),
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
        BidiChannelId(Id::new::<CS>(self.as_bytes(), b"BidiChannelId"))
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
    pub fn new<E: Engine<CS = CS>>(eng: &mut E, ch: &BidiChannel<'_, CS>) -> Result<Self, Error> {
        // Only the channel author calls this function.
        let author_id = ch.our_id;
        let author_sk = ch.our_sk;
        let peer_id = ch.their_id;
        let peer_pk = ch.their_pk;

        if author_id == peer_id {
            return Err(Error::same_user_id());
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
            return Err(Error::same_user_id());
        }

        let (_, ctx) = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send_deterministically(
            Mode::Auth(&author_sk.0),
            &peer_pk.0,
            &ch.author_info(),
            secret.0.into_inner(),
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
            return Err(Error::same_user_id());
        }

        let ctx = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_recv(
            Mode::Auth(&author_pk.0),
            enc.as_inner(),
            &peer_sk.0,
            &ch.peer_info(),
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
        let user1_id = IdentityKey::<CS>::new(&mut eng)
            .id()
            .expect("user1 ID should be valid");

        let sk2 = EncryptionKey::<CS>::new(&mut eng);
        let user2_id = IdentityKey::<CS>::new(&mut eng)
            .id()
            .expect("user2 Id should be valid");

        let label = 123;

        let cases = [
            (
                "different parent_cmd_id",
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk1,
                    our_id: user1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: user2_id,
                    label,
                },
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk2,
                    our_id: user2_id,
                    their_pk: &sk1
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: user1_id,
                    label,
                },
            ),
            (
                "different our_id",
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk1,
                    our_id: user1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: user2_id,
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
                    their_id: user1_id,
                    label,
                },
            ),
            (
                "different their_id",
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk1,
                    our_id: user1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: user2_id,
                    label,
                },
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk2,
                    our_id: user2_id,
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
                    our_id: user1_id,
                    their_pk: &sk2
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: user2_id,
                    label: 123,
                },
                BidiChannel {
                    parent_cmd_id: Id::random(&mut eng),
                    our_sk: &sk2,
                    our_id: user2_id,
                    their_pk: &sk1
                        .public()
                        .expect("receiver encryption public key should be valid"),
                    their_id: user1_id,
                    label: 456,
                },
            ),
        ];
        for (name, ch1, ch2) in cases {
            assert_ne!(ch1.author_info(), ch2.peer_info(), "test failed: {name}");
            assert_ne!(ch1.peer_info(), ch2.author_info(), "test failed: {name}");
        }
    }
}