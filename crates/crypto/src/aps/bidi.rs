use buggy::BugExt;
use serde::{Deserialize, Serialize};

use super::{
    keys::{OpenKey, SealKey, Seq},
    shared::{AuthorEncap, EphemeralDecapKey, PeerEncap, RawKey},
};
use crate::{
    aranya::{EncryptionKey, EncryptionPublicKey, UserId},
    ciphersuite::SuiteIds,
    engine::Engine,
    error::Error,
    hash::tuple_hash,
    hpke::{Hpke, Mode},
    id::Id,
    import::ImportError,
    kem::Kem,
};

/// Contextual information for a bidirectional APS channel.
///
/// In a bidirectional channel, both users can encrypt and
/// decrypt messages.
///
/// ```rust
/// # #[cfg(all(feature = "alloc", not(feature = "moonshot")))]
/// # {
/// use {
///     core::borrow::{Borrow, BorrowMut},
///     crypto::{
///         aead::{Aead, KeyData},
///         aps::{
///             BidiAuthorEncap,
///             BidiChannel,
///             BidiEncaps,
///             BidiKeys,
///             BidiPeerEncap,
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
/// struct Keys<E: Engine + ?Sized> {
///     seal: SealKey<E>,
///     open: OpenKey<E>,
/// }
///
/// impl<E: Engine + ?Sized> Keys<E> {
///     fn from_author(
///         ch: &BidiChannel<'_, E>,
///         encap: BidiAuthorEncap<E>,
///     ) -> Self {
///         let keys = BidiKeys::from_author_encap(ch, encap)
///             .expect("should be able to decapsulate author keys");
///         let (seal, open) = keys.into_keys()
///             .expect("should be able to convert `BidiKeys`");
///         Self { seal, open }
///     }
///
///     fn from_peer(
///         ch: &BidiChannel<'_, E>,
///         encap: BidiPeerEncap<E>,
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
/// let user1_sk = EncryptionKey::<E>::new(&mut eng);
/// let user1_id = IdentityKey::<E>::new(&mut eng).id();
///
/// let user2_sk = EncryptionKey::<E>::new(&mut eng);
/// let user2_id = IdentityKey::<E>::new(&mut eng).id();
///
/// // user1 creates the channel keys and sends the encapsulation
/// // to user2...
/// let user1_ch = BidiChannel {
///     parent_cmd_id,
///     our_sk: &user1_sk,
///     our_id: user1_id,
///     their_pk: &user2_sk.public(),
///     their_id: user2_id,
///     label,
/// };
/// let BidiEncaps { author, peer } = BidiEncaps::new(&mut eng, &user1_ch)
///     .expect("unable to create `BidiEncaps`");
/// let mut user1 = Keys::from_author(&user1_ch, author);
///
/// // ...and user2 decrypts the encapsulation to discover the
/// // channel keys.
/// let user2_ch = BidiChannel {
///     parent_cmd_id,
///     our_sk: &user2_sk,
///     our_id: user2_id,
///     their_pk: &user1_sk.public(),
///     their_id: user1_id,
///     label,
/// };
/// let mut user2 = Keys::from_peer(&user2_ch, peer);
///
/// fn test<E: Engine + ?Sized>(a: &mut Keys<E>, b: &Keys<E>) {
///     const GOLDEN: &[u8] = b"hello, world!";
///     const ADDITIONAL_DATA: &[u8] = b"authenticated, but not encrypted data";
///
///     let version = 4;
///     let label = 1234;
///     let (ciphertext, seq) = {
///         let mut dst = vec![0u8; GOLDEN.len() + SealKey::<E>::OVERHEAD];
///         let seq = a.seal.seal(&mut dst, GOLDEN, (version, label))
///             .expect("should be able to encrypt plaintext");
///         (dst, seq)
///     };
///     let plaintext = {
///         let mut dst = vec![0u8; ciphertext.len()];
///         b.open.open(&mut dst, &ciphertext, (version, label), seq)
///             .expect("should be able to decrypt ciphertext");
///         dst.truncate(ciphertext.len() - OpenKey::<E>::OVERHEAD);
///         dst
///     };
///     assert_eq!(&plaintext, GOLDEN);
/// }
/// test(&mut user1, &user2); // user1 -> user2
/// test(&mut user2, &user1); // user2 -> user1
/// # }
/// ```
pub struct BidiChannel<'a, E>
where
    E: Engine + ?Sized,
{
    /// The ID of the parent command.
    pub parent_cmd_id: Id,
    /// Our secret encryption key.
    pub our_sk: &'a EncryptionKey<E>,
    /// Our UserID.
    pub our_id: UserId,
    /// Their public encryption key.
    pub their_pk: &'a EncryptionPublicKey<E>,
    /// Their UserID.
    pub their_id: UserId,
    /// The policy label applied to the channel.
    pub label: u32,
}

/// A bidirectional channel author's encapsulated secret.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[serde(bound = "")]
pub struct BidiAuthorEncap<E: Engine + ?Sized>(AuthorEncap<E>);

/// A bidirectional channel peer's encapsulated secret.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BidiPeerEncap<E: Engine + ?Sized>(PeerEncap<E>);

impl<E: Engine + ?Sized> BidiPeerEncap<E> {
    /// Creates an peer's encapsulation deterministically using
    /// `ephemeral_sk`.
    fn new(
        author_sk: &EncryptionKey<E>,
        peer_pk: &EncryptionPublicKey<E>,
        info: &[u8],
        ephemeral_sk: EphemeralDecapKey<E>,
    ) -> Result<Self, Error> {
        Ok(Self(PeerEncap::new(
            author_sk,
            peer_pk,
            info,
            ephemeral_sk,
        )?))
    }

    /// Encodes itself as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns itself from its byte encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        Ok(Self(PeerEncap::from_bytes(data)?))
    }

    fn as_inner(&self) -> &<E::Kem as Kem>::Encap {
        self.0.as_inner()
    }
}

/// The encapsulated secrets for a bidirectional channel.
pub struct BidiEncaps<E: Engine + ?Sized> {
    /// The author's encapsulation.
    pub author: BidiAuthorEncap<E>,
    /// The peer's encapsulation.
    pub peer: BidiPeerEncap<E>,
}

impl<E: Engine + ?Sized> BidiEncaps<E> {
    /// Creates a new set of encapsulated secrets for the
    /// bidirectional channel.
    pub fn new(eng: &mut E, ch: &BidiChannel<'_, E>) -> Result<Self, Error> {
        // Only the author performs this function
        let author_id = ch.our_id;
        let author_sk = ch.our_sk;
        let peer_id = ch.their_id;
        let peer_pk = ch.their_pk;

        if author_id == peer_id {
            return Err(Error::same_user_id());
        }

        // info = H(
        //     "ApsChannelKeys",
        //     suite_id,
        //     engine_id,
        //     parent_cmd_id,
        //     author_id,
        //     peer_id,
        //     i2osp(label, 4),
        // )
        let info = tuple_hash::<E::Hash, _>([
            "ApsChannelKeys".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            E::ID.as_bytes(),
            ch.parent_cmd_id.as_bytes(),
            author_id.as_bytes(),
            peer_id.as_bytes(),
            &ch.label.to_be_bytes(),
        ]);

        let ephemeral_sk = EphemeralDecapKey::new(eng);
        let peer = BidiPeerEncap::new(author_sk, peer_pk, &info, ephemeral_sk.clone())?;
        let author = BidiAuthorEncap(ephemeral_sk.seal(eng, author_sk, &info)?);

        Ok(BidiEncaps { author, peer })
    }
}

/// Bidirectional channel encryption keys.
pub struct BidiKeys<E: Engine + ?Sized> {
    seal: RawKey<E>,
    open: RawKey<E>,
}

impl<E: Engine + ?Sized> BidiKeys<E> {
    /// Decrypts and authenticates an encapsulated key received
    /// from ourself.
    pub fn from_author_encap(
        ch: &BidiChannel<'_, E>,
        enc: BidiAuthorEncap<E>,
    ) -> Result<Self, Error> {
        // Only the author performs this function
        let author_id = ch.our_id;
        let author_sk = ch.our_sk;
        let peer_id = ch.their_id;
        let peer_pk = ch.their_pk;

        if author_id == peer_id {
            return Err(Error::same_user_id());
        }

        // info = H(
        //     "ApsChannelKeys",
        //     suite_id,
        //     engine_id,
        //     parent_cmd_id,
        //     our_id,
        //     peer_id,
        //     i2osp(label, 4),
        // )
        let info = tuple_hash::<E::Hash, _>([
            "ApsChannelKeys".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            E::ID.as_bytes(),
            ch.parent_cmd_id.as_bytes(),
            author_id.as_bytes(),
            peer_id.as_bytes(),
            &ch.label.to_be_bytes(),
        ]);

        let ephemeral_sk = EphemeralDecapKey::open(enc.0, author_sk, &info)?;
        let (_, ctx) = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_send_deterministically(
            Mode::Auth(&author_sk.0),
            &peer_pk.0,
            &info,
            ephemeral_sk.into_inner(),
        )?;

        let open = RawKey {
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
            RawKey { key, base_nonce }
        };
        Ok(Self { seal, open })
    }

    /// Decrypts and authenticates an encapsulated key received
    /// from a peer.
    pub fn from_peer_encap(ch: &BidiChannel<'_, E>, enc: BidiPeerEncap<E>) -> Result<Self, Error> {
        // Only the peer performs this function
        let peer_id = ch.our_id;
        let peer_sk = ch.our_sk;
        let author_id = ch.their_id;
        let author_pk = ch.their_pk;

        if author_id == peer_id {
            return Err(Error::same_user_id());
        }

        // info = H(
        //     "ApsChannelKeys",
        //     suite_id,
        //     engine_id,
        //     parent_cmd_id,
        //     author_id,
        //     peer_id,
        //     i2osp(label, 4),
        // )
        //
        // Except that we need to compute `info` from the other
        // peer's perspective, so `our_id` and `peer_id` are
        // reversed.
        let info = tuple_hash::<E::Hash, _>([
            "ApsChannelKeys".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            E::ID.as_bytes(),
            ch.parent_cmd_id.as_bytes(),
            author_id.as_bytes(),
            peer_id.as_bytes(),
            &ch.label.to_be_bytes(),
        ]);

        let ctx = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_recv(
            Mode::Auth(&author_pk.0),
            enc.as_inner(),
            &peer_sk.0,
            &info,
        )?;

        let seal = RawKey {
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
            RawKey { key, base_nonce }
        };
        Ok(Self { seal, open })
    }

    /// Returns the channel keys.
    pub fn into_keys(self) -> Result<(SealKey<E>, OpenKey<E>), Error> {
        let seal = {
            let RawKey { key, base_nonce } = self.seal;
            SealKey::from_raw(&key, &base_nonce, Seq::ZERO)?
        };
        let open = {
            let RawKey { key, base_nonce } = self.open;
            OpenKey::from_raw(&key, &base_nonce, Seq::ZERO)?
        };
        Ok((seal, open))
    }

    /// Returns the raw channel keys.
    pub fn into_raw_keys(self) -> RawBidiKeys<E> {
        RawBidiKeys {
            seal: self.seal,
            open: self.open,
        }
    }
}

#[cfg(any(test, feature = "test_util"))]
impl<E: Engine + ?Sized> BidiKeys<E> {
    pub(crate) fn seal_key(&self) -> &RawKey<E> {
        &self.seal
    }

    pub(crate) fn open_key(&self) -> &RawKey<E> {
        &self.open
    }
}

/// Raw bidirectional channel keys.
pub struct RawBidiKeys<E: Engine + ?Sized> {
    /// The encryption key.
    pub seal: RawKey<E>,
    /// The decryption keys.
    pub open: RawKey<E>,
}
