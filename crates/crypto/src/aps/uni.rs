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
    hash::{tuple_hash, Digest, Hash},
    hpke::{Hpke, Mode},
    id::Id,
    import::ImportError,
    kem::Kem,
};

/// Contextual information for a unidirectional APS channel.
///
/// In a unidirectional channel, one user is permitted to encrypt
/// messages and one user is permitted to receive decrypt
/// messages.
///
/// ```rust
/// # #[cfg(all(feature = "alloc", not(feature = "moonshot")))]
/// # {
/// use {
///     core::borrow::{Borrow, BorrowMut},
///     crypto::{
///         aead::{Aead, KeyData},
///         aps::{
///             OpenKey,
///             SealKey,
///             UniAuthorEncap,
///             UniChannel,
///             UniEncaps,
///             UniKey,
///             UniPeerEncap,
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
/// fn key_from_author<E: Engine + ?Sized>(
///     ch: &UniChannel<'_, E>,
///     encap: UniAuthorEncap<E>,
/// ) -> SealKey<E> {
///     let key = UniKey::from_author_encap(ch, encap)
///         .expect("should be able to decapsulate author key");
///     key.seal_key().expect("should be able to create `SealKey`")
/// }
///
/// fn key_from_peer<E: Engine + ?Sized>(
///     ch: &UniChannel<'_, E>,
///     encap: UniPeerEncap<E>,
/// ) -> OpenKey<E>{
///     let key = UniKey::from_peer_encap(ch, encap)
///         .expect("should be able to decapsulate peer key");
///     key.open_key().expect("should be able to create `OpenKey`")
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
/// let user1_ch = UniChannel {
///     parent_cmd_id,
///     our_sk: &user1_sk,
///     their_pk: &user2_sk.public(),
///     seal_id: user1_id,
///     open_id: user2_id,
///     label,
/// };
/// let UniEncaps { author, peer } = UniEncaps::new(&mut eng, &user1_ch)
///     .expect("unable to create `UniEncaps`");
/// let mut user1 = key_from_author(&user1_ch, author);
///
/// // ...and user2 decrypts the encapsulation to discover the
/// // channel keys.
/// let user2_ch = UniChannel {
///     parent_cmd_id,
///     our_sk: &user2_sk,
///     their_pk: &user1_sk.public(),
///     seal_id: user1_id,
///     open_id: user2_id,
///     label,
/// };
/// let user2 = key_from_peer(&user2_ch, peer);
///
/// fn test<E: Engine + ?Sized>(seal: &mut SealKey<E>, open: &OpenKey<E>) {
///     const GOLDEN: &[u8] = b"hello, world!";
///     const ADDITIONAL_DATA: &[u8] = b"authenticated, but not encrypted data";
///
///     let version = 4;
///     let label = 1234;
///     let (ciphertext, seq) = {
///         let mut dst = vec![0u8; GOLDEN.len() + SealKey::<E>::OVERHEAD];
///         let seq = seal.seal(&mut dst, GOLDEN, (version, label))
///             .expect("should be able to encrypt plaintext");
///         (dst, seq)
///     };
///     let plaintext = {
///         let mut dst = vec![0u8; ciphertext.len()];
///         open.open(&mut dst, &ciphertext, (version, label), seq)
///             .expect("should be able to decrypt ciphertext");
///         dst.truncate(ciphertext.len() - OpenKey::<E>::OVERHEAD);
///         dst
///     };
///     assert_eq!(&plaintext, GOLDEN);
/// }
/// test(&mut user1, &user2); // user1 -> user2
/// # }
/// ```
pub struct UniChannel<'a, E>
where
    E: Engine + ?Sized,
{
    /// The ID of the parent command.
    pub parent_cmd_id: Id,
    /// Our secret encryption key.
    pub our_sk: &'a EncryptionKey<E>,
    /// Their public encryption key.
    pub their_pk: &'a EncryptionPublicKey<E>,
    /// The user that is permitted to encrypt messages.
    pub seal_id: UserId,
    /// The user that is permitted to decrypt messages.
    pub open_id: UserId,
    /// The policy label applied to the channel.
    pub label: u32,
}

impl<E: Engine + ?Sized> UniChannel<'_, E> {
    fn info(&self) -> Digest<<E::Hash as Hash>::DigestSize> {
        // info = H(
        //     "ApsUnidirectionalKey",
        //     suite_id,
        //     engine_id,
        //     parent_cmd_id,
        //     seal_id,
        //     open_id,
        //     i2osp(label, 4),
        // )
        tuple_hash::<E::Hash, _>([
            "ApsUnidirectionalKey".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            E::ID.as_bytes(),
            self.parent_cmd_id.as_bytes(),
            self.seal_id.as_bytes(),
            self.open_id.as_bytes(),
            &self.label.to_be_bytes(),
        ])
    }
}

/// A unirectional channel author's encapsulated secret.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct UniAuthorEncap<E: Engine + ?Sized>(AuthorEncap<E>);

/// A unirectional channel peer's encapsulated secret.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct UniPeerEncap<E: Engine + ?Sized>(PeerEncap<E>);

impl<E: Engine + ?Sized> UniPeerEncap<E> {
    /// Creates a peer's encapsulation deterministically using
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

/// The encapsulated secrets for a unirectional channel.
pub struct UniEncaps<E: Engine + ?Sized> {
    /// The author's encapsulation.
    pub author: UniAuthorEncap<E>,
    /// The peer's encapsulation.
    pub peer: UniPeerEncap<E>,
}

impl<E: Engine + ?Sized> UniEncaps<E> {
    /// Creates a new set of encapsulated secrets for the
    /// unidirectional channel.
    pub fn new(eng: &mut E, ch: &UniChannel<'_, E>) -> Result<Self, Error> {
        // Only author does this function
        let author_sk = ch.our_sk;
        let peer_pk = ch.their_pk;

        if ch.seal_id == ch.open_id {
            return Err(Error::same_user_id());
        }

        let info = ch.info();
        let ephemeral_sk = EphemeralDecapKey::new(eng);
        let peer = UniPeerEncap::new(author_sk, peer_pk, &info, ephemeral_sk.clone())?;
        let author = UniAuthorEncap(ephemeral_sk.seal(eng, author_sk, &info)?);

        Ok(UniEncaps { author, peer })
    }
}

/// A unidirectional channel encryption key.
pub struct UniKey<E: Engine + ?Sized>(RawKey<E>);

impl<E: Engine + ?Sized> UniKey<E> {
    /// Decrypts and authenticates an encapsulated key received
    /// from ourself.
    pub fn from_author_encap(
        ch: &UniChannel<'_, E>,
        enc: UniAuthorEncap<E>,
    ) -> Result<Self, Error> {
        // Only author does this function
        let author_sk = ch.our_sk;
        let peer_pk = ch.their_pk;

        if ch.seal_id == ch.open_id {
            return Err(Error::same_user_id());
        }

        let info = ch.info();
        let ephemeral_sk = EphemeralDecapKey::open(enc.0, author_sk, &info)?;
        let (_, ctx) = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_send_deterministically(
            Mode::Auth(&author_sk.0),
            &peer_pk.0,
            &info,
            ephemeral_sk.into_inner(),
        )?;
        let key = {
            // `SendCtx` only gets rid of the raw key after the
            // first call to `seal`, etc., so it should still
            // exist at this point.
            let (key, base_nonce) = ctx
                .into_raw_parts()
                .assume("`SendCtx` should still contain the raw key")?;
            RawKey { key, base_nonce }
        };
        Ok(Self(key))
    }

    /// Decrypts and authenticates an encapsulated key received
    /// from a peer.
    pub fn from_peer_encap(ch: &UniChannel<'_, E>, enc: UniPeerEncap<E>) -> Result<Self, Error> {
        // Only peer does this function
        let peer_sk = ch.our_sk;
        let author_pk = ch.their_pk;

        if ch.seal_id == ch.open_id {
            return Err(Error::same_user_id());
        }

        let info = ch.info();
        let ctx = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_recv(
            Mode::Auth(&author_pk.0),
            enc.as_inner(),
            &peer_sk.0,
            &info,
        )?;
        let key = {
            // `Recv` only gets rid of the raw key after the
            // first call to `open`, etc., so it should still
            // exist at this point.
            let (key, base_nonce) = ctx
                .into_raw_parts()
                .assume("`RecvCtx` should still contain the raw key")?;
            RawKey { key, base_nonce }
        };
        Ok(Self(key))
    }

    /// Returns the encryption key.
    pub fn seal_key(self) -> Result<SealKey<E>, Error> {
        let RawKey { key, base_nonce } = self.0;
        let seal = SealKey::from_raw(&key, &base_nonce, Seq::ZERO)?;
        Ok(seal)
    }

    /// Returns the decryption key.
    pub fn open_key(self) -> Result<OpenKey<E>, Error> {
        let RawKey { key, base_nonce } = self.0;
        let open = OpenKey::from_raw(&key, &base_nonce, Seq::ZERO)?;
        Ok(open)
    }
}

#[cfg(any(test, feature = "test_util"))]
impl<E: Engine + ?Sized> UniKey<E> {
    pub(crate) fn raw_key(&self) -> &RawKey<E> {
        &self.0
    }
}
