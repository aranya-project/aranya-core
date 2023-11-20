//! Cryptography code for [APS].
//!
//! [APS]: https://git.spideroak-inc.com/spideroak-inc/aps

use core::borrow::{Borrow, BorrowMut};

use crate::{
    aead::KeyData,
    aranya::{Encap, EncryptionKey, EncryptionPublicKey, UserId},
    ciphersuite::SuiteIds,
    engine::Engine,
    error::Error,
    hash::tuple_hash,
    hpke::{Hpke, Mode},
    id::Id,
};

// This is different from the rest of the `crypto` API in that it
// allows users to directly access key material (`ChannelKeys`,
// `SealOnlyKey`, `OpenOnlyKey`). Unfortunately, we have to allow
// this since APS needs to store the raw key material.

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
///         aead::Aead,
///         aps::{ChannelKeys, BidiChannel},
///         CipherSuite,
///         Csprng,
///         DefaultCipherSuite,
///         DefaultEngine,
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
///     seal: E::Aead,
///     open: E::Aead,
/// }
///
/// impl<E: Engine + ?Sized> Keys<E> {
///     fn new(ck: ChannelKeys<E>) -> Self {
///         fn new_aead<E: Engine + ?Sized>(key: &[u8]) -> E::Aead {
///             let key = <<E as CipherSuite>::Aead as Aead>::Key::import(key)
///                 .expect("should be able to import key");
///             Aead::new(&key)
///         }
///         let seal = new_aead::<E>(ck.seal_key());
///         let open = new_aead::<E>(ck.open_key());
///         Self { seal, open }
///     }
/// }
///
/// type KeyData<A> = <<A as Aead>::Key as SecretKey>::Data;
/// type E = DefaultEngine<Rng, DefaultCipherSuite>;
/// let (mut eng, _) = E::from_entropy(Rng);
///
/// let cmd_id = Id::random(&mut eng);
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
/// let (enc, user1_ck) = {
///     let ch = BidiChannel {
///         cmd_id,
///         our_sk: &user1_sk,
///         our_id: user1_id,
///         peer_pk: &user2_sk.public(),
///         peer_id: user2_id,
///         label,
///     };
///     ChannelKeys::new(&mut eng, &ch)
///         .expect("unable to create `ChannelKeys`")
/// };
///
/// // ...and user2 decrypts the encapsulation to discover the
/// // channel keys.
/// let user2_ck = {
///     let ch = BidiChannel {
///         cmd_id,
///         our_sk: &user2_sk,
///         our_id: user2_id,
///         peer_pk: &user1_sk.public(),
///         peer_id: user1_id,
///         label,
///     };
///     ChannelKeys::from_encap(&ch, &enc)
///         .expect("unable to decrypt `ChannelKeys`")
/// };
///
/// let user1 = Keys::new(user1_ck);
/// let user2 = Keys::new(user2_ck);
///
/// fn test<E: Engine + ?Sized>(a: &Keys<E>, b: &Keys<E>) {
///     const GOLDEN: &[u8] = b"hello, world!";
///     const ADDITIONAL_DATA: &[u8] = b"authenticated, but not encrypted data";
///
///     let (nonce, ciphertext) = {
///         let mut dst = vec![0u8; GOLDEN.len() + <E as CipherSuite>::Aead::OVERHEAD];
///         let mut nonce = <<E as CipherSuite>::Aead as Aead>::Nonce::default();
///         Rng.fill_bytes(nonce.borrow_mut());
///         a.seal.seal(&mut dst, nonce.borrow(), GOLDEN, ADDITIONAL_DATA)
///             .expect("should be able to encrypt plaintext");
///         (nonce, dst)
///     };
///     let plaintext = {
///         let mut dst = vec![0u8; ciphertext.len()];
///         b.open.open(&mut dst, nonce.borrow(), &ciphertext, ADDITIONAL_DATA)
///             .expect("should be able to decrypt ciphertext");
///         dst.truncate(ciphertext.len() - <E as CipherSuite>::Aead::OVERHEAD);
///         dst
///     };
///     assert_eq!(&plaintext, GOLDEN);
/// }
/// test(&user1, &user2); // user1 -> user2
/// test(&user2, &user1); // user2 -> user1
/// # }
/// ```
pub struct BidiChannel<'a, E>
where
    E: Engine + ?Sized,
{
    /// The ID of the command that created the channel.
    pub cmd_id: Id,
    /// Our secret encryption key.
    pub our_sk: &'a EncryptionKey<E>,
    /// Our UserID.
    pub our_id: UserId,
    /// The peer's public encryption key.
    pub peer_pk: &'a EncryptionPublicKey<E>,
    /// The peer's UserID.
    pub peer_id: UserId,
    /// The policy label applied to the channel.
    pub label: u32,
}

/// Per-channel encryption keys.
///
/// The initiator creates the keys with [`ChannelKeys::new`] and
/// the responder accesses them with [`ChannelKeys::from_encap`].
pub struct ChannelKeys<E: Engine + ?Sized> {
    seal_key: KeyData<E::Aead>,
    open_key: KeyData<E::Aead>,
}

impl<E: Engine + ?Sized> ChannelKeys<E> {
    /// Creates a new set of [`ChannelKeys`] for the
    /// channel and an encapsulation that the peer can use to
    /// decrypt them.
    pub fn new(eng: &mut E, ch: &BidiChannel<'_, E>) -> Result<(Encap<E>, Self), Error> {
        if ch.our_id == ch.peer_id {
            return Err(Error::InvalidArgument("same `UserId`"));
        }

        // info = H(
        //     "ApsChannelKeys",
        //     suite_id,
        //     engine_id,
        //     cmd_id,
        //     our_id,
        //     peer_id,
        //     i2osp(label, 4),
        // )
        let info = tuple_hash::<E::Hash, _>([
            "ApsChannelKeys".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            E::ID.as_bytes(),
            ch.cmd_id.as_bytes(),
            ch.our_id.as_bytes(),
            ch.peer_id.as_bytes(),
            &ch.label.to_be_bytes(),
        ]);
        let (enc, ctx) = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_send(
            eng,
            Mode::Auth(&ch.our_sk.0),
            &ch.peer_pk.0,
            &info,
        )?;

        let seal_key = {
            let mut key = KeyData::<E::Aead>::default();
            ctx.export(key.borrow_mut(), ch.peer_id.as_bytes())?;
            key
        };
        let open_key = {
            let mut key = KeyData::<E::Aead>::default();
            ctx.export(key.borrow_mut(), ch.our_id.as_bytes())?;
            key
        };
        Ok((Encap(enc), Self { seal_key, open_key }))
    }

    /// Decrypts and authenticates [`ChannelKeys`] received from
    /// a peer.
    pub fn from_encap(ch: &BidiChannel<'_, E>, enc: &Encap<E>) -> Result<Self, Error> {
        if ch.our_id == ch.peer_id {
            return Err(Error::InvalidArgument("same `UserId`"));
        }

        // info = H(
        //     "ApsChannelKeys",
        //     suite_id,
        //     engine_id,
        //     cmd_id,
        //     our_id,
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
            ch.cmd_id.as_bytes(),
            ch.peer_id.as_bytes(),
            ch.our_id.as_bytes(),
            &ch.label.to_be_bytes(),
        ]);
        let ctx = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_recv(
            Mode::Auth(&ch.peer_pk.0),
            &enc.0,
            &ch.our_sk.0,
            &info,
        )?;

        // Note how this is the reverse of `new`.
        let open_key = {
            let mut key = KeyData::<E::Aead>::default();
            ctx.export(key.borrow_mut(), ch.our_id.as_bytes())?;
            key
        };
        let seal_key = {
            let mut key = KeyData::<E::Aead>::default();
            ctx.export(key.borrow_mut(), ch.peer_id.as_bytes())?;
            key
        };
        Ok(ChannelKeys { seal_key, open_key })
    }

    /// The key used to encrypt data for a peer.
    pub fn seal_key(&self) -> &[u8] {
        self.seal_key.borrow()
    }

    /// The key used to decrypt data from a peer.
    pub fn open_key(&self) -> &[u8] {
        self.open_key.borrow()
    }
}

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
///         aead::Aead,
///         aps::{OpenOnlyKey, SealOnlyKey, UniChannel},
///         CipherSuite,
///         Csprng,
///         DefaultCipherSuite,
///         DefaultEngine,
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
/// fn new_aead<E: Engine + ?Sized>(key: &[u8]) -> E::Aead {
///     let key = <<E as CipherSuite>::Aead as Aead>::Key::import(key)
///         .expect("should be able to import key");
///     Aead::new(&key)
/// }
///
/// type KeyData<A> = <<A as Aead>::Key as SecretKey>::Data;
/// type E = DefaultEngine<Rng, DefaultCipherSuite>;
/// let (mut eng, _) = E::from_entropy(Rng);
///
/// let cmd_id = Id::random(&mut eng);
/// let label = 42u32;
///
/// // In this example, user1 encrypts data...
/// let user1_sk = EncryptionKey::<E>::new(&mut eng);
/// let user1_id = IdentityKey::<E>::new(&mut eng).id();
///
/// // ...and user2 decrypts it.
/// let user2_sk = EncryptionKey::<E>::new(&mut eng);
/// let user2_id = IdentityKey::<E>::new(&mut eng).id();
///
/// // user1 creates the channel key and sends the encapsulation
/// // to user2...
/// let (enc, user1_key) = {
///     let ch = UniChannel {
///         cmd_id,
///         our_sk: &user1_sk,
///         peer_pk: &user2_sk.public(),
///         seal_id: user1_id,
///         open_id: user2_id,
///         label,
///     };
///     SealOnlyKey::new(&mut eng, &ch)
///         .expect("unable to create `SealOnlyKey`")
/// };
///
/// // ...and user2 decrypts the encapsulation to discover the
/// // channel key.
/// let user2_key = {
///     let ch = UniChannel {
///         cmd_id,
///         our_sk: &user2_sk,
///         peer_pk: &user1_sk.public(),
///         seal_id: user1_id,
///         open_id: user2_id,
///         label,
///     };
///     OpenOnlyKey::from_encap(&ch, &enc)
///         .expect("unable to decrypt `OpenOnlyKey`")
/// };
///
/// let user1 = new_aead::<E>(user1_key.as_bytes());
/// let user2 = new_aead::<E>(user2_key.as_bytes());
///
/// const GOLDEN: &[u8] = b"hello, world!";
/// const ADDITIONAL_DATA: &[u8] = b"authenticated, but not encrypted data";
///
/// let (nonce, ciphertext) = {
///     let mut dst = vec![0u8; GOLDEN.len() + <E as CipherSuite>::Aead::OVERHEAD];
///     let mut nonce = <<E as CipherSuite>::Aead as Aead>::Nonce::default();
///     Rng.fill_bytes(nonce.borrow_mut());
///     user1.seal(&mut dst, nonce.borrow(), GOLDEN, ADDITIONAL_DATA)
///         .expect("should be able to encrypt plaintext");
///     (nonce, dst)
/// };
///
/// let plaintext = {
///     let mut dst = vec![0u8; ciphertext.len()];
///     user2.open(&mut dst, nonce.borrow(), &ciphertext, ADDITIONAL_DATA)
///         .expect("should be able to decrypt ciphertext");
///     dst.truncate(ciphertext.len() - <E as CipherSuite>::Aead::OVERHEAD);
///     dst
/// };
///
/// assert_eq!(&plaintext, GOLDEN);
/// # }
pub struct UniChannel<'a, E>
where
    E: Engine + ?Sized,
{
    /// The ID of the command that created the channel.
    pub cmd_id: Id,
    /// Our secret encryption key.
    pub our_sk: &'a EncryptionKey<E>,
    /// The peer's public encryption key.
    pub peer_pk: &'a EncryptionPublicKey<E>,
    /// The user that is permitted to encrypt messages.
    pub seal_id: UserId,
    /// The user that is permitted to decrypt messages.
    pub open_id: UserId,
    /// The policy label applied to the channel.
    pub label: u32,
}

/// A per-channel encryption key.
///
/// The initiator creates the keys with [`SealOnlyKey::new`] and
/// the responder accesses them with [`OpenOnlyKey::from_encap`].
pub struct SealOnlyKey<E: Engine + ?Sized>(KeyData<E::Aead>);

impl<E: Engine + ?Sized> SealOnlyKey<E> {
    /// Creates a `SealOnlyKey` for the channel and an
    /// encapsulation that the peer can use to decrypt them.
    pub fn new(eng: &mut E, ch: &UniChannel<'_, E>) -> Result<(Encap<E>, Self), Error> {
        if ch.seal_id == ch.open_id {
            return Err(Error::InvalidArgument("same `UserId`"));
        }

        // info = H(
        //     "ApsUnidirectionalKey",
        //     suite_id,
        //     engine_id,
        //     cmd_id,
        //     seal_id,
        //     open_id,
        //     i2osp(label, 4),
        // )
        let info = tuple_hash::<E::Hash, _>([
            "ApsUnidirectionalKey".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            E::ID.as_bytes(),
            ch.cmd_id.as_bytes(),
            ch.seal_id.as_bytes(),
            ch.open_id.as_bytes(),
            &ch.label.to_be_bytes(),
        ]);
        let (enc, ctx) = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_send(
            eng,
            Mode::Auth(&ch.our_sk.0),
            &ch.peer_pk.0,
            &info,
        )?;

        let key = {
            let mut key = KeyData::<E::Aead>::default();
            ctx.export(key.borrow_mut(), b"unidirectional key")?;
            key
        };
        Ok((Encap(enc), Self(key)))
    }

    /// Returns the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.borrow()
    }
}

/// A per-channel encryption key.
///
/// The initiator creates the keys with [`SealOnlyKey::new`] and
/// the responder accesses them with [`OpenOnlyKey::from_encap`].
pub struct OpenOnlyKey<E: Engine + ?Sized>(KeyData<E::Aead>);

impl<E: Engine + ?Sized> OpenOnlyKey<E> {
    /// Decrypts and authenticates a [`OpenOnlyKey`] received
    /// from a peer.
    pub fn from_encap(ch: &UniChannel<'_, E>, enc: &Encap<E>) -> Result<Self, Error> {
        if ch.seal_id == ch.open_id {
            return Err(Error::InvalidArgument("same `UserId`"));
        }

        // info = H(
        //     "ApsUnidirectionalKey",
        //     suite_id,
        //     engine_id,
        //     cmd_id,
        //     seal_id,
        //     open_id,
        //     i2osp(label, 4),
        // )
        let info = tuple_hash::<E::Hash, _>([
            "ApsUnidirectionalKey".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            E::ID.as_bytes(),
            ch.cmd_id.as_bytes(),
            ch.seal_id.as_bytes(),
            ch.open_id.as_bytes(),
            &ch.label.to_be_bytes(),
        ]);
        let ctx = Hpke::<E::Kem, E::Kdf, E::Aead>::setup_recv(
            Mode::Auth(&ch.peer_pk.0),
            &enc.0,
            &ch.our_sk.0,
            &info,
        )?;

        let key = {
            let mut key = KeyData::<E::Aead>::default();
            ctx.export(key.borrow_mut(), b"unidirectional key")?;
            key
        };
        Ok(Self(key))
    }

    /// Returns the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.borrow()
    }
}
