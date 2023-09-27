//! Cryptography code for [APS].
//!
//! [APS]: https://github.com/spideroak-inc/aps

use {
    crate::{
        aead::KeyData,
        aranya::{Encap, EncryptionKey, EncryptionPublicKey, UserId},
        ciphersuite::SuiteIds,
        engine::Engine,
        error::Error,
        hash::tuple_hash,
        hpke::{Hpke, Mode},
        id::Id,
    },
    core::borrow::{Borrow, BorrowMut},
};

// This is different from the rest of the `crypto` API in that it
// allows users to directly access key material (`ChannelKeys`).
// Unfortunately, we have to allow this since APS needs to store
// the raw key material.

/// Contextual information for an APS channel.
pub struct Channel<'a, E>
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
pub struct ChannelKeys<E: Engine + ?Sized> {
    seal_key: KeyData<E::Aead>,
    open_key: KeyData<E::Aead>,
}

impl<E: Engine + ?Sized> ChannelKeys<E> {
    /// Creates a new set of [`ChannelKeys`] for the channel and
    /// an encapsulation that the peer can use to decrypt them.
    pub fn new(eng: &mut E, ch: &Channel<'_, E>) -> Result<(Encap<E>, Self), Error> {
        if ch.our_id == ch.peer_id {
            return Err(Error::InvalidArgument("same `UserId`"));
        }

        // info = H(
        //     "ChannelKeys",
        //     suite_id,
        //     engine_id,
        //     cmd_id,
        //     our_id,
        //     peer_id,
        //     i2osp(label, 4),
        // )
        let info = tuple_hash::<E::Hash, _>([
            "ChannelKeys".as_bytes(),
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
        Ok((Encap(enc), ChannelKeys { seal_key, open_key }))
    }

    /// Decrypts and authenticates [`ChannelKeys`] received from
    /// a peer.
    pub fn from_encap(ch: &Channel<'_, E>, enc: &Encap<E>) -> Result<Self, Error> {
        if ch.our_id == ch.peer_id {
            return Err(Error::InvalidArgument("same `UserId`"));
        }

        // info = H(
        //     "ChannelKeys",
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
            "ChannelKeys".as_bytes(),
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

        // Note how this is the reverse of `new_keys`.
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
