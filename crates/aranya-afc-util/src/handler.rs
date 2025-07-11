//! An effect handler for AFC.

use aranya_crypto::{
    CipherSuite, CmdId, DeviceId, EncryptionKeyId, Engine, KeyStore, KeyStoreExt,
    afc::{
        BidiAuthorSecret, BidiChannel, BidiPeerEncap, UniAuthorSecret, UniChannel, UniPeerEncap,
    },
    custom_id,
};
use aranya_fast_channels::{Directed, Label};
use serde::{Deserialize, Serialize};

use crate::{shared::decode_enc_pk, transform::Transform};

/// Wraps `tracing::error` to always use the `afc-handler`
/// target.
macro_rules! error {
    ($($arg:tt)+) => { ::tracing::error!(target: "afc-handler", $($arg)+) };
}

/// Handles AFC effects.
#[derive(Clone)]
pub struct Handler<S> {
    device_id: DeviceId,
    store: S,
}

impl<S> Handler<S> {
    /// Creates a new `Handler`.
    pub const fn new(device_id: DeviceId, store: S) -> Self {
        Self { device_id, store }
    }
}

// Bidi impl.
impl<S: KeyStore> Handler<S> {
    /// Retrieves the wrapped [`BidiAuthorSecret`] and converts
    /// it into a key suitable for
    /// [`AranyaState`][aranya_fast_channels::AranyaState].
    pub fn bidi_channel_created<E, SK, OK>(
        &mut self,
        eng: &mut E,
        effect: &BidiChannelCreated<'_>,
    ) -> Result<BidiKeys<SK, OK>, Error>
    where
        E: Engine,
        (SK, OK): for<'a> Transform<(&'a BidiChannel<'a, E::CS>, BidiAuthorSecret<E::CS>)>,
    {
        if self.device_id != effect.author_id {
            return Err(Error::NotAuthor);
        }

        let secret = self
            .store
            .remove_key(eng, effect.key_id.cast()) // TODO(jdygert): BidiKeyId vs BidiAuthorSecretId
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;

        let our_sk = &self
            .store
            .get_key(eng, effect.author_enc_key_id)
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;
        let their_pk = &decode_enc_pk(effect.peer_enc_pk).map_err(|err| {
            error!("unable to decode `EncryptionPublicKey`: {err}");
            Error::Encoding
        })?;
        let ch = BidiChannel {
            parent_cmd_id: effect.parent_cmd_id,
            our_sk,
            our_id: effect.author_id,
            their_pk,
            their_id: effect.peer_id,
            label: effect.label.to_u32(),
        };

        let (seal, open) = Transform::transform((&ch, secret)).map_err(|err| {
            error!("unable to transform author bidi keys: {err}");
            Error::Transform
        })?;
        Ok(BidiKeys { seal, open })
    }

    /// Converts a [`BidiPeerEncap`] into a key suitable for
    /// [`AranyaState`][aranya_fast_channels::AranyaState].
    pub fn bidi_channel_received<E, SK, OK>(
        &mut self,
        eng: &mut E,
        effect: &BidiChannelReceived<'_>,
    ) -> Result<BidiKeys<SK, OK>, Error>
    where
        E: Engine,
        (SK, OK): for<'a> Transform<(&'a BidiChannel<'a, E::CS>, BidiPeerEncap<E::CS>)>,
    {
        if self.device_id != effect.peer_id {
            return Err(Error::NotRecipient);
        }

        let encap =
            BidiPeerEncap::from_bytes(effect.encap).map_err(|err| Error::Crypto(err.into()))?;

        let our_sk = &self
            .store
            .get_key(eng, effect.peer_enc_key_id)
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;
        let their_pk = &decode_enc_pk(effect.author_enc_pk).map_err(|err| {
            error!("unable to decode `EncryptionPublicKey`: {err}");
            Error::Encoding
        })?;
        let ch = BidiChannel {
            parent_cmd_id: effect.parent_cmd_id,
            our_sk,
            our_id: effect.peer_id,
            their_pk,
            their_id: effect.author_id,
            label: effect.label.to_u32(),
        };

        let (seal, open) = Transform::transform((&ch, encap)).map_err(|err| {
            error!("unable to transform peer bidi keys: {err}");
            Error::Transform
        })?;
        Ok(BidiKeys { seal, open })
    }
}

/// Data from the `AfcBidiChannelCreated` effect.
#[derive(Clone, Serialize, Deserialize)]
pub struct BidiChannelCreated<'a> {
    /// The unique ID of the previous command.
    pub parent_cmd_id: CmdId,
    /// The channel author's device ID.
    pub author_id: DeviceId,
    /// The channel author's encryption key ID.
    pub author_enc_key_id: EncryptionKeyId,
    /// The channel peer's device ID.
    pub peer_id: DeviceId,
    /// The channel peer's encoded [`aranya_crypto::EncryptionPublicKey`].
    pub peer_enc_pk: &'a [u8],
    /// The AFC channel label.
    pub label: Label,
    /// The unique key identifier for the [`BidiAuthorSecret`].
    pub key_id: BidiKeyId,
}

/// Data from the `AfcBidiChannelReceived` effect.
#[derive(Clone, Serialize, Deserialize)]
pub struct BidiChannelReceived<'a> {
    /// The unique ID of the previous command.
    pub parent_cmd_id: CmdId,
    /// The channel author's device ID.
    pub author_id: DeviceId,
    /// The channel author's encoded [`aranya_crypto::EncryptionPublicKey`].
    pub author_enc_pk: &'a [u8],
    /// The channel peer's device ID.
    pub peer_id: DeviceId,
    /// The channel peer's encryption key ID.
    pub peer_enc_key_id: EncryptionKeyId,
    /// The AFC channel label.
    pub label: Label,
    /// The peer's encapsulation.
    pub encap: &'a [u8],
}

custom_id! {
    /// Uniquely identifies a bidirectional channel.
    pub struct BidiKeyId;
}

/// Bidirectional channel keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BidiKeys<S, O> {
    /// The encryption key.
    pub seal: S,
    /// The decryption key.
    pub open: O,
}

impl<S, O> From<BidiKeys<S, O>> for Directed<S, O> {
    fn from(key: BidiKeys<S, O>) -> Self {
        let BidiKeys { seal, open } = key;
        Self::Bidirectional { seal, open }
    }
}

// Uni impl.
impl<S: KeyStore> Handler<S> {
    /// Retrieves the wrapped [`UniAuthorSecret`] and converts it
    /// into a key suitable for
    /// [`AranyaState`][aranya_fast_channels::AranyaState].
    pub fn uni_channel_created<E, SK, OK>(
        &mut self,
        eng: &mut E,
        effect: &UniChannelCreated<'_>,
    ) -> Result<UniKey<SK, OK>, Error>
    where
        E: Engine,
        SK: for<'a> Transform<(&'a UniChannel<'a, E::CS>, UniAuthorSecret<E::CS>)>,
        OK: for<'a> Transform<(&'a UniChannel<'a, E::CS>, UniAuthorSecret<E::CS>)>,
    {
        if (self.device_id != effect.seal_id && self.device_id != effect.open_id)
            || self.device_id != effect.author_id
        {
            return Err(Error::NotAuthor);
        }

        let secret = self
            .store
            .remove_key(eng, effect.key_id.cast()) // TODO(jdygert): UniKeyId vs UniAuthorSecretId
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;

        let our_sk = &self
            .store
            .get_key(eng, effect.author_enc_key_id)
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;
        let their_pk = &decode_enc_pk(effect.peer_enc_pk).map_err(|err| {
            error!("unable to decode `EncryptionPublicKey`: {err}");
            Error::Encoding
        })?;
        let ch = UniChannel {
            parent_cmd_id: effect.parent_cmd_id,
            seal_id: effect.seal_id,
            open_id: effect.open_id,
            our_sk,
            their_pk,
            label: effect.label.to_u32(),
        };

        if self.device_id == effect.seal_id {
            UniKey::new(&ch, secret, UniKey::SealOnly)
        } else {
            UniKey::new(&ch, secret, UniKey::OpenOnly)
        }
    }

    /// Converts a [`UniPeerEncap`] into a key suitable for
    /// [`AranyaState`][aranya_fast_channels::AranyaState].
    pub fn uni_channel_received<E, SK, OK>(
        &mut self,
        eng: &mut E,
        effect: &UniChannelReceived<'_>,
    ) -> Result<UniKey<SK, OK>, Error>
    where
        E: Engine,
        SK: for<'a> Transform<(&'a UniChannel<'a, E::CS>, UniPeerEncap<E::CS>)>,
        OK: for<'a> Transform<(&'a UniChannel<'a, E::CS>, UniPeerEncap<E::CS>)>,
    {
        if (self.device_id != effect.seal_id && self.device_id != effect.open_id)
            || self.device_id == effect.author_id
        {
            return Err(Error::NotRecipient);
        }

        let encap =
            UniPeerEncap::from_bytes(effect.encap).map_err(|err| Error::Crypto(err.into()))?;

        let our_sk = &self
            .store
            .get_key(eng, effect.peer_enc_key_id)
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;
        let their_pk = &decode_enc_pk(effect.author_enc_pk).map_err(|err| {
            error!("unable to decode `EncryptionPublicKey`: {err}");
            Error::Encoding
        })?;
        let ch = UniChannel {
            parent_cmd_id: effect.parent_cmd_id,
            seal_id: effect.seal_id,
            open_id: effect.open_id,
            our_sk,
            their_pk,
            label: effect.label.to_u32(),
        };

        if self.device_id == effect.seal_id {
            UniKey::new(&ch, encap, UniKey::SealOnly)
        } else {
            UniKey::new(&ch, encap, UniKey::OpenOnly)
        }
    }
}

/// Data from the `AfcUniChannelCreated` effect.
#[derive(Clone, Serialize, Deserialize)]
pub struct UniChannelCreated<'a> {
    /// The unique ID of the previous command.
    pub parent_cmd_id: CmdId,
    /// The channel author's device ID.
    pub author_id: DeviceId,
    /// The device ID of the Device that can encrypt messages.
    pub seal_id: DeviceId,
    /// The device ID of the Device that can decrypt messages.
    pub open_id: DeviceId,
    /// The channel author's encryption key ID.
    pub author_enc_key_id: EncryptionKeyId,
    /// The channel peer's encoded [`aranya_crypto::EncryptionPublicKey`].
    pub peer_enc_pk: &'a [u8],
    /// The AFC channel label.
    pub label: Label,
    /// The unique key identifier for the [`UniAuthorSecret`].
    pub key_id: UniKeyId,
}

/// Data from the `AfcUniChannelReceived` effect.
#[derive(Clone, Serialize, Deserialize)]
pub struct UniChannelReceived<'a> {
    /// The unique ID of the previous command.
    pub parent_cmd_id: CmdId,
    /// The channel author's device ID.
    pub author_id: DeviceId,
    /// The device ID of the Device that can encrypt messages.
    pub seal_id: DeviceId,
    /// The device ID of the Device that can decrypt messages.
    pub open_id: DeviceId,
    /// The channel author's encoded [`aranya_crypto::EncryptionPublicKey`].
    pub author_enc_pk: &'a [u8],
    /// The channel peer's encryption key ID.
    pub peer_enc_key_id: EncryptionKeyId,
    /// The AFC channel label.
    pub label: Label,
    /// The peer's encapsulation.
    pub encap: &'a [u8],
}

custom_id! {
    /// Uniquely identifies a unirectional channel.
    pub struct UniKeyId;
}

/// A unidirectional channel key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UniKey<S, O> {
    /// May only be used for encryption.
    SealOnly(S),
    /// May only be used for decryption.
    OpenOnly(O),
}

impl<S, O> UniKey<S, O> {
    fn new<CS, F, K, V>(ch: &UniChannel<'_, CS>, value: V, f: F) -> Result<Self, Error>
    where
        CS: CipherSuite,
        F: FnOnce(K) -> Self,
        K: for<'a> Transform<(&'a UniChannel<'a, CS>, V)>,
    {
        let key = Transform::transform((ch, value)).map_err(|err| {
            error!("unable to transform key: {err}");
            Error::Transform
        })?;
        Ok(f(key))
    }
}

impl<S, O> From<UniKey<S, O>> for Directed<S, O> {
    fn from(key: UniKey<S, O>) -> Self {
        match key {
            UniKey::SealOnly(seal) => Self::SealOnly { seal },
            UniKey::OpenOnly(open) => Self::OpenOnly { open },
        }
    }
}

/// An error returned by [`Handler`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The current Device is not the author of the command.
    #[error("not command author")]
    NotAuthor,
    /// The current Device is not the recipient of the command.
    #[error("not command recipient")]
    NotRecipient,
    /// The keystore failed.
    #[error("keystore failure")]
    KeyStore,
    /// Unable to find a particular key.
    #[error("unable to find key")]
    KeyNotFound,
    /// Unable to transform key.
    #[error("unable to transform key")]
    Transform,
    /// Unable to encode/decode a key.
    #[error("unable to encode/decode")]
    Encoding,
    /// A `crypto` crate error.
    #[error(transparent)]
    Crypto(#[from] aranya_crypto::Error),
}
