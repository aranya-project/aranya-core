//! An effect handler for APS.

use core::fmt;

use aps::{Directed, Label};
use crypto::{
    aps::{
        BidiAuthorSecret, BidiChannel, BidiPeerEncap, UniAuthorSecret, UniChannel, UniPeerEncap,
    },
    EncryptionKeyId, Engine, Id, KeyStore, KeyStoreExt, UserId,
};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};

use crate::{shared::decode_enc_pk, transform::Transform};

/// Wraps `tracing::error` to always use the `aps-handler`
/// target.
macro_rules! error {
    ($($arg:tt)+) => { ::tracing::error!(target: "aps-handler", $($arg)+) };
}

/// Handles APS effects.
#[derive(Clone)]
pub struct Handler<S> {
    user_id: UserId,
    store: S,
}

impl<S> Handler<S> {
    /// Creates a new `Handler`.
    pub const fn new(user_id: UserId, store: S) -> Self {
        Self { user_id, store }
    }
}

// Bidi impl.
impl<S: KeyStore> Handler<S> {
    /// Retrieves the wrapped [`BidiAuthorSecret`] and converts
    /// it into a key suitable for
    /// [`AranyaState`][aps::AranyaState].
    pub fn bidi_channel_created<E, SK, OK>(
        &mut self,
        eng: &mut E,
        effect: &BidiChannelCreated<'_>,
    ) -> Result<BidiKeys<SK, OK>, Error>
    where
        E: Engine,
        (SK, OK): for<'a> Transform<(&'a BidiChannel<'a, E>, BidiAuthorSecret<E>)>,
    {
        if self.user_id != effect.author_id {
            return Err(Error::NotAuthor);
        }

        let secret = self
            .store
            .remove_key(eng, &effect.key_id.0)
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;

        let our_sk = &self
            .store
            .get_key(eng, &effect.author_enc_key_id.into())
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
    /// [`AranyaState`][aps::AranyaState].
    pub fn bidi_channel_received<E, SK, OK>(
        &mut self,
        eng: &mut E,
        effect: &BidiChannelReceived<'_>,
    ) -> Result<BidiKeys<SK, OK>, Error>
    where
        E: Engine,
        (SK, OK): for<'a> Transform<(&'a BidiChannel<'a, E>, BidiPeerEncap<E>)>,
    {
        if self.user_id != effect.peer_id {
            return Err(Error::NotRecipient);
        }

        let encap =
            BidiPeerEncap::from_bytes(effect.encap).map_err(|err| Error::Crypto(err.into()))?;

        let our_sk = &self
            .store
            .get_key(eng, &effect.peer_enc_key_id.into())
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

/// Data from the `ApsBidiChannelCreated` effect.
#[derive(Clone, Serialize, Deserialize)]
pub struct BidiChannelCreated<'a> {
    /// The unique ID of the previous command.
    pub parent_cmd_id: Id,
    /// The channel author's user ID.
    pub author_id: UserId,
    /// The channel author's encryption key ID.
    pub author_enc_key_id: EncryptionKeyId,
    /// The channel peer's user ID.
    pub peer_id: UserId,
    /// The channel peer's encoded [`crypto::EncryptionPublicKey`].
    pub peer_enc_pk: &'a [u8],
    /// The APS channel label.
    pub label: Label,
    /// The unique key identifier for the [`BidiAuthorSecret`].
    pub key_id: BidiKeyId,
}

/// Data from the `ApsBidiChannelReceived` effect.
#[derive(Clone, Serialize, Deserialize)]
pub struct BidiChannelReceived<'a> {
    /// The unique ID of the previous command.
    pub parent_cmd_id: Id,
    /// The channel author's user ID.
    pub author_id: UserId,
    /// The channel author's encoded [`crypto::EncryptionPublicKey`].
    pub author_enc_pk: &'a [u8],
    /// The channel peer's user ID.
    pub peer_id: UserId,
    /// The channel peer's encryption key ID.
    pub peer_enc_key_id: EncryptionKeyId,
    /// The APS channel label.
    pub label: Label,
    /// The peer's encapsulation.
    pub encap: &'a [u8],
}

/// Uniquely identifies a bidirectional channel.
#[derive(
    Copy, Clone, Default, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, MaxSize,
)]
pub struct BidiKeyId(Id);

impl From<Id> for BidiKeyId {
    fn from(id: Id) -> Self {
        Self(id)
    }
}

/// Bidirectional channel keys.
#[derive(Clone, Debug, Serialize, Deserialize, MaxSize)]
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
    /// [`AranyaState`][aps::AranyaState].
    pub fn uni_channel_created<E, SK, OK>(
        &mut self,
        eng: &mut E,
        effect: &UniChannelCreated<'_>,
    ) -> Result<UniKey<SK, OK>, Error>
    where
        E: Engine,
        SK: for<'a> Transform<(&'a UniChannel<'a, E>, UniAuthorSecret<E>)>,
        OK: for<'a> Transform<(&'a UniChannel<'a, E>, UniAuthorSecret<E>)>,
    {
        if (self.user_id != effect.seal_id && self.user_id != effect.open_id)
            || self.user_id != effect.author_id
        {
            return Err(Error::NotAuthor);
        }

        let secret = self
            .store
            .remove_key(eng, &effect.key_id.0)
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;

        let our_sk = &self
            .store
            .get_key(eng, &effect.author_enc_key_id.into())
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

        if self.user_id == effect.seal_id {
            UniKey::new(&ch, secret, UniKey::SealOnly)
        } else {
            UniKey::new(&ch, secret, UniKey::OpenOnly)
        }
    }

    /// Converts a [`UniPeerEncap`] into a key suitable for
    /// [`AranyaState`][aps::AranyaState].
    pub fn uni_channel_received<E, SK, OK>(
        &mut self,
        eng: &mut E,
        effect: &UniChannelReceived<'_>,
    ) -> Result<UniKey<SK, OK>, Error>
    where
        E: Engine,
        SK: for<'a> Transform<(&'a UniChannel<'a, E>, UniPeerEncap<E>)>,
        OK: for<'a> Transform<(&'a UniChannel<'a, E>, UniPeerEncap<E>)>,
    {
        if (self.user_id != effect.seal_id && self.user_id != effect.open_id)
            || self.user_id == effect.author_id
        {
            return Err(Error::NotRecipient);
        }

        let encap =
            UniPeerEncap::from_bytes(effect.encap).map_err(|err| Error::Crypto(err.into()))?;

        let our_sk = &self
            .store
            .get_key(eng, &effect.peer_enc_key_id.into())
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

        if self.user_id == effect.seal_id {
            UniKey::new(&ch, encap, UniKey::SealOnly)
        } else {
            UniKey::new(&ch, encap, UniKey::OpenOnly)
        }
    }
}

/// Data from the `ApsUniChannelCreated` effect.
#[derive(Clone, Serialize, Deserialize)]
pub struct UniChannelCreated<'a> {
    /// The unique ID of the previous command.
    pub parent_cmd_id: Id,
    /// The channel author's user ID.
    pub author_id: UserId,
    /// The user ID of the user that can encrypt messages.
    pub seal_id: UserId,
    /// The user ID of the user that can decrypt messages.
    pub open_id: UserId,
    /// The channel author's encryption key ID.
    pub author_enc_key_id: EncryptionKeyId,
    /// The channel peer's encoded [`crypto::EncryptionPublicKey`].
    pub peer_enc_pk: &'a [u8],
    /// The APS channel label.
    pub label: Label,
    /// The unique key identifier for the [`UniAuthorSecret`].
    pub key_id: UniKeyId,
}

/// Data from the `ApsUniChannelReceived` effect.
#[derive(Clone, Serialize, Deserialize)]
pub struct UniChannelReceived<'a> {
    /// The unique ID of the previous command.
    pub parent_cmd_id: Id,
    /// The channel author's user ID.
    pub author_id: UserId,
    /// The user ID of the user that can encrypt messages.
    pub seal_id: UserId,
    /// The user ID of the user that can decrypt messages.
    pub open_id: UserId,
    /// The channel author's encoded [`crypto::EncryptionPublicKey`].
    pub author_enc_pk: &'a [u8],
    /// The channel peer's encryption key ID.
    pub peer_enc_key_id: EncryptionKeyId,
    /// The APS channel label.
    pub label: Label,
    /// The peer's encapsulation.
    pub encap: &'a [u8],
}

/// Uniquely identifies a unirectional channel.
#[derive(
    Copy, Clone, Default, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, MaxSize,
)]
pub struct UniKeyId(Id);

impl From<Id> for UniKeyId {
    fn from(id: Id) -> Self {
        Self(id)
    }
}

/// A unidirectional channel key.
#[derive(Clone, Debug, Serialize, Deserialize, MaxSize)]
pub enum UniKey<S, O> {
    /// May only be used for encryption.
    SealOnly(S),
    /// May only be used for decryption.
    OpenOnly(O),
}

impl<S, O> UniKey<S, O> {
    fn new<E, F, K, V>(ch: &UniChannel<'_, E>, value: V, f: F) -> Result<Self, Error>
    where
        E: Engine,
        F: FnOnce(K) -> Self,
        K: for<'a> Transform<(&'a UniChannel<'a, E>, V)>,
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
#[derive(Debug)]
pub enum Error {
    /// The current user is not the author of the command.
    NotAuthor,
    /// The current user is not the recipient of the command.
    NotRecipient,
    /// The keystore failed.
    KeyStore,
    /// Unable to find a particular key.
    KeyNotFound,
    /// Unable to transform key.
    Transform,
    /// Unable to encode/decode a key.
    Encoding,
    /// A `crypto` crate error.
    Crypto(crypto::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAuthor => write!(f, "not command author"),
            Self::NotRecipient => write!(f, "not command recipient"),
            Self::KeyStore => write!(f, "keystore failure"),
            Self::KeyNotFound => write!(f, "unable to find key"),
            Self::Transform => write!(f, "unable to transform key"),
            Self::Encoding => write!(f, "unable to encode/decode"),
            Self::Crypto(err) => write!(f, "{err}"),
        }
    }
}

impl trouble::Error for Error {
    fn source(&self) -> Option<&(dyn trouble::Error + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            _ => None,
        }
    }
}

impl From<crypto::Error> for Error {
    fn from(err: crypto::Error) -> Self {
        Self::Crypto(err)
    }
}
