//! An effect handler for AFC.

use aranya_crypto::{
    BaseId, CipherSuite, DeviceId, EncryptionKeyId, Engine, KeyStore, KeyStoreExt as _,
    afc::{UniAuthorSecret, UniAuthorSecretId, UniChannel, UniPeerEncap},
    policy::{CmdId, LabelId},
};
use aranya_fast_channels::Directed;
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
        if self.device_id == effect.open_id {
            return Err(Error::AuthorMustBeSealer);
        }

        let secret = self
            .store
            .remove_key(eng, effect.key_id.into())
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
            seal_id: self.device_id,
            open_id: effect.open_id,
            our_sk,
            their_pk,
            label_id: effect.label_id,
        };

        UniKey::new(&ch, secret, UniKey::SealOnly)
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
        if effect.seal_id == self.device_id {
            return Err(Error::AuthorMustBeSealer);
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
            open_id: self.device_id,
            our_sk,
            their_pk,
            label_id: effect.label_id,
        };

        UniKey::new(&ch, encap, UniKey::OpenOnly)
    }
}

/// Data from the `AfcUniChannelCreated` effect.
#[derive(Clone, Serialize, Deserialize)]
pub struct UniChannelCreated<'a> {
    /// The unique ID of the previous command.
    pub parent_cmd_id: CmdId,
    /// The device ID of the Device that can decrypt messages.
    pub open_id: DeviceId,
    /// The channel author's encryption key ID.
    pub author_enc_key_id: EncryptionKeyId,
    /// The channel peer's encoded [`aranya_crypto::EncryptionPublicKey`].
    pub peer_enc_pk: &'a [u8],
    /// The AFC channel label.
    pub label_id: LabelId,
    /// The unique key identifier for the [`UniAuthorSecret`].
    pub key_id: UniKeyId,
}

/// Data from the `AfcUniChannelReceived` effect.
#[derive(Clone, Serialize, Deserialize)]
pub struct UniChannelReceived<'a> {
    /// The unique ID of the previous command.
    pub parent_cmd_id: CmdId,
    /// The device ID of the Device that can encrypt messages.
    pub seal_id: DeviceId,
    /// The channel author's encoded [`aranya_crypto::EncryptionPublicKey`].
    pub author_enc_pk: &'a [u8],
    /// The channel peer's encryption key ID.
    pub peer_enc_key_id: EncryptionKeyId,
    /// The AFC channel label.
    pub label_id: LabelId,
    /// The peer's encapsulation.
    pub encap: &'a [u8],
}

/// Uniquely identifies a unirectional channel.
#[derive(Copy, Clone, Default, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct UniKeyId(BaseId);

impl From<BaseId> for UniKeyId {
    fn from(id: BaseId) -> Self {
        Self(id)
    }
}

impl From<UniKeyId> for UniAuthorSecretId {
    fn from(id: UniKeyId) -> Self {
        Self::from_base(id.0)
    }
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
    /// Channels require that the author is the sealer.
    #[error("Channels require that the author is the sealer")]
    AuthorMustBeSealer,
    /// A `crypto` crate error.
    #[error(transparent)]
    Crypto(#[from] aranya_crypto::Error),
}
