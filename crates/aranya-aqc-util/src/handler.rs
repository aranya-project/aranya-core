//! An effect handler for AQC.

use aranya_crypto::{
    aqc::{
        BidiAuthorSecretId, BidiChannel, BidiChannelId, BidiPeerEncap, BidiSecret,
        UniAuthorSecretId, UniChannel, UniChannelId, UniPeerEncap, UniSecret,
    },
    custom_id, DeviceId, EncryptionKeyId, Engine, Id, KeyStore, KeyStoreExt,
};
use buggy::{bug, Bug};
use serde::{Deserialize, Serialize};

use crate::shared::{decode_enc_pk, LabelId};

/// Wraps `tracing::error` to always use the `aqc-handler`
/// target.
macro_rules! error {
    ($($arg:tt)+) => { ::tracing::error!(target: "aqc-handler", $($arg)+) };
}

/// Handles AQC effects.
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
    /// Retrieves the secret for the channel identified in the
    /// effect.
    ///
    /// This method removes the secret from the keystore; calling
    /// it multiple times for the same effect will result in
    /// [`Error::KeyNotFound`].
    pub fn bidi_channel_created<E: Engine>(
        &mut self,
        eng: &mut E,
        effect: &BidiChannelCreated<'_>,
    ) -> Result<BidiSecret<E::CS>, Error> {
        if self.device_id != effect.author_id {
            return Err(Error::NotAuthor);
        }

        let secret = self
            .store
            .remove_key(eng, effect.author_secrets_id.into_id())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound("BidiAuthorSecret"))?;

        let our_sk = &self
            .store
            .get_key(eng, effect.author_enc_key_id.into_id())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound("device encryption key"))?;
        let their_pk = &decode_enc_pk(effect.peer_enc_pk).map_err(|err| {
            error!("unable to decode `EncryptionPublicKey`: {err}");
            Error::Encoding
        })?;
        let ch = BidiChannel {
            psk_length_in_bytes: effect.psk_length_in_bytes,
            parent_cmd_id: effect.parent_cmd_id,
            our_sk,
            our_id: effect.author_id,
            their_pk,
            their_id: effect.peer_id,
            label: effect.label_id.into_id(),
        };

        let secret = BidiSecret::from_author_secret(&ch, secret).inspect_err(|err| {
            error!(?err, "unable to derive bidi PSK from author secret");
        })?;
        if secret.id() != &effect.channel_id {
            bug!("`BidiSecret::id` does not match `effect.channel_id`");
        }

        Ok(secret)
    }

    /// Converts a [`BidiPeerEncap`] into a PSK.
    pub fn bidi_channel_received<E: Engine>(
        &mut self,
        eng: &mut E,
        effect: &BidiChannelReceived<'_>,
    ) -> Result<BidiSecret<E::CS>, Error> {
        if self.device_id != effect.peer_id {
            return Err(Error::NotRecipient);
        }

        let encap =
            BidiPeerEncap::from_bytes(effect.encap).map_err(|err| Error::Crypto(err.into()))?;

        let our_sk = &self
            .store
            .get_key(eng, effect.peer_enc_key_id.into_id())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound("device encryption key"))?;
        let their_pk = &decode_enc_pk(effect.author_enc_pk).map_err(|err| {
            error!("unable to decode `EncryptionPublicKey`: {err}");
            Error::Encoding
        })?;
        let ch = BidiChannel {
            psk_length_in_bytes: effect.psk_length_in_bytes,
            parent_cmd_id: effect.parent_cmd_id,
            our_sk,
            our_id: effect.peer_id,
            their_pk,
            their_id: effect.author_id,
            label: effect.label_id.into_id(),
        };

        let secret = BidiSecret::from_peer_encap(&ch, encap).inspect_err(|err| {
            error!(?err, "unable to derive `BidiSecret` from peer encap");
        })?;
        if secret.id() != &effect.channel_id {
            bug!("`BidiSecret::id` does not match `effect.channel_id`");
        }
        Ok(secret)
    }
}

/// Data from the `AqcBidiChannelCreated` effect.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BidiChannelCreated<'a> {
    /// Uniquely identifies the channel.
    pub channel_id: BidiChannelId,
    /// The unique ID of the previous command.
    pub parent_cmd_id: Id,
    /// The channel author's device ID.
    pub author_id: DeviceId,
    /// The channel author's encryption key ID.
    pub author_enc_key_id: EncryptionKeyId,
    /// The channel peer's device ID.
    pub peer_id: DeviceId,
    /// The channel peer's encoded
    /// [`EncryptionPublicKey`][aranya_crypto::EncryptionPublicKey].
    pub peer_enc_pk: &'a [u8],
    /// The AQC channel label.
    pub label_id: LabelId,
    /// A unique ID that the author can use to look up the
    /// channel's secrets in the keystore.
    pub author_secrets_id: BidiAuthorSecretId,
    /// The size in bytes of the PSK.
    ///
    /// Per the AQC specification this must be at least 32. This
    /// implementation restricts it to exactly 32. This
    /// restriction may be lifted in the future.
    pub psk_length_in_bytes: u16,
}

/// Data from the `AqcBidiChannelReceived` effect.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BidiChannelReceived<'a> {
    /// Uniquely identifies the channel.
    pub channel_id: BidiChannelId,
    /// The unique ID of the previous command.
    pub parent_cmd_id: Id,
    /// The channel author's device ID.
    pub author_id: DeviceId,
    /// The channel author's encoded
    /// [`EncryptionPublicKey`][aranya_crypto::EncryptionPublicKey].
    pub author_enc_pk: &'a [u8],
    /// The channel peer's device ID.
    pub peer_id: DeviceId,
    /// The channel peer's encryption key ID.
    pub peer_enc_key_id: EncryptionKeyId,
    /// The AQC channel label.
    pub label_id: LabelId,
    /// The peer's encapsulation.
    pub encap: &'a [u8],
    /// The size in bytes of the PSK.
    ///
    /// Per the AQC specification this must be at least 32. This
    /// implementation restricts it to exactly 32. This
    /// restriction may be lifted in the future.
    pub psk_length_in_bytes: u16,
}

// Uni impl.
impl<S: KeyStore> Handler<S> {
    /// Retrieves the wrapped
    /// [`UniAuthorSecret`][aranya_crypto::aqc::UniAuthorSecret]
    /// and converts it into a PSK.
    pub fn uni_channel_created<E: Engine>(
        &mut self,
        eng: &mut E,
        effect: &UniChannelCreated<'_>,
    ) -> Result<UniSecret<E::CS>, Error> {
        if (self.device_id != effect.send_id && self.device_id != effect.recv_id)
            || self.device_id != effect.author_id
        {
            return Err(Error::NotAuthor);
        }

        let secret = self
            .store
            .remove_key(eng, effect.author_secrets_id.into_id())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound("UniAuthorSecret"))?;

        let our_sk = &self
            .store
            .get_key(eng, effect.author_enc_key_id.into_id())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound("device encryption key"))?;
        let their_pk = &decode_enc_pk(effect.peer_enc_pk).map_err(|err| {
            error!("unable to decode `EncryptionPublicKey`: {err}");
            Error::Encoding
        })?;
        let ch = UniChannel {
            psk_length_in_bytes: effect.psk_length_in_bytes,
            parent_cmd_id: effect.parent_cmd_id,
            seal_id: effect.send_id,
            open_id: effect.recv_id,
            our_sk,
            their_pk,
            label: effect.label_id.into_id(),
        };

        let secret = if self.device_id == effect.send_id {
            UniSecret::from_author_secret(&ch, secret).inspect_err(|err| {
                error!(?err, "unable to derive `UniSecret` from author secret");
            })?
        } else {
            UniSecret::from_author_secret(&ch, secret).inspect_err(|err| {
                error!(?err, "unable to derive `UniSecret`from author secret");
            })?
        };
        if secret.id() != &effect.channel_id {
            bug!("`UniSecret::id` does not match `effect.channel_id`");
        }
        Ok(secret)
    }

    /// Converts a [`UniPeerEncap`] into a PSK.
    pub fn uni_channel_received<E: Engine>(
        &mut self,
        eng: &mut E,
        effect: &UniChannelReceived<'_>,
    ) -> Result<UniSecret<E::CS>, Error> {
        if (self.device_id != effect.send_id && self.device_id != effect.recv_id)
            || self.device_id == effect.author_id
        {
            return Err(Error::NotRecipient);
        }

        let encap =
            UniPeerEncap::from_bytes(effect.encap).map_err(|err| Error::Crypto(err.into()))?;

        let our_sk = &self
            .store
            .get_key(eng, effect.peer_enc_key_id.into_id())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound("device encryption key"))?;
        let their_pk = &decode_enc_pk(effect.author_enc_pk).map_err(|err| {
            error!("unable to decode `EncryptionPublicKey`: {err}");
            Error::Encoding
        })?;
        let ch = UniChannel {
            psk_length_in_bytes: effect.psk_length_in_bytes,
            parent_cmd_id: effect.parent_cmd_id,
            seal_id: effect.send_id,
            open_id: effect.recv_id,
            our_sk,
            their_pk,
            label: effect.label_id.into_id(),
        };

        let secret = if self.device_id == effect.send_id {
            UniSecret::from_peer_encap(&ch, encap).inspect_err(|err| {
                error!(?err, "unable to derive uni send PSK from peer encap");
            })?
        } else {
            UniSecret::from_peer_encap(&ch, encap).inspect_err(|err| {
                error!(?err, "unable to derive uni recv PSK from peer encap");
            })?
        };
        if secret.id() != &effect.channel_id {
            bug!("`UniSecret::id` does not match `effect.channel_id`");
        }
        Ok(secret)
    }
}

/// Data from the `AqcUniChannelCreated` effect.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UniChannelCreated<'a> {
    /// Uniquely identifies the channel.
    pub channel_id: UniChannelId,
    /// The unique ID of the previous command.
    pub parent_cmd_id: Id,
    /// The channel author's device ID.
    pub author_id: DeviceId,
    /// The device ID of the Device that can send messages.
    pub send_id: DeviceId,
    /// The device ID of the Device that can receive messages.
    pub recv_id: DeviceId,
    /// The channel author's encryption key ID.
    pub author_enc_key_id: EncryptionKeyId,
    /// The channel peer's encoded [`aranya_crypto::EncryptionPublicKey`].
    pub peer_enc_pk: &'a [u8],
    /// The AQC channel label.
    pub label_id: LabelId,
    /// A unique ID that the author can use to look up the
    /// channel's secrets in the keystore.
    pub author_secrets_id: UniAuthorSecretId,
    /// The size in bytes of the PSK.
    ///
    /// Per the AQC specification this must be at least 32. This
    /// implementation restricts it to exactly 32. This
    /// restriction may be lifted in the future.
    pub psk_length_in_bytes: u16,
}

/// Data from the `AqcUniChannelReceived` effect.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UniChannelReceived<'a> {
    /// Uniquely identifies the channel.
    pub channel_id: UniChannelId,
    /// The unique ID of the previous command.
    pub parent_cmd_id: Id,
    /// The channel author's device ID.
    pub author_id: DeviceId,
    /// The device ID of the Device that can send messages.
    pub send_id: DeviceId,
    /// The device ID of the Device that can receive messages.
    pub recv_id: DeviceId,
    /// The channel author's encoded [`aranya_crypto::EncryptionPublicKey`].
    pub author_enc_pk: &'a [u8],
    /// The channel peer's encryption key ID.
    pub peer_enc_key_id: EncryptionKeyId,
    /// The AQC channel label.
    pub label_id: LabelId,
    /// The peer's encapsulation.
    pub encap: &'a [u8],
    /// The size in bytes of the PSK.
    ///
    /// Per the AQC specification this must be at least 32. This
    /// implementation restricts it to exactly 32. This
    /// restriction may be lifted in the future.
    pub psk_length_in_bytes: u16,
}

custom_id! {
    /// Uniquely identifies a unirectional channel.
    pub struct UniKeyId;
}

/// An error returned by [`Handler`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An internal bug occurred.
    #[error("{0}")]
    Bug(#[from] Bug),
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
    #[error("unable to find key: {0}")]
    KeyNotFound(&'static str),
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
