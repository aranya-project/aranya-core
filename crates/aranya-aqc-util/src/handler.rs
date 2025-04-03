//! An effect handler for AQC.

use aranya_crypto::{
    aqc::{
        BidiChannel, BidiChannelId, BidiPeerEncap, BidiPsk, UniChannel, UniChannelId, UniPeerEncap,
        UniRecvPsk, UniSendPsk,
    },
    custom_id, CipherSuite, DeviceId, EncryptionKeyId, Engine, Id, KeyStore, KeyStoreExt,
};
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
    /// Retrieves the wrapped
    /// [`BidiAuthorSecret`][aranya_crypto::aqc::BidiAuthorSecret]
    /// and converts it into the PSK.
    pub fn bidi_channel_created<E: Engine>(
        &mut self,
        eng: &mut E,
        effect: &BidiChannelCreated<'_>,
    ) -> Result<BidiPsk<E::CS>, Error> {
        if self.device_id != effect.author_id {
            return Err(Error::NotAuthor);
        }

        let secret = self
            .store
            .remove_key(eng, effect.channel_id.into())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;

        let our_sk = &self
            .store
            .get_key(eng, effect.author_enc_key_id.into())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;
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
            label: effect.label_id.into(),
        };

        let psk = BidiPsk::from_author_secret(&ch, secret).inspect_err(|err| {
            error!(?err, "unable to derive bidi PSK from author secret");
        })?;
        Ok(psk)
    }

    /// Converts a [`BidiPeerEncap`] into a PSK.
    pub fn bidi_channel_received<E: Engine>(
        &mut self,
        eng: &mut E,
        effect: &BidiChannelReceived<'_>,
    ) -> Result<BidiPsk<E::CS>, Error> {
        if self.device_id != effect.peer_id {
            return Err(Error::NotRecipient);
        }

        let encap =
            BidiPeerEncap::from_bytes(effect.encap).map_err(|err| Error::Crypto(err.into()))?;

        let our_sk = &self
            .store
            .get_key(eng, effect.peer_enc_key_id.into())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;
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
            label: effect.label_id.into(),
        };

        let psk = BidiPsk::from_peer_encap(&ch, encap).inspect_err(|err| {
            error!(?err, "unable to derive bidi PSK from peer encap");
        })?;
        Ok(psk)
    }
}

/// Data from the `AqcBidiChannelCreated` effect.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BidiChannelCreated<'a> {
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
    /// Uniquely identifies the channel.
    pub channel_id: BidiChannelId,
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
    /// Uniquely identifies the channel.
    pub channel_id: BidiChannelId,
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
    ) -> Result<UniPsk<E::CS>, Error> {
        if (self.device_id != effect.send_id && self.device_id != effect.recv_id)
            || self.device_id != effect.author_id
        {
            return Err(Error::NotAuthor);
        }

        let secret = self
            .store
            .remove_key(eng, effect.channel_id.into())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;

        let our_sk = &self
            .store
            .get_key(eng, effect.author_enc_key_id.into())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;
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
            label: effect.label_id.into(),
        };

        if self.device_id == effect.send_id {
            UniSendPsk::from_author_secret(&ch, secret)
                .inspect_err(|err| {
                    error!(?err, "unable to derive uni send PSK from author secret");
                })
                .map(UniPsk::SendOnly)
                .map_err(Into::into)
        } else {
            UniRecvPsk::from_author_secret(&ch, secret)
                .inspect_err(|err| {
                    error!(?err, "unable to derive uni recv PSK from author secret");
                })
                .map(UniPsk::RecvOnly)
                .map_err(Into::into)
        }
    }

    /// Converts a [`UniPeerEncap`] into a PSK.
    pub fn uni_channel_received<E: Engine>(
        &mut self,
        eng: &mut E,
        effect: &UniChannelReceived<'_>,
    ) -> Result<UniPsk<E::CS>, Error> {
        if (self.device_id != effect.send_id && self.device_id != effect.recv_id)
            || self.device_id == effect.author_id
        {
            return Err(Error::NotRecipient);
        }

        let encap =
            UniPeerEncap::from_bytes(effect.encap).map_err(|err| Error::Crypto(err.into()))?;

        let our_sk = &self
            .store
            .get_key(eng, effect.peer_enc_key_id.into())
            .map_err(|_| Error::KeyStore)?
            .ok_or(Error::KeyNotFound)?;
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
            label: effect.label_id.into(),
        };

        if self.device_id == effect.send_id {
            UniSendPsk::from_peer_encap(&ch, encap)
                .inspect_err(|err| {
                    error!(?err, "unable to derive uni send PSK from peer encap");
                })
                .map(UniPsk::SendOnly)
                .map_err(Into::into)
        } else {
            UniRecvPsk::from_peer_encap(&ch, encap)
                .inspect_err(|err| {
                    error!(?err, "unable to derive uni recv PSK from peer encap");
                })
                .map(UniPsk::RecvOnly)
                .map_err(Into::into)
        }
    }
}

/// Data from the `AqcUniChannelCreated` effect.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UniChannelCreated<'a> {
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
    /// Uniquely identifies the channel.
    pub channel_id: UniChannelId,
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
    /// Uniquely identifies the channel.
    pub channel_id: UniChannelId,
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

/// A unidirectional channel key.
#[derive(Debug)]
pub enum UniPsk<CS: CipherSuite> {
    /// May only be used to send data.
    SendOnly(UniSendPsk<CS>),
    /// May only be used to recv data.
    RecvOnly(UniRecvPsk<CS>),
}

impl<CS: CipherSuite> UniPsk<CS> {
    /// Returns the raw PSK secret.
    #[inline]
    pub fn identity(&self) -> UniChannelId {
        match self {
            Self::SendOnly(psk) => psk.identity(),
            Self::RecvOnly(psk) => psk.identity(),
        }
    }

    /// Returns the raw PSK secret.
    #[inline]
    pub fn raw_secret_bytes(&self) -> &[u8] {
        match self {
            Self::SendOnly(psk) => psk.raw_secret_bytes(),
            Self::RecvOnly(psk) => psk.raw_secret_bytes(),
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
