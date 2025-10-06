//! An FFI module for AQC.

#![cfg(feature = "alloc")]
#![cfg_attr(docsrs, doc(cfg(feature = "alloc")))]

extern crate alloc;

use alloc::vec::Vec;
use core::convert::Infallible;

use aranya_crypto::{
    self, CipherSuite, DeviceId, EncryptionKeyId, EncryptionPublicKey, Engine, ImportError,
    KeyStore, KeyStoreExt, PolicyId, UnwrapError, WrapError,
    aqc::{BidiChannel, BidiSecrets, UniChannel, UniSecrets},
    policy::{self, CmdId, LabelId},
};
use aranya_policy_vm::{
    CommandContext, MachineError, MachineErrorType, MachineIOError, Text, ffi::ffi,
};
use buggy::Bug;
use spin::Mutex;

use crate::shared::decode_enc_pk;

/// Wraps `tracing::error` to always use the `aqc-ffi` target.
macro_rules! error {
    ($($arg:tt)+) => { ::tracing::error!(target: "aqc-ffi", $($arg)+) };
}

/// An [`FfiModule`][aranya_policy_vm::ffi::FfiModule] for AQC.
pub struct Ffi<S> {
    store: Mutex<S>,
}

impl<S: KeyStore> Ffi<S> {
    /// Creates a new FFI module.
    pub const fn new(store: S) -> Self {
        Self {
            store: Mutex::new(store),
        }
    }

    /// Decodes a [`EncryptionPublicKey`].
    fn decode_enc_pk<CS: CipherSuite>(bytes: &[u8]) -> Result<EncryptionPublicKey<CS>, FfiError> {
        decode_enc_pk(bytes).map_err(|err| {
            error!("unable to decode `EncryptionPublicKey`: {err}");
            FfiError::Encoding
        })
    }
}

#[ffi(
    module = "aqc",
    def = r#"
// Returned when a bidirectional channel is created.
struct AqcBidiChannel {
    // Uniquely identifies the channel.
    channel_id id,
    // The peer's encapsulated KEM shared secret.
    //
    // This must be sent to the peer.
    peer_encap bytes,
    // A unique ID that the author can use to look up the
    // channel's secrets in the keystore.
    author_secrets_id id,
    // The size in bytes of the PSK.
    //
    // Per the AQC specification, this must be at least 32 and
    // less than 2^16.
    psk_length_in_bytes int,
}

// Returned when a unidirectional channel is created.
struct AqcUniChannel {
    // Uniquely identifies the channel.
    channel_id id,
    // The peer's encapsulated KEM shared secret.
    //
    // This must be sent to the peer.
    peer_encap bytes,
    // A unique ID that the author can use to look up the
    // channel's secrets in the keystore.
    author_secrets_id id,
    // The size in bytes of the PSK.
    //
    // Per the AQC specification, this must be at least 32 and
    // less than 2^16.
    psk_length_in_bytes int,
}
"#
)]
#[allow(clippy::too_many_arguments)]
impl<S: KeyStore> Ffi<S> {
    /// Creates a bidirectional channel.
    #[ffi_export(def = r#"
function create_bidi_channel(
    parent_cmd_id id,
    our_enc_key_id id,
    our_id id,
    their_enc_pk bytes,
    their_id id,
    label_id id,
) struct AqcBidiChannel
"#)]
    pub(crate) fn create_bidi_channel<E: Engine>(
        &self,
        _ctx: &CommandContext,
        eng: &mut E,
        parent_cmd_id: CmdId,
        our_enc_key_id: EncryptionKeyId,
        our_id: DeviceId,
        their_enc_pk: Vec<u8>,
        their_id: DeviceId,
        label_id: LabelId,
    ) -> Result<AqcBidiChannel, FfiError> {
        let our_sk = &self
            .store
            .lock()
            .get_key(eng, our_enc_key_id)
            .map_err(|_| FfiError::KeyStore)?
            .ok_or(FfiError::KeyNotFound("device encryption key"))?;
        let their_pk = &Self::decode_enc_pk::<E::CS>(&their_enc_pk)?;
        let ch = BidiChannel {
            // TODO(eric): get this from the policy?
            psk_length_in_bytes: 32,
            parent_cmd_id,
            our_sk,
            our_id,
            their_pk,
            their_id,
            label: label_id,
        };
        let BidiSecrets { author, peer } = BidiSecrets::new(eng, &ch)?;

        let author_secrets_id = self.store.lock().insert_key(eng, author).map_err(|err| {
            error!("unable to insert `BidiAuthorSecret` into KeyStore: {err}");
            FfiError::KeyStore
        })?;

        Ok(AqcBidiChannel {
            channel_id: peer.id().into(),
            peer_encap: peer.as_bytes().to_vec(),
            author_secrets_id: author_secrets_id.into(),
            psk_length_in_bytes: ch.psk_length_in_bytes.into(),
        })
    }

    /// Creates a unidirectional channel.
    #[ffi_export(def = r#"
function create_uni_channel(
    parent_cmd_id id,
    author_enc_key_id id,
    their_pk bytes,
    seal_id id,
    open_id id,
    label_id id,
) struct AqcUniChannel
"#)]
    pub(crate) fn create_uni_channel<E: Engine>(
        &self,
        _ctx: &CommandContext,
        eng: &mut E,
        parent_cmd_id: CmdId,
        author_enc_key_id: EncryptionKeyId,
        their_pk: Vec<u8>,
        seal_id: DeviceId,
        open_id: DeviceId,
        label_id: LabelId,
    ) -> Result<AqcUniChannel, FfiError> {
        let our_sk = &self
            .store
            .lock()
            .get_key(eng, author_enc_key_id)
            .map_err(|_| FfiError::KeyStore)?
            .ok_or(FfiError::KeyNotFound("device encryption key"))?;
        let their_pk = &Self::decode_enc_pk::<E::CS>(&their_pk)?;
        let ch = UniChannel {
            // TODO(eric): get this from the policy?
            psk_length_in_bytes: 32,
            parent_cmd_id,
            our_sk,
            their_pk,
            seal_id,
            open_id,
            label: label_id,
        };
        let UniSecrets { author, peer } = UniSecrets::new(eng, &ch)?;

        let author_secrets_id = self.store.lock().insert_key(eng, author).map_err(|err| {
            error!("unable to insert `UniAuthorSecret` into KeyStore: {err}");
            FfiError::KeyStore
        })?;

        Ok(AqcUniChannel {
            channel_id: peer.id().into(),
            peer_encap: peer.as_bytes().to_vec(),
            author_secrets_id: author_secrets_id.into(),
            psk_length_in_bytes: ch.psk_length_in_bytes.into(),
        })
    }

    /// Computes the ID of a label.
    #[ffi_export(def = r#"
function label_id(
    cmd_id id,
    name string,
) id
"#)]
    pub(crate) fn label_id<E: Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &mut E,
        cmd_id: CmdId,
        name: Text,
    ) -> Result<LabelId, Infallible> {
        // TODO(eric): Use the real policy ID once it's
        // available.
        let policy_id = PolicyId::default();
        let id = policy::label_id::<E::CS>(cmd_id, &name, policy_id);
        Ok(id)
    }
}

/// An error returned by [`Ffi`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum FfiError {
    /// The [`aranya_crypto`] crate failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] aranya_crypto::Error),
    /// An error occurred while manipulating the [`Stack`].
    #[error("unable to manipulate stack: {0}")]
    Stack(#[from] MachineErrorType),
    /// Unable to find a particular key.
    #[error("unable to find key: {0}")]
    KeyNotFound(&'static str),
    /// Unable to encode/decode some input.
    #[error("unable to decode type")]
    Encoding,
    /// Unable to wrap a key.
    #[error(transparent)]
    Wrap(#[from] WrapError),
    /// The keystore failed.
    #[error("keystore failure")]
    KeyStore,
    /// Bug
    #[error("bug: {0}")]
    Bug(Bug),
}

impl From<FfiError> for MachineError {
    fn from(err: FfiError) -> Self {
        error!("{err}");
        match err {
            FfiError::Stack(err) => Self::new(err),
            _ => Self::new(MachineErrorType::IO(MachineIOError::Internal)),
        }
    }
}

impl From<ImportError> for FfiError {
    #[inline]
    fn from(err: ImportError) -> Self {
        Self::Crypto(err.into())
    }
}

impl From<UnwrapError> for FfiError {
    #[inline]
    fn from(err: UnwrapError) -> Self {
        Self::Crypto(err.into())
    }
}

impl From<Bug> for FfiError {
    #[inline]
    fn from(bug: Bug) -> Self {
        Self::Bug(bug)
    }
}
