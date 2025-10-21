//! An FFI module for AFC.

#![cfg(feature = "alloc")]
#![cfg_attr(docsrs, doc(cfg(feature = "alloc")))]

extern crate alloc;

use alloc::vec::Vec;
use core::result::Result;

use aranya_crypto::{
    self, CipherSuite, DeviceId, EncryptionKeyId, EncryptionPublicKey, Engine, ImportError,
    KeyStore, KeyStoreExt as _, UnwrapError, WrapError,
    afc::{UniChannel, UniSecrets},
    policy::{CmdId, LabelId},
};
use aranya_policy_vm::{CommandContext, MachineError, MachineErrorType, MachineIOError, ffi::ffi};
use buggy::Bug;
use spin::Mutex;

use crate::shared::decode_enc_pk;

/// Wraps `tracing::error` to always use the `afc-ffi` target.
macro_rules! error {
    ($($arg:tt)+) => { ::tracing::error!(target: "afc-ffi", $($arg)+) };
}

/// An [`FfiModule`][aranya_policy_vm::ffi::FfiModule] for AFC.
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
    module = "afc",
    def = r#"
struct AfcUniChannel {
    peer_encap bytes,
    key_id id,
}
"#
)]
#[allow(clippy::too_many_arguments)]
impl<S: KeyStore> Ffi<S> {
    /// Creates a unidirectional channel.
    #[ffi_export(def = r#"
function create_uni_channel(
    parent_cmd_id id,
    author_enc_key_id id,
    their_pk bytes,
    seal_id id,
    open_id id,
    label_id id,
) struct AfcUniChannel
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
    ) -> Result<AfcUniChannel, FfiError> {
        let our_sk = &self
            .store
            .lock()
            .get_key(eng, author_enc_key_id)
            .map_err(|_| FfiError::KeyStore)?
            .ok_or(FfiError::KeyNotFound)?;
        let their_pk = &Self::decode_enc_pk::<E::CS>(&their_pk)?;
        let ch = UniChannel {
            parent_cmd_id,
            our_sk,
            their_pk,
            seal_id,
            open_id,
            label_id,
        };
        let UniSecrets { author, peer } = UniSecrets::new(eng, &ch)?;

        let key_id = self.store.lock().insert_key(eng, author).map_err(|err| {
            error!("unable to insert `UniAuthorSecret` into KeyStore: {err}");
            FfiError::KeyStore
        })?;

        Ok(AfcUniChannel {
            peer_encap: peer.as_bytes().to_vec(),
            key_id: key_id.as_base(),
        })
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
    #[error("unable to find key")]
    KeyNotFound,
    /// Unable to encode/decode some input.
    #[error("unable to decode type")]
    Encoding,
    /// AFC failed.
    #[error("AFC error: {0}")]
    Afc(#[from] aranya_fast_channels::Error),
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
    fn from(err: ImportError) -> Self {
        Self::Crypto(err.into())
    }
}

impl From<UnwrapError> for FfiError {
    fn from(err: UnwrapError) -> Self {
        Self::Crypto(err.into())
    }
}

impl From<Bug> for FfiError {
    fn from(bug: Bug) -> Self {
        Self::Bug(bug)
    }
}
