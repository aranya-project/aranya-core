//! An FFI module for AQC.

#![cfg(feature = "alloc")]
#![cfg_attr(docsrs, doc(cfg(feature = "alloc")))]

extern crate alloc;

use alloc::vec::Vec;

use aranya_crypto::{
    self,
    aqc::{BidiChannel, BidiSecrets, UniChannel, UniSecrets},
    CipherSuite, DeviceId, EncryptionKeyId, EncryptionPublicKey, Engine, Id, ImportError, KeyStore,
    KeyStoreExt, UnwrapError, WrapError,
};
use aranya_policy_vm::{
    ffi::{ffi, Type},
    CommandContext, MachineError, MachineErrorType, MachineIOError, Typed, Value,
    ValueConversionError,
};
use buggy::Bug;
use spin::Mutex;

use crate::shared::{decode_enc_pk, Label};

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
struct AqcBidiChannel {
    peer_encap bytes,
    key_id id,
}
struct AqcUniChannel {
    peer_encap bytes,
    key_id id,
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
    label int,
) struct AqcBidiChannel
"#)]
    pub(crate) fn create_bidi_channel<E: Engine>(
        &self,
        _ctx: &CommandContext<'_>,
        eng: &mut E,
        parent_cmd_id: Id,
        our_enc_key_id: EncryptionKeyId,
        our_id: DeviceId,
        their_enc_pk: Vec<u8>,
        their_id: DeviceId,
        label: Label,
    ) -> Result<AqcBidiChannel, FfiError> {
        let our_sk = &self
            .store
            .lock()
            .get_key(eng, our_enc_key_id.into())
            .map_err(|_| FfiError::KeyStore)?
            .ok_or(FfiError::KeyNotFound)?;
        let their_pk = &Self::decode_enc_pk::<E::CS>(&their_enc_pk)?;
        let ch = BidiChannel {
            // TODO(eric): get this from the policy?
            psk_length_in_bytes: 32,
            parent_cmd_id,
            our_sk,
            our_id,
            their_pk,
            their_id,
            label: label.into(),
        };
        let secrets = BidiSecrets::new(eng, &ch)?;

        let key_id = secrets.id().into();
        let wrapped = eng.wrap(secrets.author)?;
        self.store
            .lock()
            .try_insert(key_id, wrapped)
            .map_err(|err| {
                error!("unable to insert `BidiAuthorSecret` into KeyStore: {err}");
                FfiError::KeyStore
            })?;

        Ok(AqcBidiChannel {
            peer_encap: secrets.peer.as_bytes().to_vec(),
            key_id,
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
    label int,
) struct AqcUniChannel
"#)]
    pub(crate) fn create_uni_channel<E: Engine>(
        &self,
        _ctx: &CommandContext<'_>,
        eng: &mut E,
        parent_cmd_id: Id,
        author_enc_key_id: EncryptionKeyId,
        their_pk: Vec<u8>,
        seal_id: DeviceId,
        open_id: DeviceId,
        label: Label,
    ) -> Result<AqcUniChannel, FfiError> {
        let our_sk = &self
            .store
            .lock()
            .get_key(eng, author_enc_key_id.into())
            .map_err(|_| FfiError::KeyStore)?
            .ok_or(FfiError::KeyNotFound)?;
        let their_pk = &Self::decode_enc_pk::<E::CS>(&their_pk)?;
        let ch = UniChannel {
            // TODO(eric): get this from the policy?
            psk_length_in_bytes: 32,
            parent_cmd_id,
            our_sk,
            their_pk,
            seal_id,
            open_id,
            label: label.into(),
        };
        let secrets = UniSecrets::new(eng, &ch)?;

        let key_id = secrets.id().into();
        let wrapped = eng.wrap(secrets.author)?;
        self.store
            .lock()
            .try_insert(key_id, wrapped)
            .map_err(|err| {
                error!("unable to insert `UniAuthorSecret` into KeyStore: {err}");
                FfiError::KeyStore
            })?;

        Ok(AqcUniChannel {
            peer_encap: secrets.peer.as_bytes().to_vec(),
            key_id,
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

impl Typed for Label {
    const TYPE: Type<'static> = Type::Int;
}

impl TryFrom<Value> for Label {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let int: i64 = value.try_into()?;
        let x = u32::try_from(int).map_err(|_| ValueConversionError::OutOfRange)?;
        Ok(Label::from(x))
    }
}
