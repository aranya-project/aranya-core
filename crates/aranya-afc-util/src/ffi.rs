//! An FFI module for AFC.

#![cfg(feature = "alloc")]
#![cfg_attr(docsrs, doc(cfg(feature = "alloc")))]

extern crate alloc;

use alloc::vec::Vec;
use core::{fmt, result::Result};

use aranya_crypto::{
    self,
    afc::{BidiChannel, BidiSecrets, UniChannel, UniSecrets},
    CipherSuite, EncryptionKeyId, EncryptionPublicKey, Engine, Id, ImportError, KeyStore,
    KeyStoreExt, UnwrapError, UserId, WrapError,
};
use aranya_policy_vm::{
    ffi::{ffi, Type},
    CommandContext, MachineError, MachineErrorType, MachineIOError, Typed, Value,
    ValueConversionError,
};

use crate::shared::decode_enc_pk;

/// Wraps `tracing::error` to always use the `afc-ffi` target.
macro_rules! error {
    ($($arg:tt)+) => { ::tracing::error!(target: "afc-ffi", $($arg)+) };
}

/// An [`FfiModule`][aranya_policy_vm::ffi::FfiModule] for AFC.
#[derive(Clone)]
pub struct Ffi<S> {
    store: S,
}

impl<S: KeyStore> Ffi<S> {
    /// Creates a new FFI module.
    pub const fn new(store: S) -> Self {
        Self { store }
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
struct AfcBidiChannel {
    peer_encap bytes,
    key_id id,
}
struct AfcUniChannel {
    peer_encap bytes,
    key_id id,
}
"#
)]
#[allow(clippy::too_many_arguments)]
impl<S: KeyStore> Ffi<S> {
    /// Creates a bidirectional AFC channel.
    #[ffi_export(def = r#"
function create_bidi_channel(
    parent_cmd_id id,
    our_enc_key_id id,
    our_id id,
    their_enc_pk bytes,
    their_id id,
    label int,
) struct AfcBidiChannel
"#)]
    pub(crate) fn create_bidi_channel<E: Engine>(
        &mut self,
        _ctx: &CommandContext<'_>,
        eng: &mut E,
        parent_cmd_id: Id,
        our_enc_key_id: EncryptionKeyId,
        our_id: UserId,
        their_enc_pk: Vec<u8>,
        their_id: UserId,
        label: Label,
    ) -> Result<AfcBidiChannel, FfiError> {
        let label: aranya_fast_channels::Label = label.into();

        let our_sk = &self
            .store
            .get_key(eng, our_enc_key_id.into())
            .map_err(|_| FfiError::KeyStore)?
            .ok_or(FfiError::KeyNotFound)?;
        let their_pk = &Self::decode_enc_pk::<E::CS>(&their_enc_pk)?;
        let ch = BidiChannel {
            parent_cmd_id,
            our_sk,
            our_id,
            their_pk,
            their_id,
            label: label.to_u32(),
        };
        let BidiSecrets { author, peer } = BidiSecrets::new(eng, &ch)?;

        let key_id = peer.id().into();
        let wrapped = eng.wrap(author)?;
        self.store.try_insert(key_id, wrapped).map_err(|err| {
            error!("unable to insert `BidiAuthorSecret` into KeyStore: {err}");
            FfiError::KeyStore
        })?;

        Ok(AfcBidiChannel {
            peer_encap: peer.as_bytes().to_vec(),
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
) struct AfcUniChannel
"#)]
    pub(crate) fn create_uni_channel<E: Engine>(
        &mut self,
        _ctx: &CommandContext<'_>,
        eng: &mut E,
        parent_cmd_id: Id,
        author_enc_key_id: EncryptionKeyId,
        their_pk: Vec<u8>,
        seal_id: UserId,
        open_id: UserId,
        label: Label,
    ) -> Result<AfcUniChannel, FfiError> {
        let label: aranya_fast_channels::Label = label.into();

        let our_sk = &self
            .store
            .get_key(eng, author_enc_key_id.into())
            .map_err(|_| FfiError::KeyStore)?
            .ok_or(FfiError::KeyNotFound)?;
        let their_pk = &Self::decode_enc_pk::<E::CS>(&their_pk)?;
        let ch = UniChannel {
            parent_cmd_id,
            our_sk,
            their_pk,
            seal_id,
            open_id,
            label: label.to_u32(),
        };
        let UniSecrets { author, peer } = UniSecrets::new(eng, &ch)?;

        let key_id = peer.id().into();
        let wrapped = eng.wrap(author)?;
        self.store.try_insert(key_id, wrapped).map_err(|err| {
            error!("unable to insert `UniAuthorSecret` into KeyStore: {err}");
            FfiError::KeyStore
        })?;

        Ok(AfcUniChannel {
            peer_encap: peer.as_bytes().to_vec(),
            key_id,
        })
    }
}

/// An error returned by [`Ffi`].
#[derive(Debug)]
pub(crate) enum FfiError {
    /// The [`aranya_crypto`] crate failed.
    Crypto(aranya_crypto::Error),
    /// An error occurred while manipulating the [`Stack`].
    Stack(MachineErrorType),
    /// Unable to find a particular key.
    KeyNotFound,
    /// Unable to encode/decode some input.
    Encoding,
    /// AFC failed.
    Afc(aranya_fast_channels::Error),
    /// Unable to wrap a key.
    Wrap(WrapError),
    /// The keystore failed.
    KeyStore,
}

impl fmt::Display for FfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(err) => write!(f, "crypto error: {err}"),
            Self::Stack(err) => write!(f, "unable to manipulate stack: {err}"),
            Self::KeyNotFound => write!(f, "unable to find key"),
            Self::Encoding => write!(f, "unable to decode type"),
            Self::Afc(err) => write!(f, "AFC error: {err}"),
            Self::Wrap(err) => write!(f, "{err}"),
            Self::KeyStore => write!(f, "keystore failure"),
        }
    }
}

impl core::error::Error for FfiError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            Self::Stack(err) => Some(err),
            Self::Afc(err) => Some(err),
            Self::Wrap(err) => Some(err),
            _ => None,
        }
    }
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

impl From<aranya_crypto::Error> for FfiError {
    fn from(err: aranya_crypto::Error) -> Self {
        Self::Crypto(err)
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

impl From<MachineErrorType> for FfiError {
    fn from(err: MachineErrorType) -> Self {
        Self::Stack(err)
    }
}

impl From<aranya_fast_channels::Error> for FfiError {
    fn from(err: aranya_fast_channels::Error) -> Self {
        Self::Afc(err)
    }
}

impl From<WrapError> for FfiError {
    fn from(err: WrapError) -> Self {
        Self::Wrap(err)
    }
}

/// An AFC label.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Label(u32);

impl From<Label> for aranya_fast_channels::Label {
    fn from(label: Label) -> Self {
        label.0.into()
    }
}

impl From<aranya_fast_channels::Label> for Label {
    fn from(label: aranya_fast_channels::Label) -> Self {
        Self(label.to_u32())
    }
}

impl Typed for Label {
    const TYPE: Type<'static> = Type::Int;
}

impl TryFrom<Value> for Label {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let x: i64 = value.try_into()?;
        Ok(Label(
            // TODO(eric): better errors
            u32::try_from(x).map_err(|_| ValueConversionError::OutOfRange)?,
        ))
    }
}