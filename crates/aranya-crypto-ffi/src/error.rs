extern crate alloc;

use alloc::boxed::Box;
use core::fmt;

use aranya_crypto::{Id, ImportError, PkError, UnwrapError, id::IdError};
use aranya_policy_vm::{MachineError, MachineErrorType, MachineIOError};
use tracing::error;

/// An error returned by `Ffi`.
#[derive(Debug, thiserror::Error)]
#[error("{err}")]
pub struct Error {
    kind: ErrorKind,
    #[source]
    err: Box<dyn core::error::Error + Send + Sync + 'static>,
}

impl Error {
    pub(crate) fn new<E>(kind: ErrorKind, err: E) -> Self
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            err: Box::new(err),
        }
    }

    /// Attempts to downcast the error into `T`.
    #[inline]
    pub fn downcast_ref<T: core::error::Error + 'static>(&self) -> Option<&T> {
        self.err.downcast_ref::<T>()
    }

    /// Describes the kind of error.
    #[inline]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl From<Error> for MachineError {
    fn from(err: Error) -> Self {
        error!("{err}");
        // TODO(eric): correct error type.
        Self::new(MachineErrorType::IO(MachineIOError::Internal))
    }
}

impl From<IdError> for Error {
    fn from(err: IdError) -> Self {
        Self::new(ErrorKind::IdError, err)
    }
}

impl From<aranya_crypto::Error> for Error {
    fn from(err: aranya_crypto::Error) -> Self {
        Self::new(ErrorKind::Crypto, err)
    }
}

impl From<ImportError> for Error {
    fn from(err: ImportError) -> Self {
        Self::new(ErrorKind::Import, err)
    }
}

impl From<PkError> for Error {
    fn from(err: PkError) -> Self {
        Self::new(ErrorKind::PkError, err)
    }
}

impl From<InvalidCmdId> for Error {
    fn from(err: InvalidCmdId) -> Self {
        Self::new(ErrorKind::InvalidCmdId, err)
    }
}

impl From<KeyNotFound> for Error {
    fn from(err: KeyNotFound) -> Self {
        Self::new(ErrorKind::KeyNotFound, err)
    }
}

impl From<postcard::Error> for Error {
    fn from(err: postcard::Error) -> Self {
        Self::new(ErrorKind::Encoding, err)
    }
}

impl From<UnwrapError> for Error {
    fn from(err: UnwrapError) -> Self {
        Self::new(ErrorKind::Unwrap, err)
    }
}

impl From<WrongContext> for Error {
    fn from(err: WrongContext) -> Self {
        Self::new(ErrorKind::WrongContext, err)
    }
}

/// Describes [`Error`].
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum ErrorKind {
    /// The [`aranya_crypto`] crate failed.
    ///
    /// [`Error`] can be downcast to [`aranya_crypto::Error`].
    Crypto,
    /// Unable to encode/decode some input.
    ///
    /// [`Error`] can be downcast to [`postcard::Error`].
    Encoding,
    /// Unable to import a [`Signature`][aranya_crypto::Signature] or
    /// cryptographic key.
    ///
    /// [`Error`] can be downcast to [`ImportError`].
    Import,
    /// The command ID passed to `verify` is invalid.
    ///
    /// [`Error`] can be downcast to [`InvalidCmdId`].
    InvalidCmdId,
    /// The key was not found in the
    /// [`KeyStore`][aranya_crypto::KeyStore].
    KeyNotFound,
    /// The keystore failed.
    ///
    /// [`Error`] can be downcast to
    /// [`KeyStore::Error`][aranya_crypto::KeyStore::Error].
    KeyStore,
    /// Unable to unwrap a key.
    ///
    /// [`Error`] can be downcast to [`UnwrapError`].
    Unwrap,
    /// A method was called in the wrong context.
    ///
    /// [`Error`] can be downcast to [`WrongContext`].
    WrongContext,
    /// The Public Key passed in is invalid.
    PkError,
    /// The id passed in is invalid.
    IdError,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto => write!(f, "crypto error"),
            Self::Encoding => write!(f, "unable to decode type"),
            Self::Import => write!(f, "unable to import signature or cryptographic key"),
            Self::InvalidCmdId => write!(f, "invalid command ID"),
            Self::KeyNotFound => write!(f, "unable to find key"),
            Self::KeyStore => write!(f, "keystore failure"),
            Self::Unwrap => write!(f, "unable to unwrap key"),
            Self::WrongContext => write!(f, "method called in wrong context"),
            Self::PkError => write!(f, "invalid signing key"),
            Self::IdError => write!(f, "invalid id"),
        }
    }
}

/// Unable to find a key in the [`KeyStore`][aranya_crypto::KeyStore].
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid command ID")]
pub struct InvalidCmdId(pub(crate) ());

/// Unable to find a key in the [`KeyStore`][aranya_crypto::KeyStore].
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("key not found: {0}")]
pub struct KeyNotFound(pub(crate) Id);

/// A method was called in the wrong context.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct WrongContext(pub(crate) &'static str);
