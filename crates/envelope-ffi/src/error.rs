extern crate alloc;

use alloc::boxed::Box;
use core::{fmt, ops::Deref};

use policy_vm::{MachineError, MachineErrorType, MachineIOError};
use tracing::error;

/// An error returned by `Ffi`.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
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

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.err.deref())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.err.fmt(f)
    }
}

impl From<Error> for MachineError {
    fn from(err: Error) -> Self {
        error!("{err}");
        // TODO(eric): correct error type.
        Self::new(MachineErrorType::IO(MachineIOError::Internal))
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
    /// A method was called in the wrong context.
    ///
    /// [`Error`] can be downcast to [`WrongContext`].
    WrongContext,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongContext => write!(f, "method called in wrong context"),
        }
    }
}

/// A method was called in the wrong context.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WrongContext(pub(crate) &'static str);

impl core::error::Error for WrongContext {}

impl fmt::Display for WrongContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
