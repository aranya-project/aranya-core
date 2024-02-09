extern crate alloc;

use alloc::boxed::Box;
use core::{fmt, ops::Deref};

use policy_vm::{MachineError, MachineErrorType, MachineIOError};

/// An error returned by `Ffi`.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    err: Box<dyn trouble::Error + Send + Sync + 'static>,
}

impl Error {
    pub(crate) fn new<E>(kind: ErrorKind, err: E) -> Self
    where
        E: trouble::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            err: Box::new(err),
        }
    }

    /// Attempts to downcast the error into `T`.
    #[inline]
    pub fn downcast_ref<T: trouble::Error + 'static>(&self) -> Option<&T> {
        self.err.downcast_ref::<T>()
    }

    /// Describes the kind of error.
    #[inline]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl trouble::Error for Error {
    fn source(&self) -> Option<&(dyn trouble::Error + 'static)> {
        Some(self.err.deref())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.err.fmt(f)
    }
}

impl From<Error> for MachineError {
    fn from(_err: Error) -> Self {
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

impl trouble::Error for WrongContext {}

impl fmt::Display for WrongContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}