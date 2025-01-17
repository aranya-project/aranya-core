use core::{convert::Infallible, fmt};

use aranya_libc::Errno;
use tracing::error;

use crate::StorageError;

/// An error returned by this module.
#[derive(Debug)]
pub struct Error(Errno);

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Errno> for Error {
    fn from(err: Errno) -> Self {
        Self(err)
    }
}

impl From<Infallible> for Error {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

impl From<Errno> for StorageError {
    fn from(err: Errno) -> Self {
        error!(?err);
        StorageError::IoError
    }
}
