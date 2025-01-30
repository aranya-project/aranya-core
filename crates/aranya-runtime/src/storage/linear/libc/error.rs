use core::convert::Infallible;

use aranya_libc::Errno;
use tracing::error;

use crate::StorageError;

/// An error returned by this module.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(#[from] Errno);

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
