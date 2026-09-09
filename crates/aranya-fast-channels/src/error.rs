use core::{alloc::LayoutError, convert::Infallible};

use aranya_crypto::{
    ImportError,
    afc::{OpenError, SealError},
};
use buggy::Bug;

use crate::{LocalChannelId, buf::AllocError, errno::Errno, header::HeaderError};

/// Shorthand for `Result`s that use [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// An error returned from this API.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
    /// The header is invalid.
    #[error(transparent)]
    InvalidHeader(#[from] HeaderError),
    /// The channel could not be found.
    #[error("channel not found: {0}")]
    NotFound(LocalChannelId),
    /// The input is too large.
    #[error("input too large")]
    InputTooLarge,
    /// The output buffer is too small.
    #[error("output buffer too small")]
    BufferTooSmall,
    /// The cryptographic key has expired and must be rotated.
    #[error("peer's key is expired")]
    KeyExpired,
    /// The ciphertext could not be authenticated.
    #[error("authentication failure")]
    Authentication,
    /// Some other cryptographic error occurred.
    #[error("other cryptographic error: {0}")]
    Crypto(#[from] aranya_crypto::Error),
    /// An implementation of [`Buf`][crate::Buf] was unable to
    /// allocate memory.
    #[error(transparent)]
    Allocation(#[from] AllocError),
    /// A libc function failed.
    #[error(transparent)]
    Errno(#[from] Errno),
    /// The argument is invalid.
    ///
    /// This exists primarily for the C API.
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
    /// Invalid memory layout.
    #[error("invalid memory layout: {0}")]
    MemoryLayout(#[from] LayoutError),
    /// Not enough space to add a new node.
    #[error("out of space for new nodes")]
    OutOfSpace,
    /// The shared memory state failed.
    #[cfg(any(feature = "sdlib", feature = "posix"))]
    #[error(transparent)]
    SharedMem(#[from] crate::shm::Error),
    /// The state is corrupted.
    ///
    /// In general, this error is only returned when a more
    /// specific error cannot be found.
    ///
    /// For example, if the `shm` feature is enabled then
    /// [`Error::SharedMem`] will likely be returned instead.
    #[error("{0}")]
    Corrupted(&'static str),
}

#[cfg(any(feature = "sdlib", feature = "posix"))]
impl From<crate::shm::Corrupted> for Error {
    fn from(value: crate::shm::Corrupted) -> Self {
        Self::SharedMem(crate::shm::Error::Corrupted(value))
    }
}

impl From<Infallible> for Error {
    fn from(v: Infallible) -> Self {
        match v {}
    }
}

impl From<SealError> for Error {
    fn from(err: SealError) -> Self {
        match err {
            SealError::MessageLimitReached => Self::KeyExpired,
            SealError::Other(err) => Self::Crypto(aranya_crypto::Error::Hpke(err)),
            SealError::Bug(err) => Self::Bug(err),
        }
    }
}

impl From<OpenError> for Error {
    fn from(err: OpenError) -> Self {
        match err {
            OpenError::Authentication => Self::Authentication,
            OpenError::MessageLimitReached => Self::KeyExpired,
            OpenError::Other(err) => Self::Crypto(aranya_crypto::Error::Hpke(err)),
            OpenError::Bug(err) => Self::Bug(err),
        }
    }
}

impl From<ImportError> for Error {
    fn from(err: ImportError) -> Self {
        Self::Crypto(aranya_crypto::Error::Import(err))
    }
}
