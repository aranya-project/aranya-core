use core::{alloc::LayoutError, convert::Infallible, fmt};

use aranya_buggy::Bug;
use aranya_crypto::{
    afc::{OpenError, SealError},
    ImportError,
};

use crate::{buf::AllocError, errno::Errno, header::HeaderError, state::ChannelId};

/// Shorthand for `Result`s that use [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// An error returned from this API.
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// An internal bug was discovered.
    Bug(Bug),
    /// The header is invalid.
    InvalidHeader(HeaderError),
    /// The channel could not be found.
    NotFound(ChannelId),
    /// The input is too large.
    InputTooLarge,
    /// The output buffer is too small.
    BufferTooSmall,
    /// The cryptographic key has expired and must be rotated.
    KeyExpired,
    /// The ciphertext could not be authenticated.
    Authentication,
    /// Some other cryptographic error occurred.
    Crypto(aranya_crypto::Error),
    /// An implementation of [`Buf`][crate::Buf] was unable to
    /// allocate memory.
    Allocation(AllocError),
    /// A libc function failed.
    Errno(Errno),
    /// The argument is invalid.
    ///
    /// This exists primarily for the C API.
    InvalidArgument(&'static str),
    /// Invalid memory layout.
    MemoryLayout(LayoutError),
    /// Not enough space to add a new node.
    OutOfSpace,
    /// The shared memory state failed.
    #[cfg(any(feature = "sdlib", feature = "posix"))]
    SharedMem(crate::shm::Error),
    /// The state is corrupted.
    ///
    /// In general, this error is only returned when a more
    /// specific error cannot be found.
    ///
    /// For example, if the `shm` feature is enabled then
    /// [`Error::SharedMem`] will likely be returned instead.
    Corrupted(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bug(err) => write!(f, "{err}"),
            Self::InvalidHeader(err) => write!(f, "{err}"),
            Self::NotFound(ch) => write!(f, "channel not found: {ch}"),
            Self::InputTooLarge => write!(f, "input too large"),
            Self::BufferTooSmall => write!(f, "output buffer too small"),
            Self::Authentication => write!(f, "authentication failure"),
            Self::Crypto(err) => write!(f, "other cryptographic error: {err}"),
            Self::KeyExpired => write!(f, "peer's key is expired"),
            Self::Allocation(err) => write!(f, "{err}"),
            Self::Errno(err) => write!(f, "{err}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::MemoryLayout(err) => write!(f, "invalid memory layout: {err}"),
            Self::OutOfSpace => write!(f, "out of space for new nodes"),
            #[cfg(any(feature = "sdlib", feature = "posix"))]
            Self::SharedMem(err) => write!(f, "{err}"),
            Self::Corrupted(msg) => write!(f, "{msg}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<Bug> for Error {
    fn from(value: Bug) -> Self {
        Self::Bug(value)
    }
}

impl From<Errno> for Error {
    fn from(value: Errno) -> Self {
        Self::Errno(value)
    }
}

impl From<LayoutError> for Error {
    fn from(value: LayoutError) -> Self {
        Self::MemoryLayout(value)
    }
}

impl From<AllocError> for Error {
    fn from(value: AllocError) -> Self {
        Self::Allocation(value)
    }
}

#[cfg(any(feature = "sdlib", feature = "posix"))]
impl From<crate::shm::Error> for Error {
    fn from(value: crate::shm::Error) -> Self {
        Self::SharedMem(value)
    }
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

impl From<HeaderError> for Error {
    fn from(err: HeaderError) -> Self {
        Self::InvalidHeader(err)
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
