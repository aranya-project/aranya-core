use core::{convert::Infallible, fmt, str};

use aranya_buggy::Bug;

use super::{
    le::{U32, U64},
    path::InvalidPathError,
    shared::PageSizeError,
};
use crate::errno::Errno;

/// An error that occurred while using shared memory.
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// An internal bug was discovered.
    Bug(Bug),
    /// A system call failed.
    Errno(Errno),
    /// The argument is invalid.
    InvalidArgument(&'static str),
    /// The shared memory path is invalid.
    InvalidPath(InvalidPathError),
    /// The shared memory is corrupted.
    Corrupted(Corrupted),
    /// The nodes could not be represented in memory.
    Layout(LayoutError),
    /// Not enough space to add a new channel.
    OutOfSpace,
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Bug(err) => Some(err),
            Self::Errno(err) => Some(err),
            Self::InvalidPath(err) => Some(err),
            Self::Layout(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bug(err) => write!(f, "{err}"),
            Self::Errno(err) => write!(f, "{err}"),
            Self::InvalidArgument(msg) => write!(f, "{msg}"),
            Self::InvalidPath(err) => write!(f, "{err}"),
            Self::Corrupted(err) => write!(f, "{err}"),
            Self::Layout(err) => write!(f, "{err}"),
            Self::OutOfSpace => write!(f, "out of space"),
        }
    }
}

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

impl From<InvalidPathError> for Error {
    fn from(value: InvalidPathError) -> Self {
        Self::InvalidPath(value)
    }
}

impl From<Corrupted> for Error {
    fn from(value: Corrupted) -> Self {
        Self::Corrupted(value)
    }
}

impl From<LayoutError> for Error {
    fn from(value: LayoutError) -> Self {
        Self::Layout(value)
    }
}

/// Explains what part of the state is corrupted.
#[derive(Debug, Eq, PartialEq)]
pub enum Corrupted {
    /// An internal bug was discovered.
    Bug(Bug),
    /// The `SharedMem`'s magic value was incorrect.
    SharedMemMagic(u32),
    /// The `SharedMem`'s size is incorrect.
    SharedMemSize {
        /// The size in bytes of the shared memory.
        got: u64,
        /// The expected size of the shared memory.
        want: u64,
    },
    /// The `SharedMem`'s page alignment is incorrect.
    SharedMemPageAlignment(bool),
    /// The `SharedMem`'s key size is incorrect.
    SharedMemKeySize(u64),
    /// The `ChanList`'s magic value was incorrect.
    ChanListMagic(u32),
    /// The `ShmChan`'s magic value was incorrect.
    ChanMagic(u32),
    /// The `ShmChan`'s type was incorrect.
    ChanDirection(u32),
    /// Unable to compute the layout.
    Layout(LayoutError),
    /// Incompatible version.
    SharedMemVersion {
        /// The version returned from the memory.
        got: u32,
        /// The version we expect/want.
        want: u32,
    },
    /// Something else is corrupt.
    Other(&'static str),
}

impl fmt::Display for Corrupted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bug(err) => write!(f, "{err}"),
            Self::ChanMagic(magic) => write!(f, "invalid `ShmChan` magic: {magic}"),
            Self::ChanListMagic(magic) => write!(f, "invalid `ChanList` magic: {magic}"),
            Self::ChanDirection(typ) => write!(f, "invalid `ShmChan` direction: {typ}"),
            Self::SharedMemMagic(magic) => write!(f, "invalid `SharedMem` magic: {magic}"),
            Self::SharedMemSize { want, got } => {
                write!(f, "invalid SharedMem size: got={got}, want={want} ")
            }
            Self::SharedMemPageAlignment(aligned) => {
                write!(f, "invalid SharedMem page alignment: {aligned}")
            }
            Self::SharedMemKeySize(size) => write!(f, "invalid SharedMem key size: {size}"),
            Self::Layout(err) => write!(f, "{err}"),
            Self::SharedMemVersion { got, want } => {
                write!(f, "invalid SharedMem version: got {got} want {want}")
            }
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<Infallible> for Corrupted {
    fn from(v: Infallible) -> Self {
        match v {}
    }
}

impl From<Bug> for Corrupted {
    fn from(v: Bug) -> Self {
        Self::Bug(v)
    }
}

pub(super) const fn bad_state_magic(magic: U32) -> Corrupted {
    Corrupted::SharedMemMagic(magic.into())
}

pub(super) const fn bad_state_version(got: U32, want: U32) -> Corrupted {
    Corrupted::SharedMemVersion {
        got: got.into(),
        want: want.into(),
    }
}

pub(super) const fn bad_state_size(got: U64, want: U64) -> Corrupted {
    Corrupted::SharedMemSize {
        got: got.into(),
        want: want.into(),
    }
}

pub(super) const fn bad_page_alignment(aligned: bool) -> Corrupted {
    Corrupted::SharedMemPageAlignment(aligned)
}

pub(super) const fn bad_state_key_size(size: U64) -> Corrupted {
    Corrupted::SharedMemKeySize(size.into())
}

pub(super) const fn bad_chanlist_magic(magic: U32) -> Corrupted {
    Corrupted::ChanListMagic(magic.into())
}

pub(super) const fn bad_chan_magic(magic: U32) -> Corrupted {
    Corrupted::ChanMagic(magic.into())
}

pub(super) const fn bad_chan_direction(v: U32) -> Corrupted {
    Corrupted::ChanDirection(v.into())
}

pub(super) const fn corrupted(msg: &'static str) -> Corrupted {
    Corrupted::Other(msg)
}

impl From<LayoutError> for Corrupted {
    fn from(value: LayoutError) -> Self {
        Self::Layout(value)
    }
}

/// A wrapper around [`LayoutError`][core::alloc::LayoutError]
/// that includes [`Bug`].
#[derive(Debug, Eq, PartialEq)]
pub enum LayoutError {
    /// An internal bug was discovered.
    Bug(Bug),
    /// Unable to get the current page size.
    PageSize(PageSizeError),
    /// See [`LayoutError`][core::alloc::LayoutError].
    Layout(core::alloc::LayoutError),
}

impl core::error::Error for LayoutError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Bug(err) => Some(err),
            Self::PageSize(err) => Some(err),
            Self::Layout(err) => Some(err),
        }
    }
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bug(err) => write!(f, "{err}"),
            Self::PageSize(err) => write!(f, "{err}"),
            Self::Layout(err) => write!(f, "{err}"),
        }
    }
}

impl From<Bug> for LayoutError {
    fn from(err: Bug) -> Self {
        Self::Bug(err)
    }
}

impl From<PageSizeError> for LayoutError {
    fn from(err: PageSizeError) -> Self {
        Self::PageSize(err)
    }
}

impl From<core::alloc::LayoutError> for LayoutError {
    fn from(err: core::alloc::LayoutError) -> Self {
        Self::Layout(err)
    }
}
