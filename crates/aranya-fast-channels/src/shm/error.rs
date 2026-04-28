use core::{convert::Infallible, str};

use buggy::Bug;

use super::{
    le::{U32, U64},
    path::InvalidPathError,
    shared::PageSizeError,
};
use crate::{errno::Errno, state::LocalChannelId};

/// An error that occurred while using shared memory.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
    /// A system call failed.
    #[error(transparent)]
    Errno(#[from] Errno),
    /// The argument is invalid.
    #[error("{0}")]
    InvalidArgument(&'static str),
    /// The shared memory path is invalid.
    #[error(transparent)]
    InvalidPath(#[from] InvalidPathError),
    /// The shared memory is corrupted.
    #[error(transparent)]
    Corrupted(#[from] Corrupted),
    /// The nodes could not be represented in memory.
    #[error(transparent)]
    Layout(#[from] LayoutError),
    /// The channel was not found.
    #[error("channel {0} not found")]
    NotFound(LocalChannelId),
    /// Not enough space to add a new channel.
    #[error("out of space")]
    OutOfSpace,
}

/// Explains what part of the state is corrupted.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Corrupted {
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
    /// The `SharedMem`'s magic value was incorrect.
    #[error("invalid `SharedMem` magic: {0}")]
    SharedMemMagic(u32),
    /// The `SharedMem`'s size is incorrect.
    #[error("invalid SharedMem size: wanted {want}, got {got}")]
    SharedMemSize {
        /// The size in bytes of the shared memory.
        got: u64,
        /// The expected size of the shared memory.
        want: u64,
    },
    /// The `SharedMem`'s page alignment is incorrect.
    #[error("invalid SharedMem page alignment: {0}")]
    SharedMemPageAlignment(bool),
    /// The `SharedMem`'s key size is incorrect.
    #[error("invalid SharedMem key size: {0}")]
    SharedMemKeySize(u64),
    /// The `ChanList`'s magic value was incorrect.
    #[error("invalid `ChanList` magic: {0}")]
    ChanListMagic(u32),
    /// The `ShmChan`'s magic value was incorrect.
    #[error("invalid `ShmChan` magic: {0}")]
    ChanMagic(u32),
    /// The `ShmChan`'s type was incorrect.
    #[error("invalid `ShmChan` direction: {0}")]
    ChanDirection(u32),
    /// Unable to compute the layout.
    #[error(transparent)]
    Layout(#[from] LayoutError),
    /// Incompatible version.
    #[error("invalid SharedMem version: wanted {want}, got {got}")]
    SharedMemVersion {
        /// The version returned from the memory.
        got: u32,
        /// The version we expect/want.
        want: u32,
    },
    /// Something else is corrupt.
    #[error("{0}")]
    Other(&'static str),
}

impl From<Infallible> for Corrupted {
    fn from(v: Infallible) -> Self {
        match v {}
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

pub(super) const fn bad_state_size(got: U64, want: u64) -> Corrupted {
    Corrupted::SharedMemSize {
        got: got.into(),
        want,
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

/// A wrapper around [`LayoutError`][core::alloc::LayoutError]
/// that includes [`Bug`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum LayoutError {
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
    /// Unable to get the current page size.
    #[error(transparent)]
    PageSize(#[from] PageSizeError),
    /// See [`LayoutError`][core::alloc::LayoutError].
    #[error(transparent)]
    Layout(#[from] core::alloc::LayoutError),
}
