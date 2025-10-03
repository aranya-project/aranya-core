pub mod defs;

#[allow(unused_qualifications, unused)]
#[rustfmt::skip]
mod generated {
    // use include to test real usage.
    include!("generated.rs");
}

use std::{ffi::c_char, mem::MaybeUninit};

use aranya_capi_core::{ExtendedError, InvalidArg, WriteCStrError, write_c_str};
use buggy::Bug;
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Bug(#[from] Bug),

    #[error(transparent)]
    InvalidArg(#[from] InvalidArg<'static>),

    #[error("buffer too small")]
    BufferTooSmall,

    #[error(transparent)]
    Utf8(#[from] core::str::Utf8Error),
}

impl From<WriteCStrError> for Error {
    fn from(err: WriteCStrError) -> Self {
        match err {
            WriteCStrError::Bug(bug) => Self::Bug(bug),
            WriteCStrError::BufferTooSmall => Self::BufferTooSmall,
        }
    }
}

/// Underlying type for [`ExtError`][crate::defs::ExtError].
#[derive(Default)]
pub struct ExtError {
    err: Option<Error>,
}

impl ExtError {
    /// Creates an `ExtError`.
    pub const fn new(err: Error) -> Self {
        Self { err: Some(err) }
    }

    /// Copies the error message to `msg` as a null-terminated
    /// C string.
    pub fn copy_msg(&self, msg: &mut [MaybeUninit<c_char>], len: &mut usize) -> Result<(), Error> {
        if let Some(err) = &self.err {
            write_c_str(msg, err, len).map_err(Into::into)
        } else {
            warn!("empty extended error empty");
            write_c_str(msg, &"", len).map_err(Into::into)
        }
    }
}

impl ExtendedError for ExtError {
    type Error = Error;

    fn set<E>(&mut self, err: Option<E>)
    where
        E: Into<Self::Error>,
    {
        self.err = err.map(Into::into);
    }
}
