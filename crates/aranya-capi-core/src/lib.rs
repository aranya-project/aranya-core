//! A `no-std` utility library for building C APIs.

mod cstr;
mod error;
#[doc(hidden)]
pub mod internal;
mod macros;
pub mod safe;
mod traits;
pub mod types;
mod utf8;

pub use cstr::{write_c_str, WriteCStrError};
pub use error::{ErrorCode, ExtendedError, InvalidArg, InvalidArgReason};
#[doc(hidden)]
pub use internal::conv::{slice::InvalidSlice, ConvError};
pub use macros::*;
pub use traits::{Builder, InitDefault};
pub use utf8::Utf8Str;

/// Common items.
pub mod prelude {
    pub use core::mem::MaybeUninit;

    pub use super::{
        safe::{CBytes, CStr, OwnedPtr, Safe, Writer},
        Builder, ErrorCode, InitDefault,
    };
}
