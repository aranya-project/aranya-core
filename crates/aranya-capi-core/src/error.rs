use core::{
    error,
    ffi::CStr,
    fmt,
    ops::{Deref, DerefMut},
    str::Utf8Error,
};

use super::{
    safe::{self, InvalidPtr},
    InvalidSlice,
};

/// An error code returned by the C API.
///
/// This can be used with `#[derive]`; see
/// [`ErrorCode`][derive@crate::ErrorCode] for more information.
///
/// # Example
///
/// ```rust
/// use core::{fmt::Debug, ffi::CStr};
///
/// use aranya_capi_core::{
///     ErrorCode,
///     InvalidArg,
/// };
///
/// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// #[repr(u32)]
/// enum Error {
///     Success = 0,
///     OutOfMemory = 1,
///     DoesNotExist = 2,
///     InvalidArgument = 3,
/// }
///
/// impl ErrorCode for Error {
///     const SUCCESS: Self = Error::Success;
///
///     type Repr = u32;
///
///     fn try_from_repr(err: Self::Repr) -> Option<Self> {
///         match err {
///             0 => Some(Self::Success),
///             1 => Some(Self::OutOfMemory),
///             2 => Some(Self::DoesNotExist),
///             3 => Some(Self::InvalidArgument),
///             _ => None,
///         }
///     }
///
///     fn to_cstr(self) -> &'static CStr {
///         match self {
///             Self::Success => c"success",
///             Self::OutOfMemory => c"out of memory",
///             Self::DoesNotExist => c"does not exist",
///             Self::InvalidArgument => c"invalid argument",
///         }
///     }
/// }
///
/// impl From<&InvalidArg<'static>> for Error {
///     fn from(_err: &InvalidArg<'static>) -> Self {
///         Self::InvalidArgument
///     }
/// }
///
/// assert_eq!(Error::Success, Error::SUCCESS);
/// assert_eq!(c"invalid argument", Error::InvalidArgument.to_cstr());
/// ```
pub trait ErrorCode: Sized + for<'a> From<&'a InvalidArg<'static>> {
    /// The value returned on success.
    const SUCCESS: Self;

    /// A valid enumeration repr.
    type Repr: Sized;

    /// Attempts to create the error from its repr.
    fn try_from_repr(err: Self::Repr) -> Option<Self>;

    /// Converts the error to a static [`CStr`].
    fn to_cstr(self) -> &'static CStr;
}

/// Extended error information.
pub trait ExtendedError: Sized {
    // The underlying error type.
    type Error;

    /// Sets the extended error information.
    fn set<E>(&mut self, err: Option<E>)
    where
        E: Into<Self::Error>;
}

// This primarily exists so we can write
//
// ```
// type MyExtError = safe::Safe<...>
// ```
//
// and still implement `ExtendedError`.
impl<T> ExtendedError for T
where
    T: DerefMut,
    <T as Deref>::Target: ExtendedError,
{
    type Error = <<T as Deref>::Target as ExtendedError>::Error;

    fn set<E: Into<Self::Error>>(&mut self, err: Option<E>) {
        (**self).set(err)
    }
}

/// An invalid agument.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InvalidArg<'a> {
    arg: &'a str,
    err: InvalidArgReason,
}

impl<'a> InvalidArg<'a> {
    /// Creates an `InvalidArg`.
    pub fn new(arg: &'a str, reason: impl Into<InvalidArgReason>) -> Self {
        Self {
            arg,
            err: reason.into(),
        }
    }
}

impl error::Error for InvalidArg<'_> {}

impl fmt::Display for InvalidArg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid argument `{}`: {}", self.arg, self.err)
    }
}

/// The reason for an [`InvalidArg`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InvalidArgReason {
    /// A pointer argument is invalid.
    InvalidPtr(InvalidPtr),
    /// A [`Safe`][safe::Safe] argument is invalid.
    InvalidSafe(safe::Error),
    /// A (pointer, length) argument is invalid.
    ///
    /// NB: This is NOT a Rust slice.
    InvalidSlice(InvalidSlice),
    /// The string did not contain valid UTF-8.
    InvalidUtf8(Utf8Error),
    /// Some other reason.
    Other(&'static str),
}

impl fmt::Display for InvalidArgReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPtr(err) => write!(f, "{err}"),
            Self::InvalidSafe(err) => write!(f, "{err}"),
            Self::InvalidSlice(err) => write!(f, "{err}"),
            Self::InvalidUtf8(err) => write!(f, "{err}"),
            Self::Other(reason) => write!(f, "{reason}"),
        }
    }
}

impl From<&'static str> for InvalidArgReason {
    fn from(err: &'static str) -> Self {
        Self::Other(err)
    }
}

impl From<safe::Error> for InvalidArgReason {
    fn from(err: safe::Error) -> Self {
        Self::InvalidSafe(err)
    }
}

impl From<InvalidPtr> for InvalidArgReason {
    fn from(err: InvalidPtr) -> Self {
        Self::InvalidPtr(err)
    }
}

impl From<InvalidSlice> for InvalidArgReason {
    fn from(err: InvalidSlice) -> Self {
        Self::InvalidSlice(err)
    }
}

impl From<Utf8Error> for InvalidArgReason {
    fn from(err: Utf8Error) -> Self {
        Self::InvalidUtf8(err)
    }
}
