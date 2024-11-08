//! Slice conversions.

use core::{error, fmt, slice};

fn check_len(len: usize) -> Result<(), InvalidSlice> {
    isize::try_from(len)
        .map(|_| ())
        .map_err(|_| InvalidSlice("`len` out of range (> `isize::MAX`)"))
}

/// Converts `(ptr, len)` to a slice.
///
/// - If `ptr` is non-null, `len` must be non-zero.
/// - If `ptr` is null, `len` must be zero.
///
/// # Safety
///
/// - If non-null, `ptr` must be valid for reads up to `len`
///   bytes.
/// - You must uphold Rust's lifetimes.
/// - You must uphold Rust's aliasing guarantees.
pub unsafe fn try_from_raw_parts<'a, T>(
    ptr: *const T,
    len: usize,
) -> Result<&'a [T], InvalidSlice> {
    if !ptr.is_aligned() {
        // NB: null pointers are aligned.
        return Err(InvalidSlice("unaligned pointer"));
    }
    check_len(len)?;
    match (ptr.is_null(), len) {
        (false, 0) => Err(InvalidSlice("non-null pointer, zero length")),
        (true, 1..) => Err(InvalidSlice("null pointer, non-zero length")),
        (true, 0) => Ok(&[]),
        (false, 1..) => {
            // SAFETY: We've verified that `ptr` is non-null and
            // suitably aligned. We have to trust that the length
            // is valid for the pointer, etc. For everything else
            // (lifetimes, aliasing, etc.), see the function's
            // safety docs.
            Ok(unsafe { slice::from_raw_parts(ptr, len) })
        }
    }
}

/// Converts `(ptr, len)` to a slice.
///
/// - If `ptr` is non-null, `len` must be non-zero.
/// - If `ptr` is null, `len` must be zero.
///
/// # Safety
///
/// - If non-null, `ptr` must be valid for reads up to `len`
///   bytes.
/// - You must uphold Rust's lifetimes.
/// - You must uphold Rust's aliasing guarantees.
pub unsafe fn try_from_raw_parts_mut<'a, T>(
    ptr: *mut T,
    len: usize,
) -> Result<&'a mut [T], InvalidSlice> {
    if !ptr.is_aligned() {
        // NB: null pointers are aligned.
        return Err(InvalidSlice("unaligned pointer"));
    }
    check_len(len)?;
    match (ptr.is_null(), len) {
        (false, 0) => Err(InvalidSlice("non-null pointer, zero length")),
        (true, 1..) => Err(InvalidSlice("null pointer, non-zero length")),
        (true, 0) => Ok(&mut []),
        (false, 1..) => {
            // SAFETY: We've verified that `ptr` is non-null and
            // suitably aligned. We have to trust that the length
            // is valid for the pointer, etc. For everything else
            // (lifetimes, aliasing, etc.), see the function's
            // safety docs.
            Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
        }
    }
}

/// The error from [`try_as_slice`][crate::try_as_slice] and
/// [`try_as_mut_slice`][crate::try_as_mut_slice].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InvalidSlice(&'static str);

impl fmt::Display for InvalidSlice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl error::Error for InvalidSlice {}

/// Evaluates to a slice, or returns an error if `$ptr` is
/// invalid or `$ptr` and `$len` do not match.
///
/// # Safety
///
/// - If non-null, `ptr` must be valid for reads up to `len`
///   bytes.
/// - You must uphold Rust's lifetimes.
/// - You must uphold Rust's aliasing guarantees.
///
/// # Example
///
/// ```ignore
/// let want = b"hello, world!";
/// let got = try_as_slice!(want.as_ptr(), want.len());
/// assert_eq!(got, want);
/// ```
#[macro_export]
#[doc(hidden)]
macro_rules! try_as_slice {
    ($ptr:ident, $len:expr $(,)?) => {{
        // SAFETY: See the macro's safety docs.
        match unsafe { $crate::internal::conv::slice::try_from_raw_parts($ptr, $len) } {
            ::core::result::Result::Ok(v) => v,
            ::core::result::Result::Err(err) => {
                return ::core::result::Result::Err(::core::convert::From::from(
                    $crate::InvalidArg::new(
                        ::core::concat!(
                            "(",
                            ::core::stringify!($ptr),
                            ", ",
                            ::core::stringify!($len),
                            ")"
                        ),
                        err,
                    ),
                ))
            }
        }
    }};
}

/// Evaluates to a `&str`, or returns an error if `$ptr` is
/// invalid or `$ptr` and `$len` do not match.
///
/// # Safety
///
/// - If non-null, `ptr` must be valid for reads up to `len`
///   bytes.
/// - You must uphold Rust's lifetimes.
/// - You must uphold Rust's aliasing guarantees.
///
/// # Example
///
/// ```ignore
/// let want = "hello, world!";
/// let got = try_as_str!(want.as_ptr(), want.len());
/// assert_eq!(got, want);
/// ```
#[macro_export]
#[doc(hidden)]
macro_rules! try_as_str {
    ($ptr:ident, $len:expr $(,)?) => {{
        match ::core::str::from_utf8(
            // SAFETY: See the macro's safety docs.
            $crate::try_as_slice!($ptr, $len),
        ) {
            ::core::result::Result::Ok(v) => v,
            ::core::result::Result::Err(err) => {
                return ::core::result::Result::Err(::core::convert::From::from(
                    $crate::InvalidArg::new(
                        ::core::concat!(
                            "(",
                            ::core::stringify!($ptr),
                            ", ",
                            ::core::stringify!($len),
                            ")"
                        ),
                        $crate::InvalidArgReason::InvalidUtf8(err),
                    ),
                ))
            }
        }
    }};
}

/// Evaluates to a slice, or returns an error if `$ptr` is
/// invalid or `$ptr` and `$len` do not match.
///
/// # Safety
///
/// - If non-null, `ptr` must be valid for reads up to `len`
///   bytes.
/// - You must uphold Rust's lifetimes.
/// - You must uphold Rust's aliasing guarantees.
#[macro_export]
#[doc(hidden)]
macro_rules! try_as_mut_slice {
    ($ptr:ident, $len:expr $(,)?) => {{
        // SAFETY: See the macro's safety docs.
        match unsafe { $crate::internal::conv::slice::try_from_raw_parts_mut($ptr, $len) } {
            ::core::result::Result::Ok(v) => v,
            ::core::result::Result::Err(err) => {
                return ::core::result::Result::Err(::core::convert::From::from(
                    $crate::InvalidArg::new(
                        ::core::concat!(
                            "(",
                            ::core::stringify!($ptr),
                            " ",
                            ::core::stringify!($len),
                            ")"
                        ),
                        err,
                    ),
                ))
            }
        }
    }};
}

/// Evaluates to a [`Writer`][crate::safe::Writer], or returns an
/// error if `$ptr` is invalid or `$ptr` and `$len` do not match.
///
/// # Safety
///
/// - The memory pointed to by `len` must be initialized.
/// - If non-null, `ptr` must be valid for reads up to `len`
///   bytes.
/// - You must uphold Rust's lifetimes.
/// - You must uphold Rust's aliasing guarantees.
#[macro_export]
#[doc(hidden)]
macro_rules! try_as_writer {
    ($ptr:ident, $len:expr $(,)?) => {{
        // SAFETY: See the macro's safety docs.
        match unsafe { $crate::safe::Writer::try_from_raw_parts($ptr, $len) } {
            ::core::result::Result::Ok(v) => v,
            ::core::result::Result::Err(err) => {
                return ::core::result::Result::Err(::core::convert::From::from(
                    $crate::InvalidArg::new(
                        ::core::concat!(
                            "(",
                            ::core::stringify!($ptr),
                            ", ",
                            ::core::stringify!($len),
                            ")"
                        ),
                        err,
                    ),
                ))
            }
        }
    }};
}
