//! Error handling similar to [`core::unreachable`], but less panicky.
//!
//! # Configuration
//! Panicking is controlled by [`debug_assertions`](https://doc.rust-lang.org/cargo/reference/profiles.html#debug-assertions).
//! - By default, in debug/test builds, we panic to make it easier to find bugs.
//! - In release builds, we don't want to panic so we instead return `Result<T, `[`Bug`]`>`.
//!
//! # Usage
//! ```
//! use buggy::{bug, Bug, BugExt};
//!
//! #[derive(Debug)]
//! enum MyError {
//!     TooManyFrobs,
//!     Bug(Bug),
//! }
//!
//! impl From<Bug> for MyError {
//!     fn from(err: Bug) -> Self {
//!         Self::Bug(err)
//!     }
//! }
//!
//! fn main() -> Result<(), MyError> {
//!     let x: u32 = 42;
//!
//!     let sum = x.checked_add(100).assume("x is small")?;
//!
//!     if x % 2 != 0 {
//!         bug!("x is always even because I said so");
//!     }
//!
//!     Ok(())
//! }
//! ```

#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::{convert::Infallible, fmt, panic::Location};

#[derive(Clone, Debug, Eq, PartialEq)]
/// Error type for errors that should be unreachable, indicating a bug.
///
/// Use [`bug`] to return a `Result<T, Bug>`.
pub struct Bug(
    #[cfg(feature = "alloc")] Box<BugInner>,
    #[cfg(not(feature = "alloc"))] BugInner,
);

#[derive(Clone, Debug, Eq, PartialEq)]
struct BugInner {
    msg: &'static str,
    location: &'static Location<'static>,
}

impl Bug {
    #[cold]
    #[track_caller]
    #[doc(hidden)]
    pub fn new(msg: &'static str) -> Self {
        cfg_if::cfg_if! {
            if #[cfg(any(test, doc, not(debug_assertions)))] {
                #[allow(clippy::useless_conversion)]
                Self(BugInner {
                    msg,
                    location: Location::caller(),
                }.into())
            } else {{
                #![allow(clippy::disallowed_macros)]
                unreachable!("{}", msg)
            }}
        }
    }

    #[cold]
    #[track_caller]
    #[doc(hidden)]
    pub fn new_with_source(msg: &'static str, _cause: impl fmt::Display) -> Self {
        cfg_if::cfg_if! {
            if #[cfg(any(test, doc, not(debug_assertions)))] {
                Self::new(msg)
            } else {{
                #![allow(clippy::disallowed_macros)]
                unreachable!("{msg}, caused by: {_cause}")
            }}
        }
    }

    /// Get the message used when creating the [`Bug`].
    pub fn msg(&self) -> &'static str {
        self.0.msg
    }
}

impl fmt::Display for Bug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "bug: {}", self.0.msg)?;
        writeln!(f, "location: {}", self.0.location)?;
        Ok(())
    }
}

impl core::error::Error for Bug {}

impl From<Infallible> for Bug {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

/// Extension trait for assuming an option or result can be unwrapped.
pub trait BugExt<T> {
    /// Assume this value can be unwrapped. See `[crate]` docs.
    fn assume(self, msg: &'static str) -> Result<T, Bug>;
}

impl<T> BugExt<T> for Option<T> {
    #[track_caller]
    fn assume(self, msg: &'static str) -> Result<T, Bug> {
        match self {
            Some(val) => Ok(val),
            None => bug!(msg),
        }
    }
}

impl<T, E: fmt::Display> BugExt<T> for Result<T, E> {
    #[track_caller]
    fn assume(self, msg: &'static str) -> Result<T, Bug> {
        match self {
            Ok(val) => Ok(val),
            Err(_err) => bug!(msg, _err),
        }
    }
}

/// Like [`core::unreachable`], but less panicky. See also [`crate`] docs.
///
/// # Usage
/// ```
/// # use buggy::bug;
/// # fn main() -> Result<(), buggy::Bug> {
/// # let frobs = 1;
/// let inverse = match frobs {
///     0 => 1,
///     1 => 0,
///     _ => bug!("frobs is always 0 or 1"),
/// };
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! bug {
    ($msg:expr) => {
        return ::core::result::Result::Err($crate::Bug::new($msg).into()).into()
    };
    ($msg:expr, $source:expr) => {
        return ::core::result::Result::Err($crate::Bug::new_with_source($msg, $source).into())
            .into()
    };
}

#[cfg(test)]
mod test {
    #![allow(clippy::panic)]

    use super::*;

    #[test]
    fn option_some() {
        assert_eq!(Some(42).assume("").unwrap(), 42);
    }

    #[test]
    fn result_ok() {
        assert_eq!(Ok::<_, &str>(42).assume("").unwrap(), 42);
    }

    #[test]
    fn option_none() {
        let val: Option<()> = None;
        let msg = "option_none test";

        let before = Location::caller();
        let err = val.assume(msg).unwrap_err();
        let after = Location::caller();

        assert_between(err.0.location, before, after);
        assert_eq!(err.0.msg, msg);
    }

    #[test]
    fn result_err() {
        let val: Result<(), &str> = Err("inner");
        let msg = "result_err test";

        let before = Location::caller();
        let err = val.assume(msg).unwrap_err();
        let after = Location::caller();

        assert_between(err.0.location, before, after);
        assert_eq!(err.0.msg, msg);
    }

    fn assert_between(loc: &Location<'_>, before: &Location<'_>, after: &Location<'_>) {
        assert_eq!(loc.file(), before.file());
        assert_eq!(loc.file(), after.file());
        assert!(before.line() < loc.line());
        assert!(loc.line() < after.line());
    }
}
