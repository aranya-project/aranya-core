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

#![cfg_attr(all(feature = "error", not(feature = "std")), feature(error_in_core))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![deny(
    clippy::arithmetic_side_effects,
    clippy::wildcard_imports,
    missing_docs
)]

use core::{fmt, panic::Location};

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use std::error::Error as StdError;
    } else if #[cfg(feature = "error")] {
        use core::error::Error as StdError;
    }
}

#[derive(Clone, Debug)]
/// Error type for errors that should be unreachable, indicating a bug.
///
/// If you need to keep your error type small, use `&'static str` instead of `Bug`,
/// and use [`Bug::msg`] in your `From<Bug>` impl.
pub struct Bug {
    msg: &'static str,
    location: &'static Location<'static>,
}

impl Bug {
    /// Create an [`Bug`] error. You should most likely use [`bug`].
    #[cold]
    pub fn new(msg: &'static str, location: &'static Location<'static>) -> Self {
        Self { msg, location }
    }

    /// Get the message used when creating the [`Bug`].
    pub fn msg(&self) -> &'static str {
        self.msg
    }
}

impl fmt::Display for Bug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "bug: {}", self.msg)?;
        writeln!(f, "location: {}", self.location)?;
        Ok(())
    }
}

#[cfg(feature = "error")]
impl StdError for Bug {}

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
        #![allow(unused_variables)]
        match self {
            Ok(val) => Ok(val),
            Err(err) => bug!(msg, err),
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(test, doc, not(debug_assertions)))] {
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
            ($msg:expr $(, $cause:expr)?) => {
                return Err(Bug::new($msg, Location::caller()).into())
            }
        }
    } else {
        /// This doc should be unreadable.
        #[macro_export]
        macro_rules! bug {
            ($msg:expr) => {{{
                #![allow(clippy::disallowed_macros)]
                ::core::unreachable!("{}", $msg);
            }}};
            ($msg:expr, $cause:expr) => {{{
                #![allow(clippy::disallowed_macros)]
                ::core::unreachable!("{}, caused by: {}", $msg, $cause);
            }}};
        }
    }
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

        assert_between(err.location, before, after);
        assert_eq!(err.msg, msg);
    }

    #[test]
    fn result_err() {
        let val: Result<(), &str> = Err("inner");
        let msg = "result_err test";

        let before = Location::caller();
        let err = val.assume(msg).unwrap_err();
        let after = Location::caller();

        assert_between(err.location, before, after);
        assert_eq!(err.msg, msg);
    }

    fn assert_between(loc: &Location<'_>, before: &Location<'_>, after: &Location<'_>) {
        assert_eq!(loc.file(), before.file());
        assert_eq!(loc.file(), after.file());
        assert!(before.line() < loc.line());
        assert!(loc.line() < after.line());
    }
}
