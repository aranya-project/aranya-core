//! This crate exports a wrapper type to implement [`core::error::Error`] for a third-party type.

#![no_std]
#![warn(missing_docs)]

use core::{fmt, ops::Deref};

/// A wrapper around some error `E` so that it implements [`core::error::Error`].
///
/// This is useful for third-party types that have not adapted to the recently stabilized
/// `error-in-core` feature and thus do not implement the trait when `std` is not available.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Trouble<E>(pub E);

impl<E: 'static> Trouble<E> {
    /// Cast a reference to add `Trouble` around it.
    pub fn cast(err: &E) -> &Self {
        // SAFETY: `err` and `Self` have the same memory layout.
        unsafe { &*core::ptr::from_ref(err).cast() }
    }
}

impl<E: fmt::Display> fmt::Display for Trouble<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<E: fmt::Debug> fmt::Debug for Trouble<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<E: fmt::Display + fmt::Debug> core::error::Error for Trouble<E> {}

impl<E> Deref for Trouble<E> {
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
