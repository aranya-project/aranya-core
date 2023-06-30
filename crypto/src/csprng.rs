//! Cryptographically Secure Random Number Generators.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

#![forbid(unsafe_code)]

pub use getrandom;

/// A cryptographically secure pseudorandom number generator
/// (CSPRNG).
pub trait Csprng {
    /// Entirely fills `dst` with cryptographically secure
    /// pseudorandom bytes.
    ///
    /// # Error Handling
    ///
    /// If underlying CSPRNG encounters transient errors (for
    /// example, blocking on startup), it must block until the
    /// error condition subsides.
    ///
    /// If the underlying CSPRNG encounters a fatal error, it
    /// must immediately panic or abort the program.
    fn fill_bytes(&mut self, dst: &mut [u8]);

    /// Returns a fixed-number of cryptographically secure,
    /// pseudorandom bytes.
    ///
    /// # Notes
    ///
    /// Once (if) `const_generic_exprs` is stabilized, `T` will
    /// become `const N: usize`.
    fn bytes<T: AsMut<[u8]> + Default>(&mut self) -> T
    where
        Self: Sized,
    {
        let mut b = T::default();
        self.fill_bytes(b.as_mut());
        b
    }
}

#[cfg(feature = "rand_core")]
#[cfg_attr(docs, doc(cfg(feature = "rand_core")))]
impl Csprng for rand_core::OsRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, dst)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docs, doc(cfg(feature = "std")))]
impl Csprng for rand::rngs::ThreadRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, dst)
    }
}
