#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "allocator_api")]
use core::alloc::Allocator;
use core::{
    fmt,
    ops::{Deref, DerefMut},
};

#[allow(clippy::unused_trait_names, reason = "used in docs")]
use aranya_crypto::zeroize::Zeroize;
use buggy::{Bug, BugExt as _};

/// Unable to allocate memory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllocError(Repr);

impl AllocError {
    /// Creates a general allocation error.
    pub const fn new() -> Self {
        Self(Repr::Default)
    }
}

impl core::error::Error for AllocError {}

impl fmt::Display for AllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Repr::Default => write!(f, "unable to allocate memory"),
            Repr::Bug(err) => write!(f, "{err}"),
            #[cfg(feature = "alloc")]
            Repr::TryReserve(err) => write!(f, "{err}"),
        }
    }
}

impl From<Bug> for AllocError {
    fn from(err: Bug) -> Self {
        Self(Repr::Bug(err))
    }
}

#[cfg(feature = "alloc")]
impl From<alloc::collections::TryReserveError> for AllocError {
    fn from(err: alloc::collections::TryReserveError) -> Self {
        Self(Repr::TryReserve(err))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
enum Repr {
    #[default]
    Default,
    Bug(Bug),
    #[cfg(feature = "alloc")]
    TryReserve(alloc::collections::TryReserveError),
}

/// A generalization over [`Vec`].
#[allow(clippy::len_without_is_empty)]
pub trait Buf: AsRef<[u8]> + Deref<Target = [u8]> + AsMut<[u8]> + DerefMut<Target = [u8]> {
    /// See [`Vec::len`].
    fn len(&self) -> usize;
    /// See [`Vec::split_at_mut`].
    fn split_at_mut(&mut self, mid: usize) -> (&mut [u8], &mut [u8]);
    /// See [`Vec::truncate`].
    fn truncate(&mut self, len: usize);
    /// See [`Vec::try_reserve_exact`].
    fn try_reserve_exact(&mut self, additional: usize) -> Result<(), AllocError>;
    /// See [`Vec::resize`].
    fn try_resize(&mut self, new_len: usize, value: u8) -> Result<(), AllocError>;
    /// See [`Zeroize`].
    fn zeroize(&mut self) {
        self[..].zeroize();
    }
}

#[cfg(all(any(test, feature = "alloc"), feature = "allocator_api"))]
impl<A: Allocator> Buf for Vec<u8, A> {
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn split_at_mut(&mut self, mid: usize) -> (&mut [u8], &mut [u8]) {
        self[..].split_at_mut(mid)
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len);
    }

    fn try_reserve_exact(&mut self, additional: usize) -> Result<(), AllocError> {
        Ok(Vec::try_reserve_exact(self, additional)?)
    }

    fn try_resize(&mut self, new_len: usize, value: u8) -> Result<(), AllocError> {
        Vec::resize(self, new_len, value);
        Ok(())
    }
}

#[cfg(all(any(test, feature = "alloc"), not(feature = "allocator_api")))]
impl Buf for Vec<u8> {
    fn len(&self) -> usize {
        Self::len(self)
    }

    fn split_at_mut(&mut self, mid: usize) -> (&mut [u8], &mut [u8]) {
        self[..].split_at_mut(mid)
    }

    fn truncate(&mut self, len: usize) {
        Self::truncate(self, len);
    }

    fn try_reserve_exact(&mut self, additional: usize) -> Result<(), AllocError> {
        Ok(Self::try_reserve_exact(self, additional)?)
    }

    fn try_resize(&mut self, new_len: usize, value: u8) -> Result<(), AllocError> {
        Self::resize(self, new_len, value);
        Ok(())
    }
}

impl<const N: usize> Buf for heapless::Vec<u8, N> {
    fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn split_at_mut(&mut self, mid: usize) -> (&mut [u8], &mut [u8]) {
        self[..].split_at_mut(mid)
    }

    fn truncate(&mut self, len: usize) {
        Self::truncate(self, len);
    }

    fn try_reserve_exact(&mut self, additional: usize) -> Result<(), AllocError> {
        #[allow(clippy::arithmetic_side_effects, reason = "len <= cap")]
        let avail = N - self.len();
        if avail < additional {
            Err(AllocError::new())
        } else {
            Ok(())
        }
    }

    fn try_resize(&mut self, new_len: usize, value: u8) -> Result<(), AllocError> {
        match Self::resize(self, new_len, value) {
            Ok(()) => Ok(()),
            Err(()) => Err(AllocError::new()),
        }
    }
}

/// A fixed-size buffer.
///
/// It supports allocations, but only up to some pre-defined
/// capacity.
pub struct FixedBuf<'a> {
    data: &'a mut [u8],
    // Used bytes.
    len: usize,
}

impl<'a> FixedBuf<'a> {
    /// Create a [`FixedBuf`] with the data in `data[..len]` and
    /// growable capacity in `data[len..]`.
    ///
    /// Returns `None` if `len > data.len()`.
    pub fn from_slice_mut(data: &'a mut [u8], len: usize) -> Option<Self> {
        if len <= data.len() {
            Some(Self { data, len })
        } else {
            None
        }
    }

    fn capacity(&self) -> usize {
        self.data.len()
    }
}

impl AsRef<[u8]> for FixedBuf<'_> {
    fn as_ref(&self) -> &[u8] {
        #[allow(clippy::indexing_slicing)] // no alternative
        &self.data[..self.len]
    }
}

impl AsMut<[u8]> for FixedBuf<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        #[allow(clippy::indexing_slicing)] // no alternative
        &mut self.data[..self.len]
    }
}

impl Deref for FixedBuf<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl DerefMut for FixedBuf<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

impl Buf for FixedBuf<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn split_at_mut(&mut self, mid: usize) -> (&mut [u8], &mut [u8]) {
        self.as_mut().split_at_mut(mid)
    }

    fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    fn try_reserve_exact(&mut self, additional: usize) -> Result<(), AllocError> {
        #[allow(clippy::arithmetic_side_effects, reason = "len <= cap")]
        let avail = self.capacity() - self.len;
        if avail < additional {
            Err(AllocError::new())
        } else {
            Ok(())
        }
    }

    fn try_resize(&mut self, new_len: usize, value: u8) -> Result<(), AllocError> {
        let old_len = self.len;
        if let Some(diff) = new_len.checked_sub(old_len) {
            Self::try_reserve_exact(self, diff)?;
            self.data
                .get_mut(old_len..new_len)
                .assume("should have enough capacity")?
                .fill(value);
            self.len = new_len;
        } else {
            Self::truncate(self, new_len);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_112() {
        const N: usize = 45;
        let mut backing = [0u8; 50];
        let len = backing.len();
        let mut buf =
            FixedBuf::from_slice_mut(&mut backing, len - N).expect("len-N should be < len");
        buf.try_resize(N, 0).expect("try_resize expect");
        assert_eq!(buf.len(), N);
    }
}
