//! Securely zero memory.

// The following code is taken from
// https://github.com/RustCrypto/utils/tree/6ad2abf2b41feef6f8adf9fdaee5fb9c9b1e3849/zeroize
// with the addition of `Borrow` and `BorrowMut`.
//
// TODO(eric): get rid of this? I don't think we need the Borrow
// impls anymore.

#![forbid(unsafe_code)]

use core::{
    borrow::{Borrow, BorrowMut},
    ops::{Deref, DerefMut},
};

use generic_array::{ArrayLength, GenericArray};
pub use zeroize::{Zeroize, ZeroizeOnDrop};

/// Zeroizing is a a wrapper for any `Z: Zeroize` type which
/// implements a `Drop` handler which zeroizes dropped values.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Zeroizing<Z: Zeroize>(Z);

impl<Z> Zeroizing<Z>
where
    Z: Zeroize,
{
    /// Move value inside a `Zeroizing` wrapper which ensures it
    /// will be zeroized when it's dropped.
    #[inline(always)]
    pub fn new(value: Z) -> Self {
        Self(value)
    }
}

impl<Z> Borrow<[u8]> for Zeroizing<Z>
where
    Z: Borrow<[u8]> + Zeroize,
{
    #[inline(always)]
    fn borrow(&self) -> &[u8] {
        self.0.borrow()
    }
}

impl<Z> BorrowMut<[u8]> for Zeroizing<Z>
where
    Z: BorrowMut<[u8]> + Zeroize,
{
    #[inline(always)]
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.0.borrow_mut()
    }
}

impl<const N: usize, Z> Borrow<[u8; N]> for Zeroizing<Z>
where
    Z: Borrow<[u8; N]> + Zeroize,
{
    #[inline(always)]
    fn borrow(&self) -> &[u8; N] {
        self.0.borrow()
    }
}

impl<const N: usize, Z> BorrowMut<[u8; N]> for Zeroizing<Z>
where
    Z: BorrowMut<[u8; N]> + Zeroize,
{
    #[inline(always)]
    fn borrow_mut(&mut self) -> &mut [u8; N] {
        self.0.borrow_mut()
    }
}

impl<N: ArrayLength> Borrow<GenericArray<u8, N>> for Zeroizing<GenericArray<u8, N>> {
    #[inline]
    fn borrow(&self) -> &GenericArray<u8, N> {
        &self.0
    }
}

impl<N: ArrayLength> BorrowMut<GenericArray<u8, N>> for Zeroizing<GenericArray<u8, N>> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut GenericArray<u8, N> {
        &mut self.0
    }
}

impl<Z: Zeroize + Clone> Clone for Zeroizing<Z> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }

    #[inline(always)]
    fn clone_from(&mut self, source: &Self) {
        self.0.zeroize();
        self.0.clone_from(&source.0);
    }
}

impl<Z> From<Z> for Zeroizing<Z>
where
    Z: Zeroize,
{
    #[inline(always)]
    fn from(value: Z) -> Zeroizing<Z> {
        Zeroizing(value)
    }
}

impl<Z> Deref for Zeroizing<Z>
where
    Z: Zeroize,
{
    type Target = Z;

    #[inline(always)]
    fn deref(&self) -> &Z {
        &self.0
    }
}

impl<Z> DerefMut for Zeroizing<Z>
where
    Z: Zeroize,
{
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Z {
        &mut self.0
    }
}

impl<T, Z> AsRef<T> for Zeroizing<Z>
where
    T: ?Sized,
    Z: AsRef<T> + Zeroize,
{
    #[inline(always)]
    fn as_ref(&self) -> &T {
        self.0.as_ref()
    }
}

impl<T, Z> AsMut<T> for Zeroizing<Z>
where
    T: ?Sized,
    Z: AsMut<T> + Zeroize,
{
    #[inline(always)]
    fn as_mut(&mut self) -> &mut T {
        self.0.as_mut()
    }
}

impl<Z> Zeroize for Zeroizing<Z>
where
    Z: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<Z> ZeroizeOnDrop for Zeroizing<Z> where Z: Zeroize {}

impl<Z> Drop for Zeroizing<Z>
where
    Z: Zeroize,
{
    fn drop(&mut self) {
        self.0.zeroize()
    }
}
