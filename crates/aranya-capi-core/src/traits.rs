use core::mem::MaybeUninit;

use super::safe::{OwnedPtr, Safe, Typed};

/// The builder pattern, as a trait.
pub trait Builder {
    /// The output type.
    type Output;
    /// The error returned by `build`.
    type Error;

    /// Builds the output type.
    ///
    /// # Safety
    /// Implementations may have certain safety requirements.
    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error>;
}

impl<T> Builder for OwnedPtr<T>
where
    T: Builder,
{
    type Output = T::Output;
    type Error = T::Error;

    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        unsafe { self.read().build(out) }
    }
}

impl<T> Builder for Safe<T>
where
    T: Builder + Typed,
{
    type Output = T::Output;
    type Error = T::Error;

    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        unsafe { self.into_inner().build(out) }
    }
}

/// Like [`Default`], but  writes to [`MaybeUninit`].
pub trait InitDefault: Sized {
    /// Initializes `out`.
    fn init_default(out: &mut MaybeUninit<Self>);
}

impl<T: Default> InitDefault for T {
    fn init_default(out: &mut MaybeUninit<Self>) {
        out.write(Self::default());
    }
}
