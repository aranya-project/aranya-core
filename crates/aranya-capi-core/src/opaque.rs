use std::{
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
};

#[repr(C)]
pub struct Opaque<const SIZE: usize, const ALIGN: usize, T>(OpaqueRepr<SIZE, ALIGN, T>)
where
    elain::Align<ALIGN>: elain::Alignment;

impl<const SIZE: usize, const ALIGN: usize, T> Deref for Opaque<SIZE, ALIGN, T>
where
    elain::Align<ALIGN>: elain::Alignment,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        const { assert!(SIZE >= size_of::<T>()) };
        const { assert!(ALIGN >= align_of::<T>()) };

        // SAFETY: `OpaqueRepr` is always the `inner` variant.
        unsafe { &self.0.inner }
    }
}

impl<const SIZE: usize, const ALIGN: usize, T> DerefMut for Opaque<SIZE, ALIGN, T>
where
    elain::Align<ALIGN>: elain::Alignment,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        const { assert!(SIZE >= size_of::<T>()) };
        const { assert!(ALIGN >= align_of::<T>()) };

        // SAFETY: `OpaqueRepr` is always the `inner` variant.
        unsafe { &mut self.0.inner }
    }
}

#[repr(C)]
union OpaqueRepr<const SIZE: usize, const ALIGN: usize, T>
where
    elain::Align<ALIGN>: elain::Alignment,
{
    inner: ManuallyDrop<T>,
    __backing_for_size_align_only: Backing<SIZE, ALIGN>,
}

impl<const SIZE: usize, const ALIGN: usize, T> Drop for OpaqueRepr<SIZE, ALIGN, T>
where
    elain::Align<ALIGN>: elain::Alignment,
{
    fn drop(&mut self) {
        // SAFETY: `OpaqueRepr` is always the `inner` variant.
        // Forwarding the drop impl is safe.
        unsafe {
            ManuallyDrop::drop(&mut self.inner);
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Backing<const SIZE: usize, const ALIGN: usize>
where
    elain::Align<ALIGN>: elain::Alignment,
{
    size: [u8; SIZE],
    align: elain::Align<ALIGN>,
    // `Backing` should never be constructed.
    never: core::convert::Infallible,
}
