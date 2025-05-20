use core::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

use crate::{
    safe::{Safe, Typed},
    Builder, InitDefault,
};

mod imp {
    use core::mem::ManuallyDrop;

    #[repr(C)]
    pub(super) union OpaqueRepr<const SIZE: usize, const ALIGN: usize, T>
    where
        elain::Align<ALIGN>: elain::Alignment,
    {
        // Invariant: always the `inner` variant.
        // Invariant: only dropped in the drop impl.
        inner: ManuallyDrop<T>,
        __backing_for_size_align_only: Backing<SIZE, ALIGN>,
    }

    impl<const SIZE: usize, const ALIGN: usize, T> OpaqueRepr<SIZE, ALIGN, T>
    where
        elain::Align<ALIGN>: elain::Alignment,
    {
        pub fn into_inner(mut self) -> T {
            // SAFETY: always `inner`` variant
            let inner = unsafe { &mut self.inner };
            // SAFETY: consuming self
            unsafe { ManuallyDrop::take(inner) }
        }

        pub fn as_ref(&self) -> &T {
            // SAFETY: always the `inner` variant.
            unsafe { &self.inner }
        }

        pub fn as_mut(&mut self) -> &mut T {
            // SAFETY: always the `inner` variant.
            unsafe { &mut self.inner }
        }
    }

    impl<const SIZE: usize, const ALIGN: usize, T> Drop for OpaqueRepr<SIZE, ALIGN, T>
    where
        elain::Align<ALIGN>: elain::Alignment,
    {
        fn drop(&mut self) {
            // SAFETY: always the `inner` variant.
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
}

/// Opaque is a wrapper which ensures a minimum size and alignment.
///
/// This is used by the `opaque` macro so the rust and C types will have the same size.
///
/// It is expected that `SIZE >= size_of::<T>()` and `ALIGN >= align_of::<T>()`. However, if
/// that is not true, all the operations below are still safe since the repr always contains a `T`.
#[repr(C)]
pub struct Opaque<const SIZE: usize, const ALIGN: usize, T>(imp::OpaqueRepr<SIZE, ALIGN, T>)
where
    elain::Align<ALIGN>: elain::Alignment;

impl<const SIZE: usize, const ALIGN: usize, T> Opaque<SIZE, ALIGN, T>
where
    elain::Align<ALIGN>: elain::Alignment,
{
    fn into_inner(self) -> T {
        self.0.into_inner()
    }
}

impl<const SIZE: usize, const ALIGN: usize, T> Opaque<SIZE, ALIGN, Safe<T>>
where
    T: Typed,
    elain::Align<ALIGN>: elain::Alignment,
{
    pub fn init(out: &mut MaybeUninit<Self>, v: T) {
        Safe::init(downcast_maybe_uninit(out), v);
    }
}

impl<const SIZE: usize, const ALIGN: usize, T> Deref for Opaque<SIZE, ALIGN, T>
where
    elain::Align<ALIGN>: elain::Alignment,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<const SIZE: usize, const ALIGN: usize, T> DerefMut for Opaque<SIZE, ALIGN, T>
where
    elain::Align<ALIGN>: elain::Alignment,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}

impl<const SIZE: usize, const ALIGN: usize, T> Builder for Opaque<SIZE, ALIGN, T>
where
    T: Builder,
    elain::Align<ALIGN>: elain::Alignment,
{
    type Output = T::Output;
    type Error = T::Error;

    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        let inner = self.into_inner();
        // SAFETY: just forwarding requirements.
        unsafe { inner.build(out) }
    }
}

impl<const SIZE: usize, const ALIGN: usize, T> InitDefault for Opaque<SIZE, ALIGN, T>
where
    T: InitDefault,
    elain::Align<ALIGN>: elain::Alignment,
{
    fn init_default(out: &mut MaybeUninit<Self>) {
        T::init_default(downcast_maybe_uninit(out));
    }
}

fn downcast_maybe_uninit<const SIZE: usize, const ALIGN: usize, T>(
    out: &mut MaybeUninit<Opaque<SIZE, ALIGN, T>>,
) -> &mut MaybeUninit<T>
where
    elain::Align<ALIGN>: elain::Alignment,
{
    // SAFETY: `*Opaque<_, _, T>` is a valid `*T`
    unsafe {
        core::mem::transmute::<&mut MaybeUninit<Opaque<SIZE, ALIGN, T>>, &mut MaybeUninit<T>>(out)
    }
}
