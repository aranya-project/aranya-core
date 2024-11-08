//! Type alias conversions.

use core::{
    marker::PhantomData,
    mem::{self, needs_drop, ManuallyDrop, MaybeUninit},
};

/// A marker trait that signals that the type is bit-for-bit
/// identical to `T`.
///
/// # Safety
///
/// - `Self` and `T` must have the same size.
/// - `Self` and `T` must have the same alignment.
/// - If `Self` is `Drop` then so must `T` and vice versa.
/// - All attributes that affect the type's memory layout (e.g.,
///   `#[repr(...)]`) must be identical.
/// - You must uphold any lifetimes.
pub unsafe trait Alias<T: Sized>: Sized {}

/// Reflexively implements [`Alias`] for a type.
#[macro_export]
#[doc(hidden)]
macro_rules! alias {
    ($($ty:ty),* $(,)?) => {
        $(
            // SAFETY: `T` is obviously bit-for-bit identical to
            // `T`.
            unsafe impl Alias<$ty> for $ty {}
        )*
    };
}

alias! {
    (),
    bool,
    u8, u16, u32, u64, u128, usize,
    i8, i16, i32, i64, i128, isize,
    f32, f64,
}

// SAFETY: `T: Alias<U>`, so the alias is sound.
unsafe impl<T, U> Alias<&U> for &T
where
    T: Alias<U>,
    U: Sized,
{
}

// SAFETY: `T: Alias<U>`, so the alias is sound.
unsafe impl<T, U> Alias<*const U> for *const T
where
    T: Alias<U>,
    U: Sized,
{
}

// SAFETY: `T: Alias<U>`, so the alias is sound.
unsafe impl<T, U> Alias<*mut U> for *mut T
where
    T: Alias<U>,
    U: Sized,
{
}

// SAFETY: `T: Alias<U>`, so the alias is sound.
unsafe impl<T, U> Alias<&[U]> for &[T]
where
    T: Alias<U>,
    U: Sized,
{
}

// SAFETY: `T: Alias<U>`, so the alias is sound.
unsafe impl<T, U> Alias<&mut [U]> for &mut [T]
where
    T: Alias<U>,
    U: Sized,
{
}

// SAFETY: `T: Alias<U>`, so the alias is sound.
unsafe impl<T, U, const N: usize> Alias<[U; N]> for [T; N]
where
    T: Alias<U>,
    U: Sized,
{
}

// SAFETY: `T: Alias<U>`, so the alias is sound.
unsafe impl<T, U> Alias<MaybeUninit<U>> for MaybeUninit<T>
where
    T: Alias<U>,
    U: Sized,
{
}

// SAFETY: `T: Alias<U>`, so the alias is sound.
unsafe impl<T, U> Alias<PhantomData<U>> for PhantomData<T>
where
    T: Alias<U>,
    U: Sized,
{
}

/// Casts `T` to `U`.
pub fn cast<T, U>(t: T) -> U
where
    T: Alias<U>,
    U: Sized,
{
    const {
        assert!(size_of::<T>() == size_of::<U>());
        assert!(align_of::<T>() == align_of::<U>());
        assert!(needs_drop::<T>() == needs_drop::<U>());
    }
    // SAFETY: `T: Alias<U>`, so the trait implementor ensures
    // this is sound.
    unsafe { mem::transmute_copy(&ManuallyDrop::new(t)) }
}

/// Casts `&T` to `&U`.
pub const fn cast_ref<T, U>(t: &T) -> &U
where
    T: Alias<U>,
    U: Sized,
{
    const {
        assert!(size_of::<T>() == size_of::<U>());
        assert!(align_of::<T>() == align_of::<U>());
        assert!(needs_drop::<T>() == needs_drop::<U>());
    }
    // SAFETY: `T: Alias<U>`, so the trait implementor ensures
    // this is sound. `t` is a ref, so the pointer is never null
    // or unaligned.
    unsafe { &*(t as *const T as *const U) }
}

/// Casts `&mut T` to `&mut U`.
pub fn cast_mut<T, U>(t: &mut T) -> &mut U
where
    T: Alias<U>,
    U: Sized,
{
    const {
        assert!(size_of::<T>() == size_of::<U>());
        assert!(align_of::<T>() == align_of::<U>());
        assert!(needs_drop::<T>() == needs_drop::<U>());
    }
    // SAFETY: `T: Alias<U>`, so the trait implementor ensures
    // this is sound. `t` is an exclusive ref, so the pointer is
    // never null or unaligned.
    unsafe { &mut *(t as *mut T as *mut U) }
}

/// Casts `*const T` to `*const U`.
pub const fn cast_ptr<T, U>(t: *const T) -> *const U
where
    T: Alias<U>,
    U: Sized,
{
    const {
        assert!(size_of::<T>() == size_of::<U>());
        assert!(align_of::<T>() == align_of::<U>());
        assert!(needs_drop::<T>() == needs_drop::<U>());
    }
    t as *const U
}

/// Converts `*mut T` to `*mut U`.
pub const fn cast_mut_ptr<T, U>(t: *mut T) -> *mut U
where
    T: Alias<U>,
    U: Sized,
{
    const {
        assert!(size_of::<T>() == size_of::<U>());
        assert!(align_of::<T>() == align_of::<U>());
        assert!(needs_drop::<T>() == needs_drop::<U>());
    }
    t as *mut U
}

/// Converts `&[T]` to `&[U]`.
pub const fn cast_slice<T, U>(t: &[T]) -> &[U]
where
    T: Alias<U>,
    U: Sized,
{
    const {
        assert!(size_of::<T>() == size_of::<U>());
        assert!(align_of::<T>() == align_of::<U>());
        assert!(needs_drop::<T>() == needs_drop::<U>());
    }
    // SAFETY: `T: Alias<U>`, so the trait implementor ensures
    // this is sound.
    unsafe { &*(t as *const [T] as *const [U]) }
}

/// Converts `&mut [T]` to `&mut [U]`.
pub fn cast_slice_mut<T, U>(t: &mut [T]) -> &mut [U]
where
    T: Alias<U>,
    U: Sized,
{
    const {
        assert!(size_of::<T>() == size_of::<U>());
        assert!(align_of::<T>() == align_of::<U>());
        assert!(needs_drop::<T>() == needs_drop::<U>());
    }
    // SAFETY: `T: Alias<U>`, so the trait implementor ensures
    // this is sound.
    unsafe { &mut *(t as *mut [T] as *mut [U]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        #[derive(Copy, Clone)]
        struct A;
        alias!(A);

        #[derive(Copy, Clone)]
        struct B;
        alias!(B);
        unsafe impl Alias<A> for B {}

        #[derive(Copy, Clone)]
        struct C;
        alias!(C);
        unsafe impl Alias<B> for C {}

        let a: A = A;
        let _: &A = cast_ref(&a);
        let b: B = B;
        let _: &B = cast_ref(&b);
        let _: &A = cast_ref(&b);
        let c: C = C;
        let _: &C = cast_ref(&c);
        let _: &B = cast_ref(&c);
        let _: &A = cast_ref(cast_ref::<_, B>(&c));
    }

    #[test]
    fn test_slice() {
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        struct A(#[allow(dead_code)] u64);

        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        #[repr(transparent)]
        struct B(A);

        unsafe impl Alias<A> for B {}

        impl PartialEq<A> for B {
            fn eq(&self, other: &A) -> bool {
                self.0 == *other
            }
        }

        let got: &[B] = &[B(A(1)), B(A(2)), B(A(3))];
        let want: &[A] = cast_slice(got);
        assert_eq!(got, want);
    }
}
