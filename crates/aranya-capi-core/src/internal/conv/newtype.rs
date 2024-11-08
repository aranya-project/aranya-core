//! "newtype" conversions.
//!
//! `capi-codegen` generates `#[repr(transparent)]` newtype
//! structs for each type alias and struct it encounters. It then
//! implements [`NewType`] for each of those newtype structs.

use core::{
    mem::{ManuallyDrop, MaybeUninit},
    pin::Pin,
};

/// A marker trait that signals that the type is (or points to)
/// a `#[repr(transparent)]` "newtype" wrapper.
///
/// # Safety
///
/// - `Self` must be a `#[repr(transparent)]` wrapper for
///   `Inner`.
/// - It uphold all the same invariants as
///   [`Alias`][super::alias::Alias].
pub unsafe trait NewType: Sized {
    /// The inner (underlying) type.
    type Inner: Sized;
}

// SAFETY: `T` is `NewType`.
unsafe impl<'a, T: NewType> NewType for &'a T {
    type Inner = &'a T::Inner;
}

// SAFETY: `T` is `NewType`.
unsafe impl<'a, T: NewType> NewType for &'a mut T {
    type Inner = &'a mut T::Inner;
}

// SAFETY: `T` is `NewType`.
unsafe impl<T: NewType> NewType for *const T {
    type Inner = *const T::Inner;
}

// SAFETY: `T` is `NewType`.
unsafe impl<T: NewType> NewType for *mut T {
    type Inner = *mut T::Inner;
}

// SAFETY: `MaybeUninit<T>` has the same memory layout as `T`.
unsafe impl<T: NewType> NewType for MaybeUninit<T> {
    type Inner = MaybeUninit<T::Inner>;
}

// SAFETY: `ManuallyDrop<T>` has the same memory layout as `T`.
unsafe impl<T: NewType> NewType for ManuallyDrop<T> {
    type Inner = ManuallyDrop<T::Inner>;
}

// SAFETY: `Pin<T>` has the same memory layout as `T`.
unsafe impl<T: NewType> NewType for Pin<T> {
    type Inner = Pin<T::Inner>;
}
