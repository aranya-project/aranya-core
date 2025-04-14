use core::{
    ffi::c_void,
    mem::{ManuallyDrop, MaybeUninit},
    pin::Pin,
};

use crate::safe::{CStr, OwnedPtr, Safe, Typed};

macro_rules! impl_with_meta {
    (
        $(#[$meta:meta])+
        unsafe impl $trait:ident for $name:ty {}
        $($tail:tt)*
    ) => {
        $(#[$meta])+
        unsafe impl $trait for $name {}

        impl_with_meta! {
            $(#[$meta])+ $($tail)*
        }
    };
    ($(#[$meta:meta])+) => {};
    () => {};
}

macro_rules! impl_trait {
    (
        $(#[$meta:meta])+
        $trait:ident for $($name:ty),+ $(,)?
    ) => {
        impl_with_meta! {
            $(#[$meta])+
            $(
                unsafe impl $trait for $name {}
            )+
        }
    };
}

/// A marker trait for FFI safe input types.
///
/// The type must also implement at least one of:
///
/// - [`ByValue`]
/// - [`ByConstPtr`]
/// - [`ByMutPtr`]
///
/// # Safety
///
/// The type must be FFI safe.
#[diagnostic::on_unimplemented(message = "`capi::types::Input` is not implemented for `{Self}`")]
pub unsafe trait Input: Sized {}

impl_trait! {
    /// SAFETY: Scalar types where every bit pattern is valid are
    /// FFI safe.
    Input for
    u8, u16, u32, u64, usize,
    i8, i16, i32, i64, isize,
    f32, f64,
}

unsafe impl Input for c_void {}

unsafe impl<T: Input + ByConstPtr> Input for *const T {}
unsafe impl<T: Input + ByMutPtr> Input for *mut T {}

unsafe impl<T: Input + ByMutPtr> Input for OwnedPtr<T> {}
unsafe impl<T: Input> Input for ManuallyDrop<T> {}
unsafe impl<T: Input> Input for Pin<T> {}

// `MaybeUninit` doesn't need a `T: Input` bound because it by
// definition is potentially uninitialized.
unsafe impl<T> Input for MaybeUninit<T> {}

// `Safe` doesn't need a `T: Input` bound because `Safe` tracks
// initialization.
unsafe impl<T: Typed> Input for Safe<T> {}

// TODO(eric): This is an incorrect hack for C fn pointers. Fix
// this.
unsafe impl<T> Input for Option<T> {}

unsafe impl<T: Input, const N: usize> Input for [T; N] {}

/// A marker trait for FFI safe result types.
///
/// # Safety
///
/// The type must be FFI safe.
#[diagnostic::on_unimplemented(message = "`capi::types::Output` is not implemented for `{Self}`")]
pub unsafe trait Output: Sized {}

impl_trait! {
    /// SAFETY: The type is a scalar. Since it is an output type,
    /// its bit pattern is irrelevant.
    Output for
    bool, char, (),
}

// SAFETY: `T: ByValue`, so `T` is FFI safe.
unsafe impl<T: ByValue> Output for T {}

// Wrapper type
unsafe impl<T: Output, E> Output for Result<T, E> {}

/// A marker trait for FFI types that can be passed by value
/// (i.e., copied).
///
/// # Safety
///
/// The type must be FFI safe.
pub unsafe trait ByValue: Sized {}

impl_trait! {
    /// SAFETY: Scalar types where every bit pattern is valid are
    /// FFI safe.
    ByValue for
    u8, u16, u32, u64, usize,
    i8, i16, i32, i64, isize,
    f32, f64,
}

// Pointers can be passed by value.
unsafe impl ByValue for CStr {}
unsafe impl<T: ByConstPtr> ByValue for *const T {}
unsafe impl<T: ByMutPtr> ByValue for *mut T {}
unsafe impl<T: ByMutPtr> ByValue for OwnedPtr<T> {}

// Wrapper types recognized by `cbindgen`.
unsafe impl<T: ByValue> ByValue for ManuallyDrop<T> {}
unsafe impl<T: ByValue> ByValue for Pin<T> {}
// NB: `MaybeUninit` is not implemented since passing uninit
// memory by value is ~useless.

/// A marker trait for FFI types that can be passed by `*const`.
///
/// # Safety
///
/// The type must be FFI safe.
pub unsafe trait ByConstPtr {}

impl_trait! {
    /// SAFETY: Scalar types where every bit pattern is valid are
    /// FFI safe.
    ByConstPtr for
    u8, u16, u32, u64, usize,
    i8, i16, i32, i64, isize,
    f32, f64,
    c_void,
}

unsafe impl<T: ByConstPtr> ByConstPtr for *const T {}
unsafe impl<T: ByConstPtr> ByMutPtr for *const T {}

unsafe impl<T: ByConstPtr, const N: usize> ByConstPtr for [T; N] {}

// Wrapper types.
unsafe impl<T: Typed> ByConstPtr for Safe<T> {}
unsafe impl<T: ByConstPtr> ByConstPtr for ManuallyDrop<T> {}
unsafe impl<T: ByConstPtr> ByConstPtr for Pin<T> {}
// NB: `MaybeUninit` is not implemented since passing uninit
// memory by `*const` is ~useless.

/// A marker trait for FFI types that can be passed by `*mut` or
/// `OwnedPtr<T>`.
///
/// # Safety
///
/// The type must be FFI safe.
pub unsafe trait ByMutPtr {}

impl_trait! {
    /// SAFETY: Scalar types where every bit pattern is valid are
    /// FFI safe.
    ByMutPtr for
    u8, u16, u32, u64, usize,
    i8, i16, i32, i64, isize,
    f32, f64,
    c_void,
}

unsafe impl<T: ByMutPtr> ByMutPtr for *mut T {}

unsafe impl<T: ByMutPtr, const N: usize> ByMutPtr for [T; N] {}

// Wrapper types.
unsafe impl<T: Typed> ByMutPtr for Safe<T> {}
unsafe impl<T: ByMutPtr> ByMutPtr for ManuallyDrop<T> {}
unsafe impl<T: ByMutPtr> ByMutPtr for MaybeUninit<T> {}
unsafe impl ByMutPtr for MaybeUninit<bool> {}
unsafe impl<T: ByMutPtr> ByMutPtr for Pin<T> {}

// TODO(eric): This is an incorrect hack for C fn pointers. Fix
// this.
unsafe impl<T> ByMutPtr for Option<T> {}

/// Used by `capi-codegen`.
// TODO(eric): move into `internal`?
#[doc(hidden)]
pub const fn check_valid_input_ty<T: Input>(v: T) -> T {
    v
}

/// Also used by `capi-codegen`.
// TODO(eric): move into `internal`?
#[doc(hidden)]
pub const fn const_assert_valid_input_ty<T: Input>() {}

#[cfg(test)]
mod tests {
    use core::ffi::{
        c_char, c_double, c_float, c_int, c_long, c_longlong, c_schar, c_short, c_uchar, c_uint,
        c_ulong, c_ulonglong, c_ushort,
    };

    use super::*;
    use crate::safe::TypeId;

    #[test]
    fn test_assertions() {
        #[derive(Copy, Clone)]
        #[allow(dead_code)] // used in constant assertions
        struct Dummy;
        impl Typed for Dummy {
            const TYPE_ID: TypeId = TypeId::new(0);
        }
        unsafe impl Input for Dummy {}
        unsafe impl ByConstPtr for Dummy {}
        unsafe impl ByMutPtr for Dummy {}
        unsafe impl ByValue for Dummy {}

        macro_rules! const_assert_valid_input_ty {
            ($($type:ty),+ $(,)?) => {
                $(
                    const _: () = const_assert_valid_input_ty::<$type>();
                )+
            };
        }

        const_assert_valid_input_ty! {
            u8, u16, u32, u64, usize,
            i8, i16, i32, i64, isize,
            f32, f64,

            c_char, c_schar, c_short, c_int, c_long, c_longlong,
            c_uchar, c_ushort, c_uint, c_ulong, c_ulonglong,
            c_double, c_float,

            *const u8, *const u16, *const u32, *const u64, *const usize,
            *const i8, *const i16, *const i32, *const i64, *const isize,
            *const f32, *const f64,
            *const c_char, *const c_schar, *const c_short, *const c_int, *const c_long, *const c_longlong,
            *const c_uchar, *const c_ushort, *const c_uint, *const c_ulong, *const c_ulonglong,
            *const c_double, *const c_float,
            *const c_void,

            *mut u8, *mut u16, *mut u32, *mut u64, *mut usize,
            *mut i8, *mut i16, *mut i32, *mut i64, *mut isize,
            *mut f32, *mut f64,
            *mut c_char, *mut c_schar, *mut c_short, *mut c_int, *mut c_long, *mut c_longlong,
            *mut c_uchar, *mut c_ushort, *mut c_uint, *mut c_ulong, *mut c_ulonglong,
            *mut c_double, *mut c_float,
            *mut c_void,

            *const Pin<u64>,
            *mut Pin<u64>,

            *const ManuallyDrop<u64>,
            *mut ManuallyDrop<u64>,

            *mut MaybeUninit<u64>,
            *mut MaybeUninit<Safe<Dummy>>,

            *mut Safe<Dummy>,
            *const Safe<Dummy>,

            OwnedPtr<u64>,
            OwnedPtr<Safe<Dummy>>,
        }
    }
}
