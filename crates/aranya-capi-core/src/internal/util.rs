use core::{fmt, mem::MaybeUninit, ptr};

use super::conv::newtype::NewType;
use crate::{
    Builder,
    safe::OwnedPtr,
    types::{ByConstPtr, ByMutPtr, ByValue, Input, Opaque, Output},
};

#[doc(hidden)]
#[macro_export]
macro_rules! fmt_fn_ptr {
    ($f:expr) => {{
        match &$f {
            ::core::option::Option::Some(f) => $crate::internal::util::Ptr(*f as usize),
            ::core::option::Option::None => $crate::internal::util::Ptr(0),
        }
    }};
}

/// Implements `fmt::Display` for an address.
pub struct Addr(pub usize);

impl Addr {
    /// Creates an [`Addr`] from a shared ref.
    pub fn from_ref<T: ?Sized>(r: &T) -> Self {
        Self::from_ptr(ptr::from_ref(r))
    }

    /// Creates an [`Addr`] from an exclusive ref.
    pub fn from_mut<T: ?Sized>(r: &mut T) -> Self {
        Self::from_ptr(ptr::from_mut(r).cast_const())
    }

    /// Creates an [`Addr`] from a pointer.
    pub fn from_ptr<T: ?Sized>(ptr: *const T) -> Self {
        Self(ptr.cast::<()>() as usize)
    }

    /// Creates an [`Addr`] from an [`OwnedPtr`].
    pub fn from_owned_ptr<T>(ptr: &OwnedPtr<T>) -> Self {
        Self(ptr.addr())
    }

    /// Creates an [`Addr`] from an optional [`OwnedPtr`].
    pub fn from_opt_owned_ptr<T>(ptr: &Option<OwnedPtr<T>>) -> Self {
        match ptr {
            Some(ptr) => Self::from_ptr(ptr),
            None => Self(0),
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#0x}", self.0)
    }
}

/// Asserts that `T` is `Copy`.
pub const fn const_assert_is_copy<T: Copy>() {}

/// Checks that `T` is `Input` and `ByValue`.
pub const fn check_valid_input_ty_val<T: Input + ByValue>(v: T) -> T {
    v
}

/// Checks that `T` is `Input` and `ByConstPtr`.
pub const fn check_valid_input_ty_const_ptr<T: Input + ByConstPtr>(v: *const T) -> *const T {
    v
}

/// Checks that `T` is `Input` and `ByMutPtr`.
pub const fn check_valid_input_ty_mut_ptr<T: Input + ByMutPtr>(v: *mut T) -> *mut T {
    v
}

/// Checks that `T` is `Output`.
pub const fn check_valid_output_ty<T: Output>(v: T) -> T {
    v
}

/// TODO
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct Wrapper<T>(pub T);

unsafe impl<T: NewType> NewType for Wrapper<T> {
    type Inner = <T as NewType>::Inner;
}

impl<T: Builder> Builder for Wrapper<T> {
    type Output = <T as Builder>::Output;
    type Error = <T as Builder>::Error;

    unsafe fn build(self, out: &mut MaybeUninit<Self::Output>) -> Result<(), Self::Error> {
        unsafe { self.0.build(out) }
    }
}

impl<T: Opaque> Opaque for Wrapper<T> {}
unsafe impl<T: Input> Input for Wrapper<T> {}
unsafe impl<T: ByValue> ByValue for Wrapper<T> {}
