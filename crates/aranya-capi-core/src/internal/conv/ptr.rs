//! Pointer conversions.

use core::{ffi::c_char, mem::MaybeUninit};

use crate::safe::{CStr, Error, InvalidPtr, OwnedPtr, Safe, Typed, Valid};

/// Checks the type of `ptr`.
pub const fn const_assert_is_const_ptr<T>(ptr: *const T) -> *const T {
    ptr
}

/// Checks the type of `ptr`.
pub const fn const_assert_is_mut_ptr<T>(ptr: *mut T) -> *mut T {
    ptr
}

// Autoderef specialization for some generic `T`.
#[doc(hidden)]
pub struct DefaultTag;
#[doc(hidden)]
pub trait DefaultKind {
    #[inline(always)]
    fn kind(&self) -> DefaultTag {
        DefaultTag
    }
}
impl<T> DefaultKind for &&*mut T {}
impl<T> DefaultKind for &&*const T {}
impl DefaultTag {
    /// The identity function.
    pub fn try_from_repr<T>(self, repr: T) -> Option<T> {
        Some(repr)
    }

    /// Returns a shared reference from `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be initialized.
    /// - You must enforce Rust's aliasing rules.
    pub unsafe fn try_from_ptr<'a, T>(self, ptr: *const T) -> Result<&'a T, InvalidPtr> {
        Valid::new(ptr.cast_mut()).map(|ptr| {
            // SAFETY: `Valid`s are always non-null and properly
            // aligned. Also, see the macro's safety docs.
            unsafe { ptr.as_ref() }
        })
    }

    /// Returns an exclusive reference from `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be initialized.
    /// - You must enforce Rust's aliasing rules.
    pub unsafe fn try_from_mut_ptr<'a, T>(self, ptr: *mut T) -> Result<&'a mut T, InvalidPtr> {
        Valid::new(ptr).map(|mut ptr| {
            // SAFETY: `Valid`s are always non-null and properly
            // aligned. Also, see the macro's safety docs.
            unsafe { ptr.as_mut() }
        })
    }

    /// Returns a possible uninitialized exclusive reference from
    /// `ptr`.
    ///
    /// # Safety
    ///
    /// - You must enforce Rust's aliasing rules.
    pub unsafe fn try_from_uninit_mut_ptr<'a, T>(
        self,
        ptr: *mut MaybeUninit<T>,
    ) -> Result<&'a mut MaybeUninit<T>, InvalidPtr> {
        Valid::new(ptr).map(|mut ptr| {
            // SAFETY: `Valid`s are always non-null and properly
            // aligned. Also, see the macro's safety docs.
            unsafe { ptr.as_mut() }
        })
    }

    /// Returns an [`OwnedPtr`] from `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be initialized.
    /// - You must enforce Rust's aliasing rules.
    pub unsafe fn try_from_owned_ptr<T>(self, ptr: *mut T) -> Result<OwnedPtr<T>, InvalidPtr> {
        // TODO(eric): `ptr.cast()` or make `ptr: *mut
        // ManuallyDrop<T>`?
        Valid::new(ptr.cast()).map(|ptr| {
            // SAFETY: `Valid`s are always non-null and properly
            // aligned. Also, see this method's safety docs.
            unsafe { OwnedPtr::from_valid(ptr) }
        })
    }
}

// Autoderef specialization for [`CStr`].
#[doc(hidden)]
pub struct CStrTag;
#[doc(hidden)]
pub trait CStrKind {
    #[inline(always)]
    fn kind(&self) -> CStrTag {
        CStrTag
    }
}
impl CStrKind for &*const c_char {}
impl CStrTag {
    /// Returns a shared reference from `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be initialized.
    /// - You must enforce Rust's aliasing rules.
    /// - The null terminator must be within `isize::MAX` bytes
    ///   from `ptr`.
    pub unsafe fn try_from_ptr(self, ptr: *const c_char) -> Result<CStr, Error> {
        // SAFETY: See the method's docs.
        unsafe { CStr::try_from_ptr(ptr) }}
}

// Autoderef specialization for some `Safe<T>`.
#[doc(hidden)]
pub struct SafeTag;
#[doc(hidden)]
pub trait SafeKind<T> {
    #[inline(always)]
    fn kind(&self) -> SafeTag {
        SafeTag
    }
}
impl<T: Typed> SafeKind<T> for *mut Safe<T> {}
impl<T: Typed> SafeKind<T> for *const Safe<T> {}
impl<T: Typed> SafeKind<T> for *mut MaybeUninit<Safe<T>> {}
impl SafeTag {
    /// Returns a shared reference from `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be initialized.
    /// - You must enforce Rust's aliasing rules.
    pub unsafe fn try_from_ptr<'a, T: Typed>(
        self,
        ptr: *const Safe<T>,
    ) -> Result<&'a Safe<T>, Error> {
        // SAFETY: See the method's docs.
        unsafe { Safe::try_from_ptr(ptr) }}

    /// Returns an exclusive reference from `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be initialized.
    /// - You must enforce Rust's aliasing rules.
    pub unsafe fn try_from_mut_ptr<'a, T: Typed>(
        self,
        ptr: *mut Safe<T>,
    ) -> Result<&'a mut Safe<T>, Error> {
        // SAFETY: See the method's docs.
        unsafe { Safe::try_from_mut_ptr(ptr) }}

    /// Returns a possibly uninitialized exclusive reference from
    /// `ptr`.
    ///
    /// # Safety
    ///
    /// - You must enforce Rust's aliasing rules.
    pub unsafe fn try_from_uninit_mut_ptr<'a, T: Typed>(
        self,
        ptr: *mut MaybeUninit<Safe<T>>,
    ) -> Result<&'a mut MaybeUninit<Safe<T>>, Error> {
        // SAFETY: See the method's docs.
        unsafe { Safe::try_from_uninit_mut_ptr(ptr) }}

    /// Returns an [`OwnedPtr`] from `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be initialized.
    /// - You must enforce Rust's aliasing rules.
    pub unsafe fn try_from_owned_ptr<T: Typed>(
        self,
        ptr: *mut Safe<T>,
    ) -> Result<OwnedPtr<Safe<T>>, Error> {
        // SAFETY: See the method's docs.
        unsafe { Safe::try_from_owned_ptr(ptr) }}
}

/// Casts `$ptr` to `&T` if `$ptr` is non-null and suitably
/// aligned, or returns an error otherwise.
///
/// # Safety
///
/// - The pointer must be initialized.
/// - You must uphold Rust's aliasing rules.
#[macro_export]
#[doc(hidden)]
macro_rules! try_as_ref {
    ($ptr:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::ptr::{CStrKind, DefaultKind, SafeKind};
        match $crate::internal::conv::ptr::const_assert_is_const_ptr($ptr) {
            // SAFETY: See the macro's docs.
            v => match unsafe { (&&v).kind().try_from_ptr(v) } {
                ::core::result::Result::Ok(v) => v,
                ::core::result::Result::Err(err) => {
                    return ::core::result::Result::Err(::core::convert::From::from(
                        $crate::InvalidArg::new(::core::stringify!($ptr), err),
                    ))
                }
            },
        }
    }};
}

/// Casts `$ptr` to `&mut T` if `$ptr` is non-null and suitably
/// aligned, or returns an error otherwise.
///
/// # Safety
///
/// - The pointer must be initialized.
/// - You must uphold Rust's aliasing rules.
#[macro_export]
#[doc(hidden)]
macro_rules! try_as_mut {
    ($ptr:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::ptr::{CStrKind, DefaultKind, SafeKind};
        match $crate::internal::conv::ptr::const_assert_is_mut_ptr($ptr) {
            // SAFETY: See the macro's docs.
            v => match unsafe { (&&v).kind().try_from_mut_ptr(v) } {
                ::core::result::Result::Ok(v) => v,
                ::core::result::Result::Err(err) => {
                    return ::core::result::Result::Err(::core::convert::From::from(
                        $crate::InvalidArg::new(::core::stringify!($ptr), err),
                    ))
                }
            },
        }
    }};
}

/// Casts `$ptr` to `&mut T` if `$ptr` is non-null and suitably
/// aligned, or returns an error otherwise.
///
/// # Safety
///
/// - You must uphold Rust's aliasing rules.
#[macro_export]
#[doc(hidden)]
macro_rules! try_as_uninit_mut {
    ($ptr:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::ptr::{CStrKind, DefaultKind, SafeKind};
        match $crate::internal::conv::ptr::const_assert_is_mut_ptr::<::core::mem::MaybeUninit<_>>(
            $ptr,
        ) {
            // SAFETY: See the macro's docs.
            v => match unsafe { (&&v).kind().try_from_uninit_mut_ptr(v) } {
                ::core::result::Result::Ok(v) => v,
                ::core::result::Result::Err(err) => {
                    return ::core::result::Result::Err(::core::convert::From::from(
                        $crate::InvalidArg::new(::core::stringify!($ptr), err),
                    ))
                }
            },
        }
    }};
}

/// Evaluates to `Ok(&mut T)` ptr` if `$ptr` is non-null and
/// suitably aligned, or `Err(_)` otherwise.
///
/// # Safety
///
/// - You must uphold Rust's aliasing rules.
#[macro_export]
#[doc(hidden)]
macro_rules! as_mut {
    ($ptr:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::ptr::{CStrKind, DefaultKind, SafeKind};
        match $crate::internal::conv::ptr::const_assert_is_mut_ptr($ptr) {
            // SAFETY: See the macro's docs.
            v => unsafe { (&&v).kind().try_from_mut_ptr(v) },
        }
    }};
}

/// Evaluates to [`OwnedPtr`][crate::safe::OwnedPtr] if `$ptr` is
/// non-null and suitably aligned, or returns an error otherwise.
#[macro_export]
#[doc(hidden)]
macro_rules! try_consume {
    ($ptr:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::ptr::{CStrKind, DefaultKind, SafeKind};
        match $crate::internal::conv::ptr::const_assert_is_mut_ptr($ptr) {
            // SAFETY: See the macro's docs.
            v => match unsafe { (&&v).kind().try_from_owned_ptr(v) } {
                ::core::result::Result::Ok(v) => v,
                ::core::result::Result::Err(err) => {
                    return ::core::result::Result::Err(::core::convert::From::from(
                        $crate::InvalidArg::new(::core::stringify!($ptr), err),
                    ))
                }
            },
        }
    }};
}

/// Like [`try_consume`], but for `Option<OwnedPtr<T>>`.
#[macro_export]
#[doc(hidden)]
macro_rules! try_consume_opt {
    ($ptr:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::ptr::{CStrKind, DefaultKind, SafeKind};
        match $crate::internal::conv::ptr::const_assert_is_mut_ptr($ptr) {
            // SAFETY: See the macro's docs.
            v => match unsafe { (&&v).kind().try_from_owned_ptr(v) } {
                ::core::result::Result::Ok(v) => ::core::option::Option::Some(v),
                ::core::result::Result::Err($crate::safe::InvalidPtr::Null) => {
                    ::core::option::Option::None
                }
                ::core::result::Result::Err(err) => {
                    return ::core::result::Result::Err(::core::convert::From::from(
                        $crate::InvalidArg::new(::core::stringify!($ptr), err),
                    ))
                }
            },
        }
    }};
}

/// Like [`try_as_ref`], but for `Option<&T>`.
#[macro_export]
#[doc(hidden)]
macro_rules! try_as_opt {
    ($ptr:expr $(,)?) => {
        match $crate::internal::conv::ptr::const_assert_is_const_ptr($ptr) {
            ptr => {
                if ptr.is_null() {
                    ::core::option::Option::None
                } else {
                    ::core::option::Option::Some($crate::try_as_ref!($ptr))
                }
            }
        }
    };
}

/// Like [`try_as_mut`], but for `Option<&mut T>`.
#[macro_export]
#[doc(hidden)]
macro_rules! try_as_opt_mut {
    ($ptr:expr $(,)?) => {
        match $crate::internal::conv::ptr::const_assert_is_mut_ptr($ptr) {
            ptr => {
                if ptr.is_null() {
                    ::core::option::Option::None
                } else {
                    ::core::option::Option::Some($crate::try_as_mut!($ptr))
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;
    use crate::{error::InvalidArg, safe::TypeId};

    #[derive(Debug, Default, Eq, PartialEq)]
    struct Dummy(u32);
    impl Typed for Dummy {
        const TYPE_ID: TypeId = TypeId::new(0);
    }

    /// Test specialization for [`try_as_ref`].
    #[test]
    fn test_try_as_ref_specialization() {
        macro_rules! check {
            ($ptr:ty => $xref:ty) => {
                let _: Result<$xref, InvalidArg<'static>> =
                    (|| Ok(try_as_ref!(ptr::null::<$ptr>())))();
            };
        }
        check!(Dummy => &Dummy);
        check!(Safe<Dummy> => &Safe<Dummy>);
        check!(c_char => CStr);
    }

    /// Test specialization for [`try_as_mut`].
    #[test]
    fn test_try_as_mut_specialization() {
        macro_rules! check {
            ($ty:ty) => {
                let _: Result<&mut $ty, InvalidArg<'static>> =
                    (|| Ok(try_as_mut!(ptr::null_mut::<$ty>())))();
            };
        }
        check!(Dummy);
        check!(Safe<Dummy>);
    }

    /// Test specialization for [`try_as_uninit_mut`].
    #[test]
    fn test_try_as_uninit_mut_specialization() {
        macro_rules! check {
            ($ptr:ty => $xref:ty) => {
                let _: Result<$xref, InvalidArg<'static>> =
                    (|| Ok(try_as_uninit_mut!(ptr::null_mut::<$ptr>())))();
            };
        }
        check!(MaybeUninit<Safe<Dummy>> => &mut MaybeUninit<Safe<Dummy>>);
        check!(MaybeUninit<Dummy> => &mut MaybeUninit<Dummy>);
    }
}
