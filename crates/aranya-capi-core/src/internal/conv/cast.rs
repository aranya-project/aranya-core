use core::{marker::PhantomData, ptr};

use super::{
    alias::{self, Alias},
    newtype::NewType,
};

#[doc(hidden)]
#[macro_export]
macro_rules! __hide {
    ($v:expr) => {
        // NB: This must have as many `&` as we have possible
        // kinds per "to_inner*" macro. There are currently two:
        // `DefaultKind` and `ToInnerKind`.
        (&&$crate::internal::conv::cast::Hide1::new(&$v))
    };
    ($v:expr => $ty:ty) => {
        // NB: This must have as many `&` as we have possible
        // kinds per "from_inner*" macro. There are currently
        // two: `DefaultKind` and `FromInnerKind`.
        (&&$crate::internal::conv::cast::Hide2::<$ty, _>::new(::core::marker::PhantomData, &$v))
    };
    ($v:expr, $ty:expr) => {
        // NB: This must have as many `&` as we have possible
        // kinds per "from_inner*" macro. There are currently
        // two: `DefaultKind` and `FromInnerKind`.
        (&&$crate::internal::conv::cast::Hide2::<_, _>::new($ty, &$v))
    };
}

/// Casts a [`NewType`] to its inner type, or is the identity
/// function if `$v` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! to_inner {
    ($v:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, ToInnerKind};
        match $v {
            v => $crate::__hide!(v).kind().to_inner(v),
        }
    }};
}

/// Casts a [`NewType`] to its inner type, or is the identity
/// function if `$xref` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! to_inner_ref {
    ($xref:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, ToInnerKind};
        match $crate::internal::conv::cast::arg_must_be_ref($xref) {
            v => $crate::__hide!(v).kind().to_inner_ref(v),
        }
    }};
}

/// Casts a [`NewType`] to its inner type, or is the identity
/// function if `$xref` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! to_inner_mut {
    ($xref:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, ToInnerKind};
        match $crate::internal::conv::cast::arg_must_be_mut_ref($xref) {
            v => $crate::__hide!(v).kind().to_inner_mut(v),
        }
    }};
}

/// Casts a [`NewType`] to its inner type, or is the identity
/// function if `$ptr` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! to_inner_ptr {
    ($ptr:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, ToInnerKind};
        match $crate::internal::conv::cast::arg_must_be_const_ptr($ptr) {
            v => $crate::__hide!(v).kind().to_inner_ptr(v),
        }
    }};
}

/// Casts a [`NewType`] to its inner type, or is the identity
/// function if `$ptr` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! to_inner_mut_ptr {
    ($ptr:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, ToInnerKind};
        match $crate::internal::conv::cast::arg_must_be_mut_ref_ptr($ptr) {
            v => $crate::__hide!(v).kind().to_inner_mut_ptr(v),
        }
    }};
}

/// Casts a [`NewType`] to its inner type, or is the identity
/// function if `$slice` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! to_inner_slice {
    ($slice:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, ToInnerKind};
        match $crate::internal::conv::cast::arg_must_be_slice($slice) {
            v => $crate::__hide!(v).kind().to_inner_slice(v),
        }
    }};
}

/// Casts a [`NewType`] to its inner type, or is the identity
/// function if `$slice` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! to_inner_slice_mut {
    ($slice:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, ToInnerKind};
        match $crate::internal::conv::cast::arg_must_be_slice_mut($slice) {
            v => $crate::__hide!(v).kind().to_inner_slice_mut(v),
        }
    }};
}

/// Casts a [`NewType`]'s inner type to the [`NewType`], or is
/// the identity function if `$ty` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! from_inner {
    ($v:expr => $ty:ty $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, FromInnerKind};
        match $v {
            v => $crate::__hide!(v => $ty).kind().from_inner::<$ty>(v),
        }
    }};
}

/// Casts a [`NewType`]'s inner type to the [`NewType`], or is
/// the identity function if `$ty` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! from_inner_ref {
    ($xref:expr => $ty:ty $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, FromInnerKind};
        match $crate::internal::conv::cast::arg_must_be_ref($xref) {
            v => $crate::__hide!(v => &$ty).kind().from_inner_ref(v),
        }
    }};
    ($xref:expr, $ty:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, FromInnerKind};
        match $crate::internal::conv::cast::arg_must_be_ref($xref) {
            v => $crate::__hide!(v => &$ty).kind().from_inner_ref(v),
        }
    }};
}

/// Casts a [`NewType`]'s inner type to the [`NewType`], or is
/// the identity function if `$ty` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! from_inner_mut {
    ($xref:expr => $ty:ty $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, FromInnerKind};
        match $crate::internal::conv::cast::arg_must_be_mut_ref($xref) {
            v => $crate::__hide!(v => &mut $ty).kind().from_inner_mut(v),
        }
    }};
}

/// Casts a [`NewType`]'s inner type to the [`NewType`], or is
/// the identity function if `$ty` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! from_inner_ptr {
    ($ptr:expr => $ty:ty $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, FromInnerKind};
        match $crate::internal::conv::cast::arg_must_be_const_ptr($ptr) {
            v => $crate::__hide!(v => *const $ty).kind().from_inner_ptr(v),
        }
    }};
}

/// Casts a [`NewType`]'s inner type to the [`NewType`], or is
/// the identity function if `$ty` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! from_inner_mut_ptr {
    ($ptr:expr => $ty:ty $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, FromInnerKind};
        match $crate::internal::conv::cast::arg_must_be_mut_ref_ptr($ptr) {
            v => $crate::__hide!(v => *mut $ty).kind().from_inner_mut_ptr(v),
        }
    }};
}

/// Casts a [`NewType`]'s inner type to the [`NewType`], or is
/// the identity function if `$ty` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! from_inner_slice {
    ($slice:expr => $ty:ty $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, FromInnerKind};
        match $crate::internal::conv::cast::arg_must_be_slice($slice) {
            v => $crate::__hide!(v => &[$ty]).kind().from_inner_slice(v),
        }
    }};
}

/// Casts a [`NewType`]'s inner type to the [`NewType`], or is
/// the identity function if `$ty` is not [`NewType`].
#[macro_export]
#[doc(hidden)]
macro_rules! from_inner_slice_mut {
    ($slice:expr => $ty:ty $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::cast::{DefaultKind, FromInnerKind};
        match $crate::internal::conv::cast::arg_must_be_slice_mut($slice) {
            v => $crate::__hide!(v => &mut [$ty]).kind().from_inner_slice_mut(v),
        }
    }};
}

/// Masks off any other traits that `T` might implement.
#[doc(hidden)]
pub struct Hide1<T: ?Sized>(PhantomData<T>);
impl<T> Hide1<T> {
    #[doc(hidden)]
    pub const fn new(_v: &T) -> Self {
        Self(PhantomData)
    }
}

/// Like [`Hide1`], but with two generic parameters.
#[doc(hidden)]
pub struct Hide2<T: ?Sized, U: ?Sized>(PhantomData<T>, PhantomData<U>);
impl<T, U> Hide2<T, U> {
    #[doc(hidden)]
    pub const fn new(_t: PhantomData<T>, _v: &U) -> Self {
        Self(PhantomData, PhantomData)
    }
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
impl<T> DefaultKind for Hide1<T> {}
impl<T, U> DefaultKind for Hide2<T, U> {}
impl DefaultTag {
    /// The identity function.
    pub fn to_inner<T>(self, val: T) -> T {
        val
    }

    /// The identity function.
    pub const fn to_inner_ref<T>(self, val: &T) -> &T {
        val
    }

    /// The identity function.
    pub fn to_inner_mut<T>(self, val: &mut T) -> &mut T {
        val
    }

    /// The identity function.
    pub const fn to_inner_ptr<T>(self, val: *const T) -> *const T {
        val
    }

    /// The identity function.
    pub const fn to_inner_mut_ptr<T>(self, val: *mut T) -> *mut T {
        val
    }

    /// The identity function.
    pub const fn to_inner_slice<T>(self, val: &[T]) -> &[T] {
        val
    }

    /// The identity function.
    pub fn to_inner_slice_mut<T>(self, val: &mut [T]) -> &mut [T] {
        val
    }

    /// The identity function.
    pub fn from_inner<T>(self, val: T) -> T {
        val
    }

    /// The identity function.
    pub const fn from_inner_ref<T>(self, val: &T) -> &T {
        val
    }

    /// The identity function.
    pub fn from_inner_mut<T>(self, val: &mut T) -> &mut T {
        val
    }

    /// The identity function.
    pub const fn from_inner_ptr<T>(self, val: *const T) -> *const T {
        val
    }

    /// The identity function.
    pub const fn from_inner_mut_ptr<T>(self, val: *mut T) -> *mut T {
        val
    }

    /// The identity function.
    pub const fn from_inner_slice<T>(self, val: &[T]) -> &[T] {
        val
    }

    /// The identity function.
    pub fn from_inner_slice_mut<T>(self, val: &mut [T]) -> &mut [T] {
        val
    }
}

// Autoderef specialization for `NewType`.
#[doc(hidden)]
pub struct ToInnerTag;
#[doc(hidden)]
pub trait ToInnerKind {
    #[inline(always)]
    fn kind(&self) -> ToInnerTag {
        ToInnerTag
    }
}
impl<T: NewType> ToInnerKind for &Hide1<T> {}
impl<T: NewType> ToInnerKind for &Hide1<&[T]> {}
impl<T: NewType> ToInnerKind for &Hide1<&mut [T]> {}
impl<T: NewType, const N: usize> ToInnerKind for &Hide1<&[T; N]> {}
impl<T: NewType, const N: usize> ToInnerKind for &Hide1<&mut [T; N]> {}
impl ToInnerTag {
    /// Casts a [`NewType`] to its inner type.
    pub fn to_inner<T: NewType>(self, val: T) -> T::Inner {
        alias::cast(ToInner(val))
    }

    /// Casts a [`NewType`] to its inner type.
    pub fn to_inner_ref<T: NewType>(self, val: &T) -> &T::Inner {
        alias::cast_ref(
            // SAFETY:
            //
            // - `ToInner<T>` has the same memory layout as `T`.
            // - `val` is a ref, so the pointer is never null.
            unsafe { &*ptr::from_ref::<T>(val).cast::<ToInner<T>>() },
        )
    }

    /// Casts a [`NewType`] to its inner type.
    pub fn to_inner_mut<T: NewType>(self, val: &mut T) -> &mut T::Inner {
        alias::cast_mut(
            // SAFETY:
            //
            // - `ToInner<T>` has the same memory layout as `T`.
            // - `val` is an exclusive ref, so the pointer is
            //   never null.
            unsafe { &mut *ptr::from_mut::<T>(val).cast::<ToInner<T>>() },
        )
    }

    /// Casts a [`NewType`] to its inner type.
    pub fn to_inner_ptr<T: NewType>(self, val: *const T) -> *const T::Inner {
        alias::cast_ptr(val.cast::<ToInner<T>>())
    }

    /// Casts a [`NewType`] to its inner type.
    pub fn to_inner_mut_ptr<T: NewType>(self, val: *mut T) -> *mut T::Inner {
        alias::cast_mut_ptr(val.cast::<ToInner<T>>())
    }

    /// Casts a slice of [`NewType`] to its inner type.
    pub fn to_inner_slice<T: NewType>(self, val: &[T]) -> &[T::Inner] {
        alias::cast_slice(
            // SAFETY:
            //
            // - `ToInner<T>` has the same memory layout as `T`.
            // - `val` is a ref, so the pointer is never null.
            // - `val` is a slice, so its length is always less
            //   than `isize::MAX`.
            unsafe { &*(ptr::from_ref::<[T]>(val) as *const [ToInner<T>]) },
        )
    }

    /// Casts a slice of [`NewType`] to its inner type.
    pub fn to_inner_slice_mut<T: NewType>(self, val: &mut [T]) -> &mut [T::Inner] {
        alias::cast_slice_mut(
            // SAFETY:
            //
            // - `ToInner<T>` has the same memory layout as `T`.
            // - `val` is an exclusive ref, so the pointer is
            //   never null.
            // - `val` is a slice, so its length is always less
            //   than `isize::MAX`.
            unsafe { &mut *(ptr::from_mut::<[T]>(val) as *mut [ToInner<T>]) },
        )
    }
}

/// A transparent wrapper so that [`NewType`]s can implement
/// [`Alias`].
#[repr(transparent)]
struct ToInner<T>(T);

// SAFETY:
//
// - `ToInner<T>` has the same memory layout as `T`.
// - `T` has the same memory layout as `T::Inner`.
// - `NewType` has the same invariants as `Alias`.
//
// Therefore, it is sound to cast `ToInner<T>` to `T::Inner`.
unsafe impl<T, U> Alias<U> for ToInner<T> where T: NewType<Inner = U> {}

// Autoderef specialization for `NewType`.
#[doc(hidden)]
pub struct FromInnerTag;
#[doc(hidden)]
pub trait FromInnerKind {
    #[inline(always)]
    fn kind(&self) -> FromInnerTag {
        FromInnerTag
    }
}
impl<T> FromInnerKind for &Hide2<T, T::Inner> where T: NewType {}
impl<T> FromInnerKind for &Hide2<&[T], &[T::Inner]> where T: NewType {}
impl<T> FromInnerKind for &Hide2<&mut [T], &mut [T::Inner]> where T: NewType {}
impl<T, const N: usize> FromInnerKind for &Hide2<&[T; N], &[T::Inner; N]> where T: NewType {}
impl<T, const N: usize> FromInnerKind for &Hide2<&mut [T; N], &mut [T::Inner; N]> where T: NewType {}
impl FromInnerTag {
    /// Creates a [`NewType`] from its inner type.
    pub fn from_inner<T: NewType>(self, val: T::Inner) -> T {
        alias::cast(FromInner(val))
    }

    /// Creates a [`NewType`] from its inner type.
    pub fn from_inner_ref<T: NewType>(self, val: &T::Inner) -> &T {
        alias::cast_ref(
            // SAFETY:
            //
            // - `FromInner<T>` has the same memory layout as
            //   `T::Inner`.
            // - `val` is a ref, so the pointer is never null.
            unsafe { &*ptr::from_ref::<T::Inner>(val).cast::<FromInner<T::Inner>>() },
        )
    }

    /// Creates a [`NewType`] from its inner type.
    pub fn from_inner_mut<T: NewType>(self, val: &mut T::Inner) -> &mut T {
        alias::cast_mut(
            // SAFETY:
            //
            // - `FromInner<T>` has the same memory layout as
            //   `T::Inner`.
            // - `val` is an exclusive ref, so the pointer is
            //   never null.
            unsafe { &mut *ptr::from_mut::<T::Inner>(val).cast::<FromInner<T::Inner>>() },
        )
    }

    /// Creates a [`NewType`] from its inner type.
    pub fn from_inner_ptr<T: NewType>(self, val: *const T::Inner) -> *const T {
        alias::cast_ptr(val.cast::<FromInner<T::Inner>>())
    }

    /// Creates a [`NewType`] from its inner type.
    pub fn from_inner_mut_ptr<T: NewType>(self, val: *mut T::Inner) -> *mut T {
        alias::cast_mut_ptr(val.cast::<FromInner<T::Inner>>())
    }

    /// Casts a slice of [`NewType`] to its inner type.
    pub fn from_inner_slice<T: NewType>(self, val: &[T::Inner]) -> &[T] {
        alias::cast_slice(
            // SAFETY:
            //
            // - `FromInner<T>` has the same memory layout as `T`.
            // - `val` is a ref, so the pointer is never null.
            // - `val` is a slice, so its length is always less
            //   than `isize::MAX`.
            unsafe { &*(ptr::from_ref::<[T::Inner]>(val) as *const [FromInner<T::Inner>]) },
        )
    }

    /// Casts a slice of [`NewType`] to its inner type.
    pub fn from_inner_slice_mut<T: NewType>(self, val: &mut [T::Inner]) -> &mut [T] {
        alias::cast_slice_mut(
            // SAFETY:
            //
            // - `FromInner<T>` has the same memory layout as `T`.
            // - `val` is an exclusive ref, so the pointer is
            //   never null.
            // - `val` is a slice, so its length is always less
            //   than `isize::MAX`.
            unsafe { &mut *(ptr::from_mut::<[T::Inner]>(val) as *mut [FromInner<T::Inner>]) },
        )
    }
}

/// A transparent wrapper so that [`NewType`]s can implement
/// [`Alias`].
#[repr(transparent)]
struct FromInner<T>(T);

// SAFETY:
//
// - `FromInner<T>` has the same memory layout as `T`.
// - `T` has the same memory layout as `T::Inner`.
// - `NewType` has the same invariants as `Alias`.
//
// Therefore, it is sound to cast `FromInner<T>` to `T::Inner`.
unsafe impl<T, U> Alias<T> for FromInner<U> where T: NewType<Inner = U> {}

/// Checks `v` is `&T`.
pub const fn arg_must_be_ref<T>(v: &T) -> &T {
    v
}

/// Checks `v` is `&mut T`.
pub fn arg_must_be_mut_ref<T>(v: &mut T) -> &mut T {
    v
}

/// Checks `v` is `*const T`.
pub const fn arg_must_be_const_ptr<T>(v: *const T) -> *const T {
    v
}

/// Checks `v` is `*mut T`.
pub const fn arg_must_be_mut_ref_ptr<T>(v: *mut T) -> *mut T {
    v
}

/// Checks `v` is `&[T]`.
pub const fn arg_must_be_slice<T>(v: &[T]) -> &[T] {
    v
}

/// Checks `v` is `&mut [T]`.
pub fn arg_must_be_slice_mut<T>(v: &mut [T]) -> &mut [T] {
    v
}

#[cfg(test)]
mod tests {
    use core::{mem::MaybeUninit, ptr};

    use super::*;

    #[test]
    fn test_idk() {
        #[derive(Copy, Clone, Debug, Default)]
        struct A;

        #[derive(Copy, Clone, Debug, Default)]
        struct B(A);
        unsafe impl NewType for B {
            type Inner = A;
        }

        let b = B(A);
        let a: A = to_inner!(b);
        let mut out = MaybeUninit::<B>::uninit();
        let _: &mut B = MaybeUninit::write(&mut out, {
            type _B = B;
            from_inner!(a => _B)
        });
    }

    #[test]
    fn test_basic() {
        #[derive(Copy, Clone, Debug, Default)]
        struct A;

        #[derive(Copy, Clone, Debug, Default)]
        #[repr(transparent)]
        struct B(A);
        unsafe impl NewType for B {
            type Inner = A;
        }

        #[derive(Copy, Clone, Debug, Default)]
        #[repr(transparent)]
        struct C(B);
        unsafe impl NewType for C {
            type Inner = A;
        }

        // Passthrough via `DefaultKind`.
        macro_rules! to_passthrough {
            ($ty:ty, $val:expr) => {{
                let _: $ty = to_inner!($val);
                match &$val {
                    v => {
                        let _: &$ty = to_inner_ref!(v);
                    }
                }
                match &mut $val {
                    v => {
                        let _: &mut $ty = to_inner_mut!(v);
                    }
                }
                let _: *const $ty = to_inner_ptr!(ptr::null::<$ty>());
                let _: *mut $ty = to_inner_mut_ptr!(ptr::null_mut::<$ty>());
                match &[$val] {
                    v => {
                        let _: &[$ty] = to_inner_slice!(v);
                    }
                }
                match &mut [$val] {
                    v => {
                        let _: &mut [$ty] = to_inner_slice_mut!(v);
                    }
                }
            }};
        }
        to_passthrough!((), ());
        to_passthrough!(bool, true);
        to_passthrough!(u64, 42);
        to_passthrough!(&str, "hi");
        to_passthrough!(A, A);

        // Passthrough via `DefaultKind`.
        macro_rules! from_passthrough {
            ($val:expr => $ty:ty) => {{
                let _: $ty = from_inner!($val => $ty);
                match &$val {
                    v => {
                        let _: &$ty = from_inner_ref!(v => $ty);
                    }
                }
                match &mut $val {
                    v => {
                        let _: &mut $ty = from_inner_mut!(v => $ty);
                    }
                }
                let _: *const $ty = from_inner_ptr!(ptr::null::<$ty>() => $ty);
                let _: *mut $ty = from_inner_mut_ptr!(ptr::null_mut::<$ty>() => $ty);
                match &[$val] {
                    v => {
                        let _: &[$ty] = from_inner_slice!(v => $ty);
                    }
                }
                match &mut [$val] {
                    v => {
                        let _: &mut [$ty] = from_inner_slice_mut!(v => $ty);
                    }
                }
            }};
        }
        from_passthrough!(() => ());
        from_passthrough!(true => bool);
        from_passthrough!(42 => u64);
        from_passthrough!("hi" => &str);
        from_passthrough!(A => A);

        // Convert outer -> inner.
        macro_rules! check_to_inner {
            ($ty:ty, $val:expr) => {{
                let _: <$ty as NewType>::Inner = to_inner!($val);
                match &$val {
                    v => {
                        let _: &<$ty as NewType>::Inner = to_inner_ref!(v);
                    }
                }
                match &mut $val {
                    v => {
                        let _: &mut <$ty as NewType>::Inner = to_inner_mut!(v);
                    }
                }
                let _: *const <$ty as NewType>::Inner = to_inner_ptr!(ptr::null::<$ty>());
                let _: *mut <$ty as NewType>::Inner = to_inner_mut_ptr!(ptr::null_mut::<$ty>());
                match &[$val] {
                    v => {
                        let _: &[<$ty as NewType>::Inner] = to_inner_slice!(v);
                    }
                }
                match &mut [$val] {
                    v => {
                        let _: &mut [<$ty as NewType>::Inner] = to_inner_slice_mut!(v);
                    }
                }
            }};
        }
        check_to_inner!(B, B(A));

        // Convert inner -> outer.
        macro_rules! check_from_inner {
            ($val:expr => $ty:ty) => {{
                let _: $ty = from_inner!($val => $ty);
                match &$val {
                    v => {
                        let _: &$ty = from_inner_ref!(v => $ty);
                    }
                }
                match &mut $val {
                    v => {
                        let _: &mut $ty = from_inner_mut!(v => $ty);
                    }
                }
                let _: *const $ty = from_inner_ptr!(ptr::null::<<$ty as NewType>::Inner>() => $ty);
                let _: *mut $ty =
                    from_inner_mut_ptr!(ptr::null_mut::<<$ty as NewType>::Inner>() => $ty);
                match &[$val] {
                    v => {
                        let _: &[$ty] = from_inner_slice!(v => $ty);
                    }
                }
                match &mut [$val] {
                    v => {
                        let _: &mut [$ty] = from_inner_slice_mut!(v => $ty);
                    }
                }
            }};
        }
        check_from_inner!(A => B);
    }
}
