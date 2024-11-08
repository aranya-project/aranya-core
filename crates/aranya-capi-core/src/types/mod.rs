//! FFI safe type checking.

mod allowed;

pub use allowed::*;

/// A marker trait that the type is opaque.
pub trait Opaque: Sized {}

/// An enumeration.
pub trait Enum: Sized {
    // TODO(jdygert): Need restriction?
    /// The enumeration's `#[repr(...)]`.
    type Repr;

    /// Creates the enum from its repr.
    fn try_from_repr(repr: Self::Repr) -> Option<Self>;
}

/// A valid `#[repr(...)]` for an enum.
pub trait Repr: Sized + Sealed {}

impl Repr for u8 {}
impl Repr for u16 {}
impl Repr for u32 {}
impl Repr for u64 {}
impl Repr for usize {}
impl Repr for i8 {}
impl Repr for i16 {}
impl Repr for i32 {}
impl Repr for i64 {}
impl Repr for isize {}

mod private {
    pub trait Sealed {}

    impl Sealed for u8 {}
    impl Sealed for u16 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
    impl Sealed for usize {}
    impl Sealed for i8 {}
    impl Sealed for i16 {}
    impl Sealed for i32 {}
    impl Sealed for i64 {}
    impl Sealed for isize {}
}
use private::Sealed;
