//! `enum` conversions.

use crate::types::Enum;

// Autoref specialization for some generic `T`.
#[doc(hidden)]
pub struct DefaultTag;
#[doc(hidden)]
pub trait DefaultKind {
    #[inline(always)]
    fn kind(&self) -> DefaultTag {
        DefaultTag
    }
}
impl<T> DefaultKind for &T {}
impl DefaultTag {
    /// The identity function.
    pub fn try_from_repr<T>(self, repr: T) -> Option<T> {
        Some(repr)
    }
}

// Autoref specialization for `Enum`.
#[doc(hidden)]
pub struct EnumTag;
#[doc(hidden)]
pub trait EnumKind {
    #[inline(always)]
    fn kind(&self) -> EnumTag {
        EnumTag
    }
}
impl<T: Enum> EnumKind for T {}
impl EnumTag {
    /// Creates the enum from its repr.
    pub fn try_from_repr<E: Enum>(self, repr: E::Repr) -> Option<E> {
        E::try_from_repr(repr)
    }
}

/// Converts `$repr` to an enum if it's a valid repr for the enum
/// or returns an error otherwise.
#[macro_export]
#[doc(hidden)]
macro_rules! try_as_enum {
    ($type:ty, $repr:expr) => {{
        #[allow(unused_imports)]
        use $crate::internal::conv::enums::{DefaultKind, EnumKind};
        match $repr {
            // TODO(jdygert): Fix specialization
            v => match <$type as $crate::types::Enum>::try_from_repr(v) {
                ::core::option::Option::Some(v) => v,
                ::core::option::Option::None => {
                    return ::core::result::Result::Err(::core::convert::From::from(
                        $crate::InvalidArg::new(
                            ::core::stringify!($repr),
                            $crate::InvalidArgReason::Other("invalid enum repr"),
                        ),
                    ))
                }
            },
        }
    }};
}
