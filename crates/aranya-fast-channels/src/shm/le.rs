macro_rules! little_endian {
	($($name:ident => $type:ty),* $(,)?) => {
        $(
            /// A little-endian integer.
            #[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
            #[repr(transparent)]
            pub(super) struct $name($type);

            impl $name {
                /// The maximum value.
                #[allow(dead_code, reason = "U32::MAX is not used")]
                pub const MAX: Self = Self::new(<$type>::MAX);

                /// Interprets `v` as a little-endian integer.
                pub const fn new(v: $type) -> Self {
                    Self(v.to_le())
                }

                /// Returns the little-endian integer in its
                /// original endianness.
                pub const fn into(self) -> $type {
                    <$type>::from_le(self.0)
                }

                /// Checked addition.
                #[allow(dead_code, reason = "not all methods are used for all types")]
                pub const fn checked_add(self, rhs: $type) -> Option<Self> {
                    match self.into().checked_add(rhs) {
                        Some(val) => Some(Self::new(val)),
                        None => None,
                    }
                }

                /// Checked subtraction.
                #[allow(dead_code, reason = "not all methods are used for all types")]
                pub const fn checked_sub(self, rhs: $type) -> Option<Self> {
                    match self.into().checked_sub(rhs) {
                        Some(val) => Some(Self::new(val)),
                        None => None,
                    }
                }

                /// Wrapping subtraction.
                #[allow(dead_code, reason = "not all methods are used for all types")]
                pub const fn wrapping_sub(self, rhs: $type) -> Self {
                    Self::new(self.into().wrapping_sub(rhs))
                }
            }

            impl ::core::cmp::PartialEq<$type> for $name {
                fn eq(&self, other: &$type) -> bool {
                    <$type>::from_le(self.0) == *other
                }
            }

            impl ::core::cmp::PartialOrd<$type> for $name {
                fn partial_cmp(&self, other: &$type) -> ::core::option::Option<::core::cmp::Ordering> {
                    let lhs = <$type>::from_le(self.0);
                    ::core::cmp::PartialOrd::partial_cmp(&lhs, other)
                }
            }

            impl ::core::ops::AddAssign<$type> for $name {
                fn add_assign(&mut self, rhs: $type) {
                    #![allow(clippy::arithmetic_side_effects, reason = "keeping behavior")]
                    *self = Self::new(Self::into(*self) + rhs);
                }
            }

            impl ::core::ops::SubAssign<$type> for $name {
                fn sub_assign(&mut self, rhs: $type) {
                    #![allow(clippy::arithmetic_side_effects, reason = "keeping behavior")]
                    *self = Self::new(Self::into(*self) - rhs);
                }
            }

            impl ::core::convert::TryFrom<&[u8]> for $name {
                type Error = ::buggy::Bug;

                fn try_from(b: &[u8]) -> ::core::result::Result<Self, Self::Error> {
                    use ::buggy::BugExt;
                    let v = <$type>::from_le_bytes(b.try_into().assume("incorrect size")?);
                    Ok(Self(v))
                }
            }

            impl ::core::convert::From<$type> for $name {
                fn from(v: $type) -> Self {
                    Self::new(v)
                }
            }

            impl ::core::convert::From<$name> for $type {
                fn from(v: $name) -> Self {
                    <$type>::from_le(v.0)
                }
            }

            impl ::core::convert::TryFrom<$name> for usize {
                type Error = <usize as ::core::convert::TryFrom<$type>>::Error;

                fn try_from(v: $name) -> Result<Self, Self::Error> {
                    usize::try_from(v.0)
                }
            }

            impl ::core::convert::TryFrom<$name> for isize {
                type Error = <isize as ::core::convert::TryFrom<$type>>::Error;

                fn try_from(v: $name) -> Result<Self, Self::Error> {
                    isize::try_from(v.0)
                }
            }

            impl ::core::fmt::Display for $name {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    write!(f, "{}", self.0)
                }
            }
        )*
	};
}
little_endian! {
    U32 => u32,
    U64 => u64,
}
