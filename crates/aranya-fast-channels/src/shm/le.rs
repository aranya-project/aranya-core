macro_rules! little_endian {
	($($name:ident => $type:ty),* $(,)?) => {
        $(
            /// A little-endian integer.
            #[derive(Copy, Clone, Debug, Eq, PartialEq)]
            #[repr(transparent)]
            pub(super) struct $name {
                __raw: $type
            }

            impl $name {
                /// Creates a little-endian integer from native-endian `v`.
                pub const fn new(v: $type) -> Self {
                    Self { __raw: v.to_le() }
                }

                /// Converts the little-endian integer to native-endian.
                pub const fn get(self) -> $type {
                    <$type>::from_le(self.__raw)
                }
            }

            impl ::core::cmp::PartialEq<$type> for $name {
                fn eq(&self, other: &$type) -> bool {
                    self.get() == *other
                }
            }

            impl ::core::cmp::PartialOrd<$type> for $name {
                fn partial_cmp(&self, other: &$type) -> ::core::option::Option<::core::cmp::Ordering> {
                    self.get().partial_cmp(other)
                }
            }

            impl ::core::cmp::PartialOrd for $name {
                fn partial_cmp(&self, other: &Self) -> ::core::option::Option<::core::cmp::Ordering> {
                    Some(self.cmp(other))
                }
            }

            impl ::core::cmp::Ord for $name {
                fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
                    self.get().cmp(&other.get())
                }
            }

            impl ::core::ops::AddAssign<$type> for $name {
                fn add_assign(&mut self, rhs: $type) {
                    #![allow(clippy::arithmetic_side_effects, reason = "keeping behavior")]
                    *self = Self::new(self.get() + rhs);
                }
            }

            impl ::core::ops::SubAssign<$type> for $name {
                fn sub_assign(&mut self, rhs: $type) {
                    #![allow(clippy::arithmetic_side_effects, reason = "keeping behavior")]
                    *self = Self::new(self.get() - rhs);
                }
            }

            impl ::core::convert::From<$type> for $name {
                fn from(v: $type) -> Self {
                    Self::new(v)
                }
            }

            impl ::core::convert::From<$name> for $type {
                fn from(v: $name) -> Self {
                    v.get()
                }
            }

            impl ::core::convert::TryFrom<$name> for usize {
                type Error = <usize as ::core::convert::TryFrom<$type>>::Error;

                fn try_from(v: $name) -> Result<Self, Self::Error> {
                    v.get().try_into()
                }
            }

            impl ::core::fmt::Display for $name {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    ::core::fmt::Display::fmt(&self.get(), f)
                }
            }
        )*
	};
}

little_endian! {
    U32 => u32,
    U64 => u64,
}
