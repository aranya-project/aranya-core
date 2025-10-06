//! [`Id`]s and generation of [`custom_id`][crate::custom_id] types.

use core::{
    fmt::{self, Debug, Display},
    hash::Hash,
    str::FromStr,
};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
};
use spideroak_base58::ToBase58;

/// A unique cryptographic ID.
///
/// IDs are intended to be public (non-secret) identifiers.
#[repr(C)]
#[derive(
    Copy,
    Clone,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    zerocopy_derive::Immutable,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::KnownLayout,
    zerocopy_derive::Unaligned,
    zerocopy_derive::FromBytes,
)]
pub struct Id([u8; 32]);

impl Id {
    /// Same as [`Default`], but const.
    #[inline]
    pub const fn default() -> Self {
        Self([0u8; 32])
    }

    /// Creates itself from a byte array.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the [`Id`] as a byte slice.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the [`Id`] as a byte array.
    #[inline]
    pub const fn as_array(&self) -> &[u8; 32] {
        &self.0
    }

    /// Decode the [`Id`] from a base58 string.
    pub fn decode<T: AsRef<[u8]>>(s: T) -> Result<Self, ParseIdError> {
        let s32 = spideroak_base58::String32::decode(s).map_err(ParseIdError)?;
        Ok(Self::from_bytes(s32))
    }
}

impl Default for Id {
    #[inline]
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl subtle::ConstantTimeEq for Id {
    #[inline]
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl AsRef<[u8]> for Id {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<[u8; 32]> for Id {
    #[inline]
    fn from(id: [u8; 32]) -> Self {
        Self(id)
    }
}

impl From<Id> for [u8; 32] {
    #[inline]
    fn from(id: Id) -> Self {
        id.0
    }
}

impl FromStr for Id {
    type Err = ParseIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(s)
    }
}

impl Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.0.to_base58())
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_base58())
    }
}

impl ToBase58 for Id {
    type Output = spideroak_base58::String32;

    fn to_base58(&self) -> Self::Output {
        self.0.to_base58()
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_base58())
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Base58Visitor;
        impl Visitor<'_> for Base58Visitor {
            type Value = Id;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a base58 string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.parse().map_err(|e: ParseIdError| match e.0 {
                    spideroak_base58::DecodeError::BadInput => {
                        E::invalid_value(de::Unexpected::Str(v), &"a base58 string")
                    }
                    spideroak_base58::DecodeError::Bug(bug) => de::Error::custom(bug),
                })
            }
        }

        struct IdVisitor;
        impl<'de> Visitor<'de> for IdVisitor {
            type Value = Id;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an array of length {}", Id::default().0.len())
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bytes = v
                    .try_into()
                    .map_err(|_| de::Error::invalid_length(v.len(), &self))?;
                Ok(Id::from_bytes(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut id = Id::default();
                for (i, v) in id.0.iter_mut().enumerate() {
                    match seq.next_element()? {
                        Some(e) => *v = e,
                        None => return Err(de::Error::invalid_length(i, &self)),
                    }
                }
                Ok(id)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Base58Visitor)
        } else {
            deserializer.deserialize_bytes(IdVisitor)
        }
    }
}

impl rkyv::Archive for Id {
    type Archived = Self;
    type Resolver = ();

    fn resolve(&self, _: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        out.write(*self)
    }
}

impl<S: rkyv::rancor::Fallible + ?Sized> rkyv::Serialize<S> for Id {
    #[inline]
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: rkyv::rancor::Fallible + ?Sized> rkyv::Deserialize<Self, D> for Id {
    #[inline]
    fn deserialize(&self, _: &mut D) -> Result<Self, D::Error> {
        Ok(*self)
    }
}

// SAFETY: All bit patterns are valid for `Id`.
unsafe impl<C> rkyv::bytecheck::CheckBytes<C> for Id
where
    C: rkyv::rancor::Fallible + ?Sized,
{
    unsafe fn check_bytes(_value: *const Self, _context: &mut C) -> Result<(), C::Error> {
        Ok(())
    }
}

// SAFETY: `Id` contains no padding or uninit bytes.
unsafe impl rkyv::traits::NoUndef for Id {}

// SAFETY: `Id` has a consistent layout and no interior mutability.
unsafe impl rkyv::Portable for Id {}

crate::__impl_arbitrary!(Id => [u8; 32]);

/// An error returned when parsing an [`Id`] from a string fails.
#[derive(Clone, Debug)]
pub struct ParseIdError(spideroak_base58::DecodeError);

impl Display for ParseIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse ID: {}", self.0)
    }
}

impl core::error::Error for ParseIdError {}

/// Creates a custom [`Id`].
#[macro_export]
macro_rules! custom_id {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        #[repr(C)]
        #[derive(
            Copy,
            Clone,
            Default,
            Hash,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
        )]
        $(#[$meta])*
        $vis struct $name($crate::Id);

        impl $name {
            /// Same as [`Default`], but const.
            #[inline]
            pub const fn default() -> Self {
                Self($crate::Id::default())
            }

            /// Creates itself from a byte array.
            #[inline]
            pub const fn from_bytes(arr: [u8; 32]) -> Self {
                Self($crate::Id::from_bytes(arr))
            }

            /// Returns itself as a byte slice.
            #[inline]
            pub const fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }

            /// Returns itself as a byte array.
            #[inline]
            pub const fn as_array(&self) -> &[u8; 32] {
                self.0.as_array()
            }

            /// Returns itself as a plain `Id`.
            #[inline]
            pub const fn into_id(self) -> $crate::Id {
                self.0
            }

            /// Decode the ID from a base58 string.
            pub fn decode<T: ::core::convert::AsRef<[u8]>>(
                s: T,
            ) -> ::core::result::Result<Self, $crate::ParseIdError> {
                $crate::Id::decode(s).map(Self)
            }
        }

        impl $crate::__hidden::subtle::ConstantTimeEq for $name {
            #[inline]
            fn ct_eq(&self, other: &Self) -> $crate::__hidden::subtle::Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl ::core::convert::AsRef<[u8]> for $name {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl ::core::convert::From<[u8; 32]> for $name {
            #[inline]
            fn from(id: [u8; 32]) -> Self {
                Self(id.into())
            }
        }

        impl ::core::convert::From<$name> for [u8; 32] {
            #[inline]
            fn from(id: $name) -> Self {
                id.0.into()
            }
        }

        impl ::core::convert::From<$crate::Id> for $name {
            #[inline]
            fn from(id: $crate::Id) -> Self {
                Self(id)
            }
        }

        impl ::core::convert::From<$name> for $crate::Id {
            #[inline]
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::ParseIdError;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                Self::decode(s)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.0, f)
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl $crate::__hidden::spideroak_base58::ToBase58 for $name {
            type Output = $crate::__hidden::spideroak_base58::String32;

            fn to_base58(&self) -> Self::Output {
                $crate::__hidden::spideroak_base58::ToBase58::to_base58(&self.0)
            }
        }

        impl<'de> $crate::__hidden::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: $crate::__hidden::serde::Deserializer<'de>,
            {
                ::core::result::Result::map($crate::Id::deserialize(deserializer), Self)
            }
        }

        impl $crate::__hidden::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: $crate::__hidden::serde::Serializer,
            {
                $crate::__hidden::serde::Serialize::serialize(&self.0, serializer)
            }
        }

        $crate::__impl_arbitrary!($name => $crate::Id);
    };
}

#[cfg(feature = "proptest")]
#[doc(hidden)]
#[macro_export]
macro_rules! __impl_arbitrary {
    ($outer:ty => $inner:ty) => {
        #[cfg_attr(docsrs, doc(cfg(feature = "proptest")))]
        impl $crate::__hidden::proptest::arbitrary::Arbitrary for $outer {
            type Parameters =
                <$inner as $crate::__hidden::proptest::arbitrary::Arbitrary>::Parameters;
            type Strategy = $crate::__hidden::proptest::strategy::Map<
                <$inner as $crate::__hidden::proptest::arbitrary::Arbitrary>::Strategy,
                fn($inner) -> Self,
            >;
            fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
                {
                    $crate::__hidden::proptest::strategy::Strategy::prop_map(
                        <$inner as $crate::__hidden::proptest::arbitrary::Arbitrary>::arbitrary_with(params),
                        Self,
                    )
                }
            }
        }
    };
}

#[cfg(not(feature = "proptest"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __impl_arbitrary {
    ($outer:ty => $inner:ty) => {};
}
