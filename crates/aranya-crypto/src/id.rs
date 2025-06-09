//! [`Id`]s and generation of [`custom_id`] types.

#![forbid(unsafe_code)]

use core::{
    fmt::{self, Debug, Display},
    hash::Hash,
    str::FromStr,
};

#[cfg(feature = "proptest")]
#[doc(hidden)]
pub use proptest as __proptest;
use serde::{
    de::{self, DeserializeOwned, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
pub use spideroak_base58::{DecodeError, String32, ToBase58};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    ciphersuite::SuiteIds,
    csprng::Csprng,
    generic_array::GenericArray,
    hash::tuple_hash,
    signer::PkError,
    subtle::{Choice, ConstantTimeEq},
    typenum::U32,
    CipherSuite,
};

/// A unique cryptographic ID.
#[repr(C)]
#[derive(
    Copy,
    Clone,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Immutable,
    IntoBytes,
    KnownLayout,
    Unaligned,
    FromBytes,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct Id([u8; 32]);

impl Id {
    /// Derives an [`Id`] from the hash of some data.
    pub fn new<CS: CipherSuite>(data: &[u8], tag: &[u8]) -> Id {
        // id = H("ID-v1" || suites || data || tag)
        tuple_hash::<CS::Hash, _>([
            "ID-v1".as_bytes(),
            &SuiteIds::from_suite::<CS>().into_bytes(),
            data,
            tag,
        ])
        .into_array()
        .into()
    }

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

    /// Creates a random ID.
    pub fn random<R: Csprng>(rng: &mut R) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Self(b)
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
    pub fn decode<T: AsRef<[u8]>>(s: T) -> Result<Self, DecodeError> {
        String32::decode(s).map(Self::from)
    }
}

impl Default for Id {
    #[inline]
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl ConstantTimeEq for Id {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl AsRef<[u8]> for Id {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<GenericArray<u8, U32>> for Id {
    #[inline]
    fn from(id: GenericArray<u8, U32>) -> Self {
        Self(id.into())
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
    type Err = DecodeError;

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
    type Output = String32;

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
                v.parse().map_err(|e| match e {
                    DecodeError::BadInput => {
                        E::invalid_value(de::Unexpected::Str(v), &"a base58 string")
                    }
                    DecodeError::Bug(bug) => de::Error::custom(bug),
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
                let id = FromBytes::read_from_bytes(v)
                    .map_err(|_| de::Error::invalid_length(v.len(), &self))?;
                Ok(id)
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

/// Creates a custom ID.
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
            ::serde::Serialize,
            ::serde::Deserialize,
        )]
        $(#[$meta])*
        $vis struct $name($crate::Id);

        impl $name {
            /// Same as [`Default`], but const.
            #[inline]
            pub const fn default() -> Self {
                Self($crate::Id::default())
            }

            /// Creates a random ID.
            pub fn random<R: $crate::csprng::Csprng>(rng: &mut R) -> Self {
                Self($crate::Id::random(rng))
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
            ) -> ::core::result::Result<Self, $crate::id::DecodeError> {
                $crate::Id::decode(s).map(Self)
            }
        }

        impl $crate::subtle::ConstantTimeEq for $name {
            #[inline]
            fn ct_eq(&self, other: &Self) -> $crate::subtle::Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl ::core::convert::AsRef<[u8]> for $name {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl ::core::convert::From<$crate::generic_array::GenericArray<u8, $crate::typenum::U32>>
            for $name
        {
            #[inline]
            fn from(id: $crate::generic_array::GenericArray<u8, $crate::typenum::U32>) -> Self {
                Self(id.into())
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
            type Err = $crate::id::DecodeError;

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

        impl $crate::id::ToBase58 for $name {
            type Output = $crate::id::String32;

            fn to_base58(&self) -> Self::Output {
                $crate::id::ToBase58::to_base58(&self.0)
            }
        }

        $crate::__custom_id_proptest!($name);
    };
}
pub(crate) use custom_id;

#[cfg(feature = "proptest")]
#[doc(hidden)]
#[macro_export]
macro_rules! __custom_id_proptest {
    ($name:ident) => {
        impl $crate::id::__proptest::arbitrary::Arbitrary for $name {
            type Parameters =
                <$crate::Id as $crate::id::__proptest::arbitrary::Arbitrary>::Parameters;
            type Strategy = $crate::id::__proptest::strategy::Map<
                <$crate::Id as $crate::id::__proptest::arbitrary::Arbitrary>::Strategy,
                fn($crate::Id) -> Self,
            >;
            fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
                {
                    $crate::id::__proptest::strategy::Strategy::prop_map(
                        $crate::id::__proptest::arbitrary::any_with::<$crate::Id>(params),
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
macro_rules! __custom_id_proptest {
    ($name:ident) => {};
}

/// An object with a unique identifier.
pub trait Identified {
    /// Uniquely identifies the object.
    type Id: Copy
        + Clone
        + Display
        + Debug
        + Hash
        + Eq
        + PartialEq
        + Ord
        + PartialOrd
        + Serialize
        + DeserializeOwned
        + Into<Id>;

    /// Uniquely identifies the object.
    fn id(&self) -> Result<Self::Id, IdError>;
}

/// An error that may occur when accessing an Id
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct IdError(&'static str);

impl From<PkError> for IdError {
    fn from(err: PkError) -> Self {
        Self(err.msg())
    }
}
