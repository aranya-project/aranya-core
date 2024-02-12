//! [`Id`]s and generation of [`custom_id`] types.

#![forbid(unsafe_code)]

use core::{
    fmt::{self, Debug, Display},
    hash::Hash,
    str::FromStr,
};

pub use base58::DecodeError;
use base58::{String64, ToBase58};
use generic_array::GenericArray;
use postcard::experimental::max_size::MaxSize;
use serde::{
    de::{self, DeserializeOwned, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use subtle::{Choice, ConstantTimeEq};
use typenum::U64;

use crate::{ciphersuite::SuiteIds, csprng::Csprng, engine::Engine, hash::tuple_hash};

/// A unique cryptographic ID.
#[repr(C)]
#[derive(Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, MaxSize)]
pub struct Id([u8; 64]);

impl Id {
    /// Derives an [`Id`] from the hash of some data.
    pub fn new<E: Engine + ?Sized>(data: &[u8], tag: &[u8]) -> Id {
        // id = H("ID-v1" || eng_id || suites || data || tag)
        tuple_hash::<E::Hash, _>([
            "ID-v1".as_bytes(),
            E::ID.as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            data,
            tag,
        ])
        .into_array()
        .into()
    }

    /// Same as [`Default`], but const.
    #[inline]
    pub const fn default() -> Self {
        Self([0u8; 64])
    }

    /// Creates itself from a byte array.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Creates a random ID.
    pub fn random<R: Csprng>(rng: &mut R) -> Self {
        let mut b = [0u8; 64];
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
    pub const fn as_array(&self) -> &[u8; 64] {
        &self.0
    }

    /// Decode the [`Id`] from a base58 string.
    pub fn decode<T: AsRef<[u8]>>(s: T) -> Result<Self, DecodeError> {
        String64::decode(s).map(Self::from)
    }
}

impl Default for Id {
    #[inline]
    fn default() -> Self {
        Self([0u8; 64])
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

impl From<GenericArray<u8, U64>> for Id {
    #[inline]
    fn from(id: GenericArray<u8, U64>) -> Self {
        Self(id.into())
    }
}

impl From<[u8; 64]> for Id {
    #[inline]
    fn from(id: [u8; 64]) -> Self {
        Self(id)
    }
}

impl From<Id> for [u8; 64] {
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
    type Output = String64;

    fn to_base58(&self) -> Self::Output {
        self.0.to_base58()
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut t = serializer.serialize_tuple(self.0.len())?;
        for c in self.0 {
            t.serialize_element(&c)?;
        }
        t.end()
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IdVisitor;
        impl<'de> Visitor<'de> for IdVisitor {
            type Value = Id;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an array of length {}", Id::default().0.len())
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
        deserializer.deserialize_tuple(Self::default().0.len(), IdVisitor)
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
            ::postcard::experimental::max_size::MaxSize,
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
            pub const fn as_array(&self) -> &[u8; 64] {
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

        impl ::core::convert::From<$crate::generic_array::GenericArray<u8, $crate::typenum::U64>>
            for $name
        {
            #[inline]
            fn from(id: $crate::generic_array::GenericArray<u8, $crate::typenum::U64>) -> Self {
                Self(id.into())
            }
        }

        impl ::core::convert::From<[u8; 64]> for $name {
            #[inline]
            fn from(id: [u8; 64]) -> Self {
                Self(id.into())
            }
        }

        impl ::core::convert::From<$name> for [u8; 64] {
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
    };
}
pub(crate) use custom_id;

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
        + MaxSize
        + Into<Id>;

    /// Uniquely identifies the object.
    fn id(&self) -> Self::Id;
}
