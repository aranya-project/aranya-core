use core::{
    fmt::{self, Debug, Display},
    marker::PhantomData,
    str::FromStr,
};

use derive_where::derive_where;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
};
use spideroak_base58::ToBase58;

/// A unique cryptographic ID.
///
/// IDs are intended to be public (non-secret) identifiers.
#[repr(C)]
#[derive_where(Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[derive(
    zerocopy_derive::Immutable,
    zerocopy_derive::IntoBytes,
    zerocopy_derive::KnownLayout,
    zerocopy_derive::Unaligned,
    zerocopy_derive::FromBytes,
)]
pub struct Id<Tag: IdTag> {
    bytes: [u8; 32],
    tag: PhantomData<Tag>,
}

#[doc(hidden)]
pub trait Sealed {}

/// A type that can be used as a tag for [`Id`].
///
/// Do not implement this yourself. Use [`custom_id`].
pub trait IdTag: Sealed {}

custom_id! {
    /// The base ID type.
    pub struct BaseId;
}

impl<Tag: IdTag> Id<Tag> {
    /// Same as [`Default`], but const.
    #[inline]
    pub const fn default() -> Self {
        Self::from_bytes([0u8; 32])
    }

    /// Creates itself from a byte array.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            tag: PhantomData,
        }
    }

    /// Creates itself from a [`BaseId`].
    #[inline]
    pub const fn from_base(id: BaseId) -> Self {
        Self::transmute(id)
    }

    /// Returns the ID as a byte slice.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the ID as a byte array.
    #[inline]
    pub const fn as_array(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Decode the ID from a base58 string.
    pub fn decode<T: AsRef<[u8]>>(s: T) -> Result<Self, ParseIdError> {
        let s32 = spideroak_base58::String32::decode(s).map_err(ParseIdError)?;
        Ok(Self::from_bytes(s32))
    }

    /// Convert from another tagged IDs.
    #[inline]
    pub const fn transmute<Other: IdTag>(id: Id<Other>) -> Self {
        Self::from_bytes(id.bytes)
    }

    /// Convert to [`BaseId`].
    #[inline]
    pub const fn as_base(self) -> BaseId {
        BaseId::transmute(self)
    }
}

impl<Tag: IdTag> Default for Id<Tag> {
    #[inline]
    fn default() -> Self {
        Self::default()
    }
}

impl<Tag: IdTag> subtle::ConstantTimeEq for Id<Tag> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<Tag: IdTag> AsRef<[u8]> for Id<Tag> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<Tag: IdTag> AsRef<BaseId> for Id<Tag> {
    fn as_ref(&self) -> &BaseId {
        zerocopy::transmute_ref!(self)
    }
}

impl<Tag: IdTag> From<[u8; 32]> for Id<Tag> {
    #[inline]
    fn from(id: [u8; 32]) -> Self {
        Self::from_bytes(id)
    }
}

impl<Tag: IdTag> From<Id<Tag>> for [u8; 32] {
    #[inline]
    fn from(id: Id<Tag>) -> Self {
        id.bytes
    }
}

impl<Tag: IdTag> FromStr for Id<Tag> {
    type Err = ParseIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(s)
    }
}

impl<Tag: IdTag> Debug for Id<Tag> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.to_base58())
    }
}

impl<Tag: IdTag> Display for Id<Tag> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl<Tag: IdTag> ToBase58 for Id<Tag> {
    type Output = spideroak_base58::String32;

    fn to_base58(&self) -> Self::Output {
        self.bytes.to_base58()
    }
}

impl<Tag: IdTag> Serialize for Id<Tag> {
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

impl<'de, Tag: IdTag> Deserialize<'de> for Id<Tag> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Base58Visitor<Tag>(PhantomData<Tag>);
        impl<Tag: IdTag> Visitor<'_> for Base58Visitor<Tag> {
            type Value = Id<Tag>;

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

        struct IdVisitor<Tag>(PhantomData<Tag>);
        impl<'de, Tag: IdTag> Visitor<'de> for IdVisitor<Tag> {
            type Value = Id<Tag>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "an array of length {}",
                    const { Id::<Tag>::default().bytes.len() }
                )
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
                let mut id = Id::<Tag>::default();
                for (i, v) in id.bytes.iter_mut().enumerate() {
                    match seq.next_element()? {
                        Some(e) => *v = e,
                        None => return Err(de::Error::invalid_length(i, &self)),
                    }
                }
                Ok(id)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Base58Visitor(PhantomData))
        } else {
            deserializer.deserialize_bytes(IdVisitor(PhantomData))
        }
    }
}

impl<Tag: IdTag> rkyv::Archive for Id<Tag> {
    type Archived = Self;
    type Resolver = ();

    fn resolve(&self, (): Self::Resolver, out: rkyv::Place<Self::Archived>) {
        out.write(*self);
    }
}

impl<Tag: IdTag, S: rkyv::rancor::Fallible + ?Sized> rkyv::Serialize<S> for Id<Tag> {
    #[inline]
    fn serialize(&self, _: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<Tag: IdTag, D: rkyv::rancor::Fallible + ?Sized> rkyv::Deserialize<Self, D> for Id<Tag> {
    #[inline]
    fn deserialize(&self, _: &mut D) -> Result<Self, D::Error> {
        Ok(*self)
    }
}

// SAFETY: All bit patterns are valid for `BaseId`.
unsafe impl<Tag: IdTag, C> rkyv::bytecheck::CheckBytes<C> for Id<Tag>
where
    C: rkyv::rancor::Fallible + ?Sized,
{
    unsafe fn check_bytes(_value: *const Self, _context: &mut C) -> Result<(), C::Error> {
        Ok(())
    }
}

// SAFETY: `BaseId` contains no padding or uninit bytes.
unsafe impl<Tag: IdTag> rkyv::traits::NoUndef for Id<Tag> {}

// SAFETY: `BaseId` has a consistent layout and no interior mutability.
unsafe impl<Tag: IdTag> rkyv::Portable for Id<Tag> {}

#[cfg(feature = "proptest")]
#[cfg_attr(docsrs, doc(cfg(feature = "proptest")))]
impl<Tag: IdTag> proptest::arbitrary::Arbitrary for Id<Tag> {
    type Parameters = <[u8; 32] as proptest::arbitrary::Arbitrary>::Parameters;
    type Strategy = proptest::strategy::Map<
        <[u8; 32] as proptest::arbitrary::Arbitrary>::Strategy,
        fn([u8; 32]) -> Self,
    >;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        {
            proptest::strategy::Strategy::prop_map(
                <[u8; 32] as proptest::arbitrary::Arbitrary>::arbitrary_with(params),
                Self::from_bytes,
            )
        }
    }
}

/// An error returned when parsing an ID from a string fails.
#[derive(Clone, Debug)]
pub struct ParseIdError(spideroak_base58::DecodeError);

impl Display for ParseIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse ID: {}", self.0)
    }
}

impl core::error::Error for ParseIdError {}

/// Creates a custom ID.
#[macro_export]
macro_rules! custom_id {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $crate::__hidden::paste! {
            mod [< __private_ $name:snake >] {
                #[doc = "Tag for [`" $name "`][super::" $name "]"]
                pub struct [< $name Tag >];

                impl $crate::__hidden::Sealed for [< $name Tag >] {}
                impl $crate::IdTag for [< $name Tag >] {}
            }

            $(#[$meta])*
            $vis type $name = $crate::Id<[< __private_ $name:snake >]::[< $name Tag >]>;
        }
    };
}
use custom_id;
