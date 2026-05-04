use alloc::vec::Vec;
use core::{
    fmt,
    ops::{Deref, DerefMut},
};

use rkyv::{
    Archive, Deserialize, DeserializeUnsized, Serialize,
    bytecheck::Verify,
    rancor::Fallible,
    ser::{Allocator, Writer},
    vec::{ArchivedVec, VecResolver},
};
use rkyv_impl::archive_impl;

pub trait DeserInfallible<T>:
    Deserialize<T, rkyv::api::low::LowDeserializer<core::convert::Infallible>>
{
    fn deser_infallible(&self) -> T;
}

impl<T, U> DeserInfallible<T> for U
where
    U: Deserialize<T, rkyv::api::low::LowDeserializer<core::convert::Infallible>>,
{
    fn deser_infallible(&self) -> T {
        match rkyv::api::low::deserialize(self) {
            Ok(v) => v,
        }
    }
}

/// A non-empty sequence of items.
///
/// - Construct via `TryFrom`.
/// - Use as `&[T]` via deref.
#[derive(Debug)]
pub struct NonEmpty<T>(Vec<T>);

#[archive_impl]
impl<T> NonEmpty<T> {
    /// Gets the first item in the sequence.
    pub fn first(&self) -> &T {
        self.0.first().expect("non-empty")
    }

    /// Gets the last item in the sequence.
    pub fn last(&self) -> &T {
        self.0.last().expect("non-empty")
    }

    /// Gets the index of the last item in the sequence.
    pub fn last_index(&self) -> usize {
        self.0.len().checked_sub(1).expect("non-empty")
    }
}

#[archive_impl]
impl<T> Deref for NonEmpty<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for NonEmpty<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> TryFrom<Vec<T>> for NonEmpty<T> {
    type Error = Empty;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Empty)
        } else {
            Ok(Self(value))
        }
    }
}

/// An operation would create an empty [`NonEmpty`].
#[derive(Copy, Clone, Debug)]
pub struct Empty;

impl core::error::Error for Empty {}

impl fmt::Display for Empty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operation would create an empty `NonEmpty`")
    }
}

/// An archived [`NonEmpty`].
#[derive(rkyv::Portable, rkyv::bytecheck::CheckBytes)]
#[bytecheck(crate = rkyv::bytecheck)]
#[bytecheck(verify)]
#[repr(transparent)]
pub struct ArchivedNonEmpty<T>(ArchivedVec<T>);

/// The resolver for [`ArchivedNonEmpty`].
pub struct NonEmptyResolver(VecResolver);

impl<T: Archive> Archive for NonEmpty<T> {
    type Archived = ArchivedNonEmpty<T::Archived>;
    type Resolver = NonEmptyResolver;

    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        // SAFETY: `ArchivedNonEmpty<T>` is transparent repr over `ArchivedVec<T>`.
        let out = unsafe { out.cast_unchecked() };
        self.0.resolve(resolver.0, out);
    }
}

impl<T, S> Serialize<S> for NonEmpty<T>
where
    T: Serialize<S>,
    S: Writer + Allocator + Fallible + ?Sized,
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        self.0.serialize(serializer).map(NonEmptyResolver)
    }
}

impl<T, D> Deserialize<NonEmpty<T>, D> for ArchivedNonEmpty<T::Archived>
where
    T: Archive,
    D: Fallible<Error: rkyv::rancor::Source> + ?Sized,
    [T::Archived]: DeserializeUnsized<[T], D>,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<NonEmpty<T>, D::Error> {
        self.0.deserialize(deserializer).map(NonEmpty)
    }
}

unsafe impl<T, C> Verify<C> for ArchivedNonEmpty<T>
where
    C: Fallible<Error: rkyv::rancor::Source> + ?Sized,
{
    fn verify(&self, _: &mut C) -> Result<(), C::Error> {
        if self.0.is_empty() {
            rkyv::rancor::fail!(Empty);
        }
        Ok(())
    }
}
