use alloc::vec::Vec;
use core::ops::Deref;

use rkyv::{
    Archive, Deserialize, DeserializeUnsized, Serialize,
    bytecheck::Verify,
    rancor::Fallible,
    ser::{Allocator, Writer},
    vec::{ArchivedVec, VecResolver},
};

/// A non-empty sequence of items.
///
/// - Construct via `TryFrom`.
#[derive(Debug)]
pub struct NonEmpty<T>(Vec<T>);

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
#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("operation would create an empty `NonEmpty`")]
pub struct Empty;

/// An archived [`NonEmpty`].
#[derive(rkyv::Portable, rkyv::bytecheck::CheckBytes)]
#[bytecheck(crate = rkyv::bytecheck)]
#[bytecheck(verify)]
#[repr(transparent)]
pub struct ArchivedNonEmpty<T>(ArchivedVec<T>);

impl<T> ArchivedNonEmpty<T> {
    /// Gets the last item in the sequence.
    pub fn last(&self) -> &T {
        self.0.last().expect("non-empty")
    }

    /// Gets the index of the last item in the sequence.
    pub fn last_index(&self) -> usize {
        self.0.len().checked_sub(1).expect("non-empty")
    }
}

impl<T> Deref for ArchivedNonEmpty<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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
