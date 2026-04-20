use alloc::boxed::Box;
use core::{
    fmt::{self, Debug},
    ops::Deref,
};

/// Either a reference or a box.
pub enum RefOrBox<'a, T: ?Sized> {
    /// A reference.
    Ref(&'a T),
    /// A box.
    Box(Box<T>),
}

impl<T> RefOrBox<'_, T>
where
    T: ?Sized,
{
    /// Gets a reference to the underlying value.
    pub const fn as_ref(&self) -> &T {
        match self {
            Self::Ref(x) => x,
            Self::Box(x) => x,
        }
    }
}

impl<T> Clone for RefOrBox<'_, T>
where
    T: ?Sized,
    Box<T>: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Ref(x) => Self::Ref(x),
            Self::Box(x) => Self::Box(x.clone()),
        }
    }
}

impl<T> Debug for RefOrBox<'_, T>
where
    T: Debug + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl<T> PartialEq for RefOrBox<'_, T>
where
    T: PartialEq + ?Sized,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl<T> Eq for RefOrBox<'_, T> where T: Eq + ?Sized {}

impl<T> Deref for RefOrBox<'_, T>
where
    T: ?Sized,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

mod impl_serde {
    use alloc::boxed::Box;

    use serde::{Deserialize, Serialize};

    use super::RefOrBox;

    impl<'a, T> Serialize for RefOrBox<'a, T>
    where
        T: Serialize + ?Sized,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.as_ref().serialize(serializer)
        }
    }

    impl<'de, 'a, T> Deserialize<'de> for RefOrBox<'a, T>
    where
        T: ?Sized,
        Box<T>: Deserialize<'de>,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            <Box<T>>::deserialize(deserializer).map(Self::Box)
        }
    }
}

mod impl_rkyv {
    use alloc::boxed::Box;

    use rkyv::{
        Archive, ArchiveUnsized, Deserialize, DeserializeUnsized, Serialize, SerializeUnsized,
        rancor::{Fallible, Source},
        traits::LayoutRaw,
    };

    use super::RefOrBox;

    impl<'a, T> Archive for RefOrBox<'a, T>
    where
        T: ArchiveUnsized + ?Sized,
    {
        type Archived = rkyv::boxed::ArchivedBox<T::Archived>;
        type Resolver = rkyv::boxed::BoxResolver;

        fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
            rkyv::boxed::ArchivedBox::resolve_from_ref(self.as_ref(), resolver, out);
        }
    }

    impl<'a, T, S> Serialize<S> for RefOrBox<'a, T>
    where
        T: SerializeUnsized<S> + ?Sized,
        S: Fallible + ?Sized,
    {
        fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
            rkyv::boxed::ArchivedBox::serialize_from_ref(self.as_ref(), serializer)
        }
    }

    impl<'a, T, D> Deserialize<RefOrBox<'a, T>, D> for rkyv::boxed::ArchivedBox<T::Archived>
    where
        T: ArchiveUnsized + LayoutRaw + ?Sized,
        T::Archived: DeserializeUnsized<T, D>,
        D: Fallible + ?Sized,
        D::Error: Source,
    {
        fn deserialize(
            &self,
            deserializer: &mut D,
        ) -> Result<RefOrBox<'a, T>, <D as Fallible>::Error> {
            <Self as Deserialize<Box<T>, D>>::deserialize(self, deserializer).map(RefOrBox::Box)
        }
    }
}
