//! An in-memory implementation of [`KeyStore`].

#![cfg(feature = "alloc")]
#![cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{
    boxed::Box,
    collections::btree_map::{self, BTreeMap},
    vec::Vec,
};
use core::{fmt, marker::PhantomData, ops::Deref};

use super::{Entry, ErrorKind, KeyStore, Occupied, Vacant};
use crate::{engine::WrappedKey, id::Id};

/// An in-memory implementation of [`KeyStore`].
#[derive(Clone, Default, Debug)]
pub struct MemStore {
    keys: BTreeMap<Id, StoredKey>,
}

impl MemStore {
    /// Creates an empty [`MemStore`].
    #[inline]
    pub const fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }
}

impl KeyStore for MemStore {
    type Error = Error;

    type Vacant<'a, T: WrappedKey> = VacantEntry<'a, T>;
    type Occupied<'a, T: WrappedKey> = OccupiedEntry<'a, T>;

    fn entry<T: WrappedKey>(&mut self, id: Id) -> Result<Entry<'_, Self, T>, Self::Error> {
        match self.keys.entry(id) {
            btree_map::Entry::Vacant(entry) => Ok(Entry::Vacant(VacantEntry {
                entry,
                _t: PhantomData,
            })),
            btree_map::Entry::Occupied(entry) => Ok(Entry::Occupied(OccupiedEntry {
                entry,
                _t: PhantomData,
            })),
        }
    }

    fn get<T: WrappedKey>(&self, id: &Id) -> Result<Option<T>, Self::Error> {
        match self.keys.get(id) {
            Some(v) => Ok(Some(v.to_wrapped()?)),
            None => Ok(None),
        }
    }
}

/// An implementation of [`WrappedKey`].
#[derive(Clone, Debug)]
struct StoredKey(Vec<u8>);

impl StoredKey {
    fn new<T: WrappedKey>(key: T) -> Result<Self, Error> {
        let data = postcard::to_allocvec(&key)
            .map_err(|_| <Error as super::Error>::other(EncodingError))?;
        Ok(Self(data))
    }

    fn to_wrapped<T: WrappedKey>(&self) -> Result<T, Error> {
        postcard::from_bytes(&self.0).map_err(|_| <Error as super::Error>::other(DecodingError))
    }
}

/// A vacant entry.
pub struct VacantEntry<'a, T> {
    entry: btree_map::VacantEntry<'a, Id, StoredKey>,
    _t: PhantomData<T>,
}

impl<T: WrappedKey> Vacant<T> for VacantEntry<'_, T> {
    type Error = Error;

    fn insert(self, key: T) -> Result<(), Self::Error> {
        self.entry.insert(StoredKey::new(key)?);
        Ok(())
    }
}

/// An occupied entry.
pub struct OccupiedEntry<'a, T> {
    entry: btree_map::OccupiedEntry<'a, Id, StoredKey>,
    _t: PhantomData<T>,
}

impl<T: WrappedKey> Occupied<T> for OccupiedEntry<'_, T> {
    type Error = Error;

    fn get(&self) -> Result<T, Self::Error> {
        self.entry.get().to_wrapped()
    }

    fn remove(self) -> Result<T, Self::Error> {
        self.entry.remove().to_wrapped()
    }
}

/// An error returned by [`MemStore`].
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    err: Box<dyn trouble::Error + Send + Sync + 'static>,
}

impl Error {
    /// Attempts to downcast the error into `T`.
    #[inline]
    pub fn downcast_ref<T: trouble::Error + 'static>(&self) -> Option<&T> {
        self.err.downcast_ref::<T>()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.err)
    }
}

impl trouble::Error for Error {
    fn source(&self) -> Option<&(dyn trouble::Error + 'static)> {
        Some(self.err.deref())
    }
}

impl super::Error for Error {
    fn new<E>(kind: ErrorKind, err: E) -> Self
    where
        E: trouble::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            err: Box::new(err),
        }
    }

    #[inline]
    fn kind(&self) -> ErrorKind {
        self.kind
    }
}

#[derive(Debug)]
struct EncodingError;

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unable to encode key")
    }
}

impl trouble::Error for EncodingError {}

#[derive(Debug)]
struct DecodingError;

impl fmt::Display for DecodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unable to decode key")
    }
}

impl trouble::Error for DecodingError {}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::{
        default::DefaultCipherSuite,
        id::{Id, Identified},
    };

    macro_rules! id {
        ($id:expr) => {{
            let data = ($id as u64).to_le_bytes();
            Id::new::<DefaultCipherSuite>(&data, b"TestKey")
        }};
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct TestKey64(u64);

    impl WrappedKey for TestKey64 {}

    impl Identified for TestKey64 {
        type Id = Id;

        fn id(&self) -> Self::Id {
            id!(self.0)
        }
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct TestKeyId(Id);

    impl WrappedKey for TestKeyId {}

    impl Identified for TestKeyId {
        type Id = Id;

        fn id(&self) -> Self::Id {
            self.0
        }
    }

    #[test]
    fn test_get() {
        let mut store = MemStore::new();

        let want = TestKey64(1);
        store
            .try_insert(id!(1), want)
            .expect("should be able to store key");
        let got = store
            .get::<TestKey64>(&id!(1))
            .expect("`get` should not fail")
            .expect("should be able to find key");
        assert_eq!(got, want);
    }

    #[test]
    fn test_get_wrong_key_type() {
        let mut store = MemStore::new();

        let want = TestKey64(1);
        store
            .try_insert(id!(1), want)
            .expect("should be able to store key");
        store
            .get::<TestKeyId>(&id!(1))
            .expect_err("should not be able to get key");
    }

    #[test]
    fn test_remove() {
        let mut store = MemStore::new();

        store
            .try_insert(id!(1), TestKey64(1))
            .expect("should be able to store key");
        store
            .try_insert(id!(2), TestKey64(2))
            .expect("should be able to store key");

        let got = store
            .remove::<TestKey64>(&id!(1))
            .expect("`remove` should not fail")
            .expect("should be able to find key");
        assert_eq!(got, TestKey64(1));

        // After removing key=1, key=2 should still exist.
        let got = store
            .get::<TestKey64>(&id!(2))
            .expect("`get` should not fail")
            .expect("should be able to find key");
        assert_eq!(got, TestKey64(2));

        // But key=1 should not.
        assert!(store
            .get::<TestKey64>(&id!(1))
            .expect("`get` should not fail")
            .is_none());
    }
}
