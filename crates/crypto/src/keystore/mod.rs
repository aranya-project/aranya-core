//! Wrapped cryptographic key storage.

use core::fmt;

use crate::{
    engine::{Engine, UnwrappedKey, WrappedKey},
    id::Id,
};

pub mod memstore;

/// Stores wrapped secret key material.
pub trait KeyStore {
    /// The error returned by the trait methods.
    type Error: Error;

    /// A vacant entry.
    type Vacant<'a>: Vacant<Error = Self::Error>;

    /// An occupied entry.
    type Occupied<'a>: Occupied<Error = Self::Error>;

    /// Accesses a particular entry.
    fn entry(&mut self, id: Id) -> Result<Entry<'_, Self>, Self::Error>;

    /// Retrieves a stored `WrappedKey`.
    fn get<T: WrappedKey>(&self, id: &Id) -> Result<Option<T>, Self::Error>;

    /// Stores a `WrappedKey`.
    ///
    /// It is an error if the key already exists.
    fn try_insert<T: WrappedKey>(&mut self, id: Id, key: T) -> Result<(), Self::Error> {
        match self.entry(id)? {
            Entry::Vacant(v) => v.insert(key),
            Entry::Occupied(_) => Err(<Self as KeyStore>::Error::new(
                ErrorKind::AlreadyExists,
                DuplicateKey,
            )),
        }
    }

    /// Retrieves and removes a stored `WrappedKey`.
    fn remove<T: WrappedKey>(&mut self, id: &Id) -> Result<Option<T>, Self::Error> {
        match self.entry(*id)? {
            Entry::Vacant(_) => Ok(None),
            Entry::Occupied(v) => Ok(Some(v.remove()?)),
        }
    }
}

/// A view into a [`KeyStore`] entry.
pub enum Entry<'a, S>
where
    S: KeyStore + ?Sized,
{
    /// A vacant entry.
    Vacant(S::Vacant<'a>),
    /// An occupied entry.
    Occupied(S::Occupied<'a>),
}

/// A vacant entry.
pub trait Vacant {
    /// The error returned by [`insert`][Self::insert].
    type Error: Error;

    /// Inserts the entry.
    fn insert<T: WrappedKey>(self, key: T) -> Result<(), Self::Error>;
}

/// An occupied entry.
pub trait Occupied {
    /// The error returned by [`get`][Self::get] and
    /// [`remove`][Self::remove].
    type Error: Error;

    /// Retrieves the entry.
    fn get<T: WrappedKey>(&self) -> Result<T, Self::Error>;
    /// Retrieves and removes the entry.
    fn remove<T: WrappedKey>(self) -> Result<T, Self::Error>;
}

#[derive(Debug)]
struct DuplicateKey;

impl fmt::Display for DuplicateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key already exists")
    }
}

impl trouble::Error for DuplicateKey {}

/// An error returned by [`KeyStore`].
pub trait Error: trouble::Error + Send + Sync + 'static + Sized {
    /// Creates a new [`Error`].
    fn new<E>(kind: ErrorKind, err: E) -> Self
    where
        E: trouble::Error + Send + Sync + 'static;

    /// Shorthand for [`new`][Self::new] with
    /// [`ErrorKind::Other`].
    fn other<E>(err: E) -> Self
    where
        E: trouble::Error + Send + Sync + 'static,
    {
        Self::new(ErrorKind::Other, err)
    }

    /// Identifies the type of error.
    fn kind(&self) -> ErrorKind;
}

/// Categories of errors.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The entry already exists.
    AlreadyExists,
    /// Any other error.
    Other,
}

/// An extension trait.
pub trait KeyStoreExt: KeyStore {
    /// Retrieves and unwraps the key.
    fn get_key<E, K>(&self, eng: &mut E, id: &Id) -> Result<Option<K>, Self::Error>
    where
        E: Engine + ?Sized,
        K: UnwrappedKey<E>;

    /// Removes and unwraps the key.
    fn remove_key<E, K>(&mut self, eng: &mut E, id: &Id) -> Result<Option<K>, Self::Error>
    where
        E: Engine + ?Sized,
        K: UnwrappedKey<E>;
}

impl<T: KeyStore> KeyStoreExt for T {
    /// Retrieves and unwraps the key.
    fn get_key<E, K>(&self, eng: &mut E, id: &Id) -> Result<Option<K>, Self::Error>
    where
        E: Engine + ?Sized,
        K: UnwrappedKey<E>,
    {
        if let Some(wrapped) = self.get(id)? {
            let sk = eng
                .unwrap(&wrapped)
                .map_err(<<Self as KeyStore>::Error>::other)?;
            Ok(Some(sk))
        } else {
            Ok(None)
        }
    }

    /// Removes and unwraps the key.
    fn remove_key<E, K>(&mut self, eng: &mut E, id: &Id) -> Result<Option<K>, Self::Error>
    where
        E: Engine + ?Sized,
        K: UnwrappedKey<E>,
    {
        if let Some(wrapped) = self.remove(id)? {
            let sk = eng
                .unwrap(&wrapped)
                .map_err(<<Self as KeyStore>::Error>::other)?;
            Ok(Some(sk))
        } else {
            Ok(None)
        }
    }
}