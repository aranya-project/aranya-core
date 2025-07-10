//! Wrapped cryptographic key storage.

use aranya_id::{Id, IdTag};

use crate::engine::{Engine, UnwrappedKey, WrappedKey};

pub mod fs_keystore;
pub mod memstore;

/// Stores wrapped secret key material.
pub trait KeyStore {
    /// The error returned by the trait methods.
    type Error: Error;

    /// A vacant entry.
    type Vacant<'a, T: WrappedKey>: Vacant<T, Error = Self::Error>;

    /// An occupied entry.
    type Occupied<'a, T: WrappedKey>: Occupied<T, Error = Self::Error>;

    /// Accesses a particular entry.
    fn entry<T: WrappedKey>(
        &mut self,
        id: Id<impl IdTag>,
    ) -> Result<Entry<'_, Self, T>, Self::Error>;

    /// Retrieves a stored `WrappedKey`.
    fn get<T: WrappedKey>(&self, id: Id<impl IdTag>) -> Result<Option<T>, Self::Error>;

    /// Stores a `WrappedKey`.
    ///
    /// It is an error if the key already exists.
    fn try_insert<T: WrappedKey>(&mut self, id: Id<impl IdTag>, key: T) -> Result<(), Self::Error> {
        match self.entry(id)? {
            Entry::Vacant(v) => v.insert(key),
            Entry::Occupied(_) => Err(<Self as KeyStore>::Error::new(
                ErrorKind::AlreadyExists,
                DuplicateKey,
            )),
        }
    }

    /// Retrieves and removes a stored `WrappedKey`.
    fn remove<T: WrappedKey>(&mut self, id: Id<impl IdTag>) -> Result<Option<T>, Self::Error> {
        match self.entry(id)? {
            Entry::Vacant(_) => Ok(None),
            Entry::Occupied(v) => Ok(Some(v.remove()?)),
        }
    }
}

/// A view into a [`KeyStore`] entry.
pub enum Entry<'a, S, T>
where
    S: KeyStore + ?Sized,
    T: WrappedKey,
{
    /// A vacant entry.
    Vacant(S::Vacant<'a, T>),
    /// An occupied entry.
    Occupied(S::Occupied<'a, T>),
}

/// A vacant entry.
pub trait Vacant<T: WrappedKey> {
    /// The error returned by [`insert`][Self::insert].
    type Error: Error;

    /// Inserts the entry.
    fn insert(self, key: T) -> Result<(), Self::Error>;
}

/// An occupied entry.
pub trait Occupied<T: WrappedKey> {
    /// The error returned by [`get`][Self::get] and
    /// [`remove`][Self::remove].
    type Error: Error;

    /// Retrieves the entry.
    fn get(&self) -> Result<T, Self::Error>;
    /// Retrieves and removes the entry.
    fn remove(self) -> Result<T, Self::Error>;
}

#[derive(Debug, thiserror::Error)]
#[error("key already exists")]
struct DuplicateKey;

/// An error returned by [`KeyStore`].
pub trait Error: core::error::Error + Send + Sync + 'static + Sized {
    /// Creates a new [`Error`].
    fn new<E>(kind: ErrorKind, err: E) -> Self
    where
        E: core::error::Error + Send + Sync + 'static;

    /// Shorthand for [`new`][Self::new] with
    /// [`ErrorKind::Other`].
    fn other<E>(err: E) -> Self
    where
        E: core::error::Error + Send + Sync + 'static,
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
    fn get_key<E, K>(&self, eng: &mut E, id: Id<impl IdTag>) -> Result<Option<K>, Self::Error>
    where
        E: Engine,
        K: UnwrappedKey<E::CS>;

    /// Removes and unwraps the key.
    fn remove_key<E, K>(
        &mut self,
        eng: &mut E,
        id: Id<impl IdTag>,
    ) -> Result<Option<K>, Self::Error>
    where
        E: Engine,
        K: UnwrappedKey<E::CS>;
}

impl<T: KeyStore> KeyStoreExt for T {
    /// Retrieves and unwraps the key.
    fn get_key<E, K>(&self, eng: &mut E, id: Id<impl IdTag>) -> Result<Option<K>, Self::Error>
    where
        E: Engine,
        K: UnwrappedKey<E::CS>,
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
    fn remove_key<E, K>(
        &mut self,
        eng: &mut E,
        id: Id<impl IdTag>,
    ) -> Result<Option<K>, Self::Error>
    where
        E: Engine,
        K: UnwrappedKey<E::CS>,
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
