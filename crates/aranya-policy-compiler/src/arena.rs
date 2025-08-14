use std::{
    fmt,
    hash::Hash,
    iter::{Enumerate, ExactSizeIterator, FusedIterator},
    marker::PhantomData,
    ops::Index,
    slice,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Uniquely identifies an item in an [`Arena`].
///
/// See [`new_key_type!`].
pub(crate) trait Key:
    Copy
    + Clone
    + fmt::Debug
    + fmt::Display
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Hash
    + Sized
    + Serialize
    + DeserializeOwned
    + 'static
{
    #[doc(hidden)]
    fn to_usize(self) -> usize;

    #[doc(hidden)]
    fn from_usize(id: usize) -> Self;
}

/// A collection of items that are deallocated together.
///
/// Each item is assigned a unique key when inserted into the
/// arena. The key implements [`Ord`] such that the first key is
/// ordered before the second, the second before the third, etc.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Arena<K, V> {
    items: Vec<V>,
    _marker: PhantomData<fn() -> K>,
}

impl<K, V> Arena<K, V> {
    pub const fn new() -> Self {
        Self {
            items: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<K, V> Arena<K, V>
where
    K: Key,
{
    /// Adds an item to the arena and returns its unique key.
    pub fn insert(&mut self, item: V) -> K {
        self.insert_with_key(|_| item)
    }

    /// Same as [`insert`][Self::insert], but passed the key to
    /// `f`.
    ///
    /// This is useful for items that contain their own key.
    pub fn insert_with_key<F>(&mut self, f: F) -> K
    where
        F: FnOnce(K) -> V,
    {
        let id = self.items.len();
        let item = f(K::from_usize(id));
        self.items.push(item);
        K::from_usize(id)
    }

    /// Reports whether the arena contains an item.
    pub fn contains(&self, key: K) -> bool {
        self.get(key).is_some()
    }

    /// Retrieves a shared reference to an item.
    pub fn get(&self, key: K) -> Option<&V> {
        self.items.get(key.to_usize())
    }

    /// Retrieves an exclusive reference to an item.
    pub fn get_mut(&mut self, key: K) -> Option<&mut V> {
        self.items.get_mut(key.to_usize())
    }

    /// Returns an itereator over the items in the arena.
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            iter: self.items.iter().enumerate(),
            _marker: PhantomData,
        }
    }
}

impl<K, V> Index<K> for Arena<K, V>
where
    K: Key,
{
    type Output = V;

    fn index(&self, id: K) -> &Self::Output {
        &self.items[id.to_usize()]
    }
}

impl<K, V> Default for Arena<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K, V> IntoIterator for &'a Arena<K, V>
where
    K: Key,
{
    type Item = (K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator over the items in an [`Arena`].
pub(crate) struct Iter<'a, K, V> {
    iter: Enumerate<slice::Iter<'a, V>>,
    _marker: PhantomData<fn() -> K>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V>
where
    K: Key,
{
    type Item = (K, &'a V);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(i, v)| (K::from_usize(i), v))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.iter.count()
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        self.iter.last().map(|(i, v)| (K::from_usize(i), v))
    }

    #[inline]
    fn fold<B, F>(self, acc: B, mut f: F) -> B
    where
        F: FnMut(B, Self::Item) -> B,
    {
        self.iter
            .fold(acc, |acc, (i, v)| f(acc, (K::from_usize(i), v)))
    }
}

impl<K, V> ExactSizeIterator for Iter<'_, K, V>
where
    K: Key,
{
    #[inline]
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl<K, V> FusedIterator for Iter<'_, K, V> where K: Key {}

/// Creates a new key type for use in an [`Arena`].
macro_rules! new_key_type {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$meta])*
        #[derive(
            Copy,
            Clone,
            Default,
            Debug,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            std::hash::Hash,
            ::serde::Serialize,
            ::serde::Deserialize,
        )]
        $vis struct $name(pub u32);

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl $crate::arena::Key for $name {
            #[inline]
            fn to_usize(self) -> usize {
                self.0.try_into().unwrap()
            }

            #[inline]
            fn from_usize(id: usize) -> Self {
                Self(id.try_into().unwrap())
            }
        }
    };
}
pub(crate) use new_key_type;
