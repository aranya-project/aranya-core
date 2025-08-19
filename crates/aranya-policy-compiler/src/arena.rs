use std::{
    fmt,
    hash::Hash,
    iter::{Enumerate, ExactSizeIterator, FusedIterator},
    marker::PhantomData,
    ops::Index,
    slice,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Uniquely identifies an item in an [`Arena`].
///
/// See [`new_key_type!`].
pub trait Key:
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
pub struct Arena<K, V> {
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

    /// Returns the number of items in the arena.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if the arena contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
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
pub struct Iter<'a, K, V> {
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

#[cfg(test)]
mod tests {
    use super::*;

    // Create a test key type for testing
    new_key_type! {
        struct TestKey;
    }

    #[test]
    fn test_arena_new() {
        let arena = Arena::<TestKey, String>::new();
        assert_eq!(arena.len(), 0);
        assert!(arena.is_empty());
    }

    #[test]
    fn test_arena_insert_and_len() {
        let mut arena = Arena::<TestKey, String>::new();

        // Initially empty
        assert_eq!(arena.len(), 0);
        assert!(arena.is_empty());

        // Insert first item
        let key1 = arena.insert("hello".to_string());
        assert_eq!(arena.len(), 1);
        assert!(!arena.is_empty());

        // Insert second item
        let key2 = arena.insert("world".to_string());
        assert_eq!(arena.len(), 2);
        assert!(!arena.is_empty());

        // Insert third item
        let key3 = arena.insert("test".to_string());
        assert_eq!(arena.len(), 3);
        assert!(!arena.is_empty());

        // Verify keys are sequential
        assert_eq!(key1.0, 0);
        assert_eq!(key2.0, 1);
        assert_eq!(key3.0, 2);
    }

    #[test]
    fn test_arena_get() {
        let mut arena = Arena::<TestKey, i32>::new();

        let key1 = arena.insert(42);
        let key2 = arena.insert(100);

        assert_eq!(arena.get(key1), Some(&42));
        assert_eq!(arena.get(key2), Some(&100));
        assert_eq!(arena.get(TestKey::from_usize(999)), None);
    }

    #[test]
    fn test_arena_contains() {
        let mut arena = Arena::<TestKey, String>::new();

        let key = arena.insert("test".to_string());

        assert!(arena.contains(key));
        assert!(!arena.contains(TestKey::from_usize(999)));
    }

    #[test]
    fn test_arena_iter() {
        let mut arena = Arena::<TestKey, i32>::new();

        let key1 = arena.insert(10);
        let key2 = arena.insert(20);
        let key3 = arena.insert(30);

        let items: Vec<_> = arena.iter().collect();
        assert_eq!(items.len(), 3);

        // Verify items are in order
        assert_eq!(items[0], (key1, &10));
        assert_eq!(items[1], (key2, &20));
        assert_eq!(items[2], (key3, &30));
    }

    #[test]
    fn test_arena_default() {
        let arena = Arena::<TestKey, String>::default();
        assert_eq!(arena.len(), 0);
        assert!(arena.is_empty());
    }
}
