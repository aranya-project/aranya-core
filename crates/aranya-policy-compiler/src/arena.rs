use std::{
    fmt,
    hash::Hash,
    iter::{Enumerate, ExactSizeIterator, FusedIterator},
    marker::PhantomData,
    ops::Index,
    slice,
};

use serde::{Deserialize, Serialize};

pub(crate) trait Key:
    Copy + Clone + fmt::Debug + Eq + PartialEq + Hash + Sized + 'static
{
    fn to_usize(self) -> usize;
    fn from_usize(id: usize) -> Self;
}

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
    pub fn insert(&mut self, item: V) -> K {
        self.insert_with_key(|_| item)
    }

    pub fn insert_with_key<F>(&mut self, f: F) -> K
    where
        F: FnOnce(K) -> V,
    {
        let id = self.items.len();
        let item = f(K::from_usize(id));
        self.items.push(item);
        K::from_usize(id)
    }

    pub fn get(&self, id: K) -> Option<&V> {
        self.items.get(id.to_usize())
    }

    pub fn get_mut(&mut self, id: K) -> Option<&mut V> {
        self.items.get_mut(id.to_usize())
    }

    pub fn iter(&self) -> ArenaIter<'_, K, V> {
        ArenaIter {
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
    type IntoIter = ArenaIter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub(crate) struct ArenaIter<'a, K, V> {
    iter: Enumerate<slice::Iter<'a, V>>,
    _marker: PhantomData<fn() -> K>,
}

impl<'a, K, V> Iterator for ArenaIter<'a, K, V>
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

impl<K, V> ExactSizeIterator for ArenaIter<'_, K, V>
where
    K: Key,
{
    #[inline]
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl<K, V> FusedIterator for ArenaIter<'_, K, V> where K: Key {}

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
