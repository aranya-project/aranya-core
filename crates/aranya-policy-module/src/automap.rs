//! An [`AutoMap`] is a map where the item can automatically provide its
//! own key through the [`AutoKey`] trait.

extern crate alloc;

use alloc::collections::{BTreeMap, btree_map};

/// Convenience macro for implementing [`AutoKey`] on a type
macro_rules! autokey_by_name {
    ($ty:ty) => {
        impl $crate::automap::AutoKey for $ty {
            type Key = Identifier;
            fn name(&self) -> &Identifier {
                &self.name
            }
        }

        impl Ord for $ty {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.name.cmp(&other.name)
            }
        }

        impl PartialOrd for $ty {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(&other))
            }
        }
    };
}
pub(crate) use autokey_by_name;

/// Trait for an item that can report its own key, for storing in an AutoMap
pub trait AutoKey {
    /// The type of the item's key
    type Key: Ord + PartialEq + Clone;
    /// Get the name of the item
    fn name(&self) -> &Self::Key;
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A set of items, indexed by their name.
pub struct AutoMap<T: AutoKey>(BTreeMap<T::Key, T>);

impl<T: AutoKey> AutoMap<T> {
    /// Create a new, empty `NamedSet`.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Insert an item into the `NamedSet`
    pub fn insert(&mut self, item: T) -> Option<T> {
        self.0.insert(item.name().clone(), item)
    }

    /// Retrieve an item by its name, and return a reference to it if it exists.
    pub fn get(&self, key: &T::Key) -> Option<&T> {
        self.0.get(key)
    }

    /// Does the set contain an item with this name?
    pub fn contains_key(&self, key: &T::Key) -> bool {
        self.0.contains_key(key)
    }

    /// Iterate over the set, returning items by reference.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }
}

impl<T: AutoKey> IntoIterator for AutoMap<T> {
    type Item = T;

    type IntoIter = btree_map::IntoValues<T::Key, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_values()
    }
}

impl<T: AutoKey> FromIterator<(T::Key, T)> for AutoMap<T> {
    fn from_iter<I: IntoIterator<Item = (T::Key, T)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}
