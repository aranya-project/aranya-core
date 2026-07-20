//! [`NamedMap`] and associated traits and types.

use core::fmt;
use std::collections::{BTreeMap, btree_map};

use aranya_policy_ast::{Ident, Identifier, Param};

macro_rules! named {
    ($ty:ty) => {
        impl $crate::named::Named for $ty {
            fn name(&self) -> &Ident {
                &self.name
            }
        }
    };
}
pub(crate) use named;

/// A [`Named`] type has a name field and can be used in [`NamedMap`].
pub trait Named {
    /// The name of this value.
    ///
    /// This method should be pure and return the same name every time.
    fn name(&self) -> &Ident; // TODO(Steve): Update doc comments (and rename this trait to NameLoc?)
}

named!(Param);

/// A mapping of named values which preserves insertion order.
///
/// `V` must implement [`Named`].
#[derive(
    Clone, serde::Serialize, serde::Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[serde(transparent)]
#[serde(bound(
    serialize = "V: serde::Serialize + Named",
    deserialize = "V: serde::de::DeserializeOwned + Named"
))]
pub struct NamedMap<V> {
    set: indexmap::IndexSet<ByName<V>, fnv::FnvBuildHasher>,
}

impl<V> NamedMap<V> {
    /// Create an empty map.
    pub const fn new() -> Self {
        Self {
            set: indexmap::IndexSet::with_hasher(core::hash::BuildHasherDefault::new()),
        }
    }

    /// Return the number of items in the map.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Returns an iterator over the items of the map.
    ///
    /// The items are guaranteed to be in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &V> {
        self.set.iter().map(|x| &x.0)
    }
}

/// An error indicating an attempt to insert a duplicate entry.
#[derive(Clone, Debug, thiserror::Error)]
#[error("An entry with that name already exists")]
pub struct AlreadyExists {
    /// The identifier of the previously inserted entry.
    pub existing: Ident,
}

impl<V: Named> NamedMap<V> {
    /// Insert an item into the map.
    ///
    /// Returns an error if an entry with the same name already exists.
    pub fn insert(&mut self, val: V) -> Result<(), AlreadyExists> {
        match self.set.replace(ByName(val)) {
            None => Ok(()),
            Some(old) => Err(AlreadyExists {
                existing: old.0.name().clone(),
            }),
        }
    }

    /// Look up an entry for the given name.
    pub fn get(&self, name: impl AsRef<str>) -> Option<&V> {
        self.set.get(name.as_ref()).map(|x| &x.0)
    }

    /// Returns true if the map contains an entry for the given name.
    pub fn contains(&self, name: impl AsRef<str>) -> bool {
        self.set.contains(name.as_ref())
    }
}

impl<V> Default for NamedMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Named + PartialEq> PartialEq for NamedMap<V> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self.set.iter().all(|x| {
                other
                    .set
                    .get(x.0.name().as_str())
                    .is_some_and(|y| V::eq(&x.0, &y.0))
            })
    }
}
impl<V: Named + Eq> Eq for NamedMap<V> {}

impl<V: fmt::Debug> fmt::Debug for NamedMap<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.set, f)
    }
}

#[derive(
    Copy,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[serde(transparent)]
struct ByName<V>(V);

impl<V: Named> PartialEq for ByName<V> {
    fn eq(&self, other: &Self) -> bool {
        self.0.name() == other.0.name()
    }
}
impl<V: Named> Eq for ByName<V> {}

impl<V: Named> core::hash::Hash for ByName<V> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.name().hash(state);
    }
}

impl<V: Named> core::borrow::Borrow<str> for ByName<V> {
    fn borrow(&self) -> &str {
        self.0.name().as_str()
    }
}

impl<V: fmt::Debug> fmt::Debug for ByName<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

/// Convenience macro for implementing [`NamedItem`] on a type
macro_rules! named_item {
    ($ty:ty) => {
        impl $crate::named::NamedItem for $ty {
            fn name(&self) -> &Identifier {
                &self.name
            }
        }
    };
}
pub(crate) use named_item;

/// Implements an item that can report its own name, for storing in a `NamedSet`.
pub trait NamedItem {
    /// Get the name of the item
    fn name(&self) -> &Identifier;
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A set of items, indexed by their name.
pub struct NamedSet<T: NamedItem>(BTreeMap<Identifier, T>);

impl<T: NamedItem> NamedSet<T> {
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
    pub fn get(&self, key: &Identifier) -> Option<&T> {
        self.0.get(key)
    }

    /// Does the set contain an item with this name?
    pub fn contains_key(&self, key: &Identifier) -> bool {
        self.0.contains_key(key)
    }

    /// Iterate over the set, returning items by reference.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }
}

impl<T: NamedItem> IntoIterator for NamedSet<T> {
    type Item = T;

    type IntoIter = btree_map::IntoValues<Identifier, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_values()
    }
}

impl<T: NamedItem> FromIterator<(Identifier, T)> for NamedSet<T> {
    fn from_iter<I: IntoIterator<Item = (Identifier, T)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}