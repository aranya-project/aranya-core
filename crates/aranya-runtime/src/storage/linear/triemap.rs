use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::mem;

use rkyv::{Archive, Deserialize, Serialize};

use super::Bytes;

/// A `TrieMap` maps bytes keys `k1, k2, ..., kn` to a value, allowing for efficient prefix queries.
#[derive(Clone, Debug, Default, Archive, Serialize, Deserialize)]
pub struct TrieMap(Slot);

/// Tried to traverse past a leaf in a trie-map.
///
/// When used with [`crate::VmPolicy`] facts, this _should_ never trigger.
#[derive(Debug)]
pub struct InvalidDepth;

#[derive(Clone, Debug, Archive, Serialize, Deserialize)]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(
    bounds(
        __C: rkyv::validation::ArchiveContext,
        __C::Error: rkyv::rancor::Source,
    )
))]
enum Slot {
    Branch(#[rkyv(omit_bounds)] BTreeMap<Bytes, Self>),
    Leaf(Value),
}

/// Bytes value (`None` signals a tombstone).
type Value = Option<Bytes>;

impl Default for Slot {
    fn default() -> Self {
        Self::Branch(BTreeMap::default())
    }
}

impl TrieMap {
    /// Creates an empty `TrieMap`.
    pub const fn new() -> Self {
        Self(Slot::Branch(BTreeMap::new()))
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self(Slot::Branch(map)) if map.is_empty())
    }

    /// Inserts a keys/value pair.
    ///
    /// Returns the previous value if it existed.
    pub fn insert(
        &mut self,
        keys: impl IntoIterator<Item: AsRef<[u8]>>,
        value: Value,
    ) -> Result<Option<Value>, InvalidDepth> {
        let mut slot = &mut self.0;
        for key in keys {
            match slot {
                Slot::Branch(b) => slot = b.entry(key.as_ref().into()).or_default(),
                Slot::Leaf(_) => return Err(InvalidDepth),
            }
        }
        match slot {
            Slot::Leaf(l) => Ok(Some(mem::replace(l, value))),
            Slot::Branch(b) => {
                if !b.is_empty() {
                    return Err(InvalidDepth);
                }
                *slot = Slot::Leaf(value);
                Ok(None)
            }
        }
    }

    /// Inserts a keys/value pair if not already existing, creating the value lazily.
    ///
    /// Returns whether the value was newly inserted.
    pub fn try_insert_with(
        &mut self,
        keys: impl IntoIterator<Item: AsRef<[u8]>>,
        value: impl FnOnce() -> Value,
    ) -> Result<bool, InvalidDepth> {
        let mut slot = &mut self.0;
        for key in keys {
            match slot {
                Slot::Branch(b) => slot = b.entry(key.as_ref().into()).or_default(),
                Slot::Leaf(_) => return Err(InvalidDepth),
            }
        }
        match slot {
            Slot::Leaf(_) => Ok(false),
            Slot::Branch(b) => {
                if !b.is_empty() {
                    return Err(InvalidDepth);
                }
                *slot = Slot::Leaf(value());
                Ok(true)
            }
        }
    }

    /// Gets a value by exact keys query.
    pub fn get(
        &self,
        keys: impl IntoIterator<Item: AsRef<[u8]>>,
    ) -> Result<Option<Option<&[u8]>>, InvalidDepth> {
        let mut slot = &self.0;
        for key in keys {
            match slot {
                Slot::Branch(b) => match b.get(key.as_ref()) {
                    Some(s) => slot = s,
                    None => return Ok(None),
                },
                Slot::Leaf(_) => return Err(InvalidDepth),
            }
        }
        match slot {
            Slot::Branch(_) => Err(InvalidDepth),
            Slot::Leaf(l) => Ok(Some(l.as_deref())),
        }
    }

    /// Gets all values under a prefix of keys.
    pub fn get_by_prefix(
        &self,
        keys: impl IntoIterator<Item: AsRef<[u8]>>,
    ) -> Result<TrieMapIter<'_>, InvalidDepth> {
        let mut slot = &self.0;
        let mut path = Vec::new();
        for key in keys {
            match slot {
                Slot::Branch(b) => match b.get_key_value(key.as_ref()) {
                    Some((k, s)) => {
                        path.push(k.as_ref());
                        slot = s;
                    }
                    None => return Ok(TrieMapIter::empty()),
                },
                Slot::Leaf(_) => return Err(InvalidDepth),
            }
        }
        Ok(TrieMapIter {
            stack: vec![(path, slot)],
        })
    }

    pub fn remove(&mut self, _keys: impl IntoIterator<Item: AsRef<[u8]>>) {
        todo!()
    }

    /// Removes tombstones.
    pub fn prune(&mut self) {
        let old = mem::replace(self, Self::new());
        for (k, v) in old {
            if let Some(v) = v {
                _ = self.insert(k, Some(v));
            }
        }
    }
}

/// An iterator over a [`TrieMap`] by reference.
pub struct TrieMapIter<'a> {
    stack: Vec<(Vec<&'a [u8]>, &'a Slot)>,
}

impl TrieMapIter<'_> {
    fn empty() -> Self {
        Self { stack: Vec::new() }
    }
}

impl<'a> Iterator for TrieMapIter<'a> {
    type Item = (Vec<&'a [u8]>, Option<&'a [u8]>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (path, slot) = self.stack.pop()?;
            match slot {
                Slot::Branch(b) => {
                    for (k, v) in b {
                        let mut path = path.clone();
                        path.push(k);
                        self.stack.push((path, v));
                    }
                }
                Slot::Leaf(l) => break Some((path, l.as_deref())),
            }
        }
    }
}

/// An iterator over a [`TrieMap`] by value.
pub struct TrieMapIntoIter {
    stack: Vec<(Vec<Bytes>, Slot)>,
}

impl Iterator for TrieMapIntoIter {
    type Item = (Vec<Bytes>, Option<Bytes>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (path, slot) = self.stack.pop()?;
            match slot {
                Slot::Branch(b) => {
                    for (k, v) in b {
                        let mut path = path.clone();
                        path.push(k);
                        self.stack.push((path, v));
                    }
                }
                Slot::Leaf(l) => break Some((path, l)),
            }
        }
    }
}

impl IntoIterator for TrieMap {
    type Item = <Self::IntoIter as IntoIterator>::Item;
    type IntoIter = TrieMapIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        TrieMapIntoIter {
            stack: vec![(Vec::new(), self.0)],
        }
    }
}

impl ArchivedTrieMap {
    /// Gets a value by exact keys query.
    pub fn get(
        &self,
        keys: impl IntoIterator<Item: AsRef<[u8]>>,
    ) -> Result<Option<Option<&[u8]>>, InvalidDepth> {
        let mut slot = &self.0;
        for key in keys {
            match slot {
                ArchivedSlot::Branch(b) => match b.get(key.as_ref()) {
                    Some(s) => slot = s,
                    None => return Ok(None),
                },
                ArchivedSlot::Leaf(_) => return Err(InvalidDepth),
            }
        }
        match slot {
            ArchivedSlot::Branch(_) => Err(InvalidDepth),
            ArchivedSlot::Leaf(l) => Ok(Some(l.as_deref())),
        }
    }

    /// Gets all values under a prefix of keys.
    pub fn get_by_prefix(
        &self,
        keys: impl IntoIterator<Item: AsRef<[u8]>>,
    ) -> Result<ArchivedTrieMapIter<'_>, InvalidDepth> {
        let mut slot = &self.0;
        let mut path = Vec::new();
        for key in keys {
            match slot {
                ArchivedSlot::Branch(b) => match b.get_key_value(key.as_ref()) {
                    Some((k, s)) => {
                        path.push(k.as_ref());
                        slot = s;
                    }
                    None => return Ok(ArchivedTrieMapIter::empty()),
                },
                ArchivedSlot::Leaf(_) => return Err(InvalidDepth),
            }
        }
        Ok(ArchivedTrieMapIter {
            stack: vec![(path, slot)],
        })
    }
}

/// An iterator over an [`ArchivedTrieMap`] by reference.
pub struct ArchivedTrieMapIter<'a> {
    stack: Vec<(Vec<&'a [u8]>, &'a ArchivedSlot)>,
}

impl ArchivedTrieMapIter<'_> {
    fn empty() -> Self {
        Self { stack: Vec::new() }
    }
}

impl<'a> Iterator for ArchivedTrieMapIter<'a> {
    type Item = (Vec<&'a [u8]>, Option<&'a [u8]>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (path, slot) = self.stack.pop()?;
            match slot {
                ArchivedSlot::Branch(b) => {
                    for (k, v) in b.iter() {
                        let mut path = path.clone();
                        path.push(k);
                        self.stack.push((path, v));
                    }
                }
                ArchivedSlot::Leaf(l) => break Some((path, l.as_deref())),
            }
        }
    }
}

impl<'a> IntoIterator for &'a ArchivedTrieMap {
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = ArchivedTrieMapIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        ArchivedTrieMapIter {
            stack: vec![(Vec::new(), &self.0)],
        }
    }
}
