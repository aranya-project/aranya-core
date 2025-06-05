use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};
use core::{iter, mem, ops::Deref};

use serde::{Deserialize, Serialize};

use super::Bytes;
use crate::StorageError;

/// A `TrieMap` maps bytes keys `k1, k2, ..., kn` to a value, allowing for efficient prefix queries.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrieMap(Slot);

/// Tried to traverse past a leaf in a trie-map.
///
/// When used with [`crate::VmPolicy`] facts, this _should_ never trigger.
#[derive(Debug)]
pub struct InvalidDepth;

impl From<InvalidDepth> for StorageError {
    fn from(_: InvalidDepth) -> Self {
        StorageError::Bug(buggy::Bug::new("invalid depth"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum Slot {
    Branch(BTreeMap<Bytes, Self>),
    Leaf(Grave<Bytes>),
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Grave<T> {
    Found(T),
    Deleted,
}

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
        match &self.0 {
            Slot::Branch(b) => b.is_empty(),
            Slot::Leaf(_) => unreachable!(),
        }
    }

    /// Inserts a keys/value pair.
    ///
    /// Returns the previous value if it existed.
    pub fn insert(
        &mut self,
        keys: impl IntoIterator<Item: Into<Box<[u8]>>>,
        value: Grave<Bytes>,
    ) -> Result<Option<Grave<Bytes>>, InvalidDepth> {
        let mut slot = &mut self.0;
        for key in keys {
            match slot {
                Slot::Branch(b) => slot = b.entry(key.into()).or_default(),
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
        keys: impl IntoIterator<Item: AsRef<[u8]> + Into<Box<[u8]>>>,
        value: impl FnOnce() -> Grave<Bytes>,
    ) -> Result<bool, InvalidDepth> {
        let mut slot = &mut self.0;
        for key in keys {
            match slot {
                Slot::Branch(b) => slot = b.entry(key.into()).or_default(),
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
    ) -> Result<Option<Grave<&[u8]>>, InvalidDepth> {
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

    pub fn remove(
        &mut self,
        keys: impl IntoIterator<Item: AsRef<[u8]>>,
    ) -> Result<Option<Grave<Bytes>>, InvalidDepth> {
        let mut branch = match &mut self.0 {
            Slot::Branch(b) => b,
            Slot::Leaf(_) => unreachable!(),
        };
        let mut keys = keys.into_iter().peekable();
        let mut final_key = None;
        while let Some(key) = keys.next() {
            if keys.peek().is_none() {
                final_key = Some(key);
                break;
            }
            match branch.get_mut(key.as_ref()) {
                Some(Slot::Branch(b)) => branch = b,
                Some(Slot::Leaf(_)) => return Err(InvalidDepth),
                None => return Ok(None),
            }
        }
        let final_key = final_key.ok_or(InvalidDepth)?;
        match branch.remove(final_key.as_ref()) {
            Some(Slot::Branch(_)) => Err(InvalidDepth), // or ok to remove prefix?
            Some(Slot::Leaf(l)) => Ok(Some(l)),
            None => Ok(None),
        }
    }

    pub fn prune(&mut self) {
        // TODO: Prune empty maps.
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
    type Item = (Vec<&'a [u8]>, Grave<&'a [u8]>);

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
    stack: Vec<(Box<[Bytes]>, Slot)>,
}

impl Iterator for TrieMapIntoIter {
    type Item = (Box<[Bytes]>, Grave<Bytes>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (path, slot) = self.stack.pop()?;
            match slot {
                Slot::Branch(b) => {
                    for (k, v) in b {
                        let path = append(&path, k);
                        self.stack.push((path, v));
                    }
                }
                Slot::Leaf(l) => break Some((path, l)),
            }
        }
    }
}

fn append<T: Clone>(seq: &[T], item: T) -> Box<[T]> {
    let mut b = Box::new_uninit_slice(seq.len().checked_add(1).expect("won't wrap"));
    for (x, y) in iter::zip(&mut b, seq.iter().cloned().chain(iter::once(item))) {
        x.write(y);
    }
    unsafe { b.assume_init() }
}

impl IntoIterator for TrieMap {
    type Item = <Self::IntoIter as IntoIterator>::Item;
    type IntoIter = TrieMapIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        TrieMapIntoIter {
            stack: vec![(Box::new([]), self.0)],
        }
    }
}

impl<T: Deref> Grave<T> {
    fn as_deref(&self) -> Grave<&T::Target> {
        match self {
            Grave::Found(x) => Grave::Found(x.deref()),
            Grave::Deleted => Grave::Deleted,
        }
    }
}

impl Grave<&[u8]> {
    pub fn boxed(self) -> Grave<Box<[u8]>> {
        match self {
            Grave::Found(x) => Grave::Found(Box::from(x)),
            Grave::Deleted => Grave::Deleted,
        }
    }
}
