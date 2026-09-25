use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::mem;

use rkyv::{Archive, Deserialize, Serialize};

use super::Bytes;

/// A map from a sequence of byte-string keys `[k1, k2, ..., kn]` to a value.
///
/// Stored as nested maps: each key selects a child one level down, and the
/// final key reaches a leaf holding the value. Sharing a prefix means sharing
/// a subtree, so all entries under a prefix can be found by walking to it.
///
/// Every entry is expected to have the same number of keys (e.g., a fact's
/// key fields). Keys that end at a branch or continue past a leaf fail with
/// [`InvalidDepth`].
#[derive(Clone, Debug, Default, Archive, Serialize, Deserialize)]
pub struct TrieMap(Slot);

/// Tried to traverse past a leaf in a trie-map.
///
/// When used with [`crate::VmPolicy`] facts, this _should_ never trigger.
#[derive(Debug)]
pub struct InvalidDepth;

/// A node in a [`TrieMap`]: either more keys to follow, or a value.
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

    /// Removes the value at `keys`, pruning any branches left empty.
    ///
    /// Does nothing if `keys` doesn't lead exactly to a leaf.
    pub fn remove(&mut self, keys: impl IntoIterator<Item: AsRef<[u8]>>) {
        fn go<I: Iterator<Item: AsRef<[u8]>>>(slot: &mut Slot, mut keys: I) {
            let Slot::Branch(b) = slot else { return };
            let Some(key) = keys.next() else { return };
            let Some(child) = b.get_mut(key.as_ref()) else {
                return;
            };
            let now_empty = match child {
                Slot::Leaf(_) => keys.next().is_none(),
                Slot::Branch(_) => {
                    go(child, keys);
                    matches!(child, Slot::Branch(c) if c.is_empty())
                }
            };
            if now_empty {
                b.remove(key.as_ref());
            }
        }
        go(&mut self.0, keys.into_iter());
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
        while let Some((path, slot)) = self.stack.pop() {
            match slot {
                Slot::Branch(b) => {
                    let start = self.stack.len();
                    for (k, v) in b {
                        let mut path = path.clone();
                        path.push(k);
                        self.stack.push((path, v));
                    }
                    // Reverse so the smallest key is popped first.
                    self.stack[start..].reverse();
                }
                Slot::Leaf(l) => return Some((path, l.as_deref())),
            }
        }
        None
    }
}

/// An iterator over a [`TrieMap`] by value.
pub struct TrieMapIntoIter {
    stack: Vec<(Vec<Bytes>, Slot)>,
}

impl Iterator for TrieMapIntoIter {
    type Item = (Vec<Bytes>, Option<Bytes>);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((path, slot)) = self.stack.pop() {
            match slot {
                Slot::Branch(b) => {
                    let start = self.stack.len();
                    for (k, v) in b {
                        let mut path = path.clone();
                        path.push(k);
                        self.stack.push((path, v));
                    }
                    // Reverse so the smallest key is popped first.
                    self.stack[start..].reverse();
                }
                Slot::Leaf(l) => return Some((path, l)),
            }
        }
        None
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
        while let Some((path, slot)) = self.stack.pop() {
            match slot {
                ArchivedSlot::Branch(b) => {
                    let start = self.stack.len();
                    for (k, v) in b.iter() {
                        let mut path = path.clone();
                        path.push(k);
                        self.stack.push((path, v));
                    }
                    // Reverse so the smallest key is popped first.
                    self.stack[start..].reverse();
                }
                ArchivedSlot::Leaf(l) => return Some((path, l.as_deref())),
            }
        }
        None
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Iteration must yield keys in ascending order, as
    /// `Query::query_prefix` promises sorted results.
    #[test]
    fn test_iter_sorted() {
        let keys: &[[&[u8]; 2]] = &[
            [b"b", b"1"],
            [b"a", b"2"],
            [b"c", b""],
            [b"a", b"1"],
            [b"b", b"0"],
        ];
        let mut map = TrieMap::new();
        for k in keys {
            map.insert(k, Some(b"v".as_slice().into())).unwrap();
        }
        let mut expected: Vec<Vec<&[u8]>> = keys.iter().map(|k| k.to_vec()).collect();
        expected.sort();

        let empty: [&[u8]; 0] = [];
        let by_ref: Vec<Vec<&[u8]>> = map.get_by_prefix(empty).unwrap().map(|(k, _)| k).collect();
        assert_eq!(by_ref, expected);

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&map).unwrap();
        let archived = rkyv::access::<ArchivedTrieMap, rkyv::rancor::Error>(&bytes).unwrap();
        let archived: Vec<Vec<&[u8]>> = archived.into_iter().map(|(k, _)| k).collect();
        assert_eq!(archived, expected);

        let owned: Vec<Vec<Bytes>> = map.into_iter().map(|(k, _)| k).collect();
        let owned: Vec<Vec<&[u8]>> = owned
            .iter()
            .map(|k| k.iter().map(AsRef::as_ref).collect())
            .collect();
        assert_eq!(owned, expected);
    }

    #[test]
    fn test_remove() {
        let mut map = TrieMap::new();
        map.insert([b"a", b"b"], Some(b"1".as_slice().into()))
            .unwrap();
        map.insert([b"a", b"c"], Some(b"2".as_slice().into()))
            .unwrap();
        map.insert([b"d", b"e"], None).unwrap();

        // Wrong depth or missing keys are ignored.
        map.remove([b"a"]);
        map.remove([b"a", b"b", b"x"]);
        map.remove([b"a", b"x"]);
        assert_eq!(map.get([b"a", b"b"]).unwrap(), Some(Some(b"1".as_slice())));

        map.remove([b"a", b"b"]);
        assert_eq!(map.get([b"a", b"b"]).unwrap(), None);
        assert_eq!(map.get([b"a", b"c"]).unwrap(), Some(Some(b"2".as_slice())));

        // Tombstones are removed too.
        map.remove([b"d", b"e"]);
        assert_eq!(map.get([b"d", b"e"]).unwrap(), None);

        // Emptied branches are pruned.
        map.remove([b"a", b"c"]);
        assert!(map.is_empty());
    }
}
