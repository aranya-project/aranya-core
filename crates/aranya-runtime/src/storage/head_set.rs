//! A bounded set of graph heads.
//!
//! Replaces the single persisted `head: Location`. Elements are
//! [`LocatedAddress`] so callers have both the command id and its location
//! without re-fetching segments. The set is kept sorted so equality and
//! serialization are order-independent (peers converge to equal head sets).

use serde::{Deserialize, Serialize};

use crate::{
    StorageError,
    storage::{LocatedAddress, Location, MAX_HEADS},
};

/// A bounded, sorted set of graph heads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadSet {
    heads: heapless::Vec<LocatedAddress, MAX_HEADS>,
}

impl HeadSet {
    /// A one-element head set (the common single-head case).
    pub fn single(head: LocatedAddress) -> Self {
        let mut heads = heapless::Vec::new();
        // Infallible: MAX_HEADS >= 1, so a single push into an empty vec succeeds.
        let _ = heads.push(head);
        Self { heads }
    }

    /// Number of heads.
    pub fn len(&self) -> usize {
        self.heads.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
    }

    /// Heads as a slice (sorted).
    pub fn as_slice(&self) -> &[LocatedAddress] {
        &self.heads
    }

    /// Iterate over heads.
    pub fn iter(&self) -> impl Iterator<Item = LocatedAddress> + '_ {
        self.heads.iter().copied()
    }

    /// Whether `location` is one of the heads.
    ///
    /// The set is sorted by `LocatedAddress` (command id first), not by
    /// `Location`, so looking up a location is a linear scan rather than a
    /// binary search.
    pub fn contains(&self, location: Location) -> bool {
        self.heads.iter().any(|h| h.location() == location)
    }

    /// Insert keeping the set sorted and deduplicated. Returns
    /// `StorageError::HeadSetFull` if at capacity.
    pub fn push(&mut self, head: LocatedAddress) -> Result<(), StorageError> {
        let idx = match self.heads.binary_search(&head) {
            Ok(_) => return Ok(()),
            Err(idx) => idx,
        };
        self.heads
            .insert(idx, head)
            .map_err(|_| StorageError::HeadSetFull(MAX_HEADS))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CmdId,
        storage::{MaxCut, SegmentIndex},
    };

    fn la(id: u8, seg: u64, mc: u64) -> LocatedAddress {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        LocatedAddress {
            id: CmdId::from_bytes(bytes),
            segment: SegmentIndex::new(seg),
            max_cut: MaxCut::new(mc),
        }
    }

    fn la_u64(id: u64, seg: u64, mc: u64) -> LocatedAddress {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&id.to_le_bytes());
        LocatedAddress {
            id: CmdId::from_bytes(bytes),
            segment: SegmentIndex::new(seg),
            max_cut: MaxCut::new(mc),
        }
    }

    #[test]
    fn single_then_len_and_contains() {
        let h = HeadSet::single(la(1, 0, 0));
        assert_eq!(h.len(), 1);
        assert!(h.contains(la(1, 0, 0).location()));
    }

    #[test]
    fn sorted_equality_is_order_independent() {
        let mut a = HeadSet::default();
        a.push(la(2, 2, 5)).unwrap();
        a.push(la(1, 1, 3)).unwrap();
        let mut b = HeadSet::default();
        b.push(la(1, 1, 3)).unwrap();
        b.push(la(2, 2, 5)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn duplicate_insert_does_not_grow() {
        let mut set = HeadSet::default();
        set.push(la(1, 1, 3)).unwrap();
        set.push(la(1, 1, 3)).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn push_returns_full_at_capacity() {
        let mut set = HeadSet::default();
        // Fill to MAX_HEADS with distinct, increasing elements.
        for i in 0..MAX_HEADS as u64 {
            set.push(la_u64(i, i, i)).unwrap();
        }
        assert_eq!(set.len(), MAX_HEADS);
        // One more distinct element must overflow.
        let err = set.push(la_u64(u64::MAX, u64::MAX, u64::MAX)).unwrap_err();
        assert!(matches!(err, StorageError::HeadSetFull(_)));
    }
}
