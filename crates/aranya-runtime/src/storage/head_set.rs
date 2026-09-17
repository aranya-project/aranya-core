//! A set of graph heads.
//!
//! Replaces the single persisted `head: Location`. Elements are
//! [`LocatedAddress`] so callers have both the command id and its location
//! without re-fetching segments. The set is kept sorted by command id so
//! peers collapsing the same logical head set pair merges identically
//! (`CmdId` is global, unlike the peer-local `Location`).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::storage::LocatedAddress;

/// A sorted set of graph heads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadSet {
    heads: Vec<LocatedAddress>,
}

impl HeadSet {
    /// A one-element head set (the common single-head case).
    pub fn single(head: LocatedAddress) -> Self {
        Self {
            heads: alloc::vec![head],
        }
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

    /// Insert keeping the set sorted and deduplicated.
    pub fn push(&mut self, head: LocatedAddress) {
        if let Err(idx) = self.heads.binary_search(&head) {
            self.heads.insert(idx, head);
        }
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

    #[test]
    fn single_then_len() {
        let h = HeadSet::single(la(1, 0, 0));
        assert_eq!(h.len(), 1);
        assert_eq!(h.as_slice(), [la(1, 0, 0)]);
    }

    #[test]
    fn sorted_equality_is_order_independent() {
        let mut a = HeadSet::default();
        a.push(la(2, 2, 5));
        a.push(la(1, 1, 3));
        let mut b = HeadSet::default();
        b.push(la(1, 1, 3));
        b.push(la(2, 2, 5));
        assert_eq!(a, b);
    }

    #[test]
    fn duplicate_insert_does_not_grow() {
        let mut set = HeadSet::default();
        set.push(la(1, 1, 3));
        set.push(la(1, 1, 3));
        assert_eq!(set.len(), 1);
    }
}
