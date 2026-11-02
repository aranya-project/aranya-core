//! A set of graph heads.
//!
//! Replaces the single persisted `head: Location`. Elements are
//! [`LocatedAddress`] so callers have both the command id and its location
//! without re-fetching segments. The set is kept sorted by command id so
//! peers collapsing the same logical head set pair merges identically
//! (`CmdId` is global, unlike the peer-local `Location`).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::storage::{LocatedAddress, Location};

/// A sorted set of graph heads, with their last common ancestor.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct HeadSet {
    heads: Vec<LocatedAddress>,
    lca: Location,
}

impl HeadSet {
    /// A one-element head set (the common single-head case). Its LCA is the
    /// head.
    pub fn single(head: LocatedAddress) -> Self {
        Self {
            heads: alloc::vec![head],
            lca: head.location(),
        }
    }

    /// A head set of `heads`, whose last common ancestor is `lca`.
    ///
    /// `lca` must be a command every head passes through on its way to the
    /// root, such as the LCA a braid of `heads` computes.
    pub fn new(heads: impl IntoIterator<Item = LocatedAddress>, lca: Location) -> Self {
        let mut heads: Vec<LocatedAddress> = heads.into_iter().collect();
        heads.sort();
        heads.dedup();
        Self { heads, lca }
    }

    /// A command every head passes through on its way to the root. For a
    /// single head, the head itself.
    pub fn lca(&self) -> Location {
        self.lca
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
    fn single_lca_is_the_head() {
        let h = HeadSet::single(la(1, 4, 7));
        assert_eq!(h.lca(), la(1, 4, 7).location());
    }

    #[test]
    fn sorted_equality_is_order_independent() {
        let lca = la(0, 0, 0).location();
        let a = HeadSet::new([la(2, 2, 5), la(1, 1, 3)], lca);
        let b = HeadSet::new([la(1, 1, 3), la(2, 2, 5)], lca);
        assert_eq!(a, b);
    }

    #[test]
    fn duplicate_head_is_kept_once() {
        let set = HeadSet::new([la(1, 1, 3), la(1, 1, 3)], la(0, 0, 0).location());
        assert_eq!(set.len(), 1);
    }
}
