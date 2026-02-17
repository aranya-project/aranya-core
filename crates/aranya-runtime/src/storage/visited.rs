//! Capped visited set for graph traversal.
//!
//! Provides bounded-memory tracking of visited segments during DAG traversal,
//! suitable for no-alloc embedded environments. Enables skipping segment loads
//! and incremental searching.

use heapless::Vec;

use crate::SegmentIndex;

/// A fixed-size visited set for graph traversal.
///
/// Tracks visited segments during backward traversal through the DAG.
///
/// When the set is full, evicts the entry with the highest segment index,
/// as this represents the newest point visited and is least likely to be
/// encountered again during backward traversal.
///
/// # Correctness
///
/// The algorithm remains correct even when the set overflows:
/// - Eviction may cause a segment to be revisited
/// - Revisiting produces redundant work but not incorrect results
/// - The algorithm converges as long as progress is made toward the root
pub struct CappedVisited<const CAP: usize> {
    entries: Vec<SegmentIndex, CAP>,
}

impl<const CAP: usize> CappedVisited<CAP> {
    /// Creates a new empty visited set.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Resets the visited set for reuse.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Marks a segment as visited.
    ///
    /// When the set is full and a new segment needs to be inserted, evicts
    /// the entry with the highest max_cut.
    ///
    /// Returns `true` if this segment was not already visited.
    pub fn visit(&mut self, new_seg: SegmentIndex) -> bool {
        if CAP == 0 {
            return true;
        }

        // Single pass: check for existing segment and track eviction candidate
        let mut evict_idx = 0;
        let mut evict_segment = SegmentIndex(0);

        for (i, &old_seg) in self.entries.iter().enumerate() {
            if old_seg == new_seg {
                return false;
            }
            // Track entry with highest max_cut for potential eviction
            if old_seg > evict_segment {
                evict_segment = old_seg;
                evict_idx = i;
            }
        }

        // Segment not found - insert new entry
        if self.entries.len() < CAP {
            self.entries.push(new_seg).expect("len < CAP was checked");
        } else {
            // Evict entry with highest max_cut (already found above)
            self.entries[evict_idx] = new_seg;
        }

        true
    }
}

impl<const CAP: usize> Default for CappedVisited<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(n: usize) -> SegmentIndex {
        SegmentIndex(n)
    }

    #[test]
    fn test_zero_capacity() {
        let mut visited = CappedVisited::<0>::new();
        assert!(visited.visit(seg(0)));
        assert!(visited.visit(seg(0)));
    }

    #[test]
    fn test_one_capacity() {
        let mut visited = CappedVisited::<1>::new();
        assert!(visited.visit(seg(0)));
        assert!(visited.visit(seg(1)));
        assert!(!visited.visit(seg(1)));
        assert!(visited.visit(seg(0)));
        assert!(!visited.visit(seg(0)));
    }

    #[test]
    fn test_eviction() {
        let mut visited = CappedVisited::<2>::new();
        assert!(visited.visit(seg(5)));
        assert!(visited.visit(seg(4)));
        assert!(visited.visit(seg(3)));
        assert!(!visited.visit(seg(4)));
        assert!(visited.visit(seg(5)));
    }
}
