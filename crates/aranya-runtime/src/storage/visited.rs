//! Capped visited set for graph traversal.
//!
//! Provides bounded-memory tracking of visited segments during DAG traversal,
//! suitable for no-alloc embedded environments. Enable skipping segment loads
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

#[cfg(false)] // TODO: Update tests
mod tests {
    use super::*;

    const TEST_MIN_MAX_CUT: MaxCut = MaxCut(100);
    const TEST_MAX_CUT: MaxCut = MaxCut(5);

    fn seg(n: usize) -> SegmentIndex {
        SegmentIndex(n)
    }

    #[test]
    fn test_clear() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(seg(1), TEST_MIN_MAX_CUT, TEST_MAX_CUT);
        visited.insert_or_update(seg(2), MaxCut(200), MaxCut(3));
        assert!(visited.get(seg(1)).is_some());
        visited.clear();
        assert!(visited.get(seg(1)).is_none());
        assert!(visited.get(seg(2)).is_none());
    }

    #[test]
    fn test_get() {
        let mut visited = CappedVisited::<4>::new();
        assert!(visited.get(seg(1)).is_none());
        visited.insert_or_update(seg(1), TEST_MIN_MAX_CUT, TEST_MAX_CUT);
        let (min_mc, highest) = visited.get(seg(1)).unwrap();
        assert_eq!(min_mc, TEST_MIN_MAX_CUT);
        assert_eq!(highest, TEST_MAX_CUT);
    }

    #[test]
    fn test_insert_or_update_existing_higher() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(seg(1), TEST_MIN_MAX_CUT, TEST_MAX_CUT);
        visited.insert_or_update(seg(1), TEST_MIN_MAX_CUT, MaxCut(8)); // Higher max_cut
        let (_, highest) = visited.get(seg(1)).unwrap();
        assert_eq!(highest, MaxCut(8));
    }

    #[test]
    fn test_insert_or_update_existing_lower() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(seg(1), TEST_MIN_MAX_CUT, MaxCut(8));
        visited.insert_or_update(seg(1), TEST_MIN_MAX_CUT, TEST_MAX_CUT); // Lower max_cut - should not update
        let (_, highest) = visited.get(seg(1)).unwrap();
        assert_eq!(highest, MaxCut(8));
    }

    #[test]
    fn test_eviction_by_effective_max_cut() {
        let mut visited = CappedVisited::<3>::new();
        // Fill the set with different effective max_cuts (effective = min_max_cut + highest)
        visited.insert_or_update(seg(1), MaxCut(100), MaxCut(10)); // effective = 110
        visited.insert_or_update(seg(2), MaxCut(200), MaxCut(50)); // effective = 250 (highest)
        visited.insert_or_update(seg(3), MaxCut(150), MaxCut(20)); // effective = 170

        // Insert new - should evict segment 2 (highest effective max_cut = 250)
        visited.insert_or_update(seg(4), MaxCut(50), MaxCut(5));

        assert!(visited.get(seg(1)).is_some()); // still present
        assert!(visited.get(seg(2)).is_none()); // evicted
        assert!(visited.get(seg(3)).is_some()); // still present
        assert!(visited.get(seg(4)).is_some()); // newly inserted
    }

    #[test]
    fn test_segment_level_helpers() {
        let mut visited = CappedVisited::<4>::new();
        assert!(!visited.was_segment_visited(seg(1)));
        visited.mark_segment_visited(seg(1), TEST_MIN_MAX_CUT);
        assert!(visited.was_segment_visited(seg(1)));
        // mark_segment_visited uses VISITED_ALL sentinel
        let (_, highest) = visited.get(seg(1)).unwrap();
        assert_eq!(highest, VISITED_ALL);
    }

    #[test]
    fn test_empty_set() {
        let mut visited = CappedVisited::<256>::new();
        // First insert to empty set should succeed
        visited.insert_or_update(seg(42), TEST_MIN_MAX_CUT, TEST_MAX_CUT);
        assert!(visited.get(seg(42)).is_some());
    }
}
