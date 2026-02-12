//! Capped visited set for graph traversal.
//!
//! Provides bounded-memory tracking of visited segments during DAG traversal,
//! suitable for no-alloc embedded environments. Tracks entry points (highest
//! max_cut visited) per segment to enable skipping segment loads and
//! incremental searching.

use heapless::Vec;

use crate::{Location, MaxCut};

/// Visit status.
pub enum Visitation {
    /// This location has already been visited.
    Covered,
    /// This segment has been visited at a lower max cut.
    Partial,
    /// This segment has not been visited.
    New,
}

/// A fixed-size visited set for graph traversal.
///
/// Tracks visited segments during backward traversal through the DAG.
/// Each entry records the segment index, its minimum max_cut (for calculating
/// effective max_cut), and the highest max_cut we've entered at.
///
/// When the set is full, evicts the entry with the highest effective max_cut
/// (min_max_cut + highest_max_cut), as this represents the newest point
/// visited and is least likely to be encountered again during backward
/// traversal.
///
/// # Correctness
///
/// The algorithm remains correct even when the set overflows:
/// - Eviction may cause a segment to be revisited
/// - Revisiting produces redundant work but not incorrect results
/// - The algorithm converges as long as progress is made toward the root
pub struct CappedVisited<const CAP: usize> {
    entries: Vec<Location, CAP>,
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

    /// Inserts a new segment or updates the highest max_cut visited if the
    /// segment already exists and the new max_cut is higher.
    ///
    /// When the set is full and a new segment needs to be inserted, evicts
    /// the entry with the highest max_cut.
    pub fn visit(&mut self, new_loc: Location) -> Visitation {
        // Single pass: check for existing segment and track eviction candidate
        let mut evict_idx = 0;
        let mut evict_max_cut = MaxCut(0);

        for (i, old_loc) in self.entries.iter_mut().enumerate() {
            if old_loc.segment == new_loc.segment {
                // Segment exists - update max_cut if this entry point is higher
                if new_loc.max_cut > old_loc.max_cut {
                    old_loc.max_cut = new_loc.max_cut;
                    return Visitation::Partial;
                } else {
                    return Visitation::Covered;
                }
            }
            // Track entry with highest max_cut for potential eviction
            if old_loc.max_cut > evict_max_cut {
                evict_max_cut = old_loc.max_cut;
                evict_idx = i;
            }
        }

        // Segment not found - insert new entry
        if self.entries.len() < CAP {
            self.entries.push(new_loc).expect("len < CAP was checked");
        } else {
            // Evict entry with highest max_cut (already found above)
            self.entries[evict_idx] = new_loc;
        }

        Visitation::New
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
