//! Capped visited set for graph traversal.
//!
//! Provides bounded-memory tracking of visited segments during DAG traversal,
//! suitable for no-alloc embedded environments. Tracks entry points (highest
//! command visited) per segment to enable skipping segment loads and
//! incremental searching.

use heapless::Vec;

/// Index of a command within a segment.
pub type CommandIndex = usize;

/// A fixed-size visited set for graph traversal.
///
/// Tracks visited segments during backward traversal through the DAG.
/// Each entry records the segment ID, its minimum max_cut (for calculating
/// effective max_cut), and the highest command index we've entered at.
///
/// When the set is full, evicts the entry with the highest effective max_cut
/// (min_max_cut + highest_command), as this represents the newest point
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
    // (segment_id, min_max_cut, highest_command_visited)
    entries: Vec<(usize, usize, CommandIndex), CAP>,
}

impl<const CAP: usize> CappedVisited<CAP> {
    /// Creates a new empty visited set.
    #[inline]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Resets the visited set for reuse.
    #[inline]
    #[allow(dead_code)] // Part of spec API, used by find_needed_segments
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the min_max_cut and highest_command_visited for a segment
    /// if it exists in the set.
    #[inline]
    pub fn get(&self, segment: usize) -> Option<(usize, CommandIndex)> {
        self.entries
            .iter()
            .find(|(s, _, _)| *s == segment)
            .map(|(_, min_mc, highest)| (*min_mc, *highest))
    }

    /// Inserts a new segment or updates the highest_command_visited if the
    /// segment already exists and the new command is higher.
    ///
    /// When the set is full and a new segment needs to be inserted, evicts
    /// the entry with the highest effective max_cut (min_max_cut + highest_command).
    #[inline]
    pub fn insert_or_update(&mut self, segment: usize, min_max_cut: usize, command: CommandIndex) {
        // Single pass: check for existing segment and track eviction candidate
        let mut evict_idx = 0;
        let mut evict_effective_max_cut = usize::MIN;

        for (i, (s, min_mc, highest)) in self.entries.iter_mut().enumerate() {
            if *s == segment {
                // Segment exists - update highest_command if this entry point is higher
                if command > *highest {
                    *highest = command;
                }
                return;
            }
            // Track entry with highest effective max_cut for potential eviction
            // Use saturating_add to handle CommandIndex::MAX without overflow
            let effective_max_cut = min_mc.saturating_add(*highest);
            if effective_max_cut > evict_effective_max_cut {
                evict_effective_max_cut = effective_max_cut;
                evict_idx = i;
            }
        }

        // Segment not found - insert new entry
        if self.entries.len() < CAP {
            self.entries
                .push((segment, min_max_cut, command))
                .expect("len < CAP was checked");
        } else {
            // Evict entry with highest effective max_cut (already found above)
            self.entries[evict_idx] = (segment, min_max_cut, command);
        }
    }

    /// Marks an entire segment as visited (segment-level tracking only).
    ///
    /// Uses `CommandIndex::MAX` to indicate the entire segment has been visited.
    /// This allows a single buffer to be reused across different traversal
    /// operations that need segment-level vs entry-point tracking.
    #[inline]
    #[allow(dead_code)] // Part of spec API, used by find_needed_segments
    pub fn mark_segment_visited(&mut self, segment: usize, min_max_cut: usize) {
        self.insert_or_update(segment, min_max_cut, CommandIndex::MAX);
    }

    /// Checks if a segment was visited at any entry point.
    #[inline]
    #[allow(dead_code)] // Part of spec API, used by find_needed_segments
    pub fn was_segment_visited(&self, segment: usize) -> bool {
        self.get(segment).is_some()
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

    #[test]
    fn test_clear() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(1, 100, 5);
        visited.insert_or_update(2, 200, 3);
        assert!(visited.get(1).is_some());
        visited.clear();
        assert!(visited.get(1).is_none());
        assert!(visited.get(2).is_none());
    }

    #[test]
    fn test_get() {
        let mut visited = CappedVisited::<4>::new();
        assert!(visited.get(1).is_none());
        visited.insert_or_update(1, 100, 5);
        let (min_mc, highest) = visited.get(1).unwrap();
        assert_eq!(min_mc, 100);
        assert_eq!(highest, 5);
    }

    #[test]
    fn test_insert_or_update_new() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(1, 100, 5);
        let (min_mc, highest) = visited.get(1).unwrap();
        assert_eq!(min_mc, 100);
        assert_eq!(highest, 5);
    }

    #[test]
    fn test_insert_or_update_existing_higher() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(1, 100, 5);
        visited.insert_or_update(1, 100, 8); // Higher command
        let (_, highest) = visited.get(1).unwrap();
        assert_eq!(highest, 8);
    }

    #[test]
    fn test_insert_or_update_existing_lower() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(1, 100, 8);
        visited.insert_or_update(1, 100, 5); // Lower command - should not update
        let (_, highest) = visited.get(1).unwrap();
        assert_eq!(highest, 8);
    }

    #[test]
    fn test_eviction_by_effective_max_cut() {
        let mut visited = CappedVisited::<3>::new();
        // Fill the set with different effective max_cuts
        visited.insert_or_update(1, 100, 10); // effective = 110
        visited.insert_or_update(2, 200, 50); // effective = 250 (highest)
        visited.insert_or_update(3, 150, 20); // effective = 170

        // Insert new - should evict segment 2 (highest effective max_cut = 250)
        visited.insert_or_update(4, 50, 5);

        assert!(visited.get(1).is_some()); // still present
        assert!(visited.get(2).is_none()); // evicted
        assert!(visited.get(3).is_some()); // still present
        assert!(visited.get(4).is_some()); // newly inserted
    }

    #[test]
    fn test_segment_level_helpers() {
        let mut visited = CappedVisited::<4>::new();
        assert!(!visited.was_segment_visited(1));
        visited.mark_segment_visited(1, 100);
        assert!(visited.was_segment_visited(1));
        // mark_segment_visited uses CommandIndex::MAX
        let (_, highest) = visited.get(1).unwrap();
        assert_eq!(highest, usize::MAX);
    }

    #[test]
    fn test_empty_set() {
        let mut visited = CappedVisited::<256>::new();
        // First insert to empty set should succeed
        visited.insert_or_update(42, 100, 5);
        assert!(visited.get(42).is_some());
    }
}
