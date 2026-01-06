//! Capped visited set for graph traversal.
//!
//! Provides bounded-memory tracking of visited segments during DAG traversal,
//! suitable for no-alloc embedded environments.

/// A fixed-size visited set for graph traversal.
///
/// Tracks visited segments during backward traversal through the DAG.
/// When the set is full, evicts the entry with the highest max_cut
/// (least likely to be encountered again during backward traversal).
///
/// # Correctness
///
/// The algorithm remains correct even when the set overflows:
/// - Eviction may cause a segment to be revisited
/// - Revisiting produces redundant work but not incorrect results
/// - The algorithm converges as long as progress is made toward the root
pub struct CappedVisited<const CAP: usize> {
    entries: [(usize, usize); CAP], // (segment_id, max_cut)
    len: usize,
}

impl<const CAP: usize> CappedVisited<CAP> {
    /// Creates a new empty visited set.
    #[inline]
    pub const fn new() -> Self {
        Self {
            entries: [(0, 0); CAP],
            len: 0,
        }
    }

    /// Inserts a segment into the visited set.
    ///
    /// Returns `true` if the segment was not already present (newly inserted).
    /// Returns `false` if the segment was already in the set.
    ///
    /// When the set is full, evicts the entry with the highest max_cut
    /// before inserting the new entry.
    #[inline]
    pub fn insert(&mut self, segment: usize, max_cut: usize) -> bool {
        // Check if already present
        for i in 0..self.len {
            if self.entries[i].0 == segment {
                return false;
            }
        }

        if self.len < CAP {
            // Space available, just append
            self.entries[self.len] = (segment, max_cut);
            self.len += 1;
        } else {
            // Full - evict entry with highest max_cut
            let mut evict_idx = 0;
            let mut max_mc = self.entries[0].1;
            for i in 1..self.len {
                if self.entries[i].1 > max_mc {
                    max_mc = self.entries[i].1;
                    evict_idx = i;
                }
            }
            self.entries[evict_idx] = (segment, max_cut);
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

    #[test]
    fn test_insert_and_contains() {
        let mut visited = CappedVisited::<4>::new();

        // First insert should succeed
        assert!(visited.insert(1, 100));
        // Duplicate should return false
        assert!(!visited.insert(1, 100));

        // Different segments should succeed
        assert!(visited.insert(2, 200));
        assert!(visited.insert(3, 150));
        assert!(visited.insert(4, 50));

        // All should now return false (already present)
        assert!(!visited.insert(1, 100));
        assert!(!visited.insert(2, 200));
        assert!(!visited.insert(3, 150));
        assert!(!visited.insert(4, 50));
    }

    #[test]
    fn test_eviction_highest_max_cut() {
        let mut visited = CappedVisited::<3>::new();

        // Fill the set
        visited.insert(1, 100); // max_cut = 100
        visited.insert(2, 300); // max_cut = 300 (highest)
        visited.insert(3, 200); // max_cut = 200

        // Insert new entry - should evict segment 2 (highest max_cut = 300)
        assert!(visited.insert(4, 50));

        // After eviction: set contains (1, 100), (4, 50), (3, 200)
        assert!(!visited.insert(1, 100)); // still present
        assert!(!visited.insert(4, 50)); // still present
        assert!(!visited.insert(3, 200)); // still present
        assert!(visited.insert(2, 300)); // was evicted, can insert again
    }

    #[test]
    fn test_empty_set() {
        let mut visited = CappedVisited::<256>::new();
        // First insert to empty set should succeed
        assert!(visited.insert(42, 100));
        assert!(!visited.insert(42, 100));
    }
}
