use alloc::vec::Vec;
use core::cmp::Ordering;

use buggy::{Bug, BugExt as _, bug};

use crate::{Location, MaxCut, SegmentIndex, StorageError};

#[derive(Debug)]
pub(crate) struct TraversalQueueWithCoverage {
    entries: Vec<Location>,
    /// Index separating uncovered (below) from covered (at and above).
    partition: usize,
}

#[derive(Debug)]
pub(crate) struct TraversalQueueNoDuplicates {
    entries: Vec<Location>,
}

#[derive(Debug)]
pub(crate) struct TraversalQueueWithDuplicates {
    entries: Vec<Location>,
}

impl TraversalQueueWithCoverage {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
            partition: 0,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.partition = 0;
    }

    /// Enqueues a location as uncovered.
    ///
    /// If an entry with the same segment exists, its max cut will be updated
    /// to the max of the two, unless the old entry was covered.
    pub(crate) fn push_uncovered(&mut self, loc: Location) -> Result<(), StorageError> {
        self.push(loc, false)
    }

    /// Enqueues a location as covered.
    ///
    /// If an entry with the same segment exists, its max cut will be updated
    /// to the max of the two.
    pub(crate) fn push_covered(&mut self, loc: Location) -> Result<(), StorageError> {
        self.push(loc, true)
    }

    /// Enqueues a location with the given covered flag.
    ///
    /// Deduplicates segments unless doing so would transition from covered to uncovered.
    fn push(&mut self, loc: Location, covered: bool) -> Result<(), StorageError> {
        if let Some(i) = self.entries.iter().position(|x| x.same_segment(loc)) {
            let was_covered = i >= self.partition;
            let newly_covered = covered && !was_covered;
            match loc.max_cut.cmp(&self.entries[i].max_cut) {
                Ordering::Less if newly_covered => {
                    // Add new location as covered.
                    self.entries.push(loc);
                }
                Ordering::Equal if newly_covered => {
                    // Adjust old location to be covered.
                    self.cover(i)?;
                }
                Ordering::Greater if newly_covered => {
                    // Increase max cut, make covered.
                    self.entries[i].max_cut = loc.max_cut;
                    self.cover(i)?;
                }
                Ordering::Greater if !covered && was_covered => {
                    // New location is above old but is uncovered while old was covered.
                    // Add location as uncovered without disturbing old.
                    self.insert_uncovered(loc)?;
                }
                Ordering::Greater => {
                    // New location is above old, both are either covered or uncovered.
                    // Just increase max cut, covered state stays the same.
                    self.entries[i].max_cut = loc.max_cut;
                }
                _ => {
                    // No change needed.
                }
            }
        } else if covered {
            self.entries.push(loc);
        } else {
            self.insert_uncovered(loc)?;
        }
        Ok(())
    }

    /// Mark entry at `idx` as covered.
    ///
    /// Given entry must be uncovered.
    fn cover(&mut self, idx: usize) -> Result<(), Bug> {
        if idx >= self.partition {
            bug!("already covered");
        }
        self.partition = self
            .partition
            .checked_sub(1)
            .assume("partition must be >= 1 when uncovered entry exists")?;
        self.entries.swap(idx, self.partition);
        Ok(())
    }

    /// Adds a location as uncovered.
    ///
    /// Makes no checks for existing entries.
    fn insert_uncovered(&mut self, loc: Location) -> Result<(), Bug> {
        self.entries.push(loc);
        let last = self
            .entries
            .len()
            .checked_sub(1)
            .assume("just pushed, len must be >= 1")?;
        self.entries.swap(self.partition, last);
        self.partition = self
            .partition
            .checked_add(1)
            .assume("partition must not overflow")?;
        Ok(())
    }

    /// Pop the location with the highest max cut, including its covered flag.
    pub(crate) fn pop_covered(&mut self) -> Result<Option<(Location, bool)>, StorageError> {
        let Some((i, _)) = self.entries.iter().enumerate().max_by_key(|&(_, loc)| *loc) else {
            return Ok(None);
        };
        if i < self.partition {
            Ok(Some((self.remove_uncovered(i)?, false)))
        } else {
            // Removing from covered region: swap_remove is fine.
            let loc = self.entries.swap_remove(i);
            Ok(Some((loc, true)))
        }
    }

    /// Remove an entry from the uncovered region at index `i`,
    /// maintaining the partition invariant.
    fn remove_uncovered(&mut self, i: usize) -> Result<Location, StorageError> {
        self.partition = self
            .partition
            .checked_sub(1)
            .assume("partition must be >= 1 when uncovered entry exists")?;
        self.entries.swap(i, self.partition);
        Ok(self.entries.swap_remove(self.partition))
    }

    /// Returns true if all entries are covered and there is at least one entry.
    pub(crate) fn nontrivially_covered(&self) -> bool {
        !self.entries.is_empty() && self.partition == 0
    }

    /// Remove all entries with `max_cut > threshold` from the queue.
    ///
    /// Uncovered entries are passed to `f`. Covered entries are discarded
    /// (the peer already has them).
    pub(crate) fn drain_above(
        &mut self,
        threshold: MaxCut,
        mut f: impl FnMut(Location),
    ) -> Result<(), StorageError> {
        // Drain from uncovered region.
        let mut i = 0;
        while i < self.partition {
            if self.entries[i].max_cut > threshold {
                f(self.remove_uncovered(i)?);
            } else {
                i = i.checked_add(1).assume("index must not overflow")?;
            }
        }
        // Discard covered entries above the threshold — the peer
        // already has these, so they don't belong in the result.
        let mut i = self.partition;
        while i < self.entries.len() {
            if self.entries[i].max_cut > threshold {
                self.entries.swap_remove(i);
            } else {
                i = i.checked_add(1).assume("index must not overflow")?;
            }
        }
        Ok(())
    }

    /// Mark a segment as covered up to `coverage_mc`. If the segment
    /// exists in the queue:
    /// - If `coverage_mc >= longest_mc`: the segment is fully covered.
    /// - If `coverage_mc >= entry.max_cut`: the entry is updated to
    ///   `coverage_mc + 1` (still uncovered — the peer needs the rest).
    /// - If `coverage_mc < entry.max_cut`: no-op (already sending from
    ///   above the coverage point).
    pub(crate) fn cover_up_to(
        &mut self,
        segment: SegmentIndex,
        coverage_mc: MaxCut,
        longest_mc: MaxCut,
    ) -> Result<(), StorageError> {
        let Some(i) = self.entries.iter().position(|x| x.segment == segment) else {
            return Ok(());
        };
        let was_covered = i >= self.partition;
        if was_covered {
            return Ok(());
        }
        if coverage_mc >= longest_mc {
            // Fully covered — move to covered partition.
            self.cover(i)?;
        } else if coverage_mc >= self.entries[i].max_cut {
            // Partially covered — advance start past the covered portion.
            self.entries[i].max_cut = coverage_mc
                .checked_add(1)
                .assume("coverage_mc + 1 must not overflow")?;
        }
        // else: coverage is below our start, nothing to do.
        Ok(())
    }

    /// Drain all entries. Uncovered entries are passed to `f`.
    /// Covered entries are discarded. O(n) single pass.
    pub(crate) fn drain_all(&mut self, f: impl FnMut(Location)) {
        self.entries[..self.partition].iter().copied().for_each(f);
        self.clear();
    }
}

impl TraversalQueueNoDuplicates {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    /// Enqueues a location as uncovered.
    ///
    /// If an entry with the same segment exists, its max cut will be updated
    /// to the max of the two.
    pub(crate) fn push(&mut self, loc: Location) -> Result<(), StorageError> {
        if let Some(entry) = self.entries.iter_mut().find(|x| x.same_segment(loc)) {
            entry.max_cut = entry.max_cut.max(loc.max_cut);
        } else {
            self.entries.push(loc);
        }
        Ok(())
    }

    /// Pop the location with the highest max cut, discarding the covered flag.
    pub(crate) fn pop(&mut self) -> Result<Option<Location>, StorageError> {
        let Some((i, _)) = self.entries.iter().enumerate().max_by_key(|&(_, loc)| *loc) else {
            return Ok(None);
        };
        let loc = self.entries.swap_remove(i);
        Ok(Some(loc))
    }
}

impl TraversalQueueWithDuplicates {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    /// Enqueues a location without deduplication.
    ///
    /// Unlike [`Self::push`], each call adds a new entry even if the location
    /// is already present. Used by the convergence pre-pass where
    /// duplicate tracking is needed.
    pub(crate) fn push_duplicate(&mut self, loc: Location) -> Result<(), StorageError> {
        self.entries.push(loc);
        Ok(())
    }

    /// Returns the entry with the highest `max_cut` without removing it.
    pub(crate) fn peek(&self) -> Option<&Location> {
        self.entries.iter().max_by_key(|loc| *loc)
    }

    /// Pop the entry with the highest `max_cut`, removing all entries
    /// at that exact location. Returns `(location, count)`.
    ///
    /// Used by the convergence pre-pass. Entries are matched by full
    /// `Location` equality (segment + max_cut), not just max_cut.
    pub(crate) fn pop_duplicates(&mut self) -> Result<Option<(Location, usize)>, StorageError> {
        let Some(location) = self.entries.iter().max_by_key(|loc| *loc).copied() else {
            return Ok(None);
        };

        // Remove all entries matching this location.
        // Count them as we go. Iterate backward to avoid index shifts.
        let mut count: usize = 0;
        let mut j = self.entries.len();
        while j > 0 {
            j = j.checked_sub(1).assume("j > 0 checked in loop condition")?;
            if self.entries[j] == location {
                count = count
                    .checked_add(1)
                    .assume("count bounded by `entries.len()`")?;
                self.entries.swap_remove(j);
            }
        }

        Ok(Some((location, count)))
    }
}

#[cfg(false)] // TODO
#[cfg(test)]
mod tests {
    use super::*;

    fn loc(seg: usize, mc: usize) -> Location {
        Location::new(SegmentIndex::new(seg as u64), MaxCut::new(mc as u64))
    }

    #[test]
    #[ignore = "queue is currently unbounded"]
    fn test_queue_overflow_returns_error() {
        let mut queue = TraversalQueue::new();
        // Fill to capacity
        for i in 0..QUEUE_CAPACITY {
            queue.push(loc(i, i)).unwrap();
        }
        // Next push should fail with TraversalQueueOverflow
        let result = queue
            .push(loc(999, 999))
            .expect_err("expected push_queue to fail");
        assert_eq!(result, StorageError::TraversalQueueOverflow(QUEUE_CAPACITY));
    }

    #[test]
    fn test_push_defaults_covered_false() {
        let mut queue = TraversalQueue::new();
        queue.push(loc(0, 5)).unwrap();
        let (_, covered) = queue.pop_covered().unwrap().unwrap();
        assert!(!covered);
    }

    #[test]
    fn test_push_covered_preserves_flag() {
        let mut queue = TraversalQueue::new();
        queue.push_covered(loc(0, 5), true).unwrap();
        let (_, covered) = queue.pop_covered().unwrap().unwrap();
        assert!(covered);
    }

    #[test]
    fn test_push_covered_same_max_cut_ors_flags() {
        let mut queue = TraversalQueue::new();
        queue.push_covered(loc(0, 5), false).unwrap();
        queue.push_covered(loc(0, 5), true).unwrap();
        let (_, covered) = queue.pop_covered().unwrap().unwrap();
        assert!(covered);
    }

    #[test]
    fn test_push_covered_same_max_cut_cannot_uncover() {
        let mut queue = TraversalQueue::new();
        queue.push_covered(loc(0, 5), true).unwrap();
        // Pushing uncovered at the same max_cut must not clear covered.
        queue.push_covered(loc(0, 5), false).unwrap();
        let (_, covered) = queue.pop_covered().unwrap().unwrap();
        assert!(covered);
    }

    #[test]
    fn test_push_same_segment_updates_max_cut() {
        let mut queue = TraversalQueue::new();
        queue.push(loc(0, 5)).unwrap();
        queue.push(loc(0, 8)).unwrap();
        let l = queue.pop().unwrap().unwrap();
        assert_eq!(l.max_cut, MaxCut::new(8));
        assert!(queue.is_empty());
    }

    #[test]
    fn test_push_covered_higher_max_cut_adopts_new_flag() {
        let mut queue = TraversalQueue::new();
        queue.push_covered(loc(0, 5), true).unwrap();
        // Higher max_cut uncovered: segment head moved beyond covered point.
        queue.push_covered(loc(0, 8), false).unwrap();
        let (l, covered) = queue.pop_covered().unwrap().unwrap();
        assert_eq!(l.max_cut, MaxCut::new(8));
        assert!(!covered);
    }

    #[test]
    fn test_push_covered_lower_max_cut_no_change() {
        let mut queue = TraversalQueue::new();
        queue.push_covered(loc(0, 8), false).unwrap();
        // Lower max_cut should not change anything.
        queue.push_covered(loc(0, 3), true).unwrap();
        let (l, covered) = queue.pop_covered().unwrap().unwrap();
        assert_eq!(l.max_cut, MaxCut::new(8));
        assert!(!covered);
    }

    #[test]
    fn test_pop_discards_covered_flag() {
        let mut queue = TraversalQueue::new();
        queue.push_covered(loc(0, 5), true).unwrap();
        // pop() should return only the location.
        let l = queue.pop().unwrap().unwrap();
        assert_eq!(l.max_cut, MaxCut::new(5));
        assert!(queue.is_empty());
    }

    #[test]
    fn test_all_covered() {
        let mut queue = TraversalQueue::new();
        queue.push_covered(loc(0, 1), true).unwrap();
        queue.push_covered(loc(1, 2), true).unwrap();
        assert!(queue.all_covered());

        queue.push_covered(loc(2, 3), false).unwrap();
        assert!(!queue.all_covered());
    }

    #[test]
    fn test_drain_above() {
        let mut queue = TraversalQueue::new();
        queue.push(loc(0, 3)).unwrap();
        queue.push(loc(1, 7)).unwrap();
        queue.push(loc(2, 5)).unwrap();

        let mut result: heapless::Vec<Location, 8> = heapless::Vec::new();
        queue
            .drain_above(MaxCut::new(4), |loc| {
                let _ = result.push(loc);
            })
            .unwrap();

        // Entries with max_cut > 4 should be drained.
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|l| l.max_cut == MaxCut::new(7)));
        assert!(result.iter().any(|l| l.max_cut == MaxCut::new(5)));

        // Only max_cut=3 should remain in the queue.
        let remaining = queue.pop().unwrap().unwrap();
        assert_eq!(remaining.max_cut, MaxCut::new(3));
        assert!(queue.is_empty());
    }

    #[test]
    fn test_drain_above_with_covered_entries() {
        let mut queue = TraversalQueue::new();
        // Mix of uncovered and covered entries above and below threshold.
        queue.push(loc(0, 3)).unwrap(); // uncovered, below
        queue.push(loc(1, 7)).unwrap(); // uncovered, above
        queue.push_covered(loc(2, 6), true).unwrap(); // covered, above
        queue.push_covered(loc(3, 2), true).unwrap(); // covered, below
        queue.push(loc(4, 5)).unwrap(); // uncovered, above

        let mut drained: heapless::Vec<Location, 8> = heapless::Vec::new();
        queue
            .drain_above(MaxCut::new(4), |loc| {
                let _ = drained.push(loc);
            })
            .unwrap();

        // Only uncovered entries above threshold should be passed to f.
        assert_eq!(drained.len(), 2);
        assert!(drained.iter().any(|l| l.segment.get() == 1));
        assert!(drained.iter().any(|l| l.segment.get() == 4));

        // Covered entry above threshold (seg=2) should be discarded.
        // Entries below threshold should remain: seg=0 (uncovered), seg=3 (covered).
        let mut remaining = Vec::new();
        while let Some((l, covered)) = queue.pop_covered().unwrap() {
            remaining.push((l.segment, covered));
        }
        assert_eq!(remaining.len(), 2);
        assert!(remaining.contains(&(SegmentIndex::new(0), false)));
        assert!(remaining.contains(&(SegmentIndex::new(3), true)));
    }

    #[test]
    fn test_push_duplicate_keeps_separate_entries() {
        let mut queue = TraversalQueue::new();
        queue.push_duplicate(loc(0, 5)).unwrap();
        queue.push_duplicate(loc(0, 5)).unwrap();
        let first = queue.pop().unwrap();
        assert!(first.is_some());
        let second = queue.pop().unwrap();
        assert!(second.is_some());
        assert!(queue.is_empty());
    }

    #[test]
    #[ignore = "queue is currently unbounded"]
    fn test_push_duplicate_overflow() {
        let mut queue = TraversalQueue::new();
        for i in 0..QUEUE_CAPACITY {
            queue.push_duplicate(loc(0, i)).unwrap();
        }
        let result = queue.push_duplicate(loc(0, 999));
        assert_eq!(
            result.unwrap_err(),
            StorageError::TraversalQueueOverflow(QUEUE_CAPACITY)
        );
    }

    #[test]
    fn test_pop_duplicates_returns_count() {
        let mut queue = TraversalQueue::new();
        queue.push_duplicate(loc(0, 5)).unwrap();
        queue.push_duplicate(loc(0, 5)).unwrap();
        queue.push_duplicate(loc(1, 3)).unwrap();

        let (location, count) = queue.pop_duplicates().unwrap().unwrap();
        assert_eq!(location, loc(0, 5));
        assert_eq!(count, 2);

        let (location, count) = queue.pop_duplicates().unwrap().unwrap();
        assert_eq!(location, loc(1, 3));
        assert_eq!(count, 1);

        assert!(queue.pop_duplicates().unwrap().is_none());
    }

    #[test]
    fn test_pop_duplicates_different_segments_same_max_cut() {
        let mut queue = TraversalQueue::new();
        queue.push_duplicate(loc(0, 5)).unwrap();
        queue.push_duplicate(loc(1, 5)).unwrap();

        let (location, count) = queue.pop_duplicates().unwrap().unwrap();
        assert_eq!(count, 1);
        assert_eq!(location.max_cut, MaxCut::new(5));

        let (_, count) = queue.pop_duplicates().unwrap().unwrap();
        assert_eq!(count, 1);

        assert!(queue.pop_duplicates().unwrap().is_none());
    }

    #[test]
    fn test_pop_duplicates_empty() {
        let mut queue = TraversalQueue::new();
        assert!(queue.pop_duplicates().unwrap().is_none());
    }
}
