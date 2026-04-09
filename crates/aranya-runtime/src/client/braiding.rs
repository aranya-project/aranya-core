use buggy::{Bug, BugExt as _};
use tracing::trace;

use crate::{
    ClientError, Location, Prior, Segment as _, Storage, StorageError, storage::TraversalBuffer,
};

/// Returns the last common ancestor of two Locations.
///
/// This walks the graph backwards until the two locations meet. This
/// ensures that you can jump to the last common ancestor from
/// the merge command created using left and right and know that you
/// won't be jumping into a branch.
pub(super) fn last_common_ancestor<S: Storage>(
    storage: &mut S,
    left: Location,
    right: Location,
) -> Result<Location, ClientError> {
    trace!(%left, %right, "finding least common ancestor");
    let mut left = left;
    let mut right = right;
    while left != right {
        let left_seg = storage.get_segment(left)?;
        let right_seg = storage.get_segment(right)?;
        // The command with the lower max cut could be our least common ancestor
        // so we keeping following the command with the higher max cut until
        // both sides converge.
        if left.max_cut > right.max_cut {
            left = if let Some(previous) = left_seg.previous(left) {
                previous
            } else {
                match left_seg.prior() {
                    Prior::None => left,
                    Prior::Single(s) => s,
                    Prior::Merge(_, _) => {
                        if let Some(l) = left_seg.skip_list().last() {
                            // If the storage supports skip lists we return the
                            // last common ancestor of this command.
                            *l
                        } else {
                            // This case will only be hit if the storage doesn't
                            // support skip lists so we can return anything
                            // because it won't be used.
                            return Ok(left);
                        }
                    }
                }
            };
        } else {
            right = if let Some(previous) = right_seg.previous(right) {
                previous
            } else {
                match right_seg.prior() {
                    Prior::None => right,
                    Prior::Single(s) => s,
                    Prior::Merge(_, _) => {
                        if let Some(r) = right_seg.skip_list().last() {
                            // If the storage supports skip lists we return the
                            // last common ancestor of this command.
                            *r
                        } else {
                            // This case will only be hit if the storage doesn't
                            // support skip lists so we can return anything
                            // because it won't be used.
                            return Ok(right);
                        }
                    }
                }
            };
        }
    }
    Ok(left)
}

/// Number of Location entries per braid buffer block.
/// Location is 16 bytes, so 256 entries = 4096 bytes = one 4KB page.
const BRAID_BLOCK_ENTRIES: usize = 256;

/// Size of one Location on disk: 2 × u64 = 16 bytes.
const LOCATION_BYTES: usize = 16;

/// Accumulates braid locations and iterates them in reverse push order.
pub(super) struct BraidResult {
    mem: heapless::Vec<Location, BRAID_BLOCK_ENTRIES>,
    spill_file: Option<crate::storage::TempFile>,
    spill_len: usize, // total locations written to disk
}

impl BraidResult {
    fn new() -> Self {
        Self {
            mem: heapless::Vec::new(),
            spill_file: None,
            spill_len: 0,
        }
    }

    fn push(&mut self, loc: Location) -> Result<(), ClientError> {
        if self.mem.is_full() {
            self.flush_to_disk()?;
        }
        self.mem
            .push(loc)
            .map_err(|_| ClientError::from(StorageError::Bug(Bug::new("braid result overflow"))))
    }

    fn flush_to_disk(&mut self) -> Result<(), ClientError> {
        let file = match self.spill_file.as_ref() {
            Some(f) => f,
            None => {
                self.spill_file = Some(crate::storage::TempFile::new()?);
                self.spill_file.as_ref().assume("just inserted")?
            }
        };

        let mut offset = self
            .spill_len
            .checked_mul(LOCATION_BYTES)
            .assume("spill offset must not overflow")?;

        for loc in &self.mem {
            let mut buf = [0u8; LOCATION_BYTES];
            buf[0..8].copy_from_slice(&(loc.segment.0 as u64).to_le_bytes());
            buf[8..16].copy_from_slice(&(loc.max_cut.0 as u64).to_le_bytes());
            file.write_at(offset, &buf)?;
            offset = offset
                .checked_add(LOCATION_BYTES)
                .assume("spill offset must not overflow")?;
        }

        self.spill_len = self
            .spill_len
            .checked_add(self.mem.len())
            .assume("spill_len must not overflow")?;
        self.mem.clear();
        Ok(())
    }

    /// Returns an iterator that yields locations in forward braid order
    /// (reversed from push order).
    pub fn iter(&mut self) -> Result<BraidIter<'_>, ClientError> {
        BraidIter::new(self)
    }
}

/// Iterator over braid results in forward order (reversed from push order).
///
/// Reads the in-memory buffer backwards first, then reads spilled
/// blocks from disk in reverse.
///
/// Does not implement [`Iterator`] because iteration is fallible
/// (disk reads may fail). Use [`next`](Self::next) directly.
pub(super) struct BraidIter<'a> {
    /// In-memory entries, reversed for forward iteration.
    mem: &'a [Location],
    mem_pos: usize,
    file: Option<&'a crate::storage::TempFile>,
    disk_remaining: usize,
    disk_buf: heapless::Vec<Location, BRAID_BLOCK_ENTRIES>,
    disk_buf_pos: usize,
}

impl<'a> BraidIter<'a> {
    fn new(result: &'a mut BraidResult) -> Result<Self, ClientError> {
        Ok(Self {
            mem: result.mem.as_slice(),
            mem_pos: result.mem.len(),
            file: result.spill_file.as_ref(),
            disk_remaining: result.spill_len,
            disk_buf: heapless::Vec::new(),
            disk_buf_pos: 0,
        })
    }

    /// Get the next location in forward braid order.
    pub fn next(&mut self) -> Result<Option<Location>, ClientError> {
        // First yield from in-memory buffer (backwards).
        if self.mem_pos > 0 {
            self.mem_pos = self
                .mem_pos
                .checked_sub(1)
                .assume("mem_pos > 0 checked above")?;
            return Ok(Some(self.mem[self.mem_pos]));
        }

        // Then yield from disk (backwards).
        if self.disk_buf_pos > 0 {
            self.disk_buf_pos = self
                .disk_buf_pos
                .checked_sub(1)
                .assume("disk_buf_pos > 0 checked above")?;
            return Ok(Some(self.disk_buf[self.disk_buf_pos]));
        }

        if self.disk_remaining > 0 {
            self.load_prev_block()?;
            if self.disk_buf_pos > 0 {
                self.disk_buf_pos = self
                    .disk_buf_pos
                    .checked_sub(1)
                    .assume("disk_buf_pos > 0 checked above")?;
                return Ok(Some(self.disk_buf[self.disk_buf_pos]));
            }
        }

        Ok(None)
    }

    fn load_prev_block(&mut self) -> Result<(), ClientError> {
        let count = self.disk_remaining.min(BRAID_BLOCK_ENTRIES);
        let start = self
            .disk_remaining
            .checked_sub(count)
            .assume("count <= disk_remaining by min")?;

        let file = self.file.as_ref().assume("spill file must exist")?;

        self.disk_buf.clear();
        let mut offset = start
            .checked_mul(LOCATION_BYTES)
            .assume("disk offset must not overflow")?;
        for _ in 0..count {
            let mut buf = [0u8; LOCATION_BYTES];
            file.read_at(offset, &mut buf)?;
            let segment =
                u64::from_le_bytes(buf[0..8].try_into().assume("slice is exactly 8 bytes")?)
                    as usize;
            let max_cut =
                u64::from_le_bytes(buf[8..16].try_into().assume("slice is exactly 8 bytes")?)
                    as usize;
            let _ = self.disk_buf.push(Location::new(
                crate::SegmentIndex(segment),
                crate::MaxCut(max_cut),
            ));
            offset = offset
                .checked_add(LOCATION_BYTES)
                .assume("disk offset must not overflow")?;
        }
        self.disk_buf_pos = self.disk_buf.len();
        self.disk_remaining = start;
        Ok(())
    }
}

/// Produces a deterministic ordering for a set of [`Command`]s in a graph.
///
/// The `lca` parameter is the last common ancestor of `left` and `right`.
/// A BFS pre-pass (`compute_convergence`) walks backwards from both merge
/// parents to identify convergence points — locations reachable from
/// multiple paths. During braiding, each prior location is checked against
/// the convergence map for O(1) ancestor detection, replacing the previous
/// O(k) `is_ancestor` BFS per strand.
pub(super) fn braid<S: Storage>(
    storage: &mut S,
    left: Location,
    right: Location,
    lca: Location,
    buffer: &mut TraversalBuffer,
) -> Result<BraidResult, ClientError> {
    use strand_heap::{Strand, StrandHeap};

    let mut braid = BraidResult::new();
    let mut strands = StrandHeap::new();

    trace!(%left, %right, %lca, "braiding");

    let mut convergence = convergence_map::ConvergenceMap::new(left, right, lca, buffer.get())?;

    for head in [left, right] {
        strands.push(Strand::new(storage, head, None)?)?;
    }

    // Get latest command
    while let Some(strand) = strands.pop() {
        // Consume another command off the strand
        let (prior, mut maybe_cached_segment) =
            if let Some(previous) = strand.segment.previous(strand.next) {
                (Prior::Single(previous), Some(strand.segment))
            } else {
                (strand.segment.prior(), None)
            };
        if matches!(prior, Prior::Merge(..)) {
            trace!("skipping merge command at {}", strand.next);
        } else {
            trace!("adding {}", strand.next);
            braid.push(strand.next)?;
        }

        // Continue processing prior if not accessible from other strands.
        'location: for location in prior {
            // O(1) LCA skip: any prior at or below the outermost LCA
            // is shared by both branches — no need for further checks.
            if location.max_cut <= lca.max_cut {
                trace!(
                    "prior {location} at/below LCA (max_cut <= {}) skipping",
                    lca.max_cut
                );
                continue 'location;
            }

            // Same-segment check (O(1) per strand).
            for other in strands.iter() {
                if location.same_segment(other.next) && location.max_cut <= other.next.max_cut {
                    trace!("prior {location} same segment as {}", other.next);
                    continue 'location;
                }
            }

            // Convergence check (incremental BFS, O(1) amortized).
            if !convergence.should_continue(storage, location)? {
                trace!("prior {location} convergence drop");
                continue 'location;
            }

            trace!("strand at {location}");
            strands.push(Strand::new(
                storage,
                location,
                // Taking is OK here because `maybe_cached_segment` is `Some` when
                // the current strand has a single parent that is in the same segment
                Option::take(&mut maybe_cached_segment),
            )?)?;
        }
        if let Some(strand) = strands.lone() {
            // No concurrency left, done.
            let next = strand.next;
            trace!("adding {next}");
            braid.push(next)?;
            break;
        }
    }

    Ok(braid)
}

use super::convergence_map;

mod strand_heap {
    use heapless::binary_heap::Max;

    use crate::{
        ClientError, CmdId, Command as _, Location, Priority, Segment, Storage, StorageError,
        storage::QUEUE_CAPACITY,
    };

    /// Maximum number of active strands. Equal to `QUEUE_CAPACITY` since
    /// strand count is bounded by graph width, the same bound as the
    /// traversal queue.
    pub const STRAND_CAPACITY: usize = QUEUE_CAPACITY;

    pub struct Strand<S> {
        key: (Priority, CmdId),
        pub next: Location,
        pub segment: S,
    }

    impl<S: Segment> Strand<S> {
        pub fn new(
            storage: &mut impl Storage<Segment = S>,
            location: Location,
            cached_segment: Option<S>,
        ) -> Result<Self, ClientError> {
            let segment = cached_segment.map_or_else(|| storage.get_segment(location), Ok)?;

            let key = {
                let cmd = segment
                    .get_command(location)
                    .ok_or(StorageError::CommandOutOfBounds(location))?;
                (cmd.priority(), cmd.id())
            };

            Ok(Self {
                key,
                next: location,
                segment,
            })
        }
    }

    impl<S> Eq for Strand<S> {}
    impl<S> PartialEq for Strand<S> {
        fn eq(&self, other: &Self) -> bool {
            self.key == other.key
        }
    }
    impl<S> Ord for Strand<S> {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            self.key.cmp(&other.key).reverse()
        }
    }
    impl<S> PartialOrd for Strand<S> {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    /// A wrapper around a binary heap which is limited to one finalize command.
    pub struct StrandHeap<S> {
        heap: heapless::BinaryHeap<Strand<S>, Max, STRAND_CAPACITY>,
        /// Tracks whether there is a finalize command in `self.heap`.
        has_finalize: bool,
    }

    impl<S> StrandHeap<S> {
        pub const fn new() -> Self {
            Self {
                heap: heapless::BinaryHeap::new(),
                has_finalize: false,
            }
        }

        /// Adds another strand to the heap.
        ///
        /// Errors if it would add a second finalize command or the heap is full.
        pub fn push(&mut self, strand: Strand<S>) -> Result<(), ClientError> {
            if matches!(strand.key.0, Priority::Finalize) {
                if self.has_finalize {
                    return Err(ClientError::ParallelFinalize);
                }
                self.has_finalize = true;
            }
            self.heap
                .push(strand)
                .map_err(|_| StorageError::StrandHeapOverflow(STRAND_CAPACITY))?;
            Ok(())
        }

        /// Pop a strand from the heap.
        pub fn pop(&mut self) -> Option<Strand<S>> {
            let strand = self.heap.pop()?;
            if matches!(strand.key.0, Priority::Finalize) {
                debug_assert!(self.heap.is_empty());
                debug_assert!(self.has_finalize);
                self.has_finalize = false;
            }
            Some(strand)
        }

        /// Pops last strand when only one strand remains.
        pub fn lone(&mut self) -> Option<Strand<S>> {
            if self.heap.len() != 1 {
                return None;
            }
            self.has_finalize = false;
            let item = self.heap.pop();
            debug_assert!(item.is_some());
            item
        }

        pub fn iter(&self) -> impl Iterator<Item = &Strand<S>> {
            self.heap.iter()
        }
    }
}

#[cfg(test)]
mod braid_result_tests {
    use super::*;
    use crate::{MaxCut, SegmentIndex};

    fn loc(seg: usize, cut: usize) -> Location {
        Location::new(SegmentIndex(seg), MaxCut(cut))
    }

    #[test]
    fn empty_result_yields_nothing() {
        let mut result = BraidResult::new();
        let mut iter = result.iter().unwrap();
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn single_entry() {
        let mut result = BraidResult::new();
        result.push(loc(0, 1)).unwrap();
        let mut iter = result.iter().unwrap();
        assert_eq!(iter.next().unwrap(), Some(loc(0, 1)));
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn yields_in_reverse_push_order() {
        let mut result = BraidResult::new();
        result.push(loc(0, 3)).unwrap();
        result.push(loc(1, 2)).unwrap();
        result.push(loc(2, 1)).unwrap();

        let mut iter = result.iter().unwrap();
        assert_eq!(iter.next().unwrap(), Some(loc(2, 1)));
        assert_eq!(iter.next().unwrap(), Some(loc(1, 2)));
        assert_eq!(iter.next().unwrap(), Some(loc(0, 3)));
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn spill_to_disk_and_iterate() {
        let mut result = BraidResult::new();
        // Push more than BRAID_BLOCK_ENTRIES (256) to force a disk spill.
        let total = BRAID_BLOCK_ENTRIES + 10;
        for i in 0..total {
            result.push(loc(i, i)).unwrap();
        }
        assert!(result.spill_file.is_some());
        assert!(result.spill_len > 0);

        let mut iter = result.iter().unwrap();
        // Should yield in reverse push order.
        for i in (0..total).rev() {
            let entry = iter.next().unwrap().unwrap();
            assert_eq!(entry, loc(i, i), "mismatch at reverse index {i}");
        }
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn multiple_spills() {
        let mut result = BraidResult::new();
        // Push 3 full blocks worth to force multiple spills.
        let total = BRAID_BLOCK_ENTRIES * 3 + 5;
        for i in 0..total {
            result.push(loc(i, i)).unwrap();
        }

        let mut iter = result.iter().unwrap();
        for i in (0..total).rev() {
            let entry = iter.next().unwrap().unwrap();
            assert_eq!(entry, loc(i, i), "mismatch at reverse index {i}");
        }
        assert!(iter.next().unwrap().is_none());
    }
}
