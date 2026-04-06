use buggy::Bug;
use tracing::trace;

use crate::{
    ClientError, Location, Prior, Segment as _, Storage, StorageError, TraversalBuffer,
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

/// Initialize lazy convergence computation between two merge parents.
///
/// Returns a `ConvergenceMap` with the BFS queue seeded with `left` and
/// `right` but no work done yet. The BFS advances incrementally when
/// `should_continue` is called.
fn compute_convergence(
    left: Location,
    right: Location,
    lca: Location,
) -> Result<convergence_map::ConvergenceMap, ClientError> {
    convergence_map::ConvergenceMap::new(left, right, lca)
}

/// Chunk size for the braid result buffer.
const BRAID_CHUNK_SIZE: usize = 512;

/// Result of the braid algorithm, providing iteration over locations.
///
/// For small braids (the common case), all locations fit in the
/// in-memory buffer with no I/O. Disk-backed chunking for large
/// braids is a future extension.
pub(super) struct BraidResult {
    mem: heapless::Vec<Location, BRAID_CHUNK_SIZE>,
}

impl BraidResult {
    fn new() -> Self {
        Self {
            mem: heapless::Vec::new(),
        }
    }

    fn push(&mut self, loc: Location) -> Result<(), ClientError> {
        self.mem
            .push(loc)
            .map_err(|_| ClientError::from(StorageError::Bug(Bug::new("braid result overflow"))))
    }

    fn reverse(&mut self) {
        self.mem.as_mut_slice().reverse();
    }

    /// Splits the result into first and rest, like `Vec::split_first`.
    pub fn split_first(&self) -> Option<(&Location, &[Location])> {
        self.mem.split_first()
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

    let mut convergence = compute_convergence(left, right, lca)?;

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
            match convergence.should_continue(storage, location)? {
                convergence_map::Convergence::Drop => {
                    trace!("prior {location} convergence drop");
                    continue 'location;
                }
                convergence_map::Convergence::Unknown => {
                    // Convergence map overflowed — fall back to is_ancestor.
                    let mut is_ancestor = false;
                    for other in strands.iter() {
                        let other_seg = storage.get_segment(other.next)?;
                        if (location.same_segment(other.next)
                            && location.max_cut <= other.next.max_cut)
                            || storage.is_ancestor(location, &other_seg, buffer)?
                        {
                            is_ancestor = true;
                            break;
                        }
                    }
                    if is_ancestor {
                        trace!("prior {location} is_ancestor fallback drop");
                        continue 'location;
                    }
                }
                convergence_map::Convergence::Continue => {}
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

    braid.reverse();

    Ok(braid)
}

pub(super) mod convergence_map {
    use crate::{
        ClientError, Location, MaxCut, Segment as _, Storage,
        storage::TraversalQueue,
    };
    #[cfg(any(test, feature = "std"))]
    use crate::StorageError;

    /// Maximum entries per block.
    const BLOCK_ENTRIES: usize = 170;
    /// Number of in-memory blocks.
    const NUM_BLOCKS: usize = 3;
    /// Size of one entry on disk: 3 × u64 = 24 bytes.
    #[cfg(any(test, feature = "std"))]
    const ENTRY_BYTES: usize = 24;
    /// Size of one block on disk.
    #[cfg(any(test, feature = "std"))]
    const BLOCK_BYTES: usize = BLOCK_ENTRIES * ENTRY_BYTES;

    /// Result of a convergence check.
    #[allow(dead_code)] // Unknown only used in no_std builds
    pub enum Convergence {
        /// Not a convergence point, or last arrival — strand continues.
        Continue,
        /// Convergence point, not last arrival — drop strand.
        Drop,
        /// Map overflowed (no_std only), caller must fall back to `is_ancestor`.
        Unknown,
    }

    /// A convergence point: location and remaining arrival count.
    #[derive(Clone, Copy)]
    struct Entry {
        location: Location,
        count: usize,
    }

    impl Entry {
        #[cfg(any(test, feature = "std"))]
        fn to_bytes(self) -> [u8; ENTRY_BYTES] {
            let mut buf = [0u8; ENTRY_BYTES];
            buf[0..8].copy_from_slice(&(self.location.segment.0 as u64).to_le_bytes());
            buf[8..16].copy_from_slice(&(self.location.max_cut.0 as u64).to_le_bytes());
            buf[16..24].copy_from_slice(&(self.count as u64).to_le_bytes());
            buf
        }

        #[cfg(any(test, feature = "std"))]
        fn from_bytes(buf: &[u8; ENTRY_BYTES]) -> Self {
            let segment = u64::from_le_bytes(buf[0..8].try_into().unwrap()) as usize;
            let max_cut = u64::from_le_bytes(buf[8..16].try_into().unwrap()) as usize;
            let count = u64::from_le_bytes(buf[16..24].try_into().unwrap()) as usize;
            Self {
                location: Location::new(
                    crate::SegmentIndex(segment),
                    MaxCut(max_cut),
                ),
                count,
            }
        }
    }

    /// Index entry in the root node pointing to a block on disk.
    #[cfg(any(test, feature = "std"))]
    #[derive(Clone, Copy)]
    struct NodeEntry {
        min_max_cut: MaxCut,
        max_max_cut: MaxCut,
        file_offset: usize,
        num_entries: usize,
    }

    /// An in-memory block of convergence entries.
    struct Block {
        entries: heapless::Vec<Entry, BLOCK_ENTRIES>,
        last_accessed: u32,
        min_max_cut: MaxCut,
        max_max_cut: MaxCut,
    }

    impl Block {
        const fn new() -> Self {
            Self {
                entries: heapless::Vec::new(),
                last_accessed: 0,
                min_max_cut: MaxCut(usize::MAX),
                max_max_cut: MaxCut(0),
            }
        }

        fn is_full(&self) -> bool {
            self.entries.is_full()
        }

        #[cfg(any(test, feature = "std"))]
        fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }

        fn insert(&mut self, entry: Entry) {
            if entry.location.max_cut < self.min_max_cut {
                self.min_max_cut = entry.location.max_cut;
            }
            if entry.location.max_cut > self.max_max_cut {
                self.max_max_cut = entry.location.max_cut;
            }
            // Caller ensures block is not full.
            let _ = self.entries.push(entry);
        }

        fn find(&self, location: Location) -> Option<usize> {
            self.entries.iter().position(|e| e.location == location)
        }

        fn clear(&mut self) {
            self.entries.clear();
            self.min_max_cut = MaxCut(usize::MAX);
            self.max_max_cut = MaxCut(0);
        }

        #[cfg(any(test, feature = "std"))]
        fn to_bytes(&self) -> [u8; BLOCK_BYTES] {
            let mut buf = [0u8; BLOCK_BYTES];
            for (i, entry) in self.entries.iter().enumerate() {
                let offset = i.wrapping_mul(ENTRY_BYTES);
                buf[offset..offset.wrapping_add(ENTRY_BYTES)]
                    .copy_from_slice(&entry.to_bytes());
            }
            buf
        }

        #[cfg(any(test, feature = "std"))]
        fn load_from_bytes(buf: &[u8; BLOCK_BYTES], num_entries: usize) -> Self {
            let mut block = Block::new();
            for i in 0..num_entries {
                let offset = i.wrapping_mul(ENTRY_BYTES);
                let entry_bytes: &[u8; ENTRY_BYTES] =
                    buf[offset..offset.wrapping_add(ENTRY_BYTES)].try_into().unwrap();
                let entry = Entry::from_bytes(entry_bytes);
                block.insert(entry);
            }
            block
        }
    }

    /// Incrementally-computed convergence map with disk-backed overflow.
    ///
    /// Keeps up to 3 blocks of ~170 entries in memory. When a block
    /// fills, the least-recently-accessed block is spilled to a temp
    /// file. An in-memory root index maps max_cut ranges to file
    /// offsets for O(1) block lookup.
    pub struct ConvergenceMap {
        blocks: [Block; NUM_BLOCKS],
        active_block: usize,
        #[cfg(any(test, feature = "std"))]
        root: heapless::Vec<NodeEntry, BLOCK_ENTRIES>,
        queue: TraversalQueue,
        lca: Location,
        access_counter: u32,
        #[cfg(any(test, feature = "std"))]
        spill_file: Option<std::fs::File>,
        #[cfg(any(test, feature = "std"))]
        next_file_offset: usize,
        /// Tracks overflow in no_std mode (no disk spill available).
        #[cfg(not(any(test, feature = "std")))]
        overflowed: bool,
    }

    impl ConvergenceMap {
        /// Create a new convergence map with BFS seeded from `left` and `right`.
        pub fn new(
            left: Location,
            right: Location,
            lca: Location,
        ) -> Result<Self, ClientError> {
            let mut queue = TraversalQueue::new();
            queue.push_duplicate(left)?;
            queue.push_duplicate(right)?;
            Ok(Self {
                blocks: [Block::new(), Block::new(), Block::new()],
                active_block: 0,
                #[cfg(any(test, feature = "std"))]
                root: heapless::Vec::new(),
                queue,
                lca,
                access_counter: 0,
                #[cfg(any(test, feature = "std"))]
                spill_file: None,
                #[cfg(any(test, feature = "std"))]
                next_file_offset: 0,
                #[cfg(not(any(test, feature = "std")))]
                overflowed: false,
            })
        }

        /// Find the LRU block index (lowest last_accessed).
        fn lru_block(&self) -> usize {
            let mut lru = 0;
            for i in 1..NUM_BLOCKS {
                if self.blocks[i].last_accessed < self.blocks[lru].last_accessed {
                    lru = i;
                }
            }
            lru
        }

        /// Insert an entry into the active block, spilling if needed.
        fn insert_entry(&mut self, entry: Entry) -> Result<(), ClientError> {
            if self.blocks[self.active_block].is_full() {
                self.spill_lru()?;
            }
            self.blocks[self.active_block].insert(entry);
            Ok(())
        }

        /// Spill the LRU block to disk and make it the new active block.
        #[cfg(any(test, feature = "std"))]
        fn spill_lru(&mut self) -> Result<(), ClientError> {
            use std::io::{Seek, SeekFrom, Write};

            let lru = self.lru_block();
            let block = &self.blocks[lru];

            if block.is_empty() {
                self.active_block = lru;
                return Ok(());
            }

            let file = self.spill_file.get_or_insert_with(|| {
                tempfile_create().expect("failed to create convergence spill file")
            });

            let data = block.to_bytes();
            let num_entries = block.entries.len();
            let offset = self.next_file_offset;

            file.seek(SeekFrom::Start(offset as u64))
                .map_err(|_| StorageError::Bug(buggy::Bug::new("convergence spill file I/O error")))?;
            file.write_all(&data[..num_entries.wrapping_mul(ENTRY_BYTES)])
                .map_err(|_| StorageError::Bug(buggy::Bug::new("convergence spill file I/O error")))?;

            // Add to root index.
            if self.root.is_full() {
                // Root overflow — for now treat as error.
                // This requires > 28,900 convergence points.
                return Err(StorageError::Bug(buggy::Bug::new(
                    "convergence root index overflow",
                ))
                .into());
            }
            let _ = self.root.push(NodeEntry {
                min_max_cut: block.min_max_cut,
                max_max_cut: block.max_max_cut,
                file_offset: offset,
                num_entries,
            });

            self.next_file_offset = offset.wrapping_add(
                num_entries.wrapping_mul(ENTRY_BYTES),
            );

            // Clear and reuse.
            self.blocks[lru].clear();
            self.blocks[lru].last_accessed = 0;
            self.active_block = lru;
            Ok(())
        }

        #[cfg(not(any(test, feature = "std")))]
        fn spill_lru(&mut self) -> Result<(), ClientError> {
            // No disk available — mark overflow.
            self.overflowed = true;
            // Reuse the LRU block anyway (losing its entries).
            let lru = self.lru_block();
            self.blocks[lru].clear();
            self.blocks[lru].last_accessed = 0;
            self.active_block = lru;
            Ok(())
        }

        /// Read a spilled block from disk.
        #[cfg(any(test, feature = "std"))]
        fn read_block_from_disk(
            &mut self,
            root_idx: usize,
        ) -> Result<Block, ClientError> {
            use std::io::{Read, Seek, SeekFrom};

            let node = self.root[root_idx];
            let file = self
                .spill_file
                .as_mut()
                .expect("spill file must exist if root has entries");

            let num_entries = node.num_entries;
            let byte_len = num_entries.wrapping_mul(ENTRY_BYTES);

            file.seek(SeekFrom::Start(node.file_offset as u64))
                .map_err(|_| StorageError::Bug(buggy::Bug::new("convergence spill file I/O error")))?;

            let mut buf = [0u8; BLOCK_BYTES];
            file.read_exact(&mut buf[..byte_len])
                .map_err(|_| StorageError::Bug(buggy::Bug::new("convergence spill file I/O error")))?;

            Ok(Block::load_from_bytes(&buf, num_entries))
        }

        /// Load a spilled block into memory, evicting the LRU block.
        #[cfg(any(test, feature = "std"))]
        fn load_block_from_disk(
            &mut self,
            root_idx: usize,
        ) -> Result<usize, ClientError> {
            let loaded = self.read_block_from_disk(root_idx)?;

            // Remove from root index — data is now in memory.
            self.root.swap_remove(root_idx);

            // Evict LRU to disk, then replace it with the loaded block.
            self.spill_lru()?;
            let target = self.active_block;
            self.blocks[target] = loaded;
            self.blocks[target].last_accessed = self.access_counter;
            Ok(target)
        }

        /// Advance the BFS until all entries at or above `target_max_cut`
        /// have been processed.
        fn advance_to<S: Storage>(
            &mut self,
            storage: &mut S,
            target_max_cut: MaxCut,
        ) -> Result<(), ClientError> {
            while let Some(&top) = self.queue.peek() {
                if top.max_cut < target_max_cut {
                    break;
                }

                let (loc, count) = self
                    .queue
                    .pop_duplicates()
                    .expect("queue is non-empty after peek");

                if loc.max_cut <= self.lca.max_cut {
                    continue;
                }

                if count >= 2 {
                    self.insert_entry(Entry {
                        location: loc,
                        count,
                    })?;
                }

                // Expand priors.
                let segment = storage.get_segment(loc)?;
                if let Some(previous) = segment.previous(loc) {
                    self.queue.push_duplicate(previous)?;
                } else {
                    for prior in segment.prior() {
                        self.queue.push_duplicate(prior)?;
                    }
                }
            }

            Ok(())
        }

        /// Look up a location in the in-memory blocks.
        /// Returns (block_index, entry_index) if found.
        fn find_in_memory(&self, location: Location) -> Option<(usize, usize)> {
            for (bi, block) in self.blocks.iter().enumerate() {
                if let Some(ei) = block.find(location) {
                    return Some((bi, ei));
                }
            }
            None
        }

        /// Decrement or remove an entry, returning the appropriate Convergence.
        fn consume_entry(&mut self, block_idx: usize, entry_idx: usize) -> Convergence {
            self.blocks[block_idx].last_accessed = self.access_counter;
            if self.blocks[block_idx].entries[entry_idx].count > 1 {
                #[allow(clippy::arithmetic_side_effects)] // safe: count > 1
                {
                    self.blocks[block_idx].entries[entry_idx].count -= 1;
                }
                Convergence::Drop
            } else {
                self.blocks[block_idx].entries.swap_remove(entry_idx);
                Convergence::Continue
            }
        }

        /// Check whether a strand at `location` should continue.
        ///
        /// Advances the BFS as needed, then looks up the location in
        /// memory and on disk.
        ///
        /// Returns:
        /// - `Continue`: not a convergence point, or last arrival.
        /// - `Drop`: convergence point, not last arrival.
        /// - `Unknown`: no_std overflow, caller must fall back to `is_ancestor`.
        pub fn should_continue<S: Storage>(
            &mut self,
            storage: &mut S,
            location: Location,
        ) -> Result<Convergence, ClientError> {
            #[allow(clippy::arithmetic_side_effects)]
            {
                self.access_counter += 1;
            }

            // Advance BFS to cover the query location.
            self.advance_to(storage, location.max_cut)?;

            // Check in-memory blocks.
            if let Some((bi, ei)) = self.find_in_memory(location) {
                return Ok(self.consume_entry(bi, ei));
            }

            // Check spilled blocks on disk.
            #[cfg(any(test, feature = "std"))]
            {
                let mut ri = 0;
                while ri < self.root.len() {
                    let node = self.root[ri];
                    if location.max_cut >= node.min_max_cut
                        && location.max_cut <= node.max_max_cut
                    {
                        // Load block into memory (removes root[ri] via swap_remove).
                        let bi = self.load_block_from_disk(ri)?;
                        if let Some(ei) = self.blocks[bi].find(location) {
                            return Ok(self.consume_entry(bi, ei));
                        }
                        // Don't increment ri — swap_remove moved a new entry here.
                    } else {
                        #[allow(clippy::arithmetic_side_effects)]
                        {
                            ri += 1;
                        }
                    }
                }
            }

            #[cfg(not(any(test, feature = "std")))]
            if self.overflowed {
                return Ok(Convergence::Unknown);
            }

            Ok(Convergence::Continue)
        }
    }

    /// Create a temporary file for spilling convergence data.
    #[cfg(any(test, feature = "std"))]
    fn tempfile_create() -> std::io::Result<std::fs::File> {
        use std::env;
        use std::fs;

        let dir = env::var("TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| env::temp_dir());

        // Create and immediately unlink so the file is cleaned up on close.
        let path = dir.join(format!(
            ".convergence_spill_{}",
            std::process::id()
        ));
        let file = fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        let _ = fs::remove_file(&path);
        Ok(file)
    }
}

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
