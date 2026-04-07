use crate::{
    ClientError, Location, MaxCut, Segment as _, Storage, StorageError, TempFile,
    storage::TraversalQueue,
};

/// Maximum entries per block.
const BLOCK_ENTRIES: usize = 170;
/// Number of in-memory blocks.
const NUM_BLOCKS: usize = 3;
/// Size of one entry on disk: 3 × u64 = 24 bytes.
const ENTRY_BYTES: usize = 24;
/// Size of one block on disk.
const BLOCK_BYTES: usize = BLOCK_ENTRIES * ENTRY_BYTES;

/// Result of a convergence check.
pub enum Convergence {
    /// Not a convergence point, or last arrival — strand continues.
    Continue,
    /// Convergence point, not last arrival — drop strand.
    Drop,
}

/// A convergence point: location and remaining arrival count.
#[derive(Clone, Copy)]
struct Entry {
    location: Location,
    count: usize,
}

impl Entry {
    fn to_bytes(self) -> [u8; ENTRY_BYTES] {
        let mut buf = [0u8; ENTRY_BYTES];
        buf[0..8].copy_from_slice(&(self.location.segment.0 as u64).to_le_bytes());
        buf[8..16].copy_from_slice(&(self.location.max_cut.0 as u64).to_le_bytes());
        buf[16..24].copy_from_slice(&(self.count as u64).to_le_bytes());
        buf
    }

    #[allow(clippy::unwrap_used)] // infallible: slices are exactly 8 bytes
    fn from_bytes(buf: &[u8; ENTRY_BYTES]) -> Self {
        let segment = u64::from_le_bytes(buf[0..8].try_into().unwrap()) as usize;
        let max_cut = u64::from_le_bytes(buf[8..16].try_into().unwrap()) as usize;
        let count = u64::from_le_bytes(buf[16..24].try_into().unwrap()) as usize;
        Self {
            location: Location::new(crate::SegmentIndex(segment), MaxCut(max_cut)),
            count,
        }
    }
}

/// Index entry in the root node pointing to a block on disk.
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

    fn to_bytes(&self) -> [u8; BLOCK_BYTES] {
        let mut buf = [0u8; BLOCK_BYTES];
        for (i, entry) in self.entries.iter().enumerate() {
            let offset = i.wrapping_mul(ENTRY_BYTES);
            buf[offset..offset.wrapping_add(ENTRY_BYTES)].copy_from_slice(&entry.to_bytes());
        }
        buf
    }

    #[allow(clippy::unwrap_used)] // infallible: slice is exactly ENTRY_BYTES
    fn load_from_bytes(buf: &[u8; BLOCK_BYTES], num_entries: usize) -> Self {
        let mut block = Self::new();
        for i in 0..num_entries {
            let offset = i.wrapping_mul(ENTRY_BYTES);
            let entry_bytes: &[u8; ENTRY_BYTES] = buf[offset..offset.wrapping_add(ENTRY_BYTES)]
                .try_into()
                .unwrap();
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
    root: heapless::Vec<NodeEntry, BLOCK_ENTRIES>,
    queue: TraversalQueue,
    lca: Location,
    access_counter: u32,
    spill_file: Option<TempFile>,
    next_file_offset: usize,
}

impl ConvergenceMap {
    /// Create a new convergence map with BFS seeded from `left` and `right`.
    pub fn new(left: Location, right: Location, lca: Location) -> Result<Self, ClientError> {
        let mut queue = TraversalQueue::new();
        queue.push_duplicate(left)?;
        queue.push_duplicate(right)?;
        Ok(Self {
            blocks: [Block::new(), Block::new(), Block::new()],
            active_block: 0,
            root: heapless::Vec::new(),
            queue,
            lca,
            access_counter: 0,
            spill_file: None,
            next_file_offset: 0,
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
    fn spill_lru(&mut self) -> Result<(), ClientError> {
        let lru = self.lru_block();
        let block = &self.blocks[lru];

        if block.is_empty() {
            self.active_block = lru;
            return Ok(());
        }

        let file = match &self.spill_file {
            Some(_) => self.spill_file.as_ref().expect("just checked"),
            None => {
                self.spill_file = Some(TempFile::new()?);
                self.spill_file.as_ref().expect("just created")
            }
        };

        let data = block.to_bytes();
        let num_entries = block.entries.len();
        let offset = self.next_file_offset;

        file.write_at(offset, &data[..num_entries.wrapping_mul(ENTRY_BYTES)])
            .map_err(|_| StorageError::Bug(buggy::Bug::new("convergence spill file I/O error")))?;

        // Add to root index.
        if self.root.is_full() {
            // Root overflow — for now treat as error.
            // This requires > 28,900 convergence points.
            return Err(
                StorageError::Bug(buggy::Bug::new("convergence root index overflow")).into(),
            );
        }
        let _ = self.root.push(NodeEntry {
            min_max_cut: block.min_max_cut,
            max_max_cut: block.max_max_cut,
            file_offset: offset,
            num_entries,
        });

        self.next_file_offset = offset.wrapping_add(num_entries.wrapping_mul(ENTRY_BYTES));

        // Clear and reuse.
        self.blocks[lru].clear();
        self.blocks[lru].last_accessed = 0;
        self.active_block = lru;
        Ok(())
    }

    /// Read a spilled block from disk.
    fn read_block_from_disk(&self, root_idx: usize) -> Result<Block, ClientError> {
        let node = self.root[root_idx];
        let file = self
            .spill_file
            .as_ref()
            .expect("spill file must exist if root has entries");

        let num_entries = node.num_entries;
        let byte_len = num_entries.wrapping_mul(ENTRY_BYTES);

        let mut buf = [0u8; BLOCK_BYTES];
        file.read_at(node.file_offset, &mut buf[..byte_len])
            .map_err(|_| StorageError::Bug(buggy::Bug::new("convergence spill file I/O error")))?;

        Ok(Block::load_from_bytes(&buf, num_entries))
    }

    /// Load a spilled block into memory, evicting the LRU block.
    fn load_block_from_disk(&mut self, root_idx: usize) -> Result<usize, ClientError> {
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
        {
            let mut ri = 0;
            while ri < self.root.len() {
                let node = self.root[ri];
                if location.max_cut >= node.min_max_cut && location.max_cut <= node.max_max_cut {
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

        Ok(Convergence::Continue)
    }
}
