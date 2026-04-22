use core::mem::size_of;

use buggy::BugExt as _;

use crate::{
    ClientError, Location, MaxCut, Segment as _, Storage, StorageError,
    storage::{ScratchFile, TraversalQueue},
};

/// Size of one entry on disk: three `u64`s (segment, max_cut, count).
const ENTRY_BYTES: usize = size_of::<u64>() * 3;
/// Target spill-block size. Chosen to match a typical filesystem page so
/// each block read/write is one page operation; `BLOCK_ENTRIES` is sized
/// to fit within this budget (24 bytes × 170 = 4080, leaving 16 bytes
/// unused per block).
const BLOCK_BYTES: usize = 4096;
/// Maximum entries per block (floor of `BLOCK_BYTES / ENTRY_BYTES`).
const BLOCK_ENTRIES: usize = BLOCK_BYTES / ENTRY_BYTES;
/// Number of in-memory blocks retained via LRU before spilling to disk.
const NUM_BLOCKS: usize = 3;
/// Maximum entries in the root index. Sized at `3 × BLOCK_ENTRIES` so the
/// root is comparable in memory footprint to the in-memory block cache;
/// each root entry points to one spilled block, so this supports up to
/// `ROOT_CAPACITY × BLOCK_ENTRIES` = 86,700 convergence points before
/// overflow.
const ROOT_CAPACITY: usize = BLOCK_ENTRIES * 3;

/// A convergence point: location and remaining arrival count.
#[derive(Clone, Copy)]
struct Entry {
    location: Location,
    count: usize,
}

impl Entry {
    fn to_bytes(self) -> [u8; ENTRY_BYTES] {
        let mut buf = [0u8; ENTRY_BYTES];
        buf[0..8].copy_from_slice(&(self.location.segment.0 as u64).to_ne_bytes());
        buf[8..16].copy_from_slice(&(self.location.max_cut.0 as u64).to_ne_bytes());
        buf[16..24].copy_from_slice(&(self.count as u64).to_ne_bytes());
        buf
    }

    #[allow(clippy::unwrap_used)] // infallible: slices are exactly 8 bytes
    fn from_bytes(buf: &[u8; ENTRY_BYTES]) -> Self {
        let segment = u64::from_ne_bytes(buf[0..8].try_into().unwrap()) as usize;
        let max_cut = u64::from_ne_bytes(buf[8..16].try_into().unwrap()) as usize;
        let count = u64::from_ne_bytes(buf[16..24].try_into().unwrap()) as usize;
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

    fn to_bytes(&self) -> Result<[u8; BLOCK_BYTES], ClientError> {
        let mut buf = [0u8; BLOCK_BYTES];
        for (i, entry) in self.entries.iter().enumerate() {
            let offset = i
                .checked_mul(ENTRY_BYTES)
                .assume("block offset must not overflow")?;
            let end = offset
                .checked_add(ENTRY_BYTES)
                .assume("block end must not overflow")?;
            buf[offset..end].copy_from_slice(&entry.to_bytes());
        }
        Ok(buf)
    }

    fn load_from_bytes(buf: &[u8; BLOCK_BYTES], num_entries: usize) -> Result<Self, ClientError> {
        let mut block = Self::new();
        for i in 0..num_entries {
            let offset = i
                .checked_mul(ENTRY_BYTES)
                .assume("block offset must not overflow")?;
            let end = offset
                .checked_add(ENTRY_BYTES)
                .assume("block end must not overflow")?;
            let entry_bytes: &[u8; ENTRY_BYTES] = buf[offset..end]
                .try_into()
                .assume("slice is exactly ENTRY_BYTES")?;
            let entry = Entry::from_bytes(entry_bytes);
            block.insert(entry);
        }
        Ok(block)
    }
}

/// Incrementally-computed convergence map with disk-backed overflow.
///
/// Keeps up to 3 blocks of ~170 entries in memory. When a block
/// fills, the least-recently-accessed block is spilled to a temp
/// file. An in-memory root index maps max_cut ranges to file
/// offsets for O(1) block lookup.
pub struct ConvergenceMap<'a, F> {
    blocks: [Block; NUM_BLOCKS],
    active_block: usize,
    root: heapless::Vec<NodeEntry, ROOT_CAPACITY>,
    queue: &'a mut TraversalQueue,
    lca: Location,
    access_counter: u32,
    spill_file: Option<F>,
    next_file_offset: usize,
}

impl<'a, F: ScratchFile> ConvergenceMap<'a, F> {
    /// Create a new convergence map with BFS seeded from `left` and `right`.
    pub fn new(
        left: Location,
        right: Location,
        lca: Location,
        queue: &'a mut TraversalQueue,
    ) -> Result<Self, ClientError> {
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
            Some(_) => self.spill_file.as_ref().assume("just checked")?,
            None => {
                self.spill_file = Some(F::new()?);
                self.spill_file.as_ref().assume("just created")?
            }
        };

        let data = block.to_bytes()?;
        let num_entries = block.entries.len();
        let offset = self.next_file_offset;

        let byte_len = num_entries
            .checked_mul(ENTRY_BYTES)
            .assume("spill byte length must not overflow")?;
        file.write_at(offset, &data[..byte_len])?;

        // Add to root index.
        if self.root.is_full() {
            return Err(StorageError::ConvergenceRootOverflow(ROOT_CAPACITY).into());
        }
        let _ = self.root.push(NodeEntry {
            min_max_cut: block.min_max_cut,
            max_max_cut: block.max_max_cut,
            file_offset: offset,
            num_entries,
        });

        self.next_file_offset = offset
            .checked_add(byte_len)
            .assume("next file offset must not overflow")?;

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
            .assume("spill file must exist if root has entries")?;

        let num_entries = node.num_entries;
        let byte_len = num_entries
            .checked_mul(ENTRY_BYTES)
            .assume("disk byte length must not overflow")?;

        let mut buf = [0u8; BLOCK_BYTES];
        file.read_at(node.file_offset, &mut buf[..byte_len])?;

        Block::load_from_bytes(&buf, num_entries)
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
                .pop_duplicates()?
                .assume("queue is non-empty after peek")?;

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

    /// Decrement or remove an entry, returning whether the strand should continue.
    fn consume_entry(&mut self, block_idx: usize, entry_idx: usize) -> Result<bool, ClientError> {
        self.blocks[block_idx].last_accessed = self.access_counter;
        if self.blocks[block_idx].entries[entry_idx].count > 1 {
            self.blocks[block_idx].entries[entry_idx].count = self.blocks[block_idx].entries
                [entry_idx]
                .count
                .checked_sub(1)
                .assume("count > 1 checked above")?;
            Ok(false)
        } else {
            self.blocks[block_idx].entries.swap_remove(entry_idx);
            Ok(true)
        }
    }

    /// Check whether a strand at `location` should continue.
    ///
    /// Advances the BFS as needed, then looks up the location in
    /// memory and on disk.
    ///
    /// Returns `true` if the strand should continue (not a convergence
    /// point, or last arrival), `false` if it should be dropped.
    pub fn should_continue<S: Storage>(
        &mut self,
        storage: &mut S,
        location: Location,
    ) -> Result<bool, ClientError> {
        self.access_counter = self
            .access_counter
            .checked_add(1)
            .assume("access_counter must not overflow")?;

        // Advance BFS to cover the query location.
        self.advance_to(storage, location.max_cut)?;

        // Check in-memory blocks.
        if let Some((bi, ei)) = self.find_in_memory(location) {
            return self.consume_entry(bi, ei);
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
                        return self.consume_entry(bi, ei);
                    }
                    // Don't increment ri — swap_remove moved a new entry here.
                } else {
                    ri = ri.checked_add(1).assume("ri must not overflow")?;
                }
            }
        }

        Ok(true)
    }
}
