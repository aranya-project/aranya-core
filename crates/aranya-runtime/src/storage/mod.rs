//! Interfaces for graph storage.
//!
//! The [`StorageProvider`] and [`Storage`] interfaces enable high-level
//! actions on the graph. Traversing the graph is made simpler by splitting
//! its [`Command`]s into [`Segment`]s. Updating the graph is possible using
//! [`Perspective`]s, which represent a slice of state.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{fmt, ops::Deref};

use buggy::{Bug, BugExt as _};
use serde::{Deserialize, Serialize};

use crate::{Address, CmdId, Command, PolicyId, Prior};

pub mod linear;

#[cfg(any(feature = "libc", feature = "testing"))]
mod temp_file;
#[cfg(feature = "libc")]
pub use temp_file::LibcSpill;
#[cfg(feature = "testing")]
pub use temp_file::MemSpill;

/// Temporary scratch file for spilling data to disk.
pub trait ScratchFile: Sized {
    /// Create a new scratch file.
    fn new() -> Result<Self, StorageError>;
    /// Write `data` at the given byte offset.
    fn write_at(&self, offset: usize, data: &[u8]) -> Result<(), StorageError>;
    /// Read exactly `data.len()` bytes starting at the given byte offset.
    fn read_at(&self, offset: usize, data: &mut [u8]) -> Result<(), StorageError>;
}

/// Default capacity for the traversal queue.
///
/// This should be large enough to hold the maximum expected "active frontier"
/// during backward traversal, which is bounded by peer count.
pub const QUEUE_CAPACITY: usize = 512;

/// Type for the queue used in traversal operations.
///
/// Locations with the highest `max_cut` are processed first. This bounds the
/// queue size to the graph width at any given `max_cut` level, rather than
/// accumulating entries across many levels as a FIFO would.
///
/// Entries are partitioned into uncovered (`entries[0..partition]`) and
/// covered (`entries[partition..len]`). See [`push_covered`](Self::push_covered)
/// for the rules governing partition transitions.
#[derive(Debug, Default)]
pub struct TraversalQueue {
    entries: heapless::Vec<Location, QUEUE_CAPACITY>,
    /// Index separating uncovered (below) from covered (at and above).
    partition: usize,
}

impl TraversalQueue {
    /// Create an empty traversal queue.
    pub const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
            partition: 0,
        }
    }

    /// Clear the traversal queue.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.partition = 0;
    }

    /// Returns true if no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Enqueues a location as uncovered.
    ///
    /// If an entry with the same segment exists, its max cut will be updated
    /// to the max of the two.
    pub fn push(&mut self, loc: Location) -> Result<(), StorageError> {
        self.push_covered(loc, false)
    }

    /// Enqueues a location with the given covered flag.
    ///
    /// If an entry with the same segment already exists, max cut is updated
    /// to the max. When a higher max_cut changes the head, the new push's
    /// covered status is adopted (old coverage was below the new head).
    /// At the same max_cut, covered flags are OR'd. Lower max_cut is ignored.
    pub fn push_covered(&mut self, loc: Location, covered: bool) -> Result<(), StorageError> {
        if let Some(i) = self.entries.iter().position(|x| x.same_segment(loc)) {
            let was_covered = i >= self.partition;
            let new_covered = if loc.max_cut > self.entries[i].max_cut {
                self.entries[i].max_cut = loc.max_cut;
                covered
            } else if loc.max_cut == self.entries[i].max_cut {
                was_covered || covered
            } else {
                return Ok(());
            };
            if !was_covered && new_covered {
                self.partition = self
                    .partition
                    .checked_sub(1)
                    .assume("partition must be >= 1 when uncovered entry exists")?;
                self.entries.swap(i, self.partition);
            } else if was_covered && !new_covered {
                self.entries.swap(i, self.partition);
                self.partition = self
                    .partition
                    .checked_add(1)
                    .assume("partition must not overflow")?;
            }
            return Ok(());
        }
        self.entries
            .push(loc)
            .map_err(|_| StorageError::TraversalQueueOverflow(QUEUE_CAPACITY))?;
        if !covered {
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
        }
        Ok(())
    }

    /// Enqueues a location without deduplication.
    ///
    /// Unlike [`Self::push`], each call adds a new entry even if the location
    /// is already present. Used by the convergence pre-pass where
    /// duplicate tracking is needed.
    pub fn push_duplicate(&mut self, loc: Location) -> Result<(), StorageError> {
        self.entries
            .push(loc)
            .map_err(|_| StorageError::TraversalQueueOverflow(QUEUE_CAPACITY))?;
        // All duplicate entries are uncovered.
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

    /// Pop the location with the highest max cut, discarding the covered flag.
    pub fn pop(&mut self) -> Result<Option<Location>, StorageError> {
        Ok(self.pop_covered()?.map(|(loc, _)| loc))
    }

    /// Pop the location with the highest max cut, including its covered flag.
    pub fn pop_covered(&mut self) -> Result<Option<(Location, bool)>, StorageError> {
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

    /// Returns the entry with the highest `max_cut` without removing it.
    pub fn peek(&self) -> Option<&Location> {
        self.entries.iter().max_by_key(|loc| *loc)
    }

    /// Pop the entry with the highest `max_cut`, removing all entries
    /// at that exact location. Returns `(location, count)`.
    ///
    /// Used by the convergence pre-pass. Entries are matched by full
    /// `Location` equality (segment + max_cut), not just max_cut.
    pub fn pop_duplicates(&mut self) -> Result<Option<(Location, usize)>, StorageError> {
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
                    .assume("count bounded by QUEUE_CAPACITY")?;
                if j < self.partition {
                    self.partition = self
                        .partition
                        .checked_sub(1)
                        .assume("partition >= 1 when uncovered entry at j < partition")?;
                    self.entries.swap(j, self.partition);
                    self.entries.swap_remove(self.partition);
                } else {
                    self.entries.swap_remove(j);
                }
            }
        }

        Ok(Some((location, count)))
    }

    /// Returns true if all entries are covered (uncovered partition is empty).
    pub fn all_covered(&self) -> bool {
        self.partition == 0
    }

    /// Remove all entries with `max_cut > threshold` from the queue.
    ///
    /// Uncovered entries are passed to `f`. Covered entries are discarded
    /// (the peer already has them).
    pub fn drain_above(
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
    pub fn cover_up_to(
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
            self.partition = self
                .partition
                .checked_sub(1)
                .assume("partition must be >= 1 when uncovered entry exists")?;
            self.entries.swap(i, self.partition);
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
    pub fn drain_all(&mut self, mut f: impl FnMut(Location)) {
        for i in 0..self.partition {
            f(self.entries[i]);
        }
        self.entries.clear();
        self.partition = 0;
    }
}

/// A queue buffer for a single graph traversal operation.
///
/// Access via [`get()`](Self::get), which clears the buffer automatically.
pub struct TraversalBuffer {
    queue: TraversalQueue,
}

impl TraversalBuffer {
    pub const fn new() -> Self {
        Self {
            queue: TraversalQueue::new(),
        }
    }

    /// Returns a cleared queue ready for use.
    pub fn get(&mut self) -> &mut TraversalQueue {
        self.queue.clear();
        &mut self.queue
    }
}

impl Default for TraversalBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Reusable buffers for graph traversal operations.
///
/// Contains two independent queue buffers so that an outer traversal
/// (e.g. `find_needed_segments`) can maintain state in one buffer while
/// calling leaf operations (e.g. `is_ancestor`) that use the other.
pub struct TraversalBuffers {
    pub primary: TraversalBuffer,
    pub secondary: TraversalBuffer,
}

impl TraversalBuffers {
    pub const fn new() -> Self {
        Self {
            primary: TraversalBuffer::new(),
            secondary: TraversalBuffer::new(),
        }
    }
}

impl Default for TraversalBuffers {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "low-mem-usage")]
pub const MAX_COMMAND_LENGTH: usize = 400;
#[cfg(not(feature = "low-mem-usage"))]
pub const MAX_COMMAND_LENGTH: usize = 2048;

aranya_crypto::custom_id! {
    /// The ID of the graph, taken from initialization.
    pub struct GraphId;
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct SegmentIndex(pub usize);

impl fmt::Display for SegmentIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct MaxCut(pub usize);

impl fmt::Display for MaxCut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl MaxCut {
    /// Adds an amount to the max cut, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, other: usize) -> Option<Self> {
        self.0.checked_add(other).map(Self)
    }

    /// Gets a max cut one lower than this, returning `None` on overflow.
    #[must_use]
    pub fn decremented(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    /// Gets the distance between two max cuts, returning `None` on overflow.
    #[must_use]
    pub fn distance_from(self, other: Self) -> Option<usize> {
        self.0.checked_sub(other.0)
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Location {
    pub max_cut: MaxCut,
    pub segment: SegmentIndex,
}

impl From<(SegmentIndex, MaxCut)> for Location {
    fn from((segment, max_cut): (SegmentIndex, MaxCut)) -> Self {
        Self::new(segment, max_cut)
    }
}

impl AsRef<Self> for Location {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Location {
    pub fn new(segment: SegmentIndex, max_cut: MaxCut) -> Self {
        Self { max_cut, segment }
    }

    /// Returns true if other location is in the same segment.
    pub fn same_segment(self, other: Self) -> bool {
        self.segment == other.segment
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.segment, self.max_cut)
    }
}

/// An error returned by [`Storage`] or [`StorageProvider`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("storage already exists")]
    StorageExists,
    #[error("no such storage")]
    NoSuchStorage,
    #[error("segment index {} is out of bounds", .0.segment)]
    SegmentOutOfBounds(Location),
    #[error("max cut {} is out of bounds in segment {}", .0.max_cut, .0.segment)]
    CommandOutOfBounds(Location),
    #[error("IO error")]
    IoError,
    #[error("policy mismatch")]
    PolicyMismatch,
    #[error("cannot write an empty perspective")]
    EmptyPerspective,
    #[error("traversal queue overflow (capacity {0})")]
    TraversalQueueOverflow(usize),
    #[error("strand heap overflow (capacity {0})")]
    StrandHeapOverflow(usize),
    #[error("convergence root index overflow (capacity {0})")]
    ConvergenceRootOverflow(usize),
    #[error("command's parents do not match the perspective head")]
    PerspectiveHeadMismatch,
    #[error(transparent)]
    Bug(#[from] Bug),
}

/// Handle to storage implementations used by the runtime.
pub trait StorageProvider {
    type Perspective: Perspective + Revertable;
    type Segment: Segment;
    type Storage: Storage<
            Segment = Self::Segment,
            Perspective = Self::Perspective,
            FactIndex = <Self::Segment as Segment>::FactIndex,
        >;

    /// Create an unrooted perspective, intended for creating a new graph.
    ///
    /// # Arguments
    ///
    /// * `policy_id` - The policy to associate with the graph.
    fn new_perspective(&mut self, policy_id: PolicyId) -> Self::Perspective;

    /// Create a new graph.
    ///
    /// # Arguments
    ///
    /// * `graph` - ID of the graph, taken from the initialization command.
    /// * `init` - Contains the data necessary to initialize the new graph.
    fn new_storage(
        &mut self,
        init: Self::Perspective,
    ) -> Result<(GraphId, &mut Self::Storage), StorageError>;

    /// Get an existing graph.
    ///
    /// # Arguments
    ///
    /// * `graph` - ID of the graph, taken from the initialization command.
    fn get_storage(&mut self, graph: GraphId) -> Result<&mut Self::Storage, StorageError>;

    /// Remove a graph.
    ///
    /// # Arguments
    ///
    /// * `graph` - ID of the graph, taken from the initialization command.
    fn remove_storage(&mut self, graph: GraphId) -> Result<(), StorageError>;

    /// Gets a list of all stored graphs by their graph ID.
    // TODO(nikki): rewrite this once we can use coroutines/generators?
    fn list_graph_ids(
        &mut self,
    ) -> Result<impl Iterator<Item = Result<GraphId, StorageError>>, StorageError>;
}

/// Represents the runtime's graph; [`Command`]s in storage have been validated
/// by an associated policy and committed to state.
pub trait Storage {
    type Perspective: Perspective + Revertable;
    type FactPerspective: FactPerspective;
    type Segment: Segment<FactIndex = Self::FactIndex>;
    type FactIndex: FactIndex;

    /// Returns the location of Command with id if it has been stored by
    /// searching from the head.
    fn get_location(
        &self,
        address: Address,
        buffer: &mut TraversalBuffer,
    ) -> Result<Option<Location>, StorageError> {
        self.get_location_from(self.get_head()?, address, buffer)
    }

    /// Returns the location of Command with id by searching from the given location.
    ///
    /// See `aranya-docs/docs/graph-traversal.md` for the traversal algorithm specification.
    fn get_location_from(
        &self,
        start: Location,
        address: Address,
        buffer: &mut TraversalBuffer,
    ) -> Result<Option<Location>, StorageError> {
        if start.max_cut < address.max_cut {
            return Ok(None);
        }

        let queue = buffer.get();
        queue.push(start)?;

        while let Some(loc) = queue.pop()? {
            debug_assert!(
                loc.max_cut >= address.max_cut,
                "Invariant: we only enqueue locations with at least the target max cut"
            );

            // Must load segment
            let segment = self.get_segment(loc)?;

            // Search commands in this segment.
            if let Some(found) = segment.get_by_address(address) {
                return Ok(Some(found));
            }

            // Try to use skip list to jump directly backward.
            // Skip list is sorted by max_cut ascending, so the first entry
            // with max_cut >= target has the lowest valid max_cut, jumping
            // furthest back in the graph.
            if let Some(&skip) = segment
                .skip_list()
                .iter()
                .find(|skip| skip.max_cut >= address.max_cut)
            {
                queue.push(skip)?;
            } else {
                // No valid skip - add prior locations to queue
                for prior in segment.prior() {
                    if prior.max_cut >= address.max_cut {
                        queue.push(prior)?;
                    }
                }
            }
        }
        Ok(None)
    }

    /// Returns the address of the command at the given location.
    ///
    /// By default, this fetches the segment, then the command, then the address.
    fn get_command_address(&self, location: Location) -> Result<Address, StorageError> {
        let segment = self.get_segment(location)?;
        let command = segment
            .get_command(location)
            .ok_or(StorageError::CommandOutOfBounds(location))?;
        let address = command.address()?;
        Ok(address)
    }

    /// Returns a linear perspective at the given location.
    fn get_linear_perspective(&self, parent: Location) -> Result<Self::Perspective, StorageError>;

    /// Returns a fact perspective at the given location, intended for evaluating braids.
    /// The fact perspective will include the facts of the command at the given location.
    fn get_fact_perspective(&self, first: Location) -> Result<Self::FactPerspective, StorageError>;

    /// Returns a merge perspective based on the given locations with the braid as prior facts.
    fn new_merge_perspective(
        &self,
        left: Location,
        right: Location,
        last_common_ancestor: Location,
        policy_id: PolicyId,
        braid: Self::FactIndex,
    ) -> Result<Self::Perspective, StorageError>;

    /// Returns the segment at the given location.
    fn get_segment(&self, location: Location) -> Result<Self::Segment, StorageError>;

    /// Returns the location of head of the graph.
    fn get_head(&self) -> Result<Location, StorageError>;

    /// Returns the address of the head of the graph.
    fn get_head_address(&self) -> Result<Address, StorageError> {
        self.get_command_address(self.get_head()?)
    }

    /// Sets the given segment as the head of the graph.
    ///
    /// The given segment must be a descendant of the current graph head.
    /// Implementations may rely on this for correctness, but not for safety.
    fn commit(&mut self, segment: Self::Segment) -> Result<(), StorageError>;

    /// Writes the given perspective to a segment.
    fn write(&mut self, perspective: Self::Perspective) -> Result<Self::Segment, StorageError>;

    /// Writes the given fact perspective to a fact index.
    fn write_facts(
        &mut self,
        fact_perspective: Self::FactPerspective,
    ) -> Result<Self::FactIndex, StorageError>;

    /// Determine whether the given location is an ancestor of the given segment.
    fn is_ancestor(
        &self,
        search_location: Location,
        segment: &Self::Segment,
        buffer: &mut TraversalBuffer,
    ) -> Result<bool, StorageError> {
        let queue = buffer.get();

        // Try to use skip list to jump directly backward.
        // Skip list is sorted by max_cut ascending, so first valid skip
        // jumps as far back as possible.
        if let Some(&skip) = segment
            .skip_list()
            .iter()
            .find(|skip| skip.max_cut >= search_location.max_cut)
        {
            queue.push(skip)?;
        } else {
            // No valid skip - add prior locations to queue
            for prior in segment.prior() {
                if prior.max_cut >= search_location.max_cut {
                    queue.push(prior)?;
                }
            }
        }

        while let Some(loc) = queue.pop()? {
            debug_assert!(
                loc.max_cut >= search_location.max_cut,
                "Invariant: we only enqueue locations with at least the target max cut"
            );

            // Must load segment
            let segment = self.get_segment(loc)?;

            // Search commands in this segment.
            if segment.get_command(search_location).is_some() {
                return Ok(true);
            }

            // Try to use skip list to jump directly backward.
            // Skip list is sorted by max_cut ascending, so the first entry
            // with max_cut >= target has the lowest valid max_cut, jumping
            // furthest back in the graph.
            if let Some(&skip) = segment
                .skip_list()
                .iter()
                .find(|skip| skip.max_cut >= search_location.max_cut)
            {
                queue.push(skip)?;
            } else {
                // No valid skip - add prior locations to queue
                for prior in segment.prior() {
                    if prior.max_cut >= search_location.max_cut {
                        queue.push(prior)?;
                    }
                }
            }
        }
        Ok(false)
    }
}

/// A segment is a nonempty sequence of commands persisted to storage.
///
/// A segment can be one of three types. This might be encoded in a future version of the API.
/// * init   - This segment is the first segment of the graph and begins with an init command.
/// * linear - This segment has a single prior command and is simply a sequence of linear commands.
/// * merge  - This segment merges two other segments and thus begins with a merge command. A merge
///   segment has a braid as it's prior facts.
///
/// Each command past the first must have the parent of the previous command in the segment.
pub trait Segment {
    type FactIndex: FactIndex;
    type Command<'a>: Command
    where
        Self: 'a;

    /// Returns the segment's index.
    fn index(&self) -> SegmentIndex;

    /// Returns the ID of the head of the segment.
    fn head_id(&self) -> CmdId;

    /// Returns the id for the policy used for this segment.
    fn policy(&self) -> PolicyId;

    /// Returns the prior segments for this segment.
    fn prior(&self) -> Prior<Location>;

    /// Returns the command at the given location.
    fn get_command(&self, location: Location) -> Option<Self::Command<'_>>;

    /// Get the fact index associated with this segment.
    fn facts(&self) -> Result<Self::FactIndex, StorageError>;

    /// The shortest max cut for this segment.
    ///
    /// This will always the max cut of the first command in the segment.
    fn shortest_max_cut(&self) -> MaxCut;

    /// The longest max cut for this segment.
    ///
    /// This will always be the max cut of the last command in the segment.
    fn longest_max_cut(&self) -> Result<MaxCut, StorageError>;

    /// The skip list is a series of locations that can be safely jumped to
    /// when searching for a location. As long as the max cut of the location
    /// you're jumping to is greater than or equal to the location you're
    /// searching for you can jump to it and be guaranteed not to miss
    /// the location you're searching for.
    ///
    /// For merge commands the last location in the skip list is the least
    /// common ancestor.
    fn skip_list(&self) -> &[Location];

    /// Returns an iterator of commands starting at the given location.
    fn get_from(&self, location: Location) -> Vec<Self::Command<'_>> {
        let segment = location.segment;
        core::iter::successors(Some(location.max_cut), |max_cut| max_cut.checked_add(1))
            .map_while(|max_cut| self.get_command(Location { max_cut, segment }))
            .collect()
    }

    /// Returns the location of the command with the given address from within this segment.
    fn get_by_address(&self, address: Address) -> Option<Location> {
        let loc = Location::new(self.index(), address.max_cut);
        let cmd = self.get_command(loc)?;
        if cmd.id() != address.id {
            return None;
        }
        Some(loc)
    }

    /// Returns the location of the first command.
    fn first_location(&self) -> Location {
        Location {
            max_cut: self.shortest_max_cut(),
            segment: self.index(),
        }
    }

    /// Returns the location of the head of the segment.
    fn head_location(&self) -> Result<Location, StorageError> {
        Ok(Location {
            max_cut: self.longest_max_cut()?,
            segment: self.index(),
        })
    }

    /// Returns the address of the head of the segment.
    fn head_address(&self) -> Result<Address, StorageError> {
        Ok(Address {
            id: self.head_id(),
            max_cut: self.longest_max_cut()?,
        })
    }

    /// Walks a location toward init if it would still point within this segment.
    #[must_use]
    fn previous(&self, mut location: Location) -> Option<Location> {
        debug_assert_eq!(location.segment, self.index());
        if location.max_cut <= self.shortest_max_cut() {
            return None;
        }
        location.max_cut = location.max_cut.decremented()?;
        Some(location)
    }
}

/// An index of facts in storage.
pub trait FactIndex: Query {}

/// A perspective is essentially a mutable, in-memory version of a [`Segment`],
/// with the same three types.
pub trait Perspective: FactPerspective {
    /// Returns the id for the policy used for this perspective.
    fn policy(&self) -> PolicyId;

    /// Adds the given command to the head of the perspective. The command's
    /// parent must be the head of the perspective.
    fn add_command(&mut self, command: &impl Command) -> Result<usize, StorageError>;

    /// Returns true if the perspective contains a command with the given ID.
    fn includes(&self, id: CmdId) -> bool;

    /// Returns the head address in the perspective, if it exists
    fn head_address(&self) -> Result<Prior<Address>, Bug>;
}

/// A fact perspective is essentially a mutable, in-memory version of a [`FactIndex`].
pub trait FactPerspective: QueryMut {}

/// A revertable perspective can make checkpoints and be reverted such that the
/// state of the perspective matches that when the checkpoint was created.
pub trait Revertable {
    /// Create a checkpoint which can be used to revert the perspective.
    fn checkpoint(&self) -> Checkpoint;

    /// Revert the perspective to the state it was at when the checkpoint was created.
    fn revert(&mut self, checkpoint: Checkpoint) -> Result<(), Bug>;
}

/// A checkpoint used to revert perspectives.
pub struct Checkpoint {
    /// An index interpreted by a given `Revertable` implementation to revert to a prior point.
    pub index: usize,
}

/// Can be queried to look up facts.
///
/// Facts are labeled by a name, which are generally a bounded set of human-readable strings determined in advance.
///
/// Within a name, facts are an association of compound keys to values. The facts are keyed by a compound key
/// `(k_1, k_2, ..., k_n)`, where each `k` is a sequence of bytes. The fact value is also a sequence of bytes.
pub trait Query {
    /// Look up a named fact by an exact match of the compound key.
    fn query(&self, name: &str, keys: &[Box<[u8]>]) -> Result<Option<Box<[u8]>>, StorageError>;

    /// Iterator for [`Query::query_prefix`].
    type QueryIterator: Iterator<Item = Result<Fact, StorageError>>;

    /// Look up all named facts that begin with the prefix of keys, in sorted key order.
    ///
    /// The `prefix` is a partial compound key `(k_1, k_2, ..., k_n)`, where each `k` is a sequence of bytes.
    /// This returns all facts under the name with keys such that `prefix` is equal to a prefix of the fact's keys.
    fn query_prefix(
        &self,
        name: &str,
        prefix: &[Box<[u8]>],
    ) -> Result<Self::QueryIterator, StorageError>;
}

/// A fact with a key and value.
#[derive(Debug, PartialEq, Eq)]
pub struct Fact {
    /// The sequence of keys.
    pub key: Keys,
    /// The bytes of the value.
    pub value: Box<[u8]>,
}

/// Can mutate facts by inserting and deleting them.
///
/// See [`Query`] for details on the nature of facts.
pub trait QueryMut: Query {
    /// Insert a fact labeled by a name, with a given compound key and a value.
    ///
    /// This fact can later be looked up by [`Query`] methods, using the name and keys.
    fn insert(&mut self, name: String, keys: Keys, value: Box<[u8]>);

    /// Delete any fact associated to the compound key, under the given name.
    fn delete(&mut self, name: String, keys: Keys);
}

// TODO(jdygert): Expose this?
#[cfg(all(test, feature = "graphviz"))]
pub(crate) trait FactIndexExtra {
    fn name(&self) -> String;
    fn prior(&self) -> Result<Option<Self>, StorageError>
    where
        Self: Sized;
}

/// A sequence of byte-based keys, used for facts.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Keys(Box<[Box<[u8]>]>);

impl Deref for Keys {
    type Target = [Box<[u8]>];
    fn deref(&self) -> &[Box<[u8]>] {
        self.0.as_ref()
    }
}

impl AsRef<[Box<[u8]>]> for Keys {
    fn as_ref(&self) -> &[Box<[u8]>] {
        self.0.as_ref()
    }
}

impl core::borrow::Borrow<[Box<[u8]>]> for Keys {
    fn borrow(&self) -> &[Box<[u8]>] {
        self.0.as_ref()
    }
}

impl From<&[&[u8]]> for Keys {
    fn from(value: &[&[u8]]) -> Self {
        value.iter().copied().collect()
    }
}

impl Keys {
    fn starts_with(&self, prefix: &[Box<[u8]>]) -> bool {
        self.as_ref().starts_with(prefix)
    }
}

impl<B: Into<Box<[u8]>>> FromIterator<B> for Keys {
    fn from_iter<T: IntoIterator<Item = B>>(iter: T) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

mod impls {
    use alloc::boxed::Box;

    use super::{GraphId, PolicyId, StorageError, StorageProvider};

    impl<SP: StorageProvider> StorageProvider for &mut SP {
        type Perspective = SP::Perspective;
        type Segment = SP::Segment;
        type Storage = SP::Storage;

        fn new_perspective(&mut self, policy_id: PolicyId) -> Self::Perspective {
            SP::new_perspective(self, policy_id)
        }

        fn new_storage(
            &mut self,
            init: Self::Perspective,
        ) -> Result<(GraphId, &mut Self::Storage), StorageError> {
            SP::new_storage(self, init)
        }

        fn get_storage(&mut self, graph: GraphId) -> Result<&mut Self::Storage, StorageError> {
            SP::get_storage(self, graph)
        }

        fn remove_storage(&mut self, graph: GraphId) -> Result<(), StorageError> {
            SP::remove_storage(self, graph)
        }

        fn list_graph_ids(
            &mut self,
        ) -> Result<impl Iterator<Item = Result<GraphId, StorageError>>, StorageError> {
            SP::list_graph_ids(self)
        }
    }

    impl<SP: StorageProvider> StorageProvider for Box<SP> {
        type Perspective = SP::Perspective;
        type Segment = SP::Segment;
        type Storage = SP::Storage;

        fn new_perspective(&mut self, policy_id: PolicyId) -> Self::Perspective {
            SP::new_perspective(self, policy_id)
        }

        fn new_storage(
            &mut self,
            init: Self::Perspective,
        ) -> Result<(GraphId, &mut Self::Storage), StorageError> {
            SP::new_storage(self, init)
        }

        fn get_storage(&mut self, graph: GraphId) -> Result<&mut Self::Storage, StorageError> {
            SP::get_storage(self, graph)
        }

        fn remove_storage(&mut self, graph: GraphId) -> Result<(), StorageError> {
            SP::remove_storage(self, graph)
        }

        fn list_graph_ids(
            &mut self,
        ) -> Result<impl Iterator<Item = Result<GraphId, StorageError>>, StorageError> {
            SP::list_graph_ids(self)
        }
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;

    fn loc(seg: usize, mc: usize) -> Location {
        Location::new(SegmentIndex(seg), MaxCut(mc))
    }

    #[test]
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
        assert_eq!(l.max_cut, MaxCut(8));
        assert!(queue.is_empty());
    }

    #[test]
    fn test_push_covered_higher_max_cut_adopts_new_flag() {
        let mut queue = TraversalQueue::new();
        queue.push_covered(loc(0, 5), true).unwrap();
        // Higher max_cut uncovered: segment head moved beyond covered point.
        queue.push_covered(loc(0, 8), false).unwrap();
        let (l, covered) = queue.pop_covered().unwrap().unwrap();
        assert_eq!(l.max_cut, MaxCut(8));
        assert!(!covered);
    }

    #[test]
    fn test_push_covered_lower_max_cut_no_change() {
        let mut queue = TraversalQueue::new();
        queue.push_covered(loc(0, 8), false).unwrap();
        // Lower max_cut should not change anything.
        queue.push_covered(loc(0, 3), true).unwrap();
        let (l, covered) = queue.pop_covered().unwrap().unwrap();
        assert_eq!(l.max_cut, MaxCut(8));
        assert!(!covered);
    }

    #[test]
    fn test_pop_discards_covered_flag() {
        let mut queue = TraversalQueue::new();
        queue.push_covered(loc(0, 5), true).unwrap();
        // pop() should return only the location.
        let l = queue.pop().unwrap().unwrap();
        assert_eq!(l.max_cut, MaxCut(5));
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
            .drain_above(MaxCut(4), |loc| {
                let _ = result.push(loc);
            })
            .unwrap();

        // Entries with max_cut > 4 should be drained.
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|l| l.max_cut == MaxCut(7)));
        assert!(result.iter().any(|l| l.max_cut == MaxCut(5)));

        // Only max_cut=3 should remain in the queue.
        let remaining = queue.pop().unwrap().unwrap();
        assert_eq!(remaining.max_cut, MaxCut(3));
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
            .drain_above(MaxCut(4), |loc| {
                let _ = drained.push(loc);
            })
            .unwrap();

        // Only uncovered entries above threshold should be passed to f.
        assert_eq!(drained.len(), 2);
        assert!(drained.iter().any(|l| l.segment == SegmentIndex(1)));
        assert!(drained.iter().any(|l| l.segment == SegmentIndex(4)));

        // Covered entry above threshold (seg=2) should be discarded.
        // Entries below threshold should remain: seg=0 (uncovered), seg=3 (covered).
        let mut remaining = Vec::new();
        while let Some((l, covered)) = queue.pop_covered().unwrap() {
            remaining.push((l.segment, covered));
        }
        assert_eq!(remaining.len(), 2);
        assert!(remaining.contains(&(SegmentIndex(0), false)));
        assert!(remaining.contains(&(SegmentIndex(3), true)));
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
        assert_eq!(location.max_cut, MaxCut(5));

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
