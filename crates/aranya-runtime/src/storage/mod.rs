//! Interfaces for graph storage.
//!
//! The [`StorageProvider`] and [`Storage`] interfaces enable high-level
//! actions on the graph. Traversing the graph is made simpler by splitting
//! its [`Command`]s into [`Segment`]s. Updating the graph is possible using
//! [`Perspective`]s, which represent a slice of state.

pub mod head_set;
pub mod linear;
mod queue;
mod spill;

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{borrow::Borrow, fmt, ops::Deref};

use buggy::{Bug, BugExt as _};
use rend::u64_le;

pub(crate) use self::queue::TraversalQueueWithDuplicates;
use self::queue::{TraversalQueueNoDuplicates, TraversalQueueWithCoverage};
#[cfg(feature = "libc")]
pub use self::spill::LibcSpill;
pub use self::{
    head_set::HeadSet,
    spill::{MemSpill, mem_spill},
};
use crate::{Address, CmdId, Command, CommandExt as _, PolicyId, Prior, Priority, util::mem_usage};

/// Byte-addressable overflow storage for braid and convergence data.
///
/// Implemented by [`LibcSpill`] (file-backed) and [`MemSpill`] (in-memory);
/// each backend has its own constructor signature (paths, etc.), matching
/// how [`IoManager`](linear::io::IoManager) backends are constructed.
/// Callers build a spill and pass it in.
pub trait Spill {
    /// Write `data` at the given byte offset.
    fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageError>;
    /// Read exactly `data.len()` bytes starting at the given byte offset.
    fn read_at(&mut self, offset: usize, data: &mut [u8]) -> Result<(), StorageError>;
}

/// Default capacity for the traversal queue.
///
/// This should be large enough to hold the maximum expected "active frontier"
/// during backward traversal, which is bounded by peer count.
pub const QUEUE_CAPACITY: usize = 512;

/// A queue buffer for a single graph traversal operation.
///
/// Access via [`get()`](Self::get), which clears the buffer automatically.
pub struct TraversalBuffer {
    queue_with_coverage: TraversalQueueWithCoverage,
    queue_no_duplicates: TraversalQueueNoDuplicates,
    queue_with_duplicates: TraversalQueueWithDuplicates,
}

impl TraversalBuffer {
    pub fn new() -> Self {
        Self {
            queue_with_coverage: TraversalQueueWithCoverage::new(),
            queue_no_duplicates: TraversalQueueNoDuplicates::new(),
            queue_with_duplicates: TraversalQueueWithDuplicates::new(),
        }
    }

    /// Returns a cleared queue ready for use.
    pub(crate) fn get_queue_with_coverage(&mut self) -> &mut TraversalQueueWithCoverage {
        self.queue_with_coverage.clear();
        &mut self.queue_with_coverage
    }

    /// Returns a cleared queue ready for use.
    pub(crate) fn get_queue_no_duplicates(&mut self) -> &mut TraversalQueueNoDuplicates {
        self.queue_no_duplicates.clear();
        &mut self.queue_no_duplicates
    }

    /// Returns a cleared queue ready for use.
    pub(crate) fn get_queue_with_duplicates(&mut self) -> &mut TraversalQueueWithDuplicates {
        self.queue_with_duplicates.clear();
        &mut self.queue_with_duplicates
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
    pub fn new() -> Self {
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

pub const MAX_COMMAND_LENGTH: usize = mem_usage(400, 2048);

aranya_crypto::custom_id! {
    /// The ID of the graph, taken from initialization.
    pub struct GraphId;
}

#[derive(
    Copy,
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Portable,
    rkyv::bytecheck::CheckBytes,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
#[rkyv(as = Self)]
#[bytecheck(crate = rkyv::bytecheck)]
#[serde(transparent)]
#[repr(transparent)]
pub struct SegmentIndex(#[serde(with = "crate::util::u64_le_serde")] u64_le);

impl fmt::Display for SegmentIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl SegmentIndex {
    pub const fn new(val: u64) -> Self {
        Self(u64_le::from_native(val))
    }

    pub const fn get(self) -> u64 {
        self.0.to_native()
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Portable,
    rkyv::bytecheck::CheckBytes,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
#[rkyv(as = Self)]
#[bytecheck(crate = rkyv::bytecheck)]
#[serde(transparent)]
#[repr(transparent)]
pub struct MaxCut(#[serde(with = "crate::util::u64_le_serde")] u64_le);

impl fmt::Display for MaxCut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl MaxCut {
    pub const fn new(val: u64) -> Self {
        Self(u64_le::from_native(val))
    }

    pub const fn get(self) -> u64 {
        self.0.to_native()
    }

    /// Adds an amount to the max cut, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, other: u64) -> Option<Self> {
        self.get().checked_add(other).map(Self::new)
    }

    /// Gets a max cut one lower than this, returning `None` on overflow.
    #[must_use]
    pub fn decremented(self) -> Option<Self> {
        self.get().checked_sub(1).map(Self::new)
    }

    /// Gets the distance between two max cuts, returning `None` on overflow.
    #[must_use]
    pub fn distance_from(self, other: Self) -> Option<u64> {
        self.get().checked_sub(other.get())
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Portable,
    rkyv::bytecheck::CheckBytes,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
#[rkyv(as = Self)]
#[bytecheck(crate = rkyv::bytecheck)]
#[repr(C)]
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

    /// Returns the previous location in this location's segment, or `None`
    /// if this is the segment's first command (at `shortest_max_cut`).
    #[must_use]
    pub(crate) fn previous_in_segment(mut self, shortest_max_cut: MaxCut) -> Option<Self> {
        if self.max_cut <= shortest_max_cut {
            return None;
        }
        self.max_cut = self.max_cut.decremented()?;
        Some(self)
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.segment, self.max_cut)
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct LocatedAddress {
    pub id: CmdId,
    pub segment: SegmentIndex,
    pub max_cut: MaxCut,
}

impl LocatedAddress {
    pub fn address(self) -> Address {
        Address {
            id: self.id,
            max_cut: self.max_cut,
        }
    }

    pub fn location(self) -> Location {
        Location {
            segment: self.segment,
            max_cut: self.max_cut,
        }
    }
}

/// Backend-assigned stamp for the committed head set, changed by every
/// [`Storage::commit_heads`]. A captured value compared against the current
/// one detects intervening commits without cloning or comparing head sets.
/// Linear storage uses the file offset of the appended head-set record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadSetOffset(u64);

impl HeadSetOffset {
    /// Wraps a backend-provided raw value.
    pub fn new(offset: u64) -> Self {
        Self(offset)
    }
}

/// An error returned by [`Storage`] or [`StorageProvider`].
#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[non_exhaustive]
pub enum StorageError {
    #[error("storage already exists")]
    StorageExists,
    #[error("no such storage")]
    NoSuchStorage,
    #[error("storage created but not initialized by a first commit")]
    NotInitialized,
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
    #[error("graph has multiple heads ({0}); no single head to report")]
    MultipleHeads(usize),
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

/// Backward-traversal search for `address`, starting from the locations
/// already seeded into `queue`. Seeds must have `max_cut >= address.max_cut`.
///
/// See `aranya-docs/docs/graph-traversal.md` for the traversal algorithm
/// specification.
fn search_queued<S: Storage + ?Sized>(
    storage: &S,
    address: Address,
    queue: &mut TraversalQueueNoDuplicates,
) -> Result<Option<Location>, StorageError> {
    while let Some(loc) = queue.pop()? {
        debug_assert!(
            loc.max_cut >= address.max_cut,
            "Invariant: we only enqueue locations with at least the target max cut"
        );

        // Must load segment
        let segment = storage.get_segment(loc)?;

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
        // The graph may be multi-head (lazy merges). Run one search seeded
        // with every head that could reach the target, so ancestry shared
        // between heads is traversed once rather than once per head.
        let queue = buffer.get_queue_no_duplicates();
        for head in self.get_heads()?.iter() {
            if head.max_cut >= address.max_cut {
                queue.push(head.location())?;
            }
        }
        search_queued(self, address, queue)
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

        let queue = buffer.get_queue_no_duplicates();
        queue.push(start)?;
        search_queued(self, address, queue)
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

    /// Returns the committed head set.
    ///
    /// Borrows an in-memory cache, so this is cheap to call repeatedly on hot
    /// paths (no per-call deserialize or copy). Callers that need an owned set
    /// should clone the returned reference.
    fn get_heads(&self) -> Result<&HeadSet, StorageError>;

    /// Returns the stamp of the committed head set.
    ///
    /// Changes on every [`commit_heads`](Self::commit_heads), so a value
    /// captured at transaction start detects intervening commits.
    fn heads_offset(&self) -> Result<HeadSetOffset, StorageError>;

    /// Returns the cached merged fact index for the current head set.
    fn fact_cache(&self) -> Result<Self::FactIndex, StorageError>;

    /// Commit the given head set with its rebuilt fact cache.
    fn commit_heads(
        &mut self,
        heads: HeadSet,
        fact_cache: Self::FactIndex,
    ) -> Result<(), StorageError>;

    /// Returns the address of the sole graph head.
    ///
    /// Errors with [`StorageError::MultipleHeads`] on a multi-head (lazy-merge)
    /// graph, where there is no single head to report. Callers that may face a
    /// multi-head graph should use [`get_heads`](Self::get_heads) instead, or
    /// [`ClientState::hello_head`](crate::ClientState::hello_head) when
    /// advertising graph state to peers.
    ///
    /// An initialized graph always has at least one head, so an empty head set
    /// is treated as an invariant violation (a [`Bug`]).
    fn get_head_address(&self) -> Result<Address, StorageError> {
        let heads = self.get_heads()?;
        let mut it = heads.iter();
        let first = it.next().assume("initialized graph always has >= 1 head")?;
        if it.next().is_some() {
            return Err(StorageError::MultipleHeads(heads.len()));
        }
        Ok(first.address())
    }

    /// Writes the given perspective to a segment.
    fn write(&mut self, perspective: Self::Perspective) -> Result<Self::Segment, StorageError>;

    /// Writes the given fact perspective to a fact index.
    fn write_facts(
        &mut self,
        fact_perspective: Self::FactPerspective,
    ) -> Result<Self::FactIndex, StorageError>;

    /// Determine whether the given location is an ancestor of the given location.
    fn is_ancestor(
        &self,
        search_location: Location,
        start_location: Location,
        buffer: &mut TraversalBuffer,
    ) -> Result<bool, StorageError> {
        if search_location.max_cut > start_location.max_cut || search_location == start_location {
            return Ok(false);
        }

        let queue = buffer.get_queue_no_duplicates();
        queue.push(start_location)?;

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
    type Command<'a>: Command + Prioritized
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
    fn previous(&self, location: Location) -> Option<Location> {
        debug_assert_eq!(location.segment, self.index());
        location.previous_in_segment(self.shortest_max_cut())
    }
}

/// An index of facts in storage.
pub trait FactIndex: Query {}

/// A perspective is essentially a mutable, in-memory version of a [`Segment`],
/// with the same three types.
pub trait Perspective: FactPerspective {
    /// Returns the id for the policy used for this perspective.
    fn policy(&self) -> PolicyId;

    /// Adds the given command to the head of the perspective, persisting
    /// `priority` alongside it. The command's parent must be the head of the
    /// perspective.
    ///
    /// The priority must match the command's structure: `Merge` for merge
    /// commands, `Init` for init commands, and the policy's body-derived
    /// value for evaluated commands.
    fn add_command(
        &mut self,
        command: &impl Command,
        priority: Priority,
    ) -> Result<usize, StorageError>;

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
    fn revert(&mut self, checkpoint: Checkpoint) -> Result<(), StorageError>;
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
    fn query(&self, name: &str, keys: &[Bytes]) -> Result<Option<Bytes>, StorageError>;

    /// Iterator for [`Query::query_prefix`].
    type QueryIterator: Iterator<Item = Result<Fact, StorageError>>;

    /// Look up all named facts that begin with the prefix of keys, in sorted key order.
    ///
    /// The `prefix` is a partial compound key `(k_1, k_2, ..., k_n)`, where each `k` is a sequence of bytes.
    /// This returns all facts under the name with keys such that `prefix` is equal to a prefix of the fact's keys.
    fn query_prefix(
        &self,
        name: &str,
        prefix: &[Bytes],
    ) -> Result<Self::QueryIterator, StorageError>;
}

/// A fact with a key and value.
#[derive(Debug, PartialEq, Eq)]
pub struct Fact {
    /// The sequence of keys.
    pub key: Keys,
    /// The bytes of the value.
    pub value: Bytes,
}

/// Can mutate facts by inserting and deleting them.
///
/// See [`Query`] for details on the nature of facts.
pub trait QueryMut: Query {
    /// Insert a fact labeled by a name, with a given compound key and a value.
    ///
    /// This fact can later be looked up by [`Query`] methods, using the name and keys.
    fn insert(&mut self, name: String, keys: Keys, value: Bytes) -> Result<(), StorageError>;

    /// Delete any fact associated to the compound key, under the given name.
    fn delete(&mut self, name: String, keys: Keys) -> Result<(), StorageError>;
}

/// Stored commands hold their validated priority.
pub trait Prioritized {
    /// Get this command's priority.
    fn priority(&self) -> Priority;
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
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Keys(Box<[Bytes]>);

impl Deref for Keys {
    type Target = [Bytes];
    fn deref(&self) -> &[Bytes] {
        self.0.as_ref()
    }
}

impl AsRef<[Bytes]> for Keys {
    fn as_ref(&self) -> &[Bytes] {
        self.0.as_ref()
    }
}

impl Borrow<[Bytes]> for Keys {
    fn borrow(&self) -> &[Bytes] {
        self.0.as_ref()
    }
}

impl From<Vec<Bytes>> for Keys {
    fn from(value: Vec<Bytes>) -> Self {
        Self(value.into_boxed_slice())
    }
}

impl From<&[&[u8]]> for Keys {
    fn from(value: &[&[u8]]) -> Self {
        value.iter().copied().collect()
    }
}

impl<B: Into<Bytes>> FromIterator<B> for Keys {
    fn from_iter<T: IntoIterator<Item = B>>(iter: T) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

impl<'a> IntoIterator for &'a Keys {
    type Item = &'a Bytes;
    type IntoIter = core::slice::Iter<'a, Bytes>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl ArchivedKeys {
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(AsRef::as_ref)
    }
}

pub type Bytes = Box<[u8]>;

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
