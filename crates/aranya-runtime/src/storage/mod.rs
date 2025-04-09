//! Interfaces for graph storage.
//!
//! The [`StorageProvider`] and [`Storage`] interfaces enable high-level
//! actions on the graph. Traversing the graph is made simpler by splitting
//! its [`Command`]s into [`Segment`]s. Updating the graph is possible using
//! [`Perspective`]s, which represent a slice of state.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{fmt, ops::Deref};

use buggy::{Bug, BugExt};
use serde::{Deserialize, Serialize};

use crate::{Address, Command, CommandId, PolicyId, Prior};

pub mod linear;
pub mod memory;

/// The maximum size of a serialized message
pub const MAX_COMMAND_LENGTH: usize = 2048;

aranya_crypto::custom_id! {
    /// The ID of the graph, taken from initialization.
    pub struct GraphId;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Location {
    pub segment: usize,
    pub command: usize,
}

impl From<(usize, usize)> for Location {
    fn from((segment, command): (usize, usize)) -> Self {
        Self::new(segment, command)
    }
}

impl AsRef<Location> for Location {
    fn as_ref(&self) -> &Location {
        self
    }
}

impl Location {
    pub fn new(segment: usize, command: usize) -> Location {
        Location { segment, command }
    }

    /// If this is not the first command in a segment, return a location
    /// pointing to the previous command.
    #[must_use]
    pub fn previous(mut self) -> Option<Self> {
        if let Some(n) = usize::checked_sub(self.command, 1) {
            self.command = n;
            Some(self)
        } else {
            None
        }
    }

    /// Returns true if other location is in the same segment.
    pub fn same_segment(self, other: Location) -> bool {
        self.segment == other.segment
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.segment, self.command)
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
    #[error("command index {} is out of bounds in segment {}", .0.command, .0.segment)]
    CommandOutOfBounds(Location),
    #[error("IO error")]
    IoError,
    #[error("not a merge command")]
    NotMerge,
    #[error("command with id {0} not found")]
    NoSuchId(CommandId),
    #[error("policy mismatch")]
    PolicyMismatch,
    #[error("cannot write an empty perspective")]
    EmptyPerspective,
    #[error("segment must be a descendant of the head for commit")]
    HeadNotAncestor,
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

    /// Gets a list of all stored graphs by their graph ID.
    // TODO(nikki): rewrite this once we can use coroutines/generators?
    fn list_graph_ids(
        &self,
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
    fn get_location(&self, address: Address) -> Result<Option<Location>, StorageError> {
        self.get_location_from(self.get_head()?, address)
    }

    /// Returns the location of Command with id by searching from the given location.
    fn get_location_from(
        &self,
        start: Location,
        address: Address,
    ) -> Result<Option<Location>, StorageError> {
        let mut queue = Vec::new();
        queue.push(start);
        'outer: while let Some(loc) = queue.pop() {
            let head = self.get_segment(loc)?;
            if address.max_cut > head.longest_max_cut()? {
                continue;
            }
            if let Some(loc) = head.get_from_max_cut(address.max_cut)? {
                let command = head.get_command(loc).assume("command must exist")?;
                if command.id() == address.id {
                    return Ok(Some(loc));
                }
            }
            // Assumes skip list is sorted in ascending order.
            // We always want to skip as close to the root as possible.
            for (skip, max_cut) in head.skip_list() {
                if max_cut >= &address.max_cut {
                    queue.push(*skip);
                    continue 'outer;
                }
            }
            queue.extend(head.prior());
        }
        Ok(None)
    }

    /// Returns the CommandId of the command at the location.
    fn get_command_id(&self, location: Location) -> Result<CommandId, StorageError>;

    /// Returns a linear perspective at the given location.
    fn get_linear_perspective(
        &self,
        parent: Location,
    ) -> Result<Option<Self::Perspective>, StorageError>;

    /// Returns a fact perspective at the given location, intended for evaluating braids.
    /// The fact perspective will include the facts of the command at the given location.
    fn get_fact_perspective(&self, first: Location) -> Result<Self::FactPerspective, StorageError>;

    /// Returns a merge perspective based on the given locations with the braid as prior facts.
    fn new_merge_perspective(
        &self,
        left: Location,
        right: Location,
        last_common_ancestor: (Location, usize),
        policy_id: PolicyId,
        braid: Self::FactIndex,
    ) -> Result<Option<Self::Perspective>, StorageError>;

    /// Returns the segment at the given location.
    fn get_segment(&self, location: Location) -> Result<Self::Segment, StorageError>;

    /// Returns the head of the graph.
    fn get_head(&self) -> Result<Location, StorageError>;

    /// Sets the given segment as the head of the graph.  Returns an error if
    /// the current head is not an ancestor of the provided segment.
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
    ) -> Result<bool, StorageError> {
        let mut queue = Vec::new();
        queue.extend(segment.prior());
        let segment = self.get_segment(search_location)?;
        let address = segment
            .get_command(search_location)
            .assume("location must exist")?
            .address()?;
        'outer: while let Some(location) = queue.pop() {
            if location.segment == search_location.segment
                && location.command >= search_location.command
            {
                return Ok(true);
            }
            let segment = self.get_segment(location)?;
            if address.max_cut > segment.longest_max_cut()? {
                continue;
            }
            for (skip, max_cut) in segment.skip_list() {
                if max_cut >= &address.max_cut {
                    queue.push(*skip);
                    continue 'outer;
                }
            }
            queue.extend(segment.prior());
        }
        Ok(false)
    }
}

type MaxCut = usize;

/// A segment is a nonempty sequence of commands persisted to storage.
///
/// A segment can be one of three types. This might be encoded in a future version of the API.
/// * init   - This segment is the first segment of the graph and begins with an init command.
/// * linear - This segment has a single prior command and is simply a sequence of linear commands.
/// * merge  - This segment merges two other segments and thus begins with a merge command.
///            A merge segment has a braid as it's prior facts.
///
/// Each command past the first must have the parent of the previous command in the segment.
pub trait Segment {
    type FactIndex: FactIndex;
    type Command<'a>: Command
    where
        Self: 'a;

    /// Returns the head of the segment.
    fn head(&self) -> Result<Self::Command<'_>, StorageError>;

    /// Returns the first Command in the segment.
    fn first(&self) -> Self::Command<'_>;

    /// Returns the location of the head of the segment.
    fn head_location(&self) -> Location;

    /// Returns the location of the first command.
    fn first_location(&self) -> Location;

    /// Returns true if the segment contains the location.
    fn contains(&self, location: Location) -> bool;

    /// Returns the id for the policy used for this segment.
    fn policy(&self) -> PolicyId;

    /// Returns the prior segments for this segment.
    fn prior(&self) -> Prior<Location>;

    /// Returns the command at the given location.
    fn get_command(&self, location: Location) -> Option<Self::Command<'_>>;

    /// Returns the command with the given max cut from within this segment.
    fn get_from_max_cut(&self, max_cut: usize) -> Result<Option<Location>, StorageError>;

    /// Returns an iterator of commands starting at the given location.
    fn get_from(&self, location: Location) -> Vec<Self::Command<'_>>;

    /// Get the fact index associated with this segment.
    fn facts(&self) -> Result<Self::FactIndex, StorageError>;

    fn contains_any<I>(&self, locations: I) -> bool
    where
        I: IntoIterator,
        I::Item: AsRef<Location>,
    {
        locations
            .into_iter()
            .any(|loc| self.contains(*loc.as_ref()))
    }

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
    fn skip_list(&self) -> &[(Location, MaxCut)];
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
    fn includes(&self, id: CommandId) -> bool;

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

// TODO: Fix and enable
// #[cfg(test)]
// mod tests;
