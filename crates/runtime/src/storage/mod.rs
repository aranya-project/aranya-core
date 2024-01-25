//! Interfaces for graph storage.
//!
//! The [`StorageProvider`] and [`Storage`] interfaces enable high-level
//! actions on the graph. Traversing the graph is made simpler by splitting
//! its [`Command`]s into [`Segment`]s. Updating the graph is possible using
//! [`Perspective`]s, which represent a slice of state.

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use buggy::Bug;
use serde::{Deserialize, Serialize};

use crate::{Command, Id, PolicyId, Prior};

pub mod linear;
pub mod memory;

/// The maximum size of a serialized message
pub const MAX_COMMAND_LENGTH: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    segment: usize,
    command: usize,
}

impl From<(usize, usize)> for Location {
    fn from((segment, command): (usize, usize)) -> Self {
        Self::new(segment, command)
    }
}

impl Location {
    fn new(segment: usize, command: usize) -> Location {
        Location { segment, command }
    }

    /// If this is not the first command in a segment, update the location to
    /// point to the previous. Returns true on success or false if current
    /// location is the first.
    pub fn previous(&mut self) -> bool {
        if let Some(n) = usize::checked_sub(self.command, 1) {
            self.command = n;
            true
        } else {
            false
        }
    }

    /// Returns true if other location is in the same segment.
    pub fn same_segment(&self, other: &Location) -> bool {
        self.segment == other.segment
    }
}

#[derive(Debug)]
pub enum StorageError {
    StorageExists,
    NoSuchStorage,
    SegmentOutOfBounds(Location),
    CommandOutOfBounds(Location),
    IoError,
    NotMerge,
    NoSuchId(Id),
    PolicyMismatch,
    EmptyPerspective,
    HeadNotAncestor,
    Bug(Bug),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageExists => write!(f, "storage already exists"),
            Self::NoSuchStorage => write!(f, "no such storage"),
            Self::SegmentOutOfBounds(loc) => {
                write!(f, "segment index {} is out of bounds", loc.segment)
            }
            Self::CommandOutOfBounds(loc) => write!(
                f,
                "command index {} is out of bounds in segment {}",
                loc.command, loc.segment
            ),
            Self::IoError => write!(f, "IO error"),
            Self::NotMerge => write!(f, "not a merge command"),
            Self::NoSuchId(id) => write!(f, "command with id {id} not found"),
            Self::PolicyMismatch => write!(f, "policy mismatch"),
            Self::EmptyPerspective => write!(f, "cannot write an empty perspective"),
            Self::HeadNotAncestor => {
                write!(f, "segment must be a descendant of the head for commit")
            }
            Self::Bug(bug) => write!(f, "{bug}"),
        }
    }
}

impl trouble::Error for StorageError {}

impl From<Bug> for StorageError {
    fn from(bug: Bug) -> Self {
        Self::Bug(bug)
    }
}

#[cfg(feature = "rustix")]
impl From<rustix::io::Errno> for StorageError {
    fn from(_: rustix::io::Errno) -> Self {
        // TODO(jdygert): Add variant?
        StorageError::IoError
    }
}

/// Handle to storage implementations used by the runtime.
pub trait StorageProvider {
    type Perspective: Perspective + Revertable;
    type Segment: Segment;
    type Storage: Storage<Segment = Self::Segment, Perspective = Self::Perspective>;

    /// Create an unrooted perspective, intended for creating a new graph.
    ///
    /// # Arguments
    ///
    /// * `policy_id` - The policy to associate with the graph.
    fn new_perspective(&mut self, policy_id: &PolicyId) -> Self::Perspective;

    /// Create a new graph.
    ///
    /// # Arguments
    ///
    /// * `group` - Id of the command that initializes the new graph.
    /// * `init` - Contains the data necessary to initialize the new graph.
    fn new_storage<'a>(
        &'a mut self,
        group: &Id,
        init: Self::Perspective,
    ) -> Result<&'a mut Self::Storage, StorageError>;

    /// Get an existing graph.
    ///
    /// # Arguments
    ///
    /// * `group` - Id of the command that initialized the graph.
    fn get_storage<'a>(&'a mut self, group: &Id) -> Result<&'a mut Self::Storage, StorageError>;
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
    fn get_location(&self, id: &Id) -> Result<Option<Location>, StorageError> {
        self.get_location_from(&self.get_head()?, id)
    }

    /// Returns the location of Command with id by searching from the given location.
    fn get_location_from(
        &self,
        start: &Location,
        id: &Id,
    ) -> Result<Option<Location>, StorageError> {
        let mut queue = alloc::collections::VecDeque::new();
        queue.push_back(start.clone());
        while let Some(loc) = queue.pop_front() {
            let seg = self.get_segment(&loc)?;
            for (i, cmd) in seg.get_from(&loc).iter().enumerate() {
                if &cmd.id() == id {
                    return Ok(Some(Location::new(loc.segment, i)));
                }
            }
            queue.extend(seg.prior());
        }
        Ok(None)
    }

    /// Returns the ID of the command at the location.
    fn get_command_id(&self, location: &Location) -> Result<Id, StorageError>;

    /// Returns a linear perspective at the given location.
    fn get_linear_perspective(
        &self,
        parent: &Location,
    ) -> Result<Option<Self::Perspective>, StorageError>;

    /// Returns a fact perspective at the given location, intended for evaluating braids.
    /// The fact perspective will include the facts of the command at the given location.
    fn get_fact_perspective(&self, first: &Location)
        -> Result<Self::FactPerspective, StorageError>;

    /// Returns a merge perspective based on the given locations with the braid as prior facts.
    fn new_merge_perspective(
        &self,
        left: &Location,
        right: &Location,
        policy_id: PolicyId,
        braid: Self::FactIndex,
    ) -> Result<Option<Self::Perspective>, StorageError>;

    /// Returns the segment at the given location.
    fn get_segment(&self, location: &Location) -> Result<Self::Segment, StorageError>;

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
        search_location: &Location,
        segment: &Self::Segment,
    ) -> Result<bool, StorageError> {
        let mut queue = alloc::collections::VecDeque::new();
        queue.extend(segment.prior());
        while let Some(location) = queue.pop_front() {
            if location.same_segment(search_location) {
                return Ok(true);
            }
            let segment = self.get_segment(&location)?;
            queue.extend(segment.prior());
        }
        Ok(false)
    }
}

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
    type Command<'a>: Command<'a>
    where
        Self: 'a;

    /// Returns the head of the segment.
    fn head(&self) -> Self::Command<'_>;

    /// Returns the first Command in the segment.
    fn first(&self) -> Self::Command<'_>;

    /// Returns the location of the head of the segment.
    fn head_location(&self) -> Location;

    /// Returns the location of the first command.
    fn first_location(&self) -> Location;

    /// Returns true if the segment contains the location.
    fn contains(&self, location: &Location) -> bool;

    /// Returns the id for the policy used for this segment.
    fn policy(&self) -> PolicyId;

    /// Returns the prior segments for this segment.
    fn prior(&self) -> Prior<Location>;

    /// Returns the command at the given location.
    fn get_command<'a>(&'a self, location: &Location) -> Option<Self::Command<'a>>;

    /// Returns an iterator of commands starting at the given location.
    fn get_from<'a>(&'a self, location: &Location) -> Vec<Self::Command<'a>>;

    /// Get the fact index associated with this segment.
    fn facts(&self) -> Result<Self::FactIndex, StorageError>;
}

pub trait FactIndex {
    /// Look up a value associated to the given key.
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError>;
}

/// A perspective is essentially a mutable, in-memory version of a [`Segment`],
/// with the same three types.
pub trait Perspective: FactPerspective {
    /// Returns the id for the policy used for this perspective.
    fn policy(&self) -> PolicyId;

    /// Adds the given command to the head of the perspective. The command's
    /// parent must be the head of the perspective.
    fn add_command<'a>(&mut self, command: &impl Command<'a>) -> Result<usize, StorageError>;
}

/// A fact perspective is essentially a mutable, in-memory version of a [`FactIndex`].
pub trait FactPerspective {
    /// Look up a value associated to the given key.
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError>;

    /// Insert a key/value pair.
    fn insert(&mut self, key: &[u8], value: &[u8]);

    /// Delete any value associated to the key.
    fn delete(&mut self, key: &[u8]);
}

/// A revertable perspective can make checkpoints and be reverted such that the
/// state of the perspective matches that when the checkpoint was created.
pub trait Revertable {
    /// Create a checkpoint which can be used to revert the perspective.
    fn checkpoint(&self) -> Checkpoint;

    /// Revert the perspective to the state it was at when the checkpoint was created.
    fn revert(&mut self, checkpoint: Checkpoint);
}

/// A checkpoint used to revert perspectives.
pub struct Checkpoint {
    index: usize,
}

// TODO: Fix and enable
// #[cfg(test)]
// mod tests;
