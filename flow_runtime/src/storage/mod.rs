//! Interfaces for graph storage.
//!
//! The [`StorageProvider`] and [`Storage`] interfaces enable high-level
//! actions on the graph. Traversing the graph is made simpler by splitting
//! its [`Command`]s into [`Segment`]s. Updating the graph is possible using
//! [`Perspective`]s, which represent a slice of state.

use alloc::{boxed::Box, vec::Vec};

use super::*;

// TODO: Enable
// pub mod linear;

pub mod memory;

/// The maximum size of a serlized message
pub const MAX_COMMAND_LENGTH: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
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
        if self.command == 0 {
            false
        } else {
            self.command -= 1;
            true
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
    // LocationOutOfBounds,
    InternalError,
    IoError,
    NotMerge,
    NoSuchId(Id),
    PolicyMismatch,
    EmptyPerspective,
    HeadNotAncestor,
    NotBraid,
}

/// Handle to storage implementations used by the runtime.
pub trait StorageProvider {
    type Perspective: Perspective;
    type Segment: Segment;
    type Storage: Storage<Segment = Self::Segment, Perspective = Self::Perspective>;

    /// Create an unrooted perspective, intended for creating a new graph.
    ///
    /// # Arguments
    ///
    /// * `policy_id` - The policy to associated with the graph.
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
    type Perspective: Perspective;
    type Segment: Segment;

    /// Returns the location of Command with id if it has been stored by
    /// searching from the head.
    fn get_location(&self, id: &Id) -> Result<Option<Location>, StorageError>;

    /// Returns the ID of the command at the location.
    fn get_command_id(&self, location: &Location) -> Result<Id, StorageError>;

    /// Returns a linear perspective at the command with id, or None if the id
    /// can not be found.
    fn get_linear_perspective(&self, id: &Id) -> Result<Option<Self::Perspective>, StorageError>;

    /// Returns a braid perspective at the command with id, or None if the id
    /// can not be found.
    fn get_braid_perspective(&self, id: &Id) -> Result<Option<Self::Perspective>, StorageError>;

    /// Returns a perspective at the command provided, or None if the id can not
    /// be found. If the provided command is not a merge command an error will be
    /// returned. The provided command will be the first command in the
    /// perspective.
    fn new_merge_perspective<'a>(
        &self,
        command: &impl Command<'a>,
        policy_id: PolicyId,
        braid: Self::Segment,
    ) -> Result<Option<Self::Perspective>, StorageError>;

    /// Returns the segment at the given location, or None if it can't be found.
    fn get_segment(&self, location: &Location) -> Result<Option<Self::Segment>, StorageError>;

    /// Returns the head of the graph.
    fn get_head(&self) -> Result<Location, StorageError>;

    /// Sets the given segment as the head of the graph.  Returns an error if
    /// the current head is not an ancestor of the provided segment.
    fn commit(&mut self, segment: Self::Segment) -> Result<(), StorageError>;

    /// Writes the given perspective to a segment.
    fn write(&mut self, perspective: Self::Perspective) -> Result<Self::Segment, StorageError>;

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
            let segment = self
                .get_segment(&location)?
                .ok_or(StorageError::InternalError)?;
            queue.extend(segment.prior());
        }
        Ok(false)
    }
}

/// A segment is a nonempty sequence of commands persisted to storage.
///
/// A segment can be one of four types. This might be encoded in a previous version of the API.
/// * init   - This segment is the first segment of the graph and begins with an init command.
/// * linear - This segment has a single prior command and is simply a sequence of linear commands.
/// * merge  - This segment merges two other segments and thus begins with a merge command.
///            A merge segment has a braid as it's prior facts.
/// * braid  - This segment provides an ordering of a concurrent section of the graph.
///
/// Each command past the first must have the parent of the previous command in the segment.
pub trait Segment {
    type Command<'a>: Command<'a>
    where
        Self: 'a;

    /// Returns the head of the segment.
    fn head(&self) -> &Self::Command<'_>;

    /// Returns the first Command in the segment.
    fn first(&self) -> &Self::Command<'_>;

    /// Returns the locaton of the head of the segment.
    fn head_location(&self) -> Location;

    /// Returns the locaton of the first command.
    fn first_location(&self) -> Location;

    /// Returns true if the segment contains the location.
    fn contains(&self, location: &Location) -> bool;

    /// Returns the id for the policy used for this segment.
    fn policy(&self) -> PolicyId;

    /// Returns the prior segments for this segment.
    fn prior(&self) -> HVec2<Location>;

    /// Returns the command at the given location.
    fn get_command<'a>(&'a self, location: &Location) -> Option<&Self::Command<'a>>;

    /// Returns an iterator of commands starting at the given location.
    fn get_from<'a>(&'a self, location: &Location) -> Vec<&'a Self::Command<'a>>;

    /// Look up a value associated to the given key.
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError>;

    /// Return the prior segment on which this segment's facts are based.
    fn prior_facts(&self) -> Result<Option<Self>, StorageError>
    where
        Self: Sized;
}

/// A perspective is essentially a mutable, in-memory version of a [`Segment`],
/// with the same four types.
pub trait Perspective {
    /// Create a checkpoint which can be used to revert the perspective.
    fn checkpoint(&self) -> Checkpoint;

    /// Revert the perspective to the state it was at when the checkpoint was created.
    fn revert(&mut self, checkpoint: Checkpoint);

    /// Returns the prior locations on which this perspective is based.
    fn prior(&self) -> HVec2<Location>;

    /// Returns the id for the policy used for this perspective.
    fn policy(&self) -> PolicyId;

    /// Adds the given command to the head of the perspective. The command's
    /// parent must be the head of the perspective.
    fn add_command<'a>(&mut self, command: &impl Command<'a>) -> Result<usize, StorageError>;

    /// UNUSED?
    fn get_target(&mut self) -> Result<&mut [u8], StorageError>;

    /// Look up a value associated to the given key.
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError>;

    /// Insert a key/value pair.
    fn insert(&mut self, key: &[u8], value: &[u8]);

    /// Delete any value associated to the key.
    fn delete(&mut self, key: &[u8]);
}

/// A checkpoint used to revert perspectives.
pub struct Checkpoint {
    index: usize,
}

// TODO: Fix and enable
// #[cfg(test)]
// mod tests;
