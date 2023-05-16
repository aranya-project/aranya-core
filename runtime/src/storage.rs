//! Interfaces for graph storage.
//!
//! The [`StorageProvider`] and [`Storage`] interfaces enable high-level
//! actions on the graph. Traversing the graph is made simpler by splitting
//! its [`Command`]s into [`Segment`]s. Updating the graph is possible using
//! [`Perspective`]s, which represent a slice of state.
use alloc::vec::Vec;

use crate::{
    command::{self, Command},
    engine::{Engine, EngineError, PolicyId},
};

/// Handle to storage implementations used by the runtime engine.
pub trait StorageProvider {
    type Perspective: Perspective<Update = Self::Update>;
    type Update;
    type Storage: Storage<Update = Self::Update>;

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
    /// * `update` - Contains the data necessary to update the new graph.
    fn new_storage(
        &mut self,
        group: &command::Id,
        update: Self::Update,
    ) -> Result<&mut Self::Storage, StorageError>;

    /// Get an existing graph.
    ///
    /// # Arguments
    ///
    /// * `group` - Id of the command that initialized the graph.
    fn get_storage(&mut self, group: &command::Id) -> Result<&mut Self::Storage, StorageError>;
}

/// Represents the runtime's graph; [`Command`](s) in storage have been validated
/// by an associated [`Policy`] and committed to state.
pub trait Storage {
    type Perspective: Perspective<Update = Self::Update>;
    type Update;
    type Segment: Segment;

    /// Return the location of the specified command, if it has been stored
    /// in this graph.
    ///
    /// # Arguments
    ///
    /// * `id` - Uniquely identifies the (serialized) command.
    fn get_location(&self, id: &command::Id) -> Result<Option<Location>, StorageError>;

    /// Return the Id of the specified [`Command`] from the graph.
    ///
    /// # Arguments
    ///
    /// * `location` - References a point in the graph.
    fn get_id(&self, location: &Location) -> Result<command::Id, StorageError>;

    /// Return the specified [`Segment`] from the graph. Returns None if the
    /// Id cannot be found
    ///
    /// # Arguments
    ///
    /// * `location` - References a point in the graph.
    fn get_segment(&self, location: &Location) -> Result<Option<&Self::Segment>, StorageError>;

    /// Return a mutable reference to a perspective of the graph at
    /// the specified command.
    ///
    /// # Arguments
    ///
    /// * `id` - Uniquely identifies the (serialized) command.
    fn get_perspective(&self, id: &command::Id) -> Result<Option<Self::Perspective>, StorageError>;

    /// Return true if the specified command is a head.
    ///
    /// # Arguments
    ///
    /// * `location` - References a point in the graph.
    fn is_head(&self, location: &Location) -> Result<bool, StorageError>;

    /// Return the locations of command heads in the graph.
    fn get_heads(&self) -> Result<Vec<Location>, StorageError>;

    /// Add merge commands until there is one head. The final merge head's
    /// ID is returned.
    fn merge_branches(&mut self, engine: &impl Engine) -> Result<command::Id, StorageError>;

    /// Split a segment at a specified command. Returns true if the
    /// segment was split, and false if it was not.
    ///
    /// # Arguments
    ///
    /// * `location` - References a point in the graph.
    fn split(&mut self, at: &Location) -> Result<bool, StorageError>;

    /// Commit a sequence of commands to this graph.
    ///
    /// # Arguments
    ///
    /// * `update` - Contains the data necessary to update this graph.
    fn commit(&mut self, update: Self::Update) -> Result<(), StorageError>;
}

/// Represents a mutable slice of state.
pub trait Perspective {
    type Update;

    /// Consumes the perspective and produce an update, to be committed to
    /// the graph.
    fn to_update(self) -> Self::Update;

    /// Returns the fact's value, if it has been stored.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice that holds a fact key
    fn query(&self, key: &[u8]) -> Result<Option<&[u8]>, StorageError>;

    /// Adds a fact to this perspective.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice that holds a fact's key
    /// * `value` - A byte slice that holds a fact's value
    fn insert(&mut self, key: &[u8], value: &[u8]);

    /// Deletes a fact from this perspective.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice that hold's a fact's key
    fn delete(&mut self, key: &[u8]);

    /// Return the index of the perspective's latest command.
    fn checkpoint(&self) -> Checkpoint;

    /// Rollback commands since the one specified by `checkpoint`.
    ///
    /// # Arguments
    ///
    /// * `checkpoint` - A struct containing the `index` of a command in
    ///   this perspective.
    fn revert(&mut self, checkpoint: Checkpoint);

    /// Return the location of this perspective, in relation to the parent
    /// graph.
    fn location(&self) -> &Option<Location>;

    /// Return an ID for this perspective's associated policy.
    fn policy(&self) -> PolicyId;

    /// Add the `command` to this perspective, returning it's new index.
    ///
    /// # Arguments
    ///
    /// * `command` - Represents an effect on the graph
    fn add_command(&mut self, command: &impl Command) -> Result<usize, StorageError>;

    /// Get a mutable reference to this perspective's serialization buffer.
    fn get_target(&mut self) -> Result<&mut [u8], StorageError>;
}

/// Represents a sequence of linear [`Command`]s.
pub trait Segment {
    type Command: Command;
    type Commands<'a>: Iterator<Item = Option<&'a Self::Command>>
    where
        Self: 'a;

    /// Return the head of this segment.
    fn head(&self) -> Option<&Self::Command>;

    /// Return the first Command in the segment.
    fn first(&self) -> Option<&Self::Command>;

    /// Return the location of the first command in this segment.
    fn first_location(&self) -> Option<Location>;

    /// Return true if the head of this segment is a command with
    /// the supplied id, or false othewise.
    ///
    /// # Arguments
    ///
    /// * `id` - Uniquely identifies the (serialized) command.
    fn location_is_head(&self, id: command::Id) -> bool;

    /// Return true if the segment contains the given `location`.
    ///
    /// # Arguments
    ///
    /// * `location` - References a point in the graph.
    fn contains(&self, location: &Location) -> bool;

    /// Add a child to the segment and return its index.
    ///
    /// # Arguments
    ///
    /// * `command` - Represents an effect on the graph
    fn add_child(&mut self, command: &impl Command) -> usize;

    /// Return the ID for this segment's policy.
    fn policy(&self) -> PolicyId;

    /// Return the prior segnemts for this segment.
    fn prior(&self) -> Vec<Location>;

    /// Returns the command at `location`
    ///
    /// # Arguments
    ///
    /// * `location` - References a point in the graph.
    fn get_command(&self, location: &Location) -> Option<&Self::Command>;

    /// Returns an iterator of [`Command`]s starting at the given `location`.
    ///
    /// # Arguments
    ///
    /// * `location` - [`Location`] struct; contains a [`Command`] ID and its
    ///   [`Segment`] index from this graph.
    fn get_from<'a>(&'a self, location: &Location) -> Self::Commands<'a>;
}

/// Identifies the index [`Command`] within a sequence.
pub struct Checkpoint {
    _index: usize,
}

/// Represents where a [`Command`] is within the parent graph.
#[derive(Debug, Clone)]
pub struct Location {
    _segment: usize,
    _command: usize,
}

impl Location {
    fn _new(segment: usize, command: usize) -> Location {
        Location {
            _segment: segment,
            _command: command,
        }
    }
}

/// Returned by graph storage implementations.
#[derive(Debug)]
pub enum StorageError {
    StorageExists,
    NoSuchStorage,
    LocationOutOfBounds,
    InternalError,
    IoError,
    NoHeads,
    EngineError(EngineError),
}

impl From<EngineError> for StorageError {
    fn from(error: EngineError) -> Self {
        StorageError::EngineError(error)
    }
}
