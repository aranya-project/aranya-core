use alloc::vec::Vec;

use crate::{
    command::{self, Command},
    engine::{Engine, EngineError, PolicyId},
};

pub trait StorageProvider<T, K, V>
where
    T: Command,
    K: Ord,
{
    type Perspective<'a>: Perspective<'a, T, K, V, Update = Self::Update>
    where
        Self: 'a;
    type Update;
    type Storage: Storage<T, K, V, Update = Self::Update>;

    fn new_perspective<'a>(&'a mut self, policy_id: &PolicyId) -> Self::Perspective<'a>;
    fn new_storage<'a>(
        &'a mut self,
        group: &command::Id,
        update: Self::Update,
    ) -> Result<&'a mut Self::Storage, StorageError>;
    fn get_storage<'a>(
        &'a mut self,
        group: &command::Id,
    ) -> Result<&'a mut Self::Storage, StorageError>;
}

/// Represents the parent graph of commands.
pub trait Storage<T, K, V>
where
    T: Command,
{
    type Perspective<'a>: Perspective<'a, T, K, V, Update = Self::Update>
    where
        Self: 'a;
    type Update;
    type Segment;

    /// Return the location of Command with id if it has been stored.
    fn get_location(&self, id: &command::Id) -> Result<Option<Location>, StorageError>;

    /// Return a mutable reference to the fact db perspective in the graph at
    /// the command with id, or None if the id can not be found.
    fn get_perspective<'b>(
        &'b self,
        id: &command::Id,
    ) -> Result<Option<Self::Perspective<'b>>, StorageError>;

    /// Return true if the location is a head.
    fn is_head(&self, location: &Location) -> Result<bool, StorageError>;

    /// Return the heads of the graph.
    fn get_heads(&self) -> Result<Vec<Location>, StorageError>;

    /// Add merge commands until there is one head. Returns the head of the graph.
    fn merge_branches<E: Engine<T, K, V>>(
        &mut self,
        engine: &E,
    ) -> Result<command::Id, StorageError>;

    /// Split the segment if the location is not the head of the segment.
    /// Returns true if split was performed, false othewise.
    fn split(&mut self, at: &Location) -> Result<bool, StorageError>;

    fn commit(&mut self, update: Self::Update) -> Result<(), StorageError>;
}

/// Represents a mutable slice of state.
pub trait Perspective<'a, T, K, V>
where
    T: Command,
{
    type Update;
    type Location;
    /// Create an update to apply this perspective to the parent graph.
    fn to_update(self) -> Self::Update;

    fn query<'b>(&'b self, key: &K) -> Result<Option<&'b V>, StorageError>;

    fn insert(&mut self, key: K, value: V);
    fn delete(&mut self, key: K);

    fn checkpoint(&self) -> Checkpoint;
    /// Rollback commands that have occurred since the `checkpoint`.
    fn revert(&mut self, checkpoint: Checkpoint);

    fn location(&self) -> &Option<Self::Location>;

    fn policy(&self) -> PolicyId;

    fn add_command(&mut self, command: T) -> Result<usize, StorageError>;

    fn get_target(&mut self) -> Result<&mut [u8], StorageError>;
}

pub trait Segment<T: Command> {
    /// Returns the head of the segment.
    fn head(&self) -> Option<&T>;

    /// Returns the first Command in the segment.
    fn first(&self) -> Option<&T>;

    /// Return true if the head of the segment has an id that
    /// matches the supplied id, false othewise.
    fn is_head(&self, id: command::Id) -> bool;

    /// Add a child to the segment and return its index.
    fn add_child(&mut self, command: T) -> usize;

    /// Return the id for the policy used for this segment.
    fn policy(&self) -> PolicyId;
}

/// The index of a finalization command within a `Perspective`.
pub struct Checkpoint {
    _index: usize,
}

/// Identifies a command in the parent graph.
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

/// Returned by storage implementations.
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
