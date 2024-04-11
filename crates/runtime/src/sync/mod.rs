//! Interface for syncing state between clients.

use core::{convert::Infallible, fmt};

use buggy::Bug;
use postcard::Error as PostcardError;
use serde::{Deserialize, Serialize};

use crate::{
    command::{Command, CommandId, Priority},
    storage::{StorageError, MAX_COMMAND_LENGTH},
    Prior,
};

mod requester;
mod responder;

pub use requester::SyncRequester;
pub use responder::SyncResponder;

// TODO: These should all be compile time parameters

/// The maximum number of samples in a request
const COMMAND_SAMPLE_MAX: usize = 100;

/// The maximum number of missing segments that can be requested
/// in a single message
const REQUEST_MISSING_MAX: usize = 100;

/// The maximum number of commands in a response
pub const COMMAND_RESPONSE_MAX: usize = 100;

/// The maximum number of segments which can be stored to send
const SEGMENT_BUFFER_MAX: usize = 100;

/// The maximum size of a sync message
// TODO: Use postcard to calculate max size (which accounts for overhead)
// https://docs.rs/postcard/latest/postcard/experimental/max_size/index.html
pub const MAX_SYNC_MESSAGE_SIZE: usize = 1024 + MAX_COMMAND_LENGTH * COMMAND_RESPONSE_MAX;

/// Represents high-level data of a command.
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandMeta {
    id: CommandId,
    priority: Priority,
    parent: Prior<CommandId>,
    policy_length: u32,
    length: u32,
    max_cut: usize,
}

/// Enum of all supported sync messages.
// TODO: Use compile-time args. This initial definition results in this clippy warning:
// https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant.
// As the buffer consts will be compile-time variables in the future, we will be
// able to tune these buffers for smaller footprints. Right now, this enum is not
// suitable for small devices (`SyncResponse` is 8448 bytes).

/// An error returned by the syncer.
#[derive(Debug)]
pub enum SyncError {
    UnexpectedMessage,
    SessionMismatch,
    MissingSyncResponse,
    SessionState,
    StorageError,
    NotReady,
    SerilizeError,
    Bug(Bug),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedMessage => write!(f, "unexpected message"),
            Self::SessionMismatch => write!(f, "session mismatch"),
            Self::MissingSyncResponse => write!(f, "missing sync response"),
            Self::SessionState => write!(f, "session state error"),
            Self::StorageError => write!(f, "storage error"),
            Self::NotReady => write!(f, "not ready"),
            Self::SerilizeError => write!(f, "serialize error"),
            Self::Bug(bug) => write!(f, "{bug}"),
        }
    }
}

impl trouble::Error for SyncError {}

impl From<Bug> for SyncError {
    fn from(error: Bug) -> Self {
        SyncError::Bug(error)
    }
}

impl From<Infallible> for SyncError {
    fn from(error: Infallible) -> Self {
        match error {}
    }
}

impl From<StorageError> for SyncError {
    fn from(_error: StorageError) -> Self {
        SyncError::StorageError
    }
}

impl From<PostcardError> for SyncError {
    fn from(_error: PostcardError) -> Self {
        SyncError::SerilizeError
    }
}

/// Sync command to be committed to graph.
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncCommand<'a> {
    priority: Priority,
    id: CommandId,
    parent: Prior<CommandId>,
    policy: Option<&'a [u8]>,
    data: &'a [u8],
    max_cut: usize,
}

impl<'a> Command for SyncCommand<'a> {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> CommandId {
        self.id
    }

    fn parent(&self) -> Prior<CommandId> {
        self.parent
    }

    fn policy(&self) -> Option<&'a [u8]> {
        self.policy
    }

    fn bytes(&self) -> &'a [u8] {
        self.data
    }
}
