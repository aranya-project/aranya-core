//! Interface for syncing state between clients.

use buggy::Bug;
use postcard::Error as PostcardError;
use serde::{Deserialize, Serialize};

use crate::{
    Address, Prior,
    command::{Command, CommandId, Priority},
    storage::{MAX_COMMAND_LENGTH, StorageError},
};

mod dispatcher;
mod requester;
mod responder;

pub use dispatcher::{SubscribeResult, SyncType};
pub use requester::{SyncRequestMessage, SyncRequester};
pub use responder::{PeerCache, SyncResponder, SyncResponseMessage};

// TODO: These should all be compile time parameters

/// The maximum number of heads that will be stored for a peer.
pub const PEER_HEAD_MAX: usize = 10;

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
    parent: Prior<Address>,
    policy_length: u32,
    length: u32,
    max_cut: usize,
}

impl CommandMeta {
    pub fn address(&self) -> Address {
        Address {
            id: self.id,
            max_cut: self.max_cut,
        }
    }
}

/// An error returned by the syncer.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync session ID does not match")]
    SessionMismatch,
    #[error("missing sync response")]
    MissingSyncResponse,
    #[error("syncer state not valid for this message")]
    SessionState,
    #[error("syncer not ready for operation")]
    NotReady,
    #[error("too many commands sent")]
    CommandOverflow,
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("serialize error: {0}")]
    Serialize(#[from] PostcardError),
    #[error(transparent)]
    Bug(#[from] Bug),
}

/// Sync command to be committed to graph.
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncCommand<'a> {
    priority: Priority,
    id: CommandId,
    parent: Prior<Address>,
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

    fn parent(&self) -> Prior<Address> {
        self.parent
    }

    fn policy(&self) -> Option<&'a [u8]> {
        self.policy
    }

    fn bytes(&self) -> &'a [u8] {
        self.data
    }

    fn max_cut(&self) -> Result<usize, Bug> {
        Ok(self.max_cut)
    }
}
