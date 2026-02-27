//! Interface for syncing state between clients.

mod command;
mod dispatcher;
mod requester;
mod responder;

use buggy::Bug;

pub use self::{
    command::{ArchivedSyncCommand, SyncCommand},
    dispatcher::{SubscribeResult, SyncHelloType, SyncType},
    requester::{SyncRequestMessage, SyncRequester},
    responder::{PeerCache, SyncResponder, SyncResponseMessage},
};
use crate::{MAX_COMMAND_LENGTH, StorageError};

// TODO: These should all be compile time parameters

/// The maximum number of heads that will be stored for a peer.
pub const PEER_HEAD_MAX: usize = 10;

/// The maximum number of samples in a request
#[cfg(feature = "low-mem-usage")]
const COMMAND_SAMPLE_MAX: usize = 20;
#[cfg(not(feature = "low-mem-usage"))]
const COMMAND_SAMPLE_MAX: usize = 100;

/// The maximum number of missing segments that can be requested
/// in a single message
#[cfg(feature = "low-mem-usage")]
const REQUEST_MISSING_MAX: usize = 1;
#[cfg(not(feature = "low-mem-usage"))]
const REQUEST_MISSING_MAX: usize = 100;

/// The maximum number of segments which can be stored to send
#[cfg(feature = "low-mem-usage")]
const SEGMENT_BUFFER_MAX: usize = 10;
#[cfg(not(feature = "low-mem-usage"))]
const SEGMENT_BUFFER_MAX: usize = 100;

/// The maximum size of a sync message
// TODO(jdygert): Configurable and sent in request.
pub const MAX_SYNC_MESSAGE_SIZE: usize = 1024 + MAX_COMMAND_LENGTH * 100;

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
    #[error("target buffer is too small")]
    BufferTooSmall,
    #[error("could not access commands with rkyv")]
    RkyvAccess(#[from] rkyv::rancor::Error),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("serialize error: {0}")]
    Serialize(#[from] postcard::Error),
    #[error(transparent)]
    Bug(#[from] Bug),
}
