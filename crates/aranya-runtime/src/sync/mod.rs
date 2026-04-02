//! Interface for syncing state between clients.

use buggy::Bug;
use postcard::Error as PostcardError;
use responder::PeerCache;
use serde::{Deserialize, Serialize};
use wire::ResponseMessage;

use super::GraphId;
use crate::{
    Address, Location, MaxCut, Prior, Segment, Storage, TraversalBuffers,
    command::{CmdId, Command, Priority},
    storage::{MAX_COMMAND_LENGTH, StorageError},
    sync::hello::{HelloParams, HelloRequest},
};

mod diff;
mod hello;
mod requester;
mod responder;
mod wire;

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

/// The maximum number of commands in a response
#[cfg(feature = "low-mem-usage")]
pub const COMMAND_RESPONSE_MAX: usize = 5;
#[cfg(not(feature = "low-mem-usage"))]
pub const COMMAND_RESPONSE_MAX: usize = 100;

/// The maximum number of segments which can be stored to send
#[cfg(feature = "low-mem-usage")]
const SEGMENT_BUFFER_MAX: usize = 10;
#[cfg(not(feature = "low-mem-usage"))]
const SEGMENT_BUFFER_MAX: usize = 100;

/// The maximum size of a sync message
// TODO: Use postcard to calculate max size (which accounts for overhead)
// https://docs.rs/postcard/latest/postcard/experimental/max_size/index.html
pub const MAX_SYNC_MESSAGE_SIZE: usize = 1024 + MAX_COMMAND_LENGTH * COMMAND_RESPONSE_MAX;

/// Represents high-level data of a command.
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandMeta {
    id: CmdId,
    priority: Priority,
    parent: Prior<Address>,
    policy_length: u32,
    length: u32,
    max_cut: MaxCut,
}

impl CommandMeta {
    pub fn address(&self) -> Address {
        Address {
            id: self.id,
            max_cut: self.max_cut,
        }
    }
}

/// Sync command to be committed to graph.
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncCommand<'a> {
    priority: Priority,
    id: CmdId,
    parent: Prior<Address>,
    policy: Option<&'a [u8]>,
    data: &'a [u8],
    max_cut: MaxCut,
}

impl<'a> Command for SyncCommand<'a> {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> CmdId {
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

    fn max_cut(&self) -> Result<MaxCut, Bug> {
        Ok(self.max_cut)
    }
}

/// An opaque parsed sync request. Produced by [`dispatch`], consumed by
/// [`SyncResponder::receive`].
///
/// All internal fields are `pub(crate)` — the only way to obtain a
/// `SyncRequest` is through [`dispatch`], and the only way to use it is
/// by passing it to [`SyncResponder::receive`]. The type system enforces
/// correct routing.
#[derive(Debug)]
pub struct SyncRequest {
    pub(crate) session_id: u128,
    pub(crate) graph_id: GraphId,
    pub(crate) samples: heapless::Vec<Address, COMMAND_SAMPLE_MAX>,
}

impl SyncRequest {
    /// The graph this request targets. Use for authentication before
    /// passing the request to the responder.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }
}

/// Routing result from [`dispatch`]. The wire format is not exposed.
#[derive(Debug)]
pub enum IncomingRequest {
    /// A poll-sync request. Validate `graph_id` via
    /// [`SyncRequest::graph_id`], then pass to
    /// [`SyncResponder::receive`].
    Sync(SyncRequest),
    /// A hello protocol message, fully parsed.
    Hello(HelloRequest),
}

/// Route an incoming message without exposing wire types.
///
/// Deserializes the message once and produces either a [`SyncRequest`]
/// (for the responder) or a fully-parsed [`HelloRequest`] (for direct
/// handling). No double deserialization — the responder consumes the
/// already-parsed `SyncRequest`.
pub fn dispatch(data: &[u8]) -> Result<IncomingRequest, SyncError> {
    let msg: wire::RequestMessage = postcard::from_bytes(data)?;
    match msg {
        wire::RequestMessage::Sync {
            session_id,
            graph_id,
            samples,
            ..
        } => Ok(IncomingRequest::Sync(SyncRequest {
            session_id,
            graph_id,
            samples,
        })),

        wire::RequestMessage::HelloSubscribe {
            graph_id,
            graph_change_delay,
            duration,
            schedule_delay,
        } => Ok(IncomingRequest::Hello(HelloRequest::Subscribe {
            graph_id,
            params: HelloParams {
                graph_change_delay,
                duration,
                schedule_delay,
            },
        })),

        wire::RequestMessage::HelloUnsubscribe { graph_id } => {
            Ok(IncomingRequest::Hello(HelloRequest::Unsubscribe {
                graph_id,
            }))
        }

        wire::RequestMessage::HelloNotification { graph_id, head } => {
            Ok(IncomingRequest::Hello(HelloRequest::Notification {
                graph_id,
                head,
            }))
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
