//! Interface for syncing state between clients.
//!
//! Transports decode incoming bytes into a [`SyncIncoming`] and dispatch on
//! its variants; the on-wire postcard layout is hidden behind that
//! enumeration so it can evolve without breaking consumers.

use core::time::Duration;

use buggy::Bug;
use heapless::Vec;
use postcard::Error as PostcardError;
use serde::{Deserialize, Serialize};

use crate::{
    Address, MaxCut, Prior,
    command::{CmdId, Command, Priority},
    storage::{GraphId, MAX_COMMAND_LENGTH, StorageError},
};

mod requester;
mod responder;
mod wire;

use requester::SyncRequestMessage;
pub use requester::SyncRequester;
use responder::SyncResponseMessage;
pub use responder::{PeerCache, SyncResponder};
use wire::{SubscribeResult, SyncHelloType, SyncType};

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

/// A decoded incoming sync message.
///
/// Transports decode the raw bytes received over the network with
/// [`SyncIncoming::decode`] and then dispatch on the returned variant.
/// The on-wire postcard layout is encapsulated by this enum and the
/// associated helper types — consumers don't depend on the wire
/// representation directly.
#[allow(clippy::large_enum_variant)]
pub enum SyncIncoming<'a> {
    /// A sync poll. Hand to [`SyncResponder::receive`].
    Poll(PollIncoming),
    /// A subscription request from a peer.
    Subscribe {
        /// The graph being subscribed to.
        graph_id: GraphId,
        /// Number of seconds the subscription should remain open.
        remain_open: u64,
        /// Maximum bytes the responder may push.
        max_bytes: u64,
        /// The peer's known graph heads.
        heads: SyncHeads,
    },
    /// An unsubscribe request from a peer.
    Unsubscribe {
        /// The graph being unsubscribed from.
        graph_id: GraphId,
    },
    /// A push from a subscribed peer. Hand to [`SyncRequester::receive_push`].
    Push(PushIncoming<'a>),
    /// A subscription-control hello message.
    Hello(SyncHello),
}

impl<'a> SyncIncoming<'a> {
    /// Decode an incoming sync message from raw bytes.
    pub fn decode(data: &'a [u8]) -> Result<Self, SyncError> {
        let (sync_type, remaining) = postcard::take_from_bytes::<SyncType>(data)?;
        Ok(match sync_type {
            SyncType::Poll { request } => Self::Poll(PollIncoming {
                session_id: request.session_id(),
                message: request,
            }),
            SyncType::Subscribe {
                remain_open,
                max_bytes,
                commands,
                graph_id,
            } => Self::Subscribe {
                graph_id,
                remain_open,
                max_bytes,
                heads: SyncHeads { inner: commands },
            },
            SyncType::Unsubscribe { graph_id } => Self::Unsubscribe { graph_id },
            SyncType::Push { message, graph_id } => Self::Push(PushIncoming {
                graph_id,
                session_id: message.session_id(),
                message,
                command_data: remaining,
            }),
            SyncType::Hello(hello) => Self::Hello(hello.into()),
        })
    }
}

/// A peer's sample of known graph heads, carried in [`SyncIncoming::Subscribe`].
pub struct SyncHeads {
    inner: Vec<Address, COMMAND_SAMPLE_MAX>,
}

impl SyncHeads {
    /// Returns the heads as a slice.
    pub fn as_slice(&self) -> &[Address] {
        &self.inner
    }

    /// Iterates over the heads.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = Address> + ExactSizeIterator + '_ {
        self.inner.iter().copied()
    }
}

/// A subscription-control message: subscribe, unsubscribe, or hello.
#[derive(Debug)]
pub enum SyncHello {
    /// Subscribe to receive hello notifications from this peer.
    Subscribe {
        /// Specifies the graph.
        graph_id: GraphId,
        /// Delay between notifications when graph changes (rate limiting).
        graph_change_delay: Duration,
        /// How long the subscription should last.
        duration: Duration,
        /// Schedule-based hello sending delay.
        schedule_delay: Duration,
    },
    /// Unsubscribe from hello notifications.
    Unsubscribe {
        /// Specifies the graph.
        graph_id: GraphId,
    },
    /// Notification message sent to subscribers.
    Hello {
        /// Specifies the graph.
        graph_id: GraphId,
        /// The current head of the sender's graph.
        head: Address,
    },
}

impl From<SyncHelloType> for SyncHello {
    fn from(t: SyncHelloType) -> Self {
        match t {
            SyncHelloType::Subscribe {
                graph_id,
                graph_change_delay,
                duration,
                schedule_delay,
            } => Self::Subscribe {
                graph_id,
                graph_change_delay,
                duration,
                schedule_delay,
            },
            SyncHelloType::Unsubscribe { graph_id } => Self::Unsubscribe { graph_id },
            SyncHelloType::Hello { graph_id, head } => Self::Hello { graph_id, head },
        }
    }
}

/// An opaque container for a received poll message. Hand to
/// [`SyncResponder::receive`] to update the responder's state.
pub struct PollIncoming {
    session_id: u128,
    pub(crate) message: SyncRequestMessage,
}

impl PollIncoming {
    /// Returns the sender's session identifier.
    pub fn session_id(&self) -> u128 {
        self.session_id
    }
}

/// An opaque container for a received push message. Hand to
/// [`SyncRequester::receive_push`] to extract the contained commands.
pub struct PushIncoming<'a> {
    graph_id: GraphId,
    session_id: u128,
    pub(crate) message: SyncResponseMessage,
    pub(crate) command_data: &'a [u8],
}

impl PushIncoming<'_> {
    /// Returns the graph this push targets.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }

    /// Returns the sender's session identifier.
    pub fn session_id(&self) -> u128 {
        self.session_id
    }
}

/// The result of a [`SyncIncoming::Subscribe`] dispatch, sent back to the
/// requester so it knows whether the subscription was accepted.
#[derive(Debug)]
pub enum SubscribeResponse {
    /// The subscription was accepted.
    Success,
    /// The responder is at its subscription limit.
    TooManySubscriptions,
}

impl SubscribeResponse {
    /// Encode into `target`. Returns the number of bytes written.
    pub fn encode_to(self, target: &mut [u8]) -> Result<usize, SyncError> {
        let inner = match self {
            Self::Success => SubscribeResult::Success,
            Self::TooManySubscriptions => SubscribeResult::TooManySubscriptions,
        };
        Ok(postcard::to_slice(&inner, target)?.len())
    }

    /// Decode from raw bytes.
    pub fn decode(data: &[u8]) -> Result<Self, SyncError> {
        let inner: SubscribeResult = postcard::from_bytes(data)?;
        Ok(match inner {
            SubscribeResult::Success => Self::Success,
            SubscribeResult::TooManySubscriptions => Self::TooManySubscriptions,
        })
    }
}
