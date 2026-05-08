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
    Subscribe(SubscribeIncoming),
    /// An unsubscribe request from a peer.
    Unsubscribe(UnsubscribeIncoming),
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
            } => Self::Subscribe(SubscribeIncoming {
                graph_id,
                remain_open,
                max_bytes,
                heads: SyncHeads { inner: commands },
            }),
            SyncType::Unsubscribe { graph_id } => {
                Self::Unsubscribe(UnsubscribeIncoming { graph_id })
            }
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
    Subscribe(HelloSubscribe),
    /// Unsubscribe from hello notifications.
    Unsubscribe(HelloUnsubscribe),
    /// Notification message sent to subscribers.
    Hello(HelloNotification),
}

impl From<SyncHelloType> for SyncHello {
    fn from(t: SyncHelloType) -> Self {
        match t {
            SyncHelloType::Subscribe {
                graph_id,
                graph_change_delay,
                duration,
                schedule_delay,
            } => Self::Subscribe(HelloSubscribe {
                graph_id,
                graph_change_delay,
                duration,
                schedule_delay,
            }),
            SyncHelloType::Unsubscribe { graph_id } => {
                Self::Unsubscribe(HelloUnsubscribe { graph_id })
            }
            SyncHelloType::Hello { graph_id, head } => {
                Self::Hello(HelloNotification { graph_id, head })
            }
        }
    }
}

/// An opaque container for a hello-protocol subscribe request.
#[derive(Debug)]
pub struct HelloSubscribe {
    graph_id: GraphId,
    graph_change_delay: Duration,
    duration: Duration,
    schedule_delay: Duration,
}

impl HelloSubscribe {
    /// Returns the graph being subscribed to.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }

    /// Returns the delay between notifications when the graph changes (rate limiting).
    pub fn graph_change_delay(&self) -> Duration {
        self.graph_change_delay
    }

    /// Returns how long the subscription should last.
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns the schedule-based hello sending delay.
    pub fn schedule_delay(&self) -> Duration {
        self.schedule_delay
    }
}

/// An opaque container for a hello-protocol unsubscribe request.
#[derive(Debug)]
pub struct HelloUnsubscribe {
    graph_id: GraphId,
}

impl HelloUnsubscribe {
    /// Returns the graph being unsubscribed from.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }
}

/// An opaque container for a hello notification sent to subscribers.
#[derive(Debug)]
pub struct HelloNotification {
    graph_id: GraphId,
    head: Address,
}

impl HelloNotification {
    /// Returns the graph this notification is for.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }

    /// Returns the current head of the sender's graph.
    pub fn head(&self) -> Address {
        self.head
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

/// An opaque container for a received subscribe message.
pub struct SubscribeIncoming {
    graph_id: GraphId,
    remain_open: u64,
    max_bytes: u64,
    heads: SyncHeads,
}

impl SubscribeIncoming {
    /// Returns the graph being subscribed to.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }

    /// Returns how long the subscription should remain open.
    pub fn remain_open(&self) -> Duration {
        Duration::from_secs(self.remain_open)
    }

    /// Returns the maximum number of bytes the responder may push.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Returns the peer's known graph heads.
    pub fn heads(&self) -> &SyncHeads {
        &self.heads
    }
}

/// An opaque container for a received unsubscribe message.
pub struct UnsubscribeIncoming {
    graph_id: GraphId,
}

impl UnsubscribeIncoming {
    /// Returns the graph being unsubscribed from.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
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
