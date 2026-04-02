//! Hello protocol types and server-side helpers.
use core::time::Duration;

use super::{Address, GraphId, ResponseMessage, SyncError};

/// The parameters needed for subscribing to hello notifications from a peer.
///
/// While a hello subscription is active, the peer will send hello notifications when its graph head
/// changes by default. It will also send notifications on the specified schedule, regardless of if
/// the graph changed. Both of these operations are rate-limited by how often we specify that the
/// peer can notify us.
#[derive(Debug, Clone)]
pub(super) struct HelloParams {
    /// How long to wait before sending another notification (i.e. rate limiting).
    pub graph_change_delay: Duration,
    /// How often we'd like subscription updates, regardless of if the graph changed.
    pub schedule_delay: Duration,
    /// How long we want to be subscribed for.
    pub duration: Duration,
}

/// A parsed incoming hello message, returned by [`dispatch`](super::dispatch).
#[derive(Debug)]
pub(super) enum HelloRequest {
    /// Peer wants to subscribe to hello (head-change) notifications.
    Subscribe {
        /// The Graph ID a peer is requesting updates for.
        graph_id: GraphId,
        /// The parameters specified for the subscription (how long and how often).
        params: HelloParams,
    },
    /// Peer wants to cancel its existing subscription.
    Unsubscribe {
        /// The Graph ID a peer subscribed to updates for.
        graph_id: GraphId,
    },
    /// Peer notifying us of their current graph head (which may or may not have changed).
    Notification {
        /// The Graph ID the notification belongs to.
        graph_id: GraphId,
        /// The current head of the graph.
        head: Address,
    },
}

/// Serialize a hello acknowledgement into `target`.
///
/// Used by the server to respond to subscribe/unsubscribe requests.
/// Returns the number of bytes written.
pub fn create_ack(target: &mut [u8]) -> Result<usize, SyncError> {
    let value: ResponseMessage = ResponseMessage::HelloAck;
    Ok(postcard::to_slice(&value, target)?.len())
}
