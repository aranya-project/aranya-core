use core::time::Duration;

use heapless::Vec;
use serde::{Deserialize, Serialize};

use super::{COMMAND_SAMPLE_MAX, SyncResponseMessage, requester::SyncRequestMessage};
use crate::{Address, GraphId};

/// The sync hello message types for subscription-based notifications.
#[derive(Serialize, Deserialize, Debug)]
pub enum SyncHelloType<A> {
    /// Subscribe to receive hello notifications from this peer
    Subscribe {
        /// Delay between notifications when graph changes (rate limiting)
        graph_change_delay: Duration,
        /// How long the subscription should last
        duration: Duration,
        /// The subscriber's address for receiving hello notifications
        address: A,
        /// Schedule-based hello sending delay.
        /// Send hello every `schedule_delay` duration regardless of graph changes.
        schedule_delay: Duration,
    },
    /// Unsubscribe from hello notifications
    Unsubscribe {
        /// The subscriber's address to identify which subscription to remove
        address: A,
    },
    /// Notification message sent to subscribers
    Hello {
        /// The current head of the sender's graph
        head: Address,
        /// The sender's address for sync_on_hello operations
        address: A,
    },
}

/// The sync type to dispatch.
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SyncType<A> {
    /// This will include a sync request and be
    /// immediately responded to with a sync response.
    Poll {
        /// The sync request message.
        request: SyncRequestMessage,
        /// The remote address of this peer. Used to pull the correct peer cache.
        address: A,
    },
    /// Subscribes the peer to receive push syncs from this peer. Calling this
    /// again will update remain_open and max_bytes for this peer.
    Subscribe {
        /// The number of seconds the sync request will remain open.
        remain_open: u64,
        /// The maximum number of bytes that should be sent.
        max_bytes: u64,
        /// A sample of the peer's graph. This will be used to update the
        /// known heads for the peer.
        commands: Vec<Address, COMMAND_SAMPLE_MAX>,
        /// The graph this request is for.
        storage_id: GraphId,
        /// The address to send push syncs to.
        address: A,
    },
    /// Removes any open subsciptions for the peer. If there is no subscription
    /// this will be a noop.
    Unsubscribe {
        /// The remote address of this peer. Used to remove the subscription.
        address: A,
    },
    /// This will only be sent to peers who have an open subscription.
    /// Contains any new commands that come after the peer's known heads.
    Push {
        /// A message containing commands that the pusher believes the peer
        /// does not have.
        message: SyncResponseMessage,
        /// The graph this push is for.
        storage_id: GraphId,
        /// The remote address of this peer. Used to update the peer cache.
        address: A,
    },
    /// Sync hello message for subscription-based notifications.
    Hello(SyncHelloType<A>),
}

/// The result of attempting to subscribe.
#[derive(Serialize, Deserialize, Debug)]
pub enum SubscribeResult {
    Success,
    TooManySubscriptions,
}
