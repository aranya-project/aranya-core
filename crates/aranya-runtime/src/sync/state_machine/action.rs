//! Actions the syncer asks its caller to perform, and capacity errors.

use core::time::Duration;

use crate::storage::GraphId;

/// Work the caller should perform, returned by [`Syncer::poll_action`].
///
/// Every variant carries `graph_id`; [`graph_id`](Self::graph_id) returns
/// it. Deliberately not `#[non_exhaustive]`: adding a sync mechanism should
/// break integrators at compile time rather than be dropped by a wildcard
/// arm.
///
/// [`Syncer::poll_action`]: super::Syncer::poll_action
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncAction<A> {
    /// Poll-sync with `peer`: [`SyncRequester::poll`], feed the reply to
    /// [`SyncRequester::receive`], and commit.
    ///
    /// [`SyncRequester::poll`]: crate::sync::SyncRequester::poll
    /// [`SyncRequester::receive`]: crate::sync::SyncRequester::receive
    Poll {
        /// The peer to poll.
        peer: A,
        /// The graph to sync.
        graph_id: GraphId,
    },
    /// Ask `peer` to push updates to us — emitted for the initial
    /// [`Syncer::subscribe`] and each renewal: [`SyncRequester::subscribe`].
    /// Feed the reply to [`Syncer::on_subscribe_response`].
    ///
    /// [`Syncer::subscribe`]: super::Syncer::subscribe
    /// [`Syncer::on_subscribe_response`]: super::Syncer::on_subscribe_response
    /// [`SyncRequester::subscribe`]: crate::sync::SyncRequester::subscribe
    Subscribe {
        /// The peer to subscribe to.
        peer: A,
        /// The graph to subscribe to.
        graph_id: GraphId,
        /// How long the peer should keep the subscription open, in whole
        /// wire seconds.
        remain_open_secs: u64,
        /// The maximum number of bytes the peer should push.
        max_bytes: u64,
    },
    /// Cancel our push subscription with `peer`:
    /// [`SyncRequester::unsubscribe`].
    ///
    /// [`SyncRequester::unsubscribe`]: crate::sync::SyncRequester::unsubscribe
    Unsubscribe {
        /// The peer to unsubscribe from.
        peer: A,
        /// The graph to unsubscribe from.
        graph_id: GraphId,
    },
    /// Push to our push-subscriber `peer`: [`SyncResponder::start_session`]
    /// and [`SyncResponder::push`], then [`Syncer::record_push`].
    ///
    /// [`Syncer::record_push`]: super::Syncer::record_push
    /// [`SyncResponder::start_session`]: crate::sync::SyncResponder::start_session
    /// [`SyncResponder::push`]: crate::sync::SyncResponder::push
    Push {
        /// The subscriber to push to.
        peer: A,
        /// The graph to push.
        graph_id: GraphId,
    },
    /// Ask `peer` to send us hello notifications — initial request and
    /// renewals: [`HelloMessage::subscribe`]. The protocol defines no reply.
    ///
    /// [`HelloMessage::subscribe`]: crate::sync::HelloMessage::subscribe
    HelloSubscribe {
        /// The peer to subscribe to.
        peer: A,
        /// The graph to subscribe to.
        graph_id: GraphId,
        /// Requested debounce between change-triggered hellos.
        graph_change_delay: Duration,
        /// Requested subscription lifetime.
        duration: Duration,
        /// Requested cadence of scheduled hellos.
        schedule_delay: Duration,
    },
    /// Cancel hellos from `peer`: [`HelloMessage::unsubscribe`].
    ///
    /// [`HelloMessage::unsubscribe`]: crate::sync::HelloMessage::unsubscribe
    HelloUnsubscribe {
        /// The peer to unsubscribe from.
        peer: A,
        /// The graph to unsubscribe from.
        graph_id: GraphId,
    },
    /// Send our current head (from storage) as a hello to hello-subscriber
    /// `peer`: [`HelloMessage::notification`].
    ///
    /// [`HelloMessage::notification`]: crate::sync::HelloMessage::notification
    SendHello {
        /// The subscriber to notify.
        peer: A,
        /// The graph whose head to send.
        graph_id: GraphId,
    },
}

impl<A> SyncAction<A> {
    /// Returns the graph this action is for.
    pub fn graph_id(&self) -> GraphId {
        match self {
            Self::Poll { graph_id, .. }
            | Self::Subscribe { graph_id, .. }
            | Self::Unsubscribe { graph_id, .. }
            | Self::Push { graph_id, .. }
            | Self::HelloSubscribe { graph_id, .. }
            | Self::HelloUnsubscribe { graph_id, .. }
            | Self::SendHello { graph_id, .. } => *graph_id,
        }
    }
}

/// A subscribe or hello-subscribe was rejected: at the subscriber cap or out
/// of [`SyncSlots`](super::SyncSlots). Map to
/// [`SubscribeResponse::TooManySubscriptions`] where applicable.
///
/// [`SubscribeResponse::TooManySubscriptions`]: crate::sync::SubscribeResponse::TooManySubscriptions
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("subscriber limit reached")]
pub struct SubscriberLimitReached;

/// The caller-supplied [`SyncSlots`](super::SyncSlots) have no room for
/// another peer-graph pair. Free a slot or supply larger storage; never
/// returned through [`HeapSlots`](super::HeapSlots), which grows on demand.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("out of syncer slots")]
pub struct OutOfSlots;
