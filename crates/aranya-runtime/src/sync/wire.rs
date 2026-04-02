//! The internal wire format used for sync messages.
use core::time::Duration;

use heapless::Vec;
use serde::{Deserialize, Serialize};

use super::{Address, COMMAND_RESPONSE_MAX, COMMAND_SAMPLE_MAX, CommandMeta, GraphId};

/// A request message sent to a peer to request some sync operation.
#[derive(Debug, Serialize, Deserialize)]
pub(super) enum RequestMessage<const MAX_SAMPLES: usize = COMMAND_SAMPLE_MAX> {
    /// Single-round-trip poll sync.
    Sync {
        /// The current sync session this message is about.
        session_id: u128,
        /// The Graph ID we want to sync updates for.
        graph_id: GraphId,
        /// The maximum number of bytes we're able to receive.
        max_bytes: u64,
        /// A sample of commands we currently have created, used by the responder to choose which
        /// commands to sync back that we may not have.
        samples: Vec<Address, MAX_SAMPLES>,
    },

    /// Subscribe to hello (head-change) notifications.
    HelloSubscribe {
        /// The Graph ID we're requesting updates for.
        graph_id: GraphId,
        /// How long to wait before sending another notification (i.e. rate limiting).
        graph_change_delay: Duration,
        /// How often we'd like subscription updates, regardles of if the graph changed.
        schedule_delay: Duration,
        /// How long we want to be subscribed for.
        duration: Duration,
    },

    /// Unsubscribe from hello notifications.
    HelloUnsubscribe {
        /// The Graph ID we requested updates for.
        graph_id: GraphId,
    },

    /// Notification specifying our current graph head (which may or may not have changed).
    HelloNotification {
        /// The Graph ID we're sending an update about.
        graph_id: GraphId,
        /// The current head of the graph on our end.
        head: Address,
    },
}

/// The response message to a sync request.
#[derive(Debug, Serialize, Deserialize)]
pub(super) enum ResponseMessage<const MAX_COMMANDS: usize = COMMAND_RESPONSE_MAX> {
    /// Commands that the responder believes the requester is missing.
    Sync {
        /// The current sync session this message is about.
        session_id: u128,
        /// The data for a number of commands that the requester may not have yet. "Older" commands
        /// are sent before newer commands, in order to ensure the other peer can resolve the new
        /// graph state.
        commands: Vec<CommandMeta, MAX_COMMANDS>,
    },

    /// Acknowledgmenet of receiving a hello subscription/unsubscription request.
    HelloAck,
}
