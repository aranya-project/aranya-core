//! The internal wire format used for sync messages.

use core::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{
    CmdId,
    command::{Address, Priority},
    prior::Prior,
    storage::{GraphId, MaxCut},
};

/// First byte of every sync message. Deserialized first to route a message correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Tag {
    SyncRequest,
    SyncResponse,
    HelloSubscribe,
    HelloUnsubscribe,
    HelloNotify,
    HelloAck,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct SyncHeader {
    pub session_id: u128,
    pub graph_id: GraphId,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct HelloSubscribeData {
    pub graph_id: GraphId,
    pub graph_change_delay: Duration,
    pub schedule_delay: Duration,
    pub duration: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct HelloUnsubscribeData {
    pub graph_id: GraphId,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct HelloNotifyData {
    pub graph_id: GraphId,
    pub head: Address,
}

/// Represents high-level data of a command.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct CommandMeta {
    pub id: CmdId,
    pub priority: Priority,
    pub parent: Prior<Address>,
    pub policy_length: u32,
    pub length: u32,
    pub max_cut: MaxCut,
}

impl CommandMeta {
    fn address(&self) -> Address {
        Address {
            id: self.id,
            max_cut: self.max_cut,
        }
    }
}
