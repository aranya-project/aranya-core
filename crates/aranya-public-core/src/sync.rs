//! Re-exports of the sync protocol API from [`aranya_runtime::sync`].

#[doc(inline)]
pub use aranya_runtime::sync::{
    COMMAND_RESPONSE_MAX, CommandMeta, MAX_SYNC_MESSAGE_SIZE, PEER_HEAD_MAX, PeerCache,
    SubscribeResult, SyncCommand, SyncError, SyncHelloType, SyncRequestMessage, SyncRequester,
    SyncResponder, SyncResponseMessage, SyncType,
};
