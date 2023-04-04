use alloc::vec::Vec;

use crate::command;

pub enum SyncMessage<T> {
    /// Initiate a new Sync.
    /// The `session_id` should be a new random value produced by a
    /// cryptographically secure RNG.
    ///
    /// The `storage_id` specifies which graph we are syncing.
    ///
    /// The `max_bytes` specifies the maximum number of bytes worth of
    /// commands that the requester wishes to receive.
    ///
    /// The `commands` are a sample of the commands held by the requester.
    /// The responder should respond with any commands that the requester
    /// may not have based on the provided sample. When sending commands
    /// ancestors must be sent before descendents.
    SyncRequest {
        session_id: u128,
        storage_id: command::Id,
        max_bytes: u64,
        commands: Vec<command::Id>,
    },

    /// A `SyncResponse` message contains commands which the responder believes
    /// the requester does not have. If the number of commands it intends to send
    /// would result in a message beyond the responders configured maximum, there
    /// will be more than one `SyncResponse` sent. Each transmitted `SyncResponse`
    /// will have incrementing `index`, with the first message having the `index` of 1.
    SyncResponse {
        session_id: u128,
        index: u64,
        commands: Vec<T>,
    },

    //// When `SyncRequest.max_bytes` has been reached or there are not more
    /// commands to send, responder will send a `SyncEnd` message. The `max_index`
    /// is the largest index of any `SyncResponse`. The `remaining` is set to
    /// true if the sync end was sent due to reaching the `max_bytes` budget.
    SyncEnd {
        session_id: u128,
        max_index: u64,
        remaining: bool,
    },

    /// The `RequestMissing` message is used to request `SyncResponse` messages where
    /// requester can deduce that they are missing gaps in the sequence of
    /// `SyncResponse.index`s it has seen.
    RequestMissing {
        session_id: u128,
        indexies: Vec<u64>,
    },

    /// The `SyncResume` message is used to ask that the responder continue
    /// sending `SyncResponse` messages starting with the message following the
    /// given `response_index`. This message can be used at any time after a
    /// `SyncRequest` has been sent. It updates the send budget at the responder
    /// at the moment it is processed by the responder.
    ///
    /// This can be used to either continue syncing after a requester timeout or
    /// after a `SyncEnd`.
    SyncResume {
        session_id: u128,
        response_index: u64,
        max_bytes: u64,
    },

    /// A responder may send a `Offer` message after a sync has been completed but
    /// before receiving a `EndSession` if it has new commands in it's graph.
    /// If a requester wishes to respond to an Offer it should do so with a new
    /// `SyncRequest` but it may use the existing `session_id` in that new `SyncRequest`.
    Offer { session_id: u128, head: command::Id },

    /// A `EndSession` may be sent by either the requester or the responder to indicate
    /// that the session has been terminated and that `session_id` is no longer valid.
    EndSession { session_id: u128 },
}

// TODO (shannyn): Remove underscores when impl is added
enum SyncRequesterState {
    Start,
    _Waiting,
    _Idle,
    _Closed,
}

pub struct SyncRequester {
    _state: SyncRequesterState,
    _session_id: u128,
    _storage_id: command::Id,
}

impl SyncRequester {
    pub fn new(session_id: u128, storage_id: command::Id) -> Self {
        SyncRequester {
            _state: SyncRequesterState::Start,
            _session_id: session_id,
            _storage_id: storage_id,
        }
    }
}
