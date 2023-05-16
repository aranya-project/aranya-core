//! Interface for syncing state between clients.
use heapless::Vec;
use serde::{Deserialize, Serialize};

use crate::command::{Id, Parent, Priority};

// TODO: These should all be compile time parameters

// This variable is more a configuration setting
// for storage. Defining here for ease, until these
// all become compile time params.
const MAX_COMMAND_LENGTH: usize = 1024;

/// The maximum number of samples in a request
const COMMAND_SAMPLE_MAX: usize = 100;

/// The maximum number of missing segments that can be requested
/// in a single message.
const REQUEST_MISSING_MAX: usize = 100;

/// The maximum number of commands in a response
const COMMAND_RESPONSE_MAX: usize = 100;

/// The maximum number of segments which can be stored to send
const _SEGMENT_BUFFER_MAX: usize = 100;

/// The maximum size of a sync message
// TODO: Use postcard to calculate max size (which accounts for overhead)
// https://docs.rs/postcard/latest/postcard/experimental/max_size/index.html
pub const MAX_SYNC_MESSAGE_SIZE: usize = 1024 + MAX_COMMAND_LENGTH * COMMAND_RESPONSE_MAX;

/// Represents high-level data of a [`Command`].
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandMeta {
    priority: Priority,
    parent: Parent,
    policy_length: u32,
    length: u32,
}

// TODO: Use compile-time args. This initial definition results in this clippy warning:
// https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant.
// As the buffer consts will be compile-time variables in the future, we will be
// able to tune these buffers for smaller footprints. Right now, this enum is not
// suitable for small devices (`SyncRequest` is ~3256 bytes and change).
#[derive(Serialize, Deserialize, Debug)]
pub enum SyncMessage {
    /// Initiate a new Sync
    SyncRequest {
        /// A new random value produced by a cryptographically secure RNG.
        session_id: u128,
        /// Specifies the graph to be synced.
        storage_id: Id,
        /// Specifies the maximum number of bytes worth of commands that
        /// the requester wishes to receive.
        max_bytes: u64,
        /// Sample of the commands held by the requester. The responder should
        /// respond with any commands that the requester may not have based on
        /// the provided sample. When sending commands ancestors must be sent
        /// before descendents.
        commands: Vec<Id, COMMAND_SAMPLE_MAX>,
    },

    /// Sent in response to a `SyncRequest`
    SyncResponse {
        /// A random-value produced by a cryptographically secure RNG.
        session_id: u128,
        /// If the responder intends to send a value of command bytes
        /// greater than the responder's configured maximum, the responder
        /// will send more than one `SyncResponse`. The first message has an
        /// index of 1, and each following is incremented.
        index: u64,
        /// Commands that the responder believes the requester does not have.
        commands: Vec<CommandMeta, COMMAND_RESPONSE_MAX>,
    },

    /// End a sync session if `SyncRequest.max_bytes` has been reached or
    /// there are no remaining commands to send.
    SyncEnd {
        /// A random-value produced by a cryptographically secure RNG
        /// corresponding to the `session_id` in the initial `SyncRequest`.
        session_id: u128,
        /// Largest index of any `SyncResponse`
        max_index: u64,
        /// Set `true` if this message was sent due to reaching the `max_bytes`
        /// budget.
        remaining: bool,
    },

    /// Sent by the requester if it deduces a `SyncResponse` message has been
    /// dropped.
    RequestMissing {
        /// A random-value produced by a cryptographically secure RNG
        /// corresponding to the `session_id` in the initial `SyncRequest`.
        session_id: u128,
        /// `SyncResponse` indexes that the requester has not received.
        indexes: Vec<u64, REQUEST_MISSING_MAX>,
    },

    /// Message to request the responder resumes sending `SyncResponse`s
    /// following the specified message. This may be sent after a requester
    /// timeout or after a `SyncEnd` has been sent.
    SyncResume {
        /// A random-value produced by a cryptographically secure RNG
        /// corresponding to the `session_id` in the initial `SyncRequest`.
        session_id: u128,
        /// Indicates the last response message the requester received.
        response_index: u64,
        /// Updates the maximum number of bytes worth of commands that
        /// the requester wishes to receive.
        max_bytes: u64,
    },

    /// Message sent by a responder after a sync has been completed, but before
    /// the session has ended, if it has new commands in it's graph. If a
    /// requester wishes to respond to this message, it should do so with a
    /// new `SyncRequest`. This message may use the existing `session_id`.
    Offer {
        /// A random-value produced by a cryptographically secure RNG
        /// corresponding to the `session_id` in the initial `SyncRequest`.
        session_id: u128,
        /// Head of the branch the responder wishes to send.
        head: Id,
    },

    /// Message sent by either requester or responder to indicate the session
    /// has been terminated or the `session_id` is no longer valid.
    EndSession { session_id: u128 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncRequesterState {
    New,
    Start,
    Waiting,
    Idle,
    Closed,
    Resync,
    PartialSync,
    Reset,
}

// The length of the Out Of Order buffer
const OOO_LEN: usize = 4;
pub struct SyncRequester<'a> {
    _session_id: u128,
    _storage_id: Id,
    _state: SyncRequesterState,
    _max_bytes: u64,
    _next_index: u64,
    _ooo_buffer: [Option<&'a [u8]>; OOO_LEN],
}

impl SyncRequester<'_> {
    pub fn new(_session_id: u128, _storage_id: Id) -> Self {
        SyncRequester {
            _session_id,
            _storage_id,
            _state: SyncRequesterState::New,
            _max_bytes: 0,
            _next_index: 0,
            _ooo_buffer: core::array::from_fn(|_| None),
        }
    }
}
