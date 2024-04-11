use alloc::vec;

use buggy::BugExt;
use crypto::Csprng;
use heapless::Vec;
use serde::{Deserialize, Serialize};

use super::{
    responder::SyncResponseMessage, SyncCommand, SyncError, COMMAND_RESPONSE_MAX,
    COMMAND_SAMPLE_MAX, REQUEST_MISSING_MAX,
};
use crate::{
    command::{Command, CommandId},
    storage::{GraphId, Segment, Storage, StorageError, StorageProvider},
};

// TODO: Use compile-time args. This initial definition results in this clippy warning:
// https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant.
// As the buffer consts will be compile-time variables in the future, we will be
// able to tune these buffers for smaller footprints. Right now, this enum is not
// suitable for small devices (`SyncRequest` is 6512 bytes).
/// Messages sent from the requester to the responder.
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SyncRequestMessage {
    /// Initiate a new Sync
    SyncRequest {
        /// A new random value produced by a cryptographically secure RNG.
        session_id: u128,
        /// Specifies the graph to be synced.
        storage_id: GraphId,
        /// Specifies the maximum number of bytes worth of commands that
        /// the requester wishes to receive.
        max_bytes: u64,
        /// Sample of the commands held by the requester. The responder should
        /// respond with any commands that the requester may not have based on
        /// the provided sample. When sending commands ancestors must be sent
        /// before descendents.
        commands: Vec<CommandId, COMMAND_SAMPLE_MAX>,
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

    /// Message sent by either requester or responder to indicate the session
    /// has been terminated or the `session_id` is no longer valid.
    EndSession { session_id: u128 },
}

impl SyncRequestMessage {
    pub fn session_id(&self) -> u128 {
        match self {
            Self::SyncRequest { session_id, .. } => *session_id,
            Self::RequestMissing { session_id, .. } => *session_id,
            Self::SyncResume { session_id, .. } => *session_id,
            Self::EndSession { session_id, .. } => *session_id,
        }
    }
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
    session_id: u128,
    storage_id: GraphId,
    state: SyncRequesterState,
    max_bytes: u64,
    next_index: u64,
    #[allow(unused)] // TODO(jdygert): Figure out what this is for...
    ooo_buffer: [Option<&'a [u8]>; OOO_LEN],
}

impl SyncRequester<'_> {
    /// Create a new [`SyncRequester`] with a random session ID.
    pub fn new<R: Csprng>(storage_id: GraphId, rng: &mut R) -> Self {
        // Randomly generate session id.
        let mut dst = [0u8; 16];
        rng.fill_bytes(&mut dst);
        let session_id = u128::from_le_bytes(dst);

        SyncRequester {
            session_id,
            storage_id,
            state: SyncRequesterState::New,
            max_bytes: 0,
            next_index: 0,
            ooo_buffer: core::array::from_fn(|_| None),
        }
    }

    /// Returns true if [`Self::poll`] would produce a message.
    pub fn ready(&self) -> bool {
        use SyncRequesterState as S;
        match self.state {
            S::New | S::Resync | S::Reset => true,
            S::Start | S::Waiting | S::Idle | S::Closed | S::PartialSync => false,
        }
    }

    /// Write a sync message in to the target buffer. Returns the number
    /// of bytes written.
    pub fn poll(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<usize, SyncError> {
        use SyncRequesterState as S;
        let result = match self.state {
            S::Start | S::Waiting | S::Idle | S::Closed | S::PartialSync => {
                return Err(SyncError::NotReady)
            }
            S::New => {
                self.state = S::Start;
                self.start(self.max_bytes, target, provider)?
            }
            S::Resync => self.resume(self.max_bytes, target)?,
            S::Reset => {
                self.state = S::Closed;
                self.end_session(target)?
            }
        };

        Ok(result)
    }

    /// Receive a sync message. Returns parsed sync commands.
    pub fn receive<'a>(
        &mut self,
        data: &'a [u8],
    ) -> Result<Option<Vec<SyncCommand<'a>, COMMAND_RESPONSE_MAX>>, SyncError> {
        let (message, remaining): (SyncResponseMessage, &'a [u8]) =
            postcard::take_from_bytes(data)?;

        if message.session_id() != self.session_id {
            return Err(SyncError::SessionMismatch);
        }

        let result = match message {
            SyncResponseMessage::SyncResponse {
                index, commands, ..
            } => {
                if !matches!(
                    self.state,
                    SyncRequesterState::Start | SyncRequesterState::Waiting
                ) {
                    return Err(SyncError::SessionState);
                }

                if index != self.next_index {
                    self.state = SyncRequesterState::Resync;
                    return Err(SyncError::MissingSyncResponse);
                }
                self.next_index = self
                    .next_index
                    .checked_add(1)
                    .assume("next_index + 1 mustn't overflow")?;
                self.state = SyncRequesterState::Waiting;

                let mut result = Vec::new();
                let mut start: usize = 0;
                for meta in commands {
                    let policy_len = meta.policy_length as usize;

                    let policy = match policy_len == 0 {
                        true => None,
                        false => {
                            let end = start
                                .checked_add(policy_len)
                                .assume("start + policy_len mustn't overflow")?;
                            let policy = &remaining[start..end];
                            start = end;
                            Some(policy)
                        }
                    };

                    let len = meta.length as usize;
                    let end = start
                        .checked_add(len)
                        .assume("start + len mustn't overflow")?;
                    let payload = &remaining[start..end];
                    start = end;

                    let command = SyncCommand {
                        id: meta.id,
                        priority: meta.priority,
                        parent: meta.parent,
                        policy,
                        data: payload,
                        max_cut: meta.max_cut,
                    };

                    result
                        .push(command)
                        .ok()
                        .assume("commands is not larger than result")?;
                }

                Some(result)
            }

            SyncResponseMessage::SyncEnd { max_index, .. } => {
                if !matches!(
                    self.state,
                    SyncRequesterState::Start | SyncRequesterState::Waiting
                ) {
                    return Err(SyncError::SessionState);
                }

                if max_index
                    != self
                        .next_index
                        .checked_sub(1)
                        .assume("next_index must be positive")?
                {
                    self.state = SyncRequesterState::Resync;
                    return Err(SyncError::MissingSyncResponse);
                }

                self.state = SyncRequesterState::PartialSync;

                None
            }

            SyncResponseMessage::Offer { .. } => {
                if self.state != SyncRequesterState::Idle {
                    return Err(SyncError::SessionState);
                }
                self.state = SyncRequesterState::Resync;

                None
            }

            SyncResponseMessage::EndSession { .. } => {
                self.state = SyncRequesterState::Closed;
                None
            }
        };

        Ok(result)
    }

    fn write(target: &mut [u8], msg: SyncRequestMessage) -> Result<usize, SyncError> {
        Ok(postcard::to_slice(&msg, target)?.len())
    }

    fn end_session(&mut self, target: &mut [u8]) -> Result<usize, SyncError> {
        Self::write(
            target,
            SyncRequestMessage::EndSession {
                session_id: self.session_id,
            },
        )
    }

    fn resume(&mut self, max_bytes: u64, target: &mut [u8]) -> Result<usize, SyncError> {
        if !matches!(
            self.state,
            SyncRequesterState::Resync | SyncRequesterState::Idle
        ) {
            return Err(SyncError::SessionState);
        }

        self.state = SyncRequesterState::Waiting;
        let message = SyncRequestMessage::SyncResume {
            session_id: self.session_id,
            response_index: self
                .next_index
                .checked_sub(1)
                .assume("next_index must be positive")?,
            max_bytes,
        };

        Self::write(target, message)
    }

    fn start(
        &mut self,
        max_bytes: u64,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<usize, SyncError> {
        if !matches!(
            self.state,
            SyncRequesterState::Start | SyncRequesterState::New
        ) {
            self.state = SyncRequesterState::Reset;
            return Err(SyncError::SessionState);
        }

        self.state = SyncRequesterState::Start;
        self.max_bytes = max_bytes;

        let mut commands: Vec<CommandId, COMMAND_SAMPLE_MAX> = Vec::new();

        match provider.get_storage(&self.storage_id) {
            Err(StorageError::NoSuchStorage) => (),
            Err(_) => {
                return Err(SyncError::StorageError);
            }
            Ok(storage) => {
                let head = storage.get_head()?;

                let mut current = vec![head];

                // Here we just get the first command from the most reaseant
                // COMMAND_SAMPLE_MAX segments in the graph. This is probbly
                // not the best strategy as if you are far enough ahead of
                // the other client they will just send you everything they have.
                while commands.len() < COMMAND_SAMPLE_MAX && !current.is_empty() {
                    let mut next = alloc::vec::Vec::new(); //BUG not constant memory

                    'current: for &location in &current {
                        let segment = storage.get_segment(location)?;

                        let head = segment.head();
                        commands.push(head.id()).assume("can push to commands")?;
                        next.extend(segment.prior());
                        if commands.len() >= COMMAND_SAMPLE_MAX {
                            break 'current;
                        }
                    }

                    current = next.to_vec();
                }
            }
        }

        let message = SyncRequestMessage::SyncRequest {
            session_id: self.session_id,
            storage_id: self.storage_id,
            max_bytes,
            commands,
        };

        Self::write(target, message)
    }
}
