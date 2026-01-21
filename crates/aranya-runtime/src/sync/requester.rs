use alloc::vec;

use aranya_crypto::Csprng;
use buggy::BugExt as _;
use heapless::Vec;
use serde::{Deserialize, Serialize};

use super::{
    COMMAND_RESPONSE_MAX, COMMAND_SAMPLE_MAX, PEER_HEAD_MAX, PeerCache, REQUEST_MISSING_MAX,
    SyncCommand, SyncError, dispatcher::SyncType, responder::SyncResponseMessage,
};
use crate::{
    Address, Command as _, GraphId, Location,
    storage::{Segment as _, Storage as _, StorageError, StorageProvider},
};

// TODO: Use compile-time args. This initial definition results in this clippy warning:
// https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant.
// As the buffer consts will be compile-time variables in the future, we will be
// able to tune these buffers for smaller footprints. Right now, this enum is not
// suitable for small devices (`SyncRequest` is 4080 bytes).
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
        commands: Vec<Address, COMMAND_SAMPLE_MAX>,
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
enum SyncRequesterState {
    /// Object initialized; no messages sent
    New,
    /// Have sent a start message but have received no response
    Start,
    /// Received some response messages; session not yet complete
    Waiting,
    /// Sync is complete; byte count has not yet been reached
    Idle,
    /// Session is done and no more messages should be processed
    Closed,
    /// Sync response received out of order
    Resync,
    /// SyncEnd received but not everything has been received
    PartialSync,
    /// Session will be closed
    Reset,
}

pub struct SyncRequester {
    session_id: u128,
    storage_id: GraphId,
    state: SyncRequesterState,
    max_bytes: u64,
    next_message_index: u64,
}

impl SyncRequester {
    /// Create a new [`SyncRequester`] with a random session ID.
    pub fn new<R: Csprng>(storage_id: GraphId, rng: &mut R) -> Self {
        // Randomly generate session id.
        let mut dst = [0u8; 16];
        rng.fill_bytes(&mut dst);
        let session_id = u128::from_le_bytes(dst);

        Self {
            session_id,
            storage_id,
            state: SyncRequesterState::New,
            max_bytes: 0,
            next_message_index: 0,
        }
    }

    /// Create a new [`SyncRequester`] for an existing session.
    pub fn new_session_id(storage_id: GraphId, session_id: u128) -> Self {
        Self {
            session_id,
            storage_id,
            state: SyncRequesterState::Waiting,
            max_bytes: 0,
            next_message_index: 0,
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
    /// of bytes written and the number of commands sent in the sample.
    pub fn poll(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        heads: &mut PeerCache,
    ) -> Result<(usize, usize), SyncError> {
        use SyncRequesterState as S;
        let result = match self.state {
            S::Start | S::Waiting | S::Idle | S::Closed | S::PartialSync => {
                return Err(SyncError::NotReady);
            }
            S::New => {
                self.state = S::Start;
                self.start(self.max_bytes, target, provider, heads)?
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

        self.get_sync_commands(message, remaining)
    }

    /// Extract SyncCommands from a SyncResponseMessage and remaining bytes.
    pub fn get_sync_commands<'a>(
        &mut self,
        message: SyncResponseMessage,
        remaining: &'a [u8],
    ) -> Result<Option<Vec<SyncCommand<'a>, COMMAND_RESPONSE_MAX>>, SyncError> {
        if message.session_id() != self.session_id {
            return Err(SyncError::SessionMismatch);
        }

        let result = match message {
            SyncResponseMessage::SyncResponse {
                response_index,
                commands,
                ..
            } => {
                if !matches!(
                    self.state,
                    SyncRequesterState::Start | SyncRequesterState::Waiting
                ) {
                    return Err(SyncError::SessionState);
                }

                if response_index != self.next_message_index {
                    self.state = SyncRequesterState::Resync;
                    return Err(SyncError::MissingSyncResponse);
                }
                self.next_message_index = self
                    .next_message_index
                    .checked_add(1)
                    .assume("next_message_index + 1 mustn't overflow")?;
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

                if max_index != self.next_message_index {
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

    fn write(target: &mut [u8], msg: SyncType) -> Result<usize, SyncError> {
        Ok(postcard::to_slice(&msg, target)?.len())
    }

    fn end_session(&mut self, target: &mut [u8]) -> Result<(usize, usize), SyncError> {
        Ok((
            Self::write(
                target,
                SyncType::Poll {
                    request: SyncRequestMessage::EndSession {
                        session_id: self.session_id,
                    },
                },
            )?,
            0,
        ))
    }

    fn resume(&mut self, max_bytes: u64, target: &mut [u8]) -> Result<(usize, usize), SyncError> {
        if !matches!(
            self.state,
            SyncRequesterState::Resync | SyncRequesterState::Idle
        ) {
            return Err(SyncError::SessionState);
        }

        self.state = SyncRequesterState::Waiting;
        let message = SyncType::Poll {
            request: SyncRequestMessage::SyncResume {
                session_id: self.session_id,
                response_index: self
                    .next_message_index
                    .checked_sub(1)
                    .assume("next_index must be positive")?,
                max_bytes,
            },
        };

        Ok((Self::write(target, message)?, 0))
    }

    fn get_commands(
        &self,
        provider: &mut impl StorageProvider,
        peer_cache: &mut PeerCache,
    ) -> Result<Vec<Address, COMMAND_SAMPLE_MAX>, SyncError> {
        let mut commands: Vec<Address, COMMAND_SAMPLE_MAX> = Vec::new();

        match provider.get_storage(self.storage_id) {
            Err(StorageError::NoSuchStorage) => (),
            Err(err) => {
                return Err(SyncError::Storage(err));
            }
            Ok(storage) => {
                let mut cache_locations: Vec<Location, PEER_HEAD_MAX> = Vec::new();
                for address in peer_cache.heads() {
                    let loc = storage
                        .get_location(*address)?
                        .assume("location must exist")?;
                    cache_locations
                        .push(loc)
                        .ok()
                        .assume("command locations should not be full")?;
                    if commands.len() < COMMAND_SAMPLE_MAX {
                        commands
                            .push(*address)
                            .map_err(|_| SyncError::CommandOverflow)?;
                    }
                }
                // Start traversal from graph head and work backwards until we hit a PeerCache head
                let head = storage.get_head()?;
                let mut current = vec![head];

                // Here we just get the first command from the most reaseant
                // COMMAND_SAMPLE_MAX segments in the graph. This is probbly
                // not the best strategy as if you are far enough ahead of
                // the other client they will just send you everything they have.
                while commands.len() < COMMAND_SAMPLE_MAX && !current.is_empty() {
                    let mut next = vec::Vec::new(); //BUG not constant memory

                    'current: for &location in &current {
                        let segment = storage.get_segment(location)?;

                        let head = segment.head()?;
                        let head_address = head.address()?;

                        // Check if we've hit a PeerCache head - if so, stop traversing this path
                        for &peer_cache_loc in &cache_locations {
                            // If this is the same location as a PeerCache head, we've hit it
                            if location == peer_cache_loc {
                                continue 'current;
                            }
                            // If the current location is an ancestor of a PeerCache head,
                            // we've passed the PeerCache head, so stop traversing this path
                            let peer_cache_segment = storage.get_segment(peer_cache_loc)?;
                            if (peer_cache_loc.same_segment(location)
                                && location.command <= peer_cache_loc.command)
                                || storage.is_ancestor(location, &peer_cache_segment)?
                            {
                                continue 'current;
                            }
                        }

                        commands
                            .push(head_address)
                            .map_err(|_| SyncError::CommandOverflow)?;
                        next.extend(segment.prior());
                        if commands.len() >= COMMAND_SAMPLE_MAX {
                            break 'current;
                        }
                    }

                    current.clone_from(&next);
                }
            }
        }

        Ok(commands)
    }

    /// Writes a Subscribe message to target.
    pub fn subscribe(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        heads: &mut PeerCache,
        remain_open: u64,
        max_bytes: u64,
    ) -> Result<usize, SyncError> {
        let commands = self.get_commands(provider, heads)?;
        let message = SyncType::Subscribe {
            remain_open,
            max_bytes,
            commands,
            storage_id: self.storage_id,
        };

        Self::write(target, message)
    }

    /// Writes an Unsubscribe message to target.
    pub fn unsubscribe(&mut self, target: &mut [u8]) -> Result<usize, SyncError> {
        let message = SyncType::Unsubscribe {
            storage_id: self.storage_id,
        };

        Self::write(target, message)
    }

    fn start(
        &mut self,
        max_bytes: u64,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        heads: &mut PeerCache,
    ) -> Result<(usize, usize), SyncError> {
        if !matches!(
            self.state,
            SyncRequesterState::Start | SyncRequesterState::New
        ) {
            self.state = SyncRequesterState::Reset;
            return Err(SyncError::SessionState);
        }

        self.state = SyncRequesterState::Start;
        self.max_bytes = max_bytes;

        let command_sample = self.get_commands(provider, heads)?;

        let sent = command_sample.len();
        let message = SyncType::Poll {
            request: SyncRequestMessage::SyncRequest {
                session_id: self.session_id,
                storage_id: self.storage_id,
                max_bytes,
                commands: command_sample,
            },
        };

        Ok((Self::write(target, message)?, sent))
    }
}
