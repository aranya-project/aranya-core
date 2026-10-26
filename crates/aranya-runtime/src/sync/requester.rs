use alloc::vec;

use aranya_crypto::Csprng;
use buggy::BugExt as _;
use heapless::Vec;
use serde::{Deserialize, Serialize};

use super::{
    COMMAND_SAMPLE_MAX, PeerCache, PushIncoming, REQUEST_MISSING_MAX, SessionHeads, SyncCommand,
    SyncError, SyncReply, responder::SyncResponseMessage, sample, wire::SyncType,
};
use crate::{
    Address, GraphId, LocatedAddress,
    storage::{Storage as _, StorageError, StorageProvider},
};

// TODO: Use compile-time args. This initial definition results in this clippy warning:
// https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant.
// As the buffer consts will be compile-time variables in the future, we will be
// able to tune these buffers for smaller footprints. Right now, this enum is not
// suitable for small devices (`SyncRequest` is 4080 bytes).
/// Messages sent from the requester to the responder.
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SyncRequestMessage {
    /// Initiate a new Sync
    SyncRequest {
        /// A new random value produced by a cryptographically secure RNG.
        session_id: u128,
        /// Specifies the graph to be synced.
        graph_id: GraphId,
        /// Specifies the maximum number of bytes worth of commands that
        /// the requester wishes to receive.
        max_bytes: u64,
        /// Sample of the commands held by the requester. The responder should
        /// respond with any commands that the requester may not have based on
        /// the provided sample. When sending commands ancestors must be sent
        /// before descendents.
        commands: Vec<Address, COMMAND_SAMPLE_MAX>,
        /// How many of the first `commands` are session heads: commands
        /// the requester has received but not committed. The responder
        /// treats them as held for this request but does not cache them.
        session_heads: u8,
        /// Asks the responder to forget what it knows the requester holds
        /// before resolving `commands`, because that knowledge may be wrong.
        reset: bool,
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
    pub(crate) fn session_id(&self) -> u128 {
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
    graph_id: GraphId,
    state: SyncRequesterState,
    max_bytes: u64,
    next_message_index: u64,
}

impl SyncRequester {
    /// Create a new [`SyncRequester`] with a random session ID.
    pub fn new<R: Csprng>(graph_id: GraphId, rng: R) -> Self {
        // Randomly generate session id.
        let mut dst = [0u8; 16];
        rng.fill_bytes(&mut dst);
        let session_id = u128::from_le_bytes(dst);

        Self {
            session_id,
            graph_id,
            state: SyncRequesterState::New,
            max_bytes: 0,
            next_message_index: 0,
        }
    }

    /// Create a new [`SyncRequester`] for an existing session.
    pub fn new_session_id(graph_id: GraphId, session_id: u128) -> Self {
        Self {
            session_id,
            graph_id,
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
    ///
    /// `heads` is the frontier to advertise: [`PeerCache::session_heads`]
    /// when no transaction is open, or `Transaction::session_heads` to also
    /// advertise an open transaction's uncommitted frontier so progressive
    /// fetch advances across exchanges before commit.
    ///
    /// [`PeerCache::session_heads`]: super::PeerCache::session_heads
    pub fn poll(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        heads: SessionHeads<'_>,
        rng: &impl Csprng,
    ) -> Result<(usize, usize), SyncError> {
        use SyncRequesterState as S;
        let result = match self.state {
            S::Start | S::Waiting | S::Idle | S::Closed | S::PartialSync => {
                return Err(SyncError::NotReady);
            }
            S::New => {
                self.state = S::Start;
                self.start(self.max_bytes, target, provider, heads, rng)?
            }
            S::Resync => self.resume(self.max_bytes, target)?,
            S::Reset => {
                self.state = S::Closed;
                self.end_session(target)?
            }
        };

        Ok(result)
    }

    /// Receive a sync message. Returns the parsed reply, if it carried one.
    ///
    /// `cache` is this side's peer cache for the responder. A reply to our
    /// request means the responder received any reset it asked for.
    pub fn receive<'data>(
        &mut self,
        data: &'data [u8],
        cache: &mut PeerCache,
    ) -> Result<Option<SyncReply<'data>>, SyncError> {
        let (message, remaining): (SyncResponseMessage, &'data [u8]) =
            postcard::take_from_bytes(data)?;

        let replied = matches!(
            message,
            SyncResponseMessage::SyncResponse { .. } | SyncResponseMessage::SyncEnd { .. }
        );
        let reply = self.get_sync_commands(message, remaining)?;
        if replied {
            cache.reply_received();
        }
        Ok(reply)
    }

    /// Apply a push received via [`SyncIncoming::Push`](super::SyncIncoming::Push).
    /// Returns the parsed reply, borrowing from the original push payload.
    pub fn receive_push<'data>(
        &mut self,
        push: PushIncoming<'data>,
    ) -> Result<Option<SyncReply<'data>>, SyncError> {
        self.get_sync_commands(push.message, push.command_data)
    }

    /// Extract a SyncReply from a SyncResponseMessage and remaining bytes.
    fn get_sync_commands<'data>(
        &mut self,
        message: SyncResponseMessage,
        remaining: &'data [u8],
    ) -> Result<Option<SyncReply<'data>>, SyncError> {
        if message.session_id() != self.session_id {
            return Err(SyncError::SessionMismatch);
        }

        let result = match message {
            SyncResponseMessage::SyncResponse {
                response_index,
                commands,
                sample,
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
                                .ok_or(SyncError::MalformedResponse)?;
                            let policy = remaining
                                .get(start..end)
                                .ok_or(SyncError::MalformedResponse)?;
                            start = end;
                            Some(policy)
                        }
                    };

                    let len = meta.length as usize;
                    let end = start.checked_add(len).ok_or(SyncError::MalformedResponse)?;
                    let payload = remaining
                        .get(start..end)
                        .ok_or(SyncError::MalformedResponse)?;
                    start = end;

                    let command = SyncCommand {
                        id: meta.id,
                        parent: meta.parent,
                        policy,
                        data: payload,
                    };

                    result
                        .push(command)
                        .ok()
                        .assume("commands is not larger than result")?;
                }

                Some(SyncReply {
                    commands: result,
                    sample,
                })
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

        // `SyncResume` identifies the last response received; if no response
        // has ever been received, the session cannot be resumed.
        let Some(response_index) = self.next_message_index.checked_sub(1) else {
            self.state = SyncRequesterState::Reset;
            return Err(SyncError::MissingSyncResponse);
        };

        self.state = SyncRequesterState::Waiting;
        let message = SyncType::Poll {
            request: SyncRequestMessage::SyncResume {
                session_id: self.session_id,
                response_index,
                max_bytes,
            },
        };

        Ok((Self::write(target, message)?, 0))
    }

    /// Builds the request's sample: the session heads, peer cache heads and
    /// our graph heads, then random commands spread across the graph.
    /// Returns the sample and how many of its first entries are session
    /// heads.
    fn get_commands(
        &mut self,
        provider: &mut impl StorageProvider,
        heads: &SessionHeads<'_>,
        rng: &impl Csprng,
    ) -> Result<(Vec<Address, COMMAND_SAMPLE_MAX>, u8), SyncError> {
        let storage = match provider.get_storage(self.graph_id) {
            Err(StorageError::NoSuchStorage) => return Ok((Vec::new(), 0)),
            Err(err) => return Err(SyncError::Storage(err)),
            Ok(storage) => storage,
        };

        // The transaction's heads include the committed heads it started
        // from. Only the others are uncommitted.
        let committed = storage.get_heads()?;
        let session_heads: vec::Vec<Address> = heads
            .session_iter()
            .filter(|h| !committed.iter().any(|c| c.id == h.id))
            .map(LocatedAddress::address)
            .collect();
        let cache_heads: vec::Vec<Address> =
            heads.cache.heads().iter().map(|h| h.address()).collect();
        let graph_heads: vec::Vec<Address> = committed
            .iter()
            .map(LocatedAddress::address)
            .filter(|a| !cache_heads.contains(a))
            .collect();

        let floor = sample::floor(&*storage, heads.cache.heads())?;
        let sample = sample::build(
            &*storage,
            &[&session_heads, &cache_heads, &graph_heads],
            floor,
            rng,
            |_| false,
        )?;
        // `build` adds the session heads first.
        let sent_session_heads = sample
            .iter()
            .take_while(|a| session_heads.contains(a))
            .count();
        let sent_session_heads =
            u8::try_from(sent_session_heads).assume("session heads fit in a u8")?;
        Ok((sample, sent_session_heads))
    }

    /// Writes a Subscribe message to target.
    ///
    /// The peer caches every command in a subscribe's sample, so it carries
    /// no session heads.
    pub fn subscribe(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        cache: &PeerCache,
        rng: &impl Csprng,
        remain_open: u64,
        max_bytes: u64,
    ) -> Result<usize, SyncError> {
        let (commands, _) = self.get_commands(provider, &cache.session_heads(), rng)?;
        let message = SyncType::Subscribe {
            remain_open,
            max_bytes,
            commands,
            graph_id: self.graph_id,
        };

        Self::write(target, message)
    }

    /// Writes an Unsubscribe message to target.
    pub fn unsubscribe(&mut self, target: &mut [u8]) -> Result<usize, SyncError> {
        let message = SyncType::Unsubscribe {
            graph_id: self.graph_id,
        };

        Self::write(target, message)
    }

    fn start(
        &mut self,
        max_bytes: u64,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        heads: SessionHeads<'_>,
        rng: &impl Csprng,
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

        let reset = heads.cache.needs_reset();
        let (command_sample, session_heads) = self.get_commands(provider, &heads, rng)?;

        let sent = command_sample.len();
        let message = SyncType::Poll {
            request: SyncRequestMessage::SyncRequest {
                session_id: self.session_id,
                graph_id: self.graph_id,
                max_bytes,
                commands: command_sample,
                session_heads,
                reset,
            },
        };

        Ok((Self::write(target, message)?, sent))
    }
}
