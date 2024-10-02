use alloc::vec;
use core::mem;

use buggy::{bug, BugExt};
use heapless::{Deque, Vec};
use serde::{Deserialize, Serialize};

use super::{
    requester::SyncRequestMessage, CommandMeta, SyncError, COMMAND_RESPONSE_MAX,
    COMMAND_SAMPLE_MAX, MAX_SYNC_MESSAGE_SIZE, PEER_HEAD_MAX, SEGMENT_BUFFER_MAX,
};
use crate::{
    command::{Address, Command, CommandId},
    storage::{GraphId, Location, Segment, Storage, StorageProvider},
    StorageError,
};

#[derive(Default, Debug)]
pub struct PeerCache {
    heads: Vec<Address, { PEER_HEAD_MAX }>,
}

impl PeerCache {
    pub fn new() -> Self {
        PeerCache { heads: Vec::new() }
    }

    pub fn heads(&self) -> &[Address] {
        &self.heads
    }

    pub fn add_command<S>(
        &mut self,
        storage: &mut S,
        command: Address,
        cmd_loc: Location,
    ) -> Result<(), StorageError>
    where
        S: Storage,
    {
        let mut add_command = true;
        let mut retain_head = |request_head: &Address, new_head: Location| {
            let new_head_seg = storage.get_segment(new_head)?;
            let req_head_loc = storage
                .get_location(*request_head)?
                .assume("location must exist")?;
            let req_head_seg = storage.get_segment(req_head_loc)?;
            if let Some(new_head_command) = new_head_seg.get_command(new_head) {
                if request_head.id == new_head_command.address()?.id {
                    add_command = false;
                }
            }
            if storage.is_ancestor(new_head, &req_head_seg)? {
                add_command = false;
            }
            Ok::<bool, StorageError>(!storage.is_ancestor(req_head_loc, &new_head_seg)?)
        };
        self.heads
            .retain(|h| retain_head(h, cmd_loc).unwrap_or(false));
        if add_command && !self.heads.is_full() {
            self.heads
                .push(command)
                .ok()
                .assume("command locations should not be full")?;
        };
        Ok(())
    }
}

// TODO: Use compile-time args. This initial definition results in this clippy warning:
// https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant.
// As the buffer consts will be compile-time variables in the future, we will be
// able to tune these buffers for smaller footprints. Right now, this enum is not
// suitable for small devices (`SyncResponse` is 14848 bytes).
/// Messages sent from the responder to the requester.
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SyncResponseMessage {
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

    /// Message sent by a responder after a sync has been completed, but before
    /// the session has ended, if it has new commands in it's graph. If a
    /// requester wishes to respond to this message, it should do so with a
    /// new `SyncRequest`. This message may use the existing `session_id`.
    Offer {
        /// A random-value produced by a cryptographically secure RNG
        /// corresponding to the `session_id` in the initial `SyncRequest`.
        session_id: u128,
        /// Head of the branch the responder wishes to send.
        head: CommandId,
    },

    /// Message sent by either requester or responder to indicate the session
    /// has been terminated or the `session_id` is no longer valid.
    EndSession { session_id: u128 },
}

impl SyncResponseMessage {
    pub fn session_id(&self) -> u128 {
        match self {
            Self::SyncResponse { session_id, .. } => *session_id,
            Self::SyncEnd { session_id, .. } => *session_id,
            Self::Offer { session_id, .. } => *session_id,
            Self::EndSession { session_id, .. } => *session_id,
        }
    }
}

#[derive(Debug)]
enum SyncResponderState {
    New,
    Start,
    Send,
    Idle,
    Reset,
    Stopped,
}

impl Default for SyncResponderState {
    fn default() -> Self {
        Self::New
    }
}

#[derive(Default)]
pub struct SyncResponder {
    session_id: Option<u128>,
    storage_id: Option<GraphId>,
    state: SyncResponderState,
    bytes_sent: u64,
    next_send: usize,
    has: Vec<Address, COMMAND_SAMPLE_MAX>,
    to_send: Vec<Location, SEGMENT_BUFFER_MAX>,
}

impl SyncResponder {
    /// Create a new [`SyncResponder`].
    pub fn new() -> Self {
        SyncResponder {
            session_id: None,
            storage_id: None,
            state: SyncResponderState::New,
            bytes_sent: 0,
            next_send: 0,
            has: Vec::new(),
            to_send: Vec::new(),
        }
    }

    /// Returns true if [`Self::poll`] would produce a message.
    pub fn ready(&self) -> bool {
        use SyncResponderState::*;
        match self.state {
            Reset | Start | Send => true,
            New | Idle | Stopped => false,
        }
    }

    /// Write a sync message in to the target buffer. Returns the number
    /// of bytes written.
    pub fn poll(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        response_cache: &mut PeerCache,
    ) -> Result<usize, SyncError> {
        use SyncResponderState as S;
        let length = match self.state {
            S::New | S::Idle | S::Stopped => {
                return Err(SyncError::NotReady);
            }
            S::Start => {
                let Some(storage_id) = self.storage_id else {
                    self.state = S::Reset;
                    bug!("poll called before storage_id was set");
                };

                let storage = match provider.get_storage(storage_id) {
                    Ok(s) => s,
                    Err(e) => {
                        self.state = S::Reset;
                        return Err(e.into());
                    }
                };

                self.state = S::Send;
                for command in &self.has {
                    // We only need to check commands that are a part of our graph.
                    if let Some(cmd_loc) = storage.get_location(*command)? {
                        response_cache.add_command(storage, *command, cmd_loc)?;
                    }
                }
                self.to_send = SyncResponder::find_needed_segments(&self.has, storage)?;

                self.get_next(target, provider)?
            }
            S::Send => self.get_next(target, provider)?,
            S::Reset => {
                self.state = S::Stopped;
                let message = SyncResponseMessage::EndSession {
                    session_id: self.session_id()?,
                };
                Self::write(target, message)?
            }
        };

        Ok(length)
    }

    /// Receive a sync message. Updates the responders state for later polling.
    pub fn receive(&mut self, data: &[u8]) -> Result<(), SyncError> {
        let message: SyncRequestMessage = postcard::from_bytes(data)?;
        if self.session_id.is_none() {
            self.session_id = Some(message.session_id());
        }
        if self.session_id != Some(message.session_id()) {
            return Err(SyncError::SessionMismatch);
        }

        match message {
            SyncRequestMessage::SyncRequest {
                storage_id,
                max_bytes,
                commands,
                ..
            } => {
                self.state = SyncResponderState::Start;
                self.storage_id = Some(storage_id);
                self.bytes_sent = max_bytes;
                self.to_send = Vec::new();
                self.has = commands;
                self.next_send = 0;
                return Ok(());
            }
            SyncRequestMessage::RequestMissing { .. } => {
                todo!()
            }
            SyncRequestMessage::SyncResume { .. } => {
                todo!()
            }
            SyncRequestMessage::EndSession { .. } => {
                self.state = SyncResponderState::Stopped;
            }
        };

        Ok(())
    }

    fn write(target: &mut [u8], msg: SyncResponseMessage) -> Result<usize, SyncError> {
        Ok(postcard::to_slice(&msg, target)?.len())
    }

    fn find_needed_segments(
        commands: &[Address],
        storage: &impl Storage,
    ) -> Result<Vec<Location, SEGMENT_BUFFER_MAX>, SyncError> {
        let mut have_locations = vec::Vec::new(); //BUG: not constant size
        for &addr in commands {
            let Some(location) = storage.get_location(addr)? else {
                // Note: We could use things we don't
                // have as a hint to know we should
                // perform a sync request.
                continue;
            };

            have_locations.push(location);
        }

        let mut heads = vec::Vec::new();
        heads.push(storage.get_head()?);

        let mut result: Deque<Location, SEGMENT_BUFFER_MAX> = Deque::new();

        while !heads.is_empty() {
            let current = mem::take(&mut heads);
            'heads: for head in current {
                let segment = storage.get_segment(head)?;
                if segment.contains_any(&result) {
                    continue 'heads;
                }

                for &location in &have_locations {
                    if segment.contains(location) {
                        if location != segment.head_location() {
                            if result.is_full() {
                                result.pop_back();
                            }
                            result
                                .push_front(location)
                                .ok()
                                .assume("too many segments")?;
                        }
                        continue 'heads;
                    }
                }
                heads.extend(segment.prior());

                if result.is_full() {
                    result.pop_back();
                }

                let location = segment.first_location();
                result
                    .push_front(location)
                    .ok()
                    .assume("too many segments")?;
            }
        }
        let mut r: Vec<Location, SEGMENT_BUFFER_MAX> = Vec::new();
        for l in result {
            r.push(l).ok().assume("too many segments")?;
        }
        // Order segments to ensure that a segment isn't received before its
        // ancestor segments.
        r.sort();
        Ok(r)
    }

    fn get_next(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<usize, SyncError> {
        let Some(storage_id) = self.storage_id else {
            self.state = SyncResponderState::Reset;
            bug!("get_next called before storage_id was set");
        };

        let storage = match provider.get_storage(storage_id) {
            Ok(s) => s,
            Err(e) => {
                self.state = SyncResponderState::Reset;
                return Err(e.into());
            }
        };

        if self.next_send >= self.to_send.len() {
            self.state = SyncResponderState::Idle;
            return Ok(0);
        }

        let mut commands: Vec<CommandMeta, COMMAND_RESPONSE_MAX> = Vec::new();
        let mut command_data: Vec<u8, MAX_SYNC_MESSAGE_SIZE> = Vec::new();
        let mut index = self.next_send;

        for i in self.next_send..self.to_send.len() {
            if commands.is_full() {
                break;
            }
            index = index.checked_add(1).assume("index + 1 mustn't overflow")?;
            let Some(&location) = self.to_send.get(i) else {
                self.state = SyncResponderState::Reset;
                bug!("send index OOB");
            };

            let Ok(segment) = storage.get_segment(location) else {
                self.state = SyncResponderState::Reset;
                return Err(SyncError::StorageError);
            };

            let found = segment.get_from(location);

            for command in &found {
                let mut policy_length = 0;

                if let Some(policy) = command.policy() {
                    policy_length = policy.len();
                    command_data
                        .extend_from_slice(policy)
                        .ok()
                        .assume("command_data is too large")?;
                }

                let bytes = command.bytes();
                command_data
                    .extend_from_slice(bytes)
                    .ok()
                    .assume("command_data is too large")?;

                let meta = CommandMeta {
                    id: command.id(),
                    priority: command.priority(),
                    parent: command.parent(),
                    policy_length: policy_length as u32,
                    length: bytes.len() as u32,
                    max_cut: command.max_cut()?,
                };

                // FIXME(jdygert): Handle segments with more than COMMAND_RESPONSE_MAX commands.
                commands
                    .push(meta)
                    .ok()
                    .assume("too many commands in segment")?;
                if commands.is_full() {
                    break;
                }
            }
        }

        let message = SyncResponseMessage::SyncResponse {
            session_id: self.session_id()?,
            index: self.next_send as u64,
            commands,
        };

        self.next_send = index;

        let mut length = Self::write(target, message)?;
        let total_length = length
            .checked_add(command_data.len())
            .assume("length + command_data_length mustn't overflow")?;
        target
            .get_mut(length..total_length)
            .assume("sync message fits in target")?
            .copy_from_slice(&command_data);
        length = total_length;
        Ok(length)
    }

    fn session_id(&self) -> Result<u128, SyncError> {
        Ok(self.session_id.assume("session id is set")?)
    }
}
