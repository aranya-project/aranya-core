use alloc::vec;

use buggy::{BugExt as _, bug};
use heapless::{Deque, Vec};
use serde::{Deserialize, Serialize};

use super::{
    COMMAND_RESPONSE_MAX, COMMAND_SAMPLE_MAX, CommandMeta, MAX_SYNC_MESSAGE_SIZE, PEER_HEAD_MAX,
    SEGMENT_BUFFER_MAX, SyncError, requester::SyncRequestMessage,
};
use crate::{
    StorageError, SyncType,
    command::{Address, CmdId, Command as _},
    storage::{
        GraphId, Location, Segment as _, Storage, StorageProvider, TraversalBuffer,
        TraversalBuffers, push_queue, push_queue_unique,
    },
};

#[derive(Default, Debug)]
pub struct PeerCache {
    heads: Vec<Address, { PEER_HEAD_MAX }>,
}

impl PeerCache {
    pub const fn new() -> Self {
        Self { heads: Vec::new() }
    }

    pub fn heads(&self) -> &[Address] {
        &self.heads
    }

    pub fn add_command<S>(
        &mut self,
        storage: &S,
        command: Address,
        cmd_loc: Location,
        buffers: &mut TraversalBuffer,
    ) -> Result<(), StorageError>
    where
        S: Storage,
    {
        let mut add_command = true;

        let mut retain_head = |request_head: &Address, new_head: Location| {
            let new_head_seg = storage.get_segment(new_head)?;
            let req_head_loc = storage
                .get_location(*request_head, buffers)?
                .assume("location must exist")?;
            let req_head_seg = storage.get_segment(req_head_loc)?;
            if request_head.id
                == new_head_seg
                    .get_command(new_head)
                    .assume("location must exist")?
                    .address()?
                    .id
            {
                add_command = false;
            }
            // If the new head is an ancestor of the request head, don't add it
            if (new_head.same_segment(req_head_loc) && new_head.max_cut <= req_head_loc.max_cut)
                || storage.is_ancestor(new_head, &req_head_seg, buffers)?
            {
                add_command = false;
            }
            Ok::<bool, StorageError>(!storage.is_ancestor(req_head_loc, &new_head_seg, buffers)?)
        };
        self.heads
            .retain(|h| retain_head(h, cmd_loc).unwrap_or(false));
        if add_command && !self.heads.is_full() {
            self.heads
                .push(command)
                .ok()
                .assume("command locations should not be full")?;
        }

        Ok(())
    }
}

// TODO: Use compile-time args. This initial definition results in this clippy warning:
// https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant.
// As the buffer consts will be compile-time variables in the future, we will be
// able to tune these buffers for smaller footprints. Right now, this enum is not
// suitable for small devices (`SyncResponse` is 14448 bytes).
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
        response_index: u64,
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
        head: CmdId,
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

#[derive(Debug, Default)]
enum SyncResponderState {
    #[default]
    New,
    Start,
    Send,
    Idle,
    Reset,
    Stopped,
}

pub struct SyncResponder {
    session_id: Option<u128>,
    graph_id: Option<GraphId>,
    state: SyncResponderState,
    bytes_sent: u64,
    next_send: usize,
    message_index: usize,
    has: Vec<Address, COMMAND_SAMPLE_MAX>,
    to_send: Vec<Location, SEGMENT_BUFFER_MAX>,
    buffers: TraversalBuffers,
}

impl SyncResponder {
    /// Create a new [`SyncResponder`].
    pub fn new(buffers: TraversalBuffers) -> Self {
        Self {
            session_id: None,
            graph_id: None,
            state: SyncResponderState::New,
            bytes_sent: 0,
            next_send: 0,
            message_index: 0,
            has: Vec::new(),
            to_send: Vec::new(),
            buffers,
        }
    }

    /// Returns true if [`Self::poll`] would produce a message.
    pub fn ready(&self) -> bool {
        use SyncResponderState::*;
        match self.state {
            Reset | Start | Send => true, // TODO(chip): For Send, check whether to_send has anything to send
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
        // TODO(chip): return a status enum instead of usize
        use SyncResponderState as S;
        let length = match self.state {
            S::New | S::Idle | S::Stopped => {
                return Err(SyncError::NotReady); // TODO(chip): return Ok(NotReady)
            }
            S::Start => {
                let Some(graph_id) = self.graph_id else {
                    self.state = S::Reset;
                    bug!("poll called before graph_id was set");
                };

                let storage = match provider.get_storage(graph_id) {
                    Ok(s) => s,
                    Err(e) => {
                        self.state = S::Reset;
                        return Err(e.into());
                    }
                };

                self.state = S::Send;
                for command in &self.has {
                    // We only need to check commands that are a part of our graph.
                    if let Some(cmd_loc) =
                        storage.get_location(*command, &mut self.buffers.primary)?
                    {
                        response_cache.add_command(
                            storage,
                            *command,
                            cmd_loc,
                            &mut self.buffers.primary,
                        )?;
                    }
                }
                self.to_send = Self::find_needed_segments(&self.has, storage, &mut self.buffers)?;

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
    pub fn receive(&mut self, message: SyncRequestMessage) -> Result<(), SyncError> {
        if self.session_id.is_none() {
            self.session_id = Some(message.session_id());
        }
        if self.session_id != Some(message.session_id()) {
            return Err(SyncError::SessionMismatch);
        }

        match message {
            SyncRequestMessage::SyncRequest {
                graph_id,
                max_bytes,
                commands,
                ..
            } => {
                self.state = SyncResponderState::Start;
                self.graph_id = Some(graph_id);
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
        }

        Ok(())
    }

    fn write_sync_type(target: &mut [u8], msg: SyncType) -> Result<usize, SyncError> {
        Ok(postcard::to_slice(&msg, target)?.len())
    }

    fn write(target: &mut [u8], msg: SyncResponseMessage) -> Result<usize, SyncError> {
        Ok(postcard::to_slice(&msg, target)?.len())
    }

    /// This (probably) returns a Vec of segment addresses where the head of each segment is
    /// not the ancestor of any samples we have been sent. If that is longer than
    /// SEGMENT_BUFFER_MAX, it contains the oldest segment heads where that holds.
    fn find_needed_segments(
        commands: &[Address],
        storage: &impl Storage,
        buffers: &mut TraversalBuffers,
    ) -> Result<Vec<Location, SEGMENT_BUFFER_MAX>, SyncError> {
        let mut have_locations = vec::Vec::new(); //BUG: not constant size
        for &addr in commands {
            // Note: We could use things we don't have as a hint to
            // know we should perform a sync request.
            if let Some(location) = storage.get_location(addr, &mut buffers.secondary)? {
                have_locations.push(location);
            }
        }

        // Filter out locations that are ancestors of other locations in the list.
        // If location A is an ancestor of location B, we only need to keep B since
        // having B implies having A and all its ancestors.
        // Iterate backwards so we can safely remove items
        for i in (0..have_locations.len()).rev() {
            let location_a = have_locations[i];
            let mut is_ancestor_of_other = false;
            for &location_b in &have_locations {
                if location_a != location_b {
                    let segment_b = storage.get_segment(location_b)?;
                    if location_a.same_segment(location_b)
                        && location_a.max_cut <= location_b.max_cut
                        || storage.is_ancestor(location_a, &segment_b, &mut buffers.secondary)?
                    {
                        is_ancestor_of_other = true;
                        break;
                    }
                }
            }
            if is_ancestor_of_other {
                have_locations.remove(i);
            }
        }

        let queue = buffers.primary.get();
        push_queue(queue, storage.get_head()?)?;

        let mut result: Deque<Location, SEGMENT_BUFFER_MAX> = Deque::new();

        while let Some(head) = queue.pop() {
            // Check if the current segment head is an ancestor of any location in have_locations.
            // If so, stop traversing backward from this point since the requester already has
            // this command and all its ancestors.
            let mut is_have_ancestor = false;
            for &have_location in &have_locations {
                let have_segment = storage.get_segment(have_location)?;
                if storage.is_ancestor(head, &have_segment, &mut buffers.secondary)? {
                    is_have_ancestor = true;
                    break;
                }
            }
            if is_have_ancestor {
                continue;
            }

            let segment = storage.get_segment(head)?;

            // If the requester has any commands in this segment, send from the next command
            if let Some(latest_loc) = have_locations
                .iter()
                .filter(|&&location| location.same_segment(head))
                .max_by_key(|&&location| location.max_cut)
            {
                let next_max_cut = latest_loc
                    .max_cut
                    .checked_add(1)
                    .assume("command + 1 mustn't overflow")?;
                let next_location = Location {
                    max_cut: next_max_cut,
                    segment: head.segment,
                };

                let head_loc = segment.head_location()?;
                if next_location.max_cut > head_loc.max_cut {
                    continue;
                }
                if result.is_full() {
                    result.pop_back();
                }
                result
                    .push_front(next_location)
                    .ok()
                    .assume("too many segments")?;
                continue;
            }

            if result.is_full() {
                result.pop_back();
            }

            for prior in segment.prior() {
                push_queue_unique(queue, prior)?;
            }

            let location = segment.first_location();
            result
                .push_front(location)
                .ok()
                .assume("too many segments")?;
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
        if self.next_send >= self.to_send.len() {
            self.state = SyncResponderState::Idle;
            let message = SyncResponseMessage::SyncEnd {
                session_id: self.session_id()?,
                max_index: self.message_index as u64,
                remaining: false,
            };
            let length = Self::write(target, message)?;
            return Ok(length);
        }

        let (commands, command_data, next_send) = self.get_commands(provider)?;

        let message = SyncResponseMessage::SyncResponse {
            session_id: self.session_id()?,
            response_index: self.message_index as u64,
            commands,
        };
        self.message_index = self
            .message_index
            .checked_add(1)
            .assume("message_index overflow")?;
        self.next_send = next_send;

        let length = Self::write(target, message)?;
        let total_length = length
            .checked_add(command_data.len())
            .assume("length + command_data_length mustn't overflow")?;
        target
            .get_mut(length..total_length)
            .assume("sync message fits in target")?
            .copy_from_slice(&command_data);
        Ok(total_length)
    }

    /// Writes a sync push message to target for the peer. The message will
    /// contain any commands that are after the commands in response_cache.
    pub fn push(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<usize, SyncError> {
        use SyncResponderState as S;
        let Some(graph_id) = self.graph_id else {
            self.state = S::Reset;
            bug!("poll called before graph_id was set");
        };

        let storage = match provider.get_storage(graph_id) {
            Ok(s) => s,
            Err(e) => {
                self.state = S::Reset;
                return Err(e.into());
            }
        };
        self.to_send = Self::find_needed_segments(&self.has, storage, &mut self.buffers)?;
        let (commands, command_data, next_send) = self.get_commands(provider)?;
        let mut length = 0;
        if !commands.is_empty() {
            let message = SyncType::Push {
                message: SyncResponseMessage::SyncResponse {
                    session_id: self.session_id()?,
                    response_index: self.message_index as u64,
                    commands,
                },
                graph_id: self.graph_id.assume("graph id must exist")?,
            };
            self.message_index = self
                .message_index
                .checked_add(1)
                .assume("message_index increment overflow")?;
            self.next_send = next_send;

            length = Self::write_sync_type(target, message)?;
            let total_length = length
                .checked_add(command_data.len())
                .assume("length + command_data_length mustn't overflow")?;
            target
                .get_mut(length..total_length)
                .assume("sync message fits in target")?
                .copy_from_slice(&command_data);
            length = total_length;
        }
        Ok(length)
    }

    fn get_commands(
        &mut self,
        provider: &mut impl StorageProvider,
    ) -> Result<
        (
            Vec<CommandMeta, COMMAND_RESPONSE_MAX>,
            Vec<u8, MAX_SYNC_MESSAGE_SIZE>,
            usize,
        ),
        SyncError,
    > {
        let Some(graph_id) = self.graph_id.as_ref() else {
            self.state = SyncResponderState::Reset;
            bug!("get_next called before graph_id was set");
        };
        let storage = match provider.get_storage(*graph_id) {
            Ok(s) => s,
            Err(e) => {
                self.state = SyncResponderState::Reset;
                return Err(e.into());
            }
        };
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

            let segment = storage
                .get_segment(location)
                .inspect_err(|_| self.state = SyncResponderState::Reset)?;

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

                let max_cut = command.max_cut()?;
                let meta = CommandMeta {
                    id: command.id(),
                    priority: command.priority(),
                    parent: command.parent(),
                    policy_length: policy_length as u32,
                    length: bytes.len() as u32,
                    max_cut,
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
        Ok((commands, command_data, index))
    }

    fn session_id(&self) -> Result<u128, SyncError> {
        Ok(self.session_id.assume("session id is set")?)
    }
}
