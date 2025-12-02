use alloc::{format, string::String, vec};
use core::mem;

use buggy::{BugExt as _, bug};
use heapless::{Deque, Vec};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::{
    COMMAND_RESPONSE_MAX, COMMAND_SAMPLE_MAX, CommandMeta, MAX_SYNC_MESSAGE_SIZE, PEER_HEAD_MAX,
    SEGMENT_BUFFER_MAX, SyncError, requester::SyncRequestMessage,
};
use crate::{
    Prior, StorageError, SyncType,
    command::{Address, CmdId, Command as _},
    storage::{GraphId, Location, Segment as _, Storage, StorageProvider},
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
        storage: &mut S,
        command: Address,
        cmd_loc: Location,
    ) -> Result<(), StorageError>
    where
        S: Storage,
    {
        let num_heads_before = self.heads.len();

        // Verify the command exists in the graph at the given location
        let segment = storage.get_segment(cmd_loc)?;

        let Some(cmd_at_loc) = segment.get_command(cmd_loc) else {
            debug!(
                "PEER_CACHE: Command {:?} not found at location {:?}, not adding to cache",
                command, cmd_loc
            );
            return Ok(());
        };
        let cmd_address = cmd_at_loc.address()?;
        if cmd_address != command {
            debug!(
                "PEER_CACHE: Command at location {:?} has address {:?}, expected {:?}, not adding to cache",
                cmd_loc, cmd_address, command
            );
            return Ok(());
        }

        // OPTIMIZATION: Early check - if this command is an ancestor of any existing head,
        // skip it immediately. Since we process commands in descending max_cut order,
        // many commands will be ancestors of already-added commands.
        //
        // Note: We can't skip just based on max_cut comparison because commands on different
        // branches might have different max_cuts without being ancestors/descendants.
        for existing_head in &self.heads {
            // Fast path: if command.max_cut > head.max_cut, it can't be an ancestor, skip the check
            if command.max_cut > existing_head.max_cut {
                continue;
            }
            // Check if this command is an ancestor of the existing head
            let head_loc = storage
                .get_location(*existing_head)?
                .assume("location must exist")?;
            let head_seg = storage.get_segment(head_loc)?;
            let is_ancestor_result = storage.is_ancestor(cmd_loc, &head_seg)?;
            info!(
                "add_command: EARLY CHECK - cmd(max_cut={}, id={:?}, loc={:?}) vs head(max_cut={}, id={:?}, loc={:?}): is_ancestor={}",
                command.max_cut,
                command.id,
                cmd_loc,
                existing_head.max_cut,
                existing_head.id,
                head_loc,
                is_ancestor_result
            );
            if is_ancestor_result {
                // This command is an ancestor of an existing head, skip it
                info!(
                    "add_command: cmd(max_cut={}, id={:?}): EARLY SKIP - ancestor of existing head (head max_cut={}, checked {} heads)",
                    command.max_cut,
                    command.id,
                    existing_head.max_cut,
                    self.heads.len()
                );
                return Ok(());
            }
        }

        let mut add_command = true;
        let mut retain_ops = 0usize;
        let mut is_ancestor_calls = 0usize;
        let mut get_segment_calls = 0usize;
        let mut get_location_calls = 0usize;
        let mut ancestors_found = 0usize;
        let mut descendants_found = 0usize;

        let mut retain_head = |request_head: &Address, new_head: Location| {
            retain_ops += 1;
            get_segment_calls += 1;
            let new_head_seg = storage.get_segment(new_head)?;
            get_location_calls += 1;
            let req_head_loc = storage
                .get_location(*request_head)?
                .assume("location must exist")?;
            get_segment_calls += 1;
            let req_head_seg = storage.get_segment(req_head_loc)?;
            if let Some(new_head_command) = new_head_seg.get_command(new_head) {
                if request_head.id == new_head_command.address()?.id {
                    add_command = false;
                }
            }
            is_ancestor_calls += 1;
            if storage.is_ancestor(new_head, &req_head_seg)? {
                add_command = false;
                ancestors_found += 1;
            }
            is_ancestor_calls += 1;
            let is_descendant = storage.is_ancestor(req_head_loc, &new_head_seg)?;
            if is_descendant {
                descendants_found += 1;
            }
            Ok::<bool, StorageError>(!is_descendant)
        };
        self.heads
            .retain(|h| retain_head(h, cmd_loc).unwrap_or(false));

        let was_added = if add_command && !self.heads.is_full() {
            self.heads
                .push(command)
                .ok()
                .assume("command locations should not be full")?;
            true
        } else {
            false
        };

        let num_heads_after = self.heads.len();

        // Log when a head is added with parent information
        if was_added {
            let parent = cmd_at_loc.parent();
            let parent_str = match &parent {
                Prior::None => String::from("None"),
                Prior::Single(addr) => {
                    format!("Single(max_cut={}, id={:?})", addr.max_cut, addr.id)
                }
                Prior::Merge(left, right) => format!(
                    "Merge(left=max_cut={}, id={:?}, right=max_cut={}, id={:?})",
                    left.max_cut, left.id, right.max_cut, right.id
                ),
            };
            let existing_heads_str: alloc::vec::Vec<String> = self
                .heads
                .iter()
                .map(|h| format!("max_cut={}, id={:?}", h.max_cut, h.id))
                .collect();
            info!(
                "add_command: HEAD ADDED - cmd(max_cut={}, id={:?}), parent={}, heads_before={}, heads_after={}, existing_heads=[{}]",
                command.max_cut,
                command.id,
                parent_str,
                num_heads_before,
                num_heads_after,
                existing_heads_str.join("; ")
            );
        }

        // Log detailed information to identify bottlenecks
        // Log all operations if there are many heads (potential bottleneck) or if command wasn't added
        if num_heads_before > 3 || !was_added || retain_ops > 0 {
            info!(
                "add_command: cmd(max_cut={}, id={:?}): heads_before={}, heads_after={}, was_added={}, retain_ops={}, is_ancestor_calls={}, get_segment_calls={}, get_location_calls={}, ancestors_found={}, descendants_found={}",
                command.max_cut,
                command.id,
                num_heads_before,
                num_heads_after,
                was_added,
                retain_ops,
                is_ancestor_calls,
                get_segment_calls,
                get_location_calls,
                ancestors_found,
                descendants_found
            );
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

#[derive(Default)]
pub struct SyncResponder<A> {
    session_id: Option<u128>,
    storage_id: Option<GraphId>,
    state: SyncResponderState,
    bytes_sent: u64,
    next_send: usize,
    message_index: usize,
    has: Vec<Address, COMMAND_SAMPLE_MAX>,
    to_send: Vec<Location, SEGMENT_BUFFER_MAX>,
    server_address: A,
}

impl<A: Serialize + Clone> SyncResponder<A> {
    /// Create a new [`SyncResponder`].
    pub fn new(server_address: A) -> Self {
        Self {
            session_id: None,
            storage_id: None,
            state: SyncResponderState::New,
            bytes_sent: 0,
            next_send: 0,
            message_index: 0,
            has: Vec::new(),
            to_send: Vec::new(),
            server_address,
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
                self.to_send = Self::find_needed_segments(&self.has, storage)?;

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
        }

        Ok(())
    }

    fn write_sync_type(target: &mut [u8], msg: SyncType<A>) -> Result<usize, SyncError> {
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
        self.to_send = Self::find_needed_segments(&self.has, storage)?;
        let (commands, command_data, next_send) = self.get_commands(provider)?;
        let mut length = 0;
        if !commands.is_empty() {
            let message = SyncType::Push {
                message: SyncResponseMessage::SyncResponse {
                    session_id: self.session_id()?,
                    response_index: self.message_index as u64,
                    commands,
                },
                storage_id: self.storage_id.assume("storage id must exist")?,
                address: self.server_address.clone(),
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
        let Some(storage_id) = self.storage_id.as_ref() else {
            self.state = SyncResponderState::Reset;
            bug!("get_next called before storage_id was set");
        };
        let storage = match provider.get_storage(*storage_id) {
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
        Ok((commands, command_data, index))
    }

    fn session_id(&self) -> Result<u128, SyncError> {
        Ok(self.session_id.assume("session id is set")?)
    }
}
