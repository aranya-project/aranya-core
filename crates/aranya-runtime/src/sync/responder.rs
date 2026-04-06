use buggy::{BugExt as _, bug};
use heapless::Vec;
use serde::{Deserialize, Serialize};

use super::{
    COMMAND_RESPONSE_MAX, COMMAND_SAMPLE_MAX, CommandMeta, MAX_SYNC_MESSAGE_SIZE, PEER_HEAD_MAX,
    SEGMENT_BUFFER_MAX, SyncError, requester::SyncRequestMessage,
};
use crate::{
    LocatedAddress, StorageError, SyncType,
    command::{Address, CmdId, Command as _},
    storage::{
        GraphId, Location, MaxCut, Segment as _, Storage, StorageProvider, TraversalBuffer,
        TraversalBuffers,
    },
};

#[derive(Default, Debug)]
pub struct PeerCache {
    heads: Vec<LocatedAddress, { PEER_HEAD_MAX }>,
}

impl PeerCache {
    pub const fn new() -> Self {
        Self { heads: Vec::new() }
    }

    pub fn heads(&self) -> &[LocatedAddress] {
        &self.heads
    }

    pub fn add_command<S>(
        &mut self,
        storage: &S,
        new: LocatedAddress,
        buffer: &mut TraversalBuffer,
    ) -> Result<(), StorageError>
    where
        S: Storage,
    {
        let mut add_command = true;

        let mut retain_head = |old: &LocatedAddress| -> Result<bool, StorageError> {
            if old.id == new.id || storage.is_ancestor(new.location(), old.location(), buffer)? {
                // Don't add this command, keep existing command
                add_command = false;
                return Ok(true);
            }
            if storage.is_ancestor(old.location(), new.location(), buffer)? {
                // Remove existing head.
                return Ok(false);
            }
            // Just keep existing head.
            Ok(true)
        };
        self.heads.retain(|h| retain_head(h).unwrap_or(false));
        if add_command {
            // TODO(jdygert): Replace an old head when full?
            self.heads.push(new).ok();
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
}

impl Default for SyncResponder {
    fn default() -> Self {
        Self::new()
    }
}

/// Insert `loc` into a bounded vec that keeps the lowest `max_cut`
/// entries. If full, replaces the highest `max_cut` entry when the
/// new one is lower.
fn push_bounded(v: &mut Vec<Location, SEGMENT_BUFFER_MAX>, loc: Location) {
    if v.push(loc).is_err() {
        // Full — find the entry with the highest max_cut.
        let (max_idx, _) = v
            .iter()
            .enumerate()
            .max_by_key(|(_, l)| l.max_cut)
            .expect("non-empty");
        if loc.max_cut < v[max_idx].max_cut {
            v[max_idx] = loc;
        }
    }
}

impl SyncResponder {
    /// Create a new [`SyncResponder`].
    pub const fn new() -> Self {
        Self {
            session_id: None,
            graph_id: None,
            state: SyncResponderState::New,
            bytes_sent: 0,
            next_send: 0,
            message_index: 0,
            has: Vec::new(),
            to_send: Vec::new(),
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
        buffers: &mut TraversalBuffers,
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
                    if let Some(cmd_loc) = storage.get_location(*command, &mut buffers.primary)? {
                        response_cache.add_command(
                            storage,
                            LocatedAddress {
                                id: command.id,
                                segment: cmd_loc.segment,
                                max_cut: command.max_cut,
                            },
                            &mut buffers.primary,
                        )?;
                    }
                }
                self.to_send = Self::find_needed_segments(&self.has, storage, buffers)?;

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

    /// Returns segments (or partial segments) that the peer doesn't have.
    ///
    /// Uses a single backward traversal with coverage propagation to
    /// eliminate all `is_ancestor()` calls. See
    /// `aranya-docs/docs/find-needed-segments-optimization.md`.
    fn find_needed_segments(
        commands: &[Address],
        storage: &impl Storage,
        buffers: &mut TraversalBuffers,
    ) -> Result<Vec<Location, SEGMENT_BUFFER_MAX>, SyncError> {
        // Resolve command addresses to locations. Use buffers.primary as
        // scratch for each get_location call (it gets cleared before main loop).
        if commands.len() > COMMAND_SAMPLE_MAX {
            bug!(
                "commands length {} exceeds COMMAND_SAMPLE_MAX",
                commands.len()
            );
        }
        let mut have_locations: Vec<Location, COMMAND_SAMPLE_MAX> = Vec::new();
        for &addr in commands {
            if let Some(location) = storage.get_location(addr, &mut buffers.primary)? {
                let _ = have_locations.push(location);
            }
        }

        // Sort descending by max_cut so we can discard from the front as we
        // descend through the graph.
        have_locations.sort_by_key(|loc| core::cmp::Reverse(loc.max_cut));

        // Index into have_locations: everything before this has max_cut above
        // the current segment's longest_max_cut and can be skipped.
        let mut have_cursor: usize = 0;

        // heads queue: segments to process, popped by highest max_cut.
        let heads = buffers.primary.get();
        heads.push(storage.get_head()?)?;

        // pending queue: segments tentatively needed by the peer.
        let pending = buffers.secondary.get();

        // Accumulate needed segments, keeping only the SEGMENT_BUFFER_MAX
        // entries with the lowest max_cut (ancestors first). When full,
        // the highest max_cut entry is replaced if the new one is lower.
        let mut collected: Vec<Location, SEGMENT_BUFFER_MAX> = Vec::new();
        let mut prev_max_cut: Option<MaxCut> = None;

        while let Some((head, covered)) = heads.pop_covered()? {
            // Flush pending entries whose shortest_max_cut (stored as max_cut)
            // is above the just-popped entry's longest_max_cut. No future
            // have_location can reach them since we process in descending order.
            if prev_max_cut != Some(head.max_cut) {
                pending.drain_above(head.max_cut, |loc| push_bounded(&mut collected, loc))?;
                prev_max_cut = Some(head.max_cut);
            }

            let segment = storage.get_segment(head)?;

            if covered {
                // Case 1: Covered — the peer has this segment up to
                // head.max_cut. Update pending to reflect partial or full
                // coverage so we don't send what the peer already has.
                let longest = segment.longest_max_cut()?;
                pending.cover_up_to(head.segment, head.max_cut, longest)?;
                // Propagate coverage to priors so they'll be processed as
                // covered if not yet visited.
                for prior in segment.prior() {
                    heads.push_covered(prior, true)?;
                }
                // Early termination: if all remaining heads are covered, stop.
                // Every remaining path leads to segments the peer already has.
                if heads.all_covered() && !heads.is_empty() {
                    break;
                }
                continue;
            }

            // Advance have_cursor past locations with max_cut above this
            // segment's longest_max_cut — they've already been passed.
            let longest = segment.longest_max_cut()?;
            while have_locations
                .get(have_cursor)
                .is_some_and(|h| h.max_cut > longest)
            {
                have_cursor = have_cursor
                    .checked_add(1)
                    .assume("index must not overflow")?;
            }

            // Look for a have_location in this segment: same SegmentIndex
            // with max_cut within shortest_max_cut..=longest_max_cut.
            let shortest = segment.shortest_max_cut();
            let mut best_have: Option<(usize, Location)> = None;
            for scan in have_cursor..have_locations.len() {
                let hloc = have_locations[scan];
                if hloc.max_cut < shortest {
                    break; // rest are even lower, can't be in this segment
                }
                if hloc.segment == head.segment {
                    best_have = Some((scan, hloc));
                    break; // sorted in descending order, so first match is the highest max_cut
                }
            }

            if let Some((_idx, hloc)) = best_have {
                // Case 2: Contains a have_location. Push priors as
                // covered — the peer has at least part of this segment,
                // so its priors are reachable.
                for prior in segment.prior() {
                    heads.push_covered(prior, true)?;
                }

                // If the peer doesn't have the whole segment (have_location
                // is not at the segment head), add a partial entry to pending
                // starting from the command after the highest have_location.
                if hloc.max_cut < longest {
                    let next_max_cut = hloc
                        .max_cut
                        .checked_add(1)
                        .assume("command + 1 mustn't overflow")?;
                    let partial_loc = Location {
                        max_cut: next_max_cut,
                        segment: head.segment,
                    };
                    pending.push(partial_loc)?;
                }
                // else: peer has the entire segment, nothing to send.
            } else {
                // Case 3: Uncovered, no have_location. Add to pending and
                // continue traversal through priors.
                pending.push(segment.first_location())?;
                for prior in segment.prior() {
                    heads.push(prior)?;
                }
            }

            // Early termination: if all remaining heads are covered, stop.
            // Every remaining path leads to segments the peer already has.
            if heads.all_covered() && !heads.is_empty() {
                break;
            }
        }

        // Flush remaining uncovered pending segments. Covered entries
        // are discarded — the peer already has them.
        pending.drain_all(|loc| push_bounded(&mut collected, loc));

        // Sort to ensure causal order (parents before children).
        collected.sort();

        Ok(collected)
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
        buffers: &mut TraversalBuffers,
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
        self.to_send = Self::find_needed_segments(&self.has, storage, buffers)?;
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
