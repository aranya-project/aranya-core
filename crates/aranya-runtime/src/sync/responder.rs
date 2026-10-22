use alloc::vec;

use aranya_crypto::Csprng;
use buggy::{BugExt as _, bug};
use heapless::Vec;
use serde::{Deserialize, Serialize};

use super::{
    COMMAND_RESPONSE_MAX, COMMAND_SAMPLE_MAX, MAX_SYNC_MESSAGE_SIZE, PollIncoming,
    SEGMENT_BUFFER_MAX, SyncError,
    requester::SyncRequestMessage,
    sample::{self, skip_jump},
    wire::{
        ADDRESS_SERIALIZED_UPPER_BOUND, COMMAND_META_SERIALIZED_UPPER_BOUND, CommandMeta, SyncType,
    },
};
use crate::{
    LocatedAddress, StorageError,
    command::{Address, CmdId, Command},
    storage::{
        GraphId, Location, MaxCut, Segment as _, Storage, StorageProvider, TraversalBuffer,
        TraversalBuffers,
    },
};

/// The maximum number of heads that will be stored for a peer.
const PEER_HEAD_MAX: usize = 100;

/// The committed commands a peer is known to hold, kept as the heads of
/// that set: no head is an ancestor of another.
#[derive(Default, Debug)]
pub struct PeerCache {
    heads: Vec<LocatedAddress, PEER_HEAD_MAX>,
    /// Session heads were sent to the peer in a transaction that has not
    /// committed.
    sent_session_heads: bool,
    /// A reply from the peer had a command whose parent we lack.
    missing_parent: bool,
}

impl PeerCache {
    pub const fn new() -> Self {
        Self {
            heads: Vec::new(),
            sent_session_heads: false,
            missing_parent: false,
        }
    }

    pub fn heads(&self) -> &[LocatedAddress] {
        &self.heads
    }

    /// Record that a reply from the peer failed with
    /// [`ClientError::NoSuchParent`](crate::ClientError::NoSuchParent). The
    /// peer's picture of what we hold is wrong, so the next request asks it
    /// to reset.
    pub fn saw_missing_parent(&mut self) {
        self.missing_parent = true;
    }

    /// Record that a request carried session heads.
    pub(super) fn sent_session_heads(&mut self) {
        self.sent_session_heads = true;
    }

    /// Record that a reply from the peer arrived and its commands, if any,
    /// were committed. This clears the conditions that make the next request
    /// ask the peer to reset. [`ClientState::update_heads`] calls this, so
    /// call it directly only for a reply with no commands. Do not call it
    /// while a transaction that sent session heads is still open.
    ///
    /// [`ClientState::update_heads`]: crate::ClientState::update_heads
    pub fn reply_committed(&mut self) {
        self.sent_session_heads = false;
        self.missing_parent = false;
    }

    /// Whether the next request should ask the peer to reset its cache for
    /// us. `in_session` is whether the request is sent within a transaction
    /// that has received commands.
    pub(super) fn needs_reset(&self, in_session: bool) -> bool {
        self.heads.is_empty() || self.missing_parent || (self.sent_session_heads && !in_session)
    }

    /// Forget every head, after the peer asks us to reset.
    pub(super) fn clear(&mut self) {
        self.heads.clear();
    }

    /// Record that the peer holds `addr`. The location is derived here from
    /// committed storage (`get_location` traverses from committed heads
    /// only), so a command that is not committed on this node is silently
    /// ignored and can never enter the cache. When the cache is full, a
    /// random head is evicted.
    pub fn add_command<S>(
        &mut self,
        storage: &S,
        addr: Address,
        buffer: &mut TraversalBuffer,
        rng: &impl Csprng,
    ) -> Result<(), StorageError>
    where
        S: Storage,
    {
        let Some(loc) = storage.get_location(addr, buffer)? else {
            return Ok(());
        };
        let new = LocatedAddress {
            id: addr.id,
            segment: loc.segment,
            max_cut: addr.max_cut,
        };

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
            if self.heads.is_full() {
                let evict = sample::random_index(rng, self.heads.len())?;
                self.heads.swap_remove(evict);
            }
            self.heads.push(new).ok().assume("cache has room")?;
        }

        Ok(())
    }
}

/// An upper bound on the size of serialized [`SyncResponseMessage::SyncResponse`].
const SYNC_RESPONSE_SERIALIZED_UPPER_BOUND: usize = {
    let tag = 1;
    let session_id = size_of::<u128>() + 1; // varint
    let response_index = size_of::<u64>() + 1; // varint
    let command_length = COMMAND_RESPONSE_MAX.ilog2().div_ceil(8) as usize + 1; // varint
    let commands = command_length + COMMAND_RESPONSE_MAX * COMMAND_META_SERIALIZED_UPPER_BOUND; // sizeof(n) + n * sizeof(meta)
    let sample_length = COMMAND_SAMPLE_MAX.ilog2().div_ceil(8) as usize + 1; // varint
    let sample = sample_length + COMMAND_SAMPLE_MAX * ADDRESS_SERIALIZED_UPPER_BOUND;
    tag + session_id + response_index + commands + sample
};

// TODO: Use compile-time args. This initial definition results in this clippy warning:
// https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant.
// As the buffer consts will be compile-time variables in the future, we will be
// able to tune these buffers for smaller footprints. Right now, this enum is not
// suitable for small devices (`SyncResponse` is 14448 bytes).
/// Messages sent from the responder to the requester.
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SyncResponseMessage {
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
        /// A sample of the responder's graph, sent when the commands the
        /// requester lacks do not fit in this reply. Empty otherwise.
        sample: Vec<Address, COMMAND_SAMPLE_MAX>,
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
    pub(crate) fn session_id(&self) -> u128 {
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
    /// Whether the requester asked us to forget what we know it holds.
    reset: bool,
    to_send: Vec<Location, SEGMENT_BUFFER_MAX>,
    /// Whether `to_send` was cut short by `SEGMENT_BUFFER_MAX`.
    truncated: bool,
    /// Whether the next reply may carry a sample. Only the first reply to a
    /// request does.
    send_sample: bool,
}

impl Default for SyncResponder {
    fn default() -> Self {
        Self::new()
    }
}

/// Insert `loc` into a bounded vec that keeps the lowest `max_cut`
/// entries. If full, replaces the highest `max_cut` entry when the
/// new one is lower, and sets `truncated`.
fn push_bounded(v: &mut Vec<Location, SEGMENT_BUFFER_MAX>, loc: Location, truncated: &mut bool) {
    if v.push(loc).is_err() {
        *truncated = true;
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
            reset: false,
            to_send: Vec::new(),
            truncated: false,
            send_sample: false,
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
    ///
    /// `response_cache` holds the commands the requester is known to have.
    /// It is cleared first if the request asks for a reset. The request's
    /// sample is added to it, and everything it covers is treated as held by
    /// the requester.
    pub fn poll(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        response_cache: &mut PeerCache,
        buffers: &mut TraversalBuffers,
        rng: &impl Csprng,
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
                if self.reset {
                    response_cache.clear();
                }
                for command in &self.has {
                    // Commands not in our graph are ignored by the cache.
                    response_cache.add_command(storage, *command, &mut buffers.primary, rng)?;
                }
                // The cache now covers every resolved sample command.
                let have = response_cache
                    .heads()
                    .iter()
                    .map(|h| h.location())
                    .collect();
                (self.to_send, self.truncated) =
                    Self::find_needed_segments(have, storage, buffers)?;
                self.send_sample = true;

                self.get_next(target, provider, response_cache, rng)?
            }
            S::Send => self.get_next(target, provider, response_cache, rng)?,
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

    /// Receive a sync poll. Updates the responder's state for later polling.
    pub fn receive(&mut self, poll: PollIncoming) -> Result<(), SyncError> {
        self.dispatch(poll.message)
    }

    /// Begin a new session in-process, without going through the wire.
    ///
    /// Used by transports that need to push out an unsolicited update to a
    /// subscribed peer: instead of round-tripping a `SyncRequest` through the
    /// network, the transport seeds the responder directly with the heads it
    /// already knows about.
    pub fn start_session(
        &mut self,
        session_id: u128,
        graph_id: GraphId,
        max_bytes: u64,
        heads: impl IntoIterator<Item = Address>,
    ) -> Result<(), SyncError> {
        let mut commands: Vec<Address, COMMAND_SAMPLE_MAX> = Vec::new();
        heads
            .into_iter()
            .try_for_each(|head| commands.push(head).ok())
            .ok_or(SyncError::CommandOverflow)?;
        self.dispatch(SyncRequestMessage::SyncRequest {
            session_id,
            graph_id,
            max_bytes,
            commands,
            reset: false,
        })
    }

    fn dispatch(&mut self, message: SyncRequestMessage) -> Result<(), SyncError> {
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
                reset,
                ..
            } => {
                self.state = SyncResponderState::Start;
                self.graph_id = Some(graph_id);
                self.bytes_sent = max_bytes;
                self.to_send = Vec::new();
                self.has = commands;
                self.reset = reset;
                self.next_send = 0;
                return Ok(());
            }
            // Neither of these is implemented yet, and a peer can send either
            // at any point in a session. Reset the session and report the
            // error.
            SyncRequestMessage::RequestMissing { .. } | SyncRequestMessage::SyncResume { .. } => {
                self.state = SyncResponderState::Reset;
                return Err(SyncError::UnsupportedRequest);
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

    /// Returns segments (or partial segments) that the peer doesn't have,
    /// given the locations of commands it holds, and whether the result was
    /// cut short by `SEGMENT_BUFFER_MAX`.
    ///
    /// Uses a single backward traversal with coverage propagation to
    /// eliminate all `is_ancestor()` calls. See
    /// `aranya-docs/docs/find-needed-segments-optimization.md`.
    fn find_needed_segments(
        mut have_locations: vec::Vec<Location>,
        storage: &impl Storage,
        buffers: &mut TraversalBuffers,
    ) -> Result<(Vec<Location, SEGMENT_BUFFER_MAX>, bool), SyncError> {
        // Sort descending by max_cut so we can discard from the front as we
        // descend through the graph.
        have_locations.sort_by_key(|loc| core::cmp::Reverse(loc.max_cut));

        // Index into have_locations: everything before this has max_cut above
        // the current segment's longest_max_cut and can be skipped.
        let mut have_cursor: usize = 0;

        // heads queue: segments to process, popped by highest max_cut.
        let heads = buffers.primary.get();

        // Jump from each head toward highest_have + SEGMENT_BUFFER_MAX before
        // starting the main traversal, so per-round cost is O(log n) instead
        // of O(n). The graph may be multi-head (lazy merges), so seed the
        // traversal from every head.
        let highest_have = have_locations
            .first()
            .map(|l| l.max_cut)
            .unwrap_or(MaxCut::new(0));
        let skip_target = highest_have
            .checked_add(SEGMENT_BUFFER_MAX as u64)
            .assume("skip target overflow")?;
        // A jump skips uncovered segments above the target, so the result is
        // cut short.
        let mut truncated = false;
        for head in storage.get_heads()?.iter() {
            let start = if head.max_cut <= skip_target {
                head.location()
            } else {
                truncated = true;
                skip_jump(storage, head.location(), skip_target, |_, _| Ok(None))?
            };
            heads.push(start)?;
        }

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
                pending.drain_above(head.max_cut, |loc| {
                    push_bounded(&mut collected, loc, &mut truncated);
                })?;
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
            for (scan, &hloc) in have_locations.iter().enumerate().skip(have_cursor) {
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
        pending.drain_all(|loc| push_bounded(&mut collected, loc, &mut truncated));

        // Sort to ensure causal order (parents before children).
        collected.sort();

        Ok((collected, truncated))
    }

    fn get_next(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        response_cache: &PeerCache,
        rng: &impl Csprng,
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

        // When the requester lacks more than fits in this reply, sample our
        // graph so it can tell us what it holds that its own sample missed.
        let mut sample = Vec::new();
        if core::mem::take(&mut self.send_sample)
            && (next_send < self.to_send.len() || self.truncated)
        {
            let graph_id = self.graph_id.assume("graph_id is set")?;
            let storage = provider.get_storage(graph_id)?;
            let heads: vec::Vec<Address> = storage
                .get_heads()?
                .iter()
                .map(LocatedAddress::address)
                .collect();
            let floor = sample::floor(&*storage, response_cache.heads())?;
            sample = sample::build(&*storage, &[&heads], floor, rng, |addr| {
                commands.iter().any(|meta| meta.id == addr.id)
            })?;
        }

        let message = SyncResponseMessage::SyncResponse {
            session_id: self.session_id()?,
            response_index: self.message_index as u64,
            commands,
            sample,
        };

        let length = Self::write(target, message)?;
        let total_length = length
            .checked_add(command_data.len())
            .assume("length + command_data_length mustn't overflow")?;
        // Don't advance the session until the whole message fits, so the
        // caller can retry with a larger buffer without losing commands.
        let data_target = target
            .get_mut(length..total_length)
            .ok_or(SyncError::BufferTooSmall)?;
        data_target.copy_from_slice(&command_data);

        self.message_index = self
            .message_index
            .checked_add(1)
            .assume("message_index overflow")?;
        self.next_send = next_send;
        Ok(total_length)
    }

    /// Writes a sync push message to target for the peer. The message will
    /// contain any commands not covered by the session's heads or by
    /// `response_cache`, the commands the peer is known to have.
    pub fn push(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        response_cache: &PeerCache,
        buffers: &mut TraversalBuffers,
    ) -> Result<usize, SyncError> {
        use SyncResponderState as S;
        let Some(graph_id) = self.graph_id else {
            // `push` is public; calling it before a sync request set the
            // graph id is a usage error, not a bug.
            self.state = S::Reset;
            return Err(SyncError::NotReady);
        };

        let storage = match provider.get_storage(graph_id) {
            Ok(s) => s,
            Err(e) => {
                self.state = S::Reset;
                return Err(e.into());
            }
        };
        let mut have: vec::Vec<Location> = response_cache
            .heads()
            .iter()
            .map(|h| h.location())
            .collect();
        for &addr in &self.has {
            if let Some(location) = storage.get_location(addr, &mut buffers.primary)? {
                have.push(location);
            }
        }
        (self.to_send, self.truncated) = Self::find_needed_segments(have, storage, buffers)?;
        let (commands, command_data, next_send) = self.get_commands(provider)?;
        let mut length = 0;
        if !commands.is_empty() {
            let message = SyncType::Push {
                message: SyncResponseMessage::SyncResponse {
                    session_id: self.session_id()?,
                    response_index: self.message_index as u64,
                    commands,
                    sample: Vec::new(),
                },
                graph_id,
            };

            length = Self::write_sync_type(target, message)?;
            let total_length = length
                .checked_add(command_data.len())
                .assume("length + command_data_length mustn't overflow")?;
            // Don't advance the session until the whole message fits, so the
            // caller can retry with a larger buffer without losing commands.
            let data_target = target
                .get_mut(length..total_length)
                .ok_or(SyncError::BufferTooSmall)?;
            data_target.copy_from_slice(&command_data);

            self.message_index = self
                .message_index
                .checked_add(1)
                .assume("message_index increment overflow")?;
            self.next_send = next_send;
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
            Vec<u8, COMMAND_DATA_BUF_SIZE>,
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
        let mut command_data: Vec<u8, COMMAND_DATA_BUF_SIZE> = Vec::new();
        let mut index = self.next_send;
        for i in self.next_send..self.to_send.len() {
            if commands.is_full() {
                break;
            }
            let Some(location) = self.to_send.get_mut(i) else {
                self.state = SyncResponderState::Reset;
                bug!("send index OOB");
            };

            let segment = storage
                .get_segment(*location)
                .inspect_err(|_| self.state = SyncResponderState::Reset)?;

            let found = segment.get_from(*location);

            let mut sent: usize = 0;
            for command in &found {
                if commands.is_full() {
                    break;
                }

                let Ok(meta) = add_command_data(&mut command_data, command) else {
                    break;
                };

                commands.push(meta).ok().assume("commands is not full")?;
                sent = sent.checked_add(1).assume("sent + 1 mustn't overflow")?;
            }

            if sent < found.len() {
                // The response filled up partway through this segment.
                // Point this entry at the first unsent command so the next
                // response resumes inside the segment; a command's location
                // within a segment advances one max_cut per command.
                let resume_max_cut = location
                    .max_cut
                    .checked_add(sent as u64)
                    .assume("max_cut + sent mustn't overflow")?;
                location.max_cut = resume_max_cut;
                index = i;
                break;
            }

            index = i.checked_add(1).assume("index + 1 mustn't overflow")?;
        }
        Ok((commands, command_data, index))
    }

    fn session_id(&self) -> Result<u128, SyncError> {
        Ok(self.session_id.assume("session id is set")?)
    }
}

/// Atomically add both the command policy and bytes.
fn add_command_data(
    buf: &mut Vec<u8, COMMAND_DATA_BUF_SIZE>,
    cmd: &impl Command,
) -> Result<CommandMeta, ()> {
    let before = buf.len();

    if let Some(policy) = cmd.policy() {
        buf.extend_from_slice(policy)?;
    }

    buf.extend_from_slice(cmd.bytes()).inspect_err(|()| {
        buf.truncate(before);
    })?;

    Ok(CommandMeta {
        id: cmd.id(),
        parent: cmd.parent(),
        policy_length: cmd.policy().unwrap_or_default().len() as u32,
        length: cmd.bytes().len() as u32,
    })
}

/// Size of the buffer for storing the command data.
///
/// This is smaller than the max sync message size to account for the serialized
/// `SyncResponseMessage::SyncResponse` to ensure the response will always fit
/// within a supplied buffer of size `MAX_SYNC_MESSAGE_SIZE`.
const COMMAND_DATA_BUF_SIZE: usize = MAX_SYNC_MESSAGE_SIZE - SYNC_RESPONSE_SERIALIZED_UPPER_BOUND;

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use aranya_crypto::Rng;

    use super::*;
    use crate::{
        ClientState, RuntimeBuffers, mem_spill,
        storage::linear::testing::MemStorageProvider,
        sync::{MAX_SYNC_MESSAGE_SIZE, SessionHeads, SyncIncoming, SyncRequester},
        testing::protocol::{TestActions, TestPolicyStore, TestSink},
    };

    type TestClient = ClientState<TestPolicyStore, MemStorageProvider>;

    fn new_client() -> TestClient {
        ClientState::new(TestPolicyStore::new(), MemStorageProvider::default())
    }

    fn new_sink() -> TestSink {
        let mut sink = TestSink::new();
        sink.ignore_expectations(true);
        sink
    }

    /// Runs one complete sync session from `source` (responder side) to
    /// `dest` (requester side), reusing a single `SyncResponder` and polling
    /// it repeatedly until it reports `SyncEnd`, exactly like a production
    /// transport's poll loop. Returns the number of new commands `dest`
    /// accepted.
    fn run_full_session(
        source: &mut TestClient,
        dest: &mut TestClient,
        graph_id: GraphId,
    ) -> usize {
        let mut sink = new_sink();
        let mut rt_buffers = RuntimeBuffers::new();
        let mut req_cache = PeerCache::new();
        let mut resp_cache = PeerCache::new();

        let mut requester = SyncRequester::new(graph_id, Rng);
        let mut responder = SyncResponder::new();

        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let (len, _sent) = requester
            .poll(
                &mut buffer,
                dest.provider(),
                req_cache.session_heads(),
                &Rng,
            )
            .expect("requester poll");

        match SyncIncoming::decode(&buffer[..len]).expect("decode") {
            SyncIncoming::Poll(poll) => responder.receive(poll).expect("responder receive"),
            _ => panic!("expected a poll message"),
        }

        let mut trx = dest.transaction(graph_id);
        let mut received = 0;
        let mut rounds = 0;
        while responder.ready() {
            rounds += 1;
            assert!(rounds <= 64, "sync session did not terminate");
            let len = responder
                .poll(
                    &mut buffer,
                    source.provider(),
                    &mut resp_cache,
                    &mut rt_buffers.traversal,
                    &Rng,
                )
                .expect("responder poll");
            if len == 0 {
                break;
            }
            let Some(reply) = requester
                .receive(&buffer[..len])
                .expect("requester receive")
            else {
                // SyncEnd: the responder claims the session is complete.
                break;
            };
            received += dest
                .add_commands(
                    &mut trx,
                    &mut sink,
                    reply.commands(),
                    &mut rt_buffers,
                    mem_spill,
                )
                .expect("add_commands");
        }
        dest.commit(trx, &mut sink, &mut rt_buffers, mem_spill)
            .expect("commit");
        received
    }

    /// Builds a client whose graph is `2 * stage` commands arranged so a
    /// *second* client that syncs from it holds exactly two `stage`-command
    /// segments (the receiver batches each session's contiguous commands
    /// into one segment). Returns the second client.
    fn client_with_two_segments(stage: u64) -> (TestClient, GraphId) {
        let mut sink = new_sink();
        let mut rt_buffers = RuntimeBuffers::new();
        let mut a = new_client();
        let graph_id = a
            .new_graph(&0u64.to_be_bytes(), TestActions::Init(0), &mut sink)
            .expect("new_graph");
        // Stage 1: init + (stage - 1) actions = `stage` commands.
        for i in 1..stage {
            a.action(
                graph_id,
                &mut sink,
                TestActions::SetValue(i, i),
                &mut rt_buffers,
                mem_spill,
            )
            .expect("action");
        }
        let mut b = new_client();
        run_full_session(&mut a, &mut b, graph_id);
        assert_eq!(
            b.head_address(graph_id).expect("b head"),
            a.head_address(graph_id).expect("a head"),
            "stage 1 sync must fully transfer (below response limit)"
        );

        // Stage 2: `stage` more commands, transferred in a second session so
        // they land in a second segment on `b`.
        for i in stage..(2 * stage) {
            a.action(
                graph_id,
                &mut sink,
                TestActions::SetValue(i, i),
                &mut rt_buffers,
                mem_spill,
            )
            .expect("action");
        }
        run_full_session(&mut a, &mut b, graph_id);
        assert_eq!(
            b.head_address(graph_id).expect("b head"),
            a.head_address(graph_id).expect("a head"),
            "stage 2 sync must fully transfer (below response limit)"
        );

        (b, graph_id)
    }

    /// Harness soundness check: with two 40-command segments (80 total,
    /// under `COMMAND_RESPONSE_MAX`), a full session transfers everything.
    #[test]
    fn multi_round_session_below_response_max_converges() {
        let (mut b, graph_id) = client_with_two_segments(40);
        let mut c = new_client();
        let received = run_full_session(&mut b, &mut c, graph_id);
        assert_eq!(received, 80);
        assert_eq!(
            c.head_address(graph_id).expect("c head"),
            b.head_address(graph_id).expect("b head"),
        );
    }

    /// Reproduces S1: `get_commands` advances `next_send` past a segment
    /// *before* copying its commands, so when `COMMAND_RESPONSE_MAX` fills
    /// mid-segment the rest of that segment is never sent for the remainder
    /// of the session, which nonetheless ends with a clean
    /// `SyncEnd { remaining: false }`.
    ///
    /// Layout: two 60-command segments (120 commands). Round 1 sends 100
    /// commands (all of segment 1 + 40 of segment 2) but records both
    /// segments as fully sent; round 2 emits `SyncEnd`, silently dropping
    /// the last 20 commands.
    #[test]
    fn multi_round_session_drops_tail_of_straddling_segment() {
        let (mut b, graph_id) = client_with_two_segments(60);
        let mut c = new_client();
        let received = run_full_session(&mut b, &mut c, graph_id);
        assert_eq!(
            c.head_address(graph_id).expect("c head"),
            b.head_address(graph_id).expect("b head"),
            "session ended with SyncEnd but receiver is missing commands \
             (received {received} of 120)",
        );
    }

    /// Builds a client whose graph is a chain of `n` commands.
    fn client_with_commands(n: u64) -> (TestClient, GraphId) {
        let mut sink = new_sink();
        let mut client = new_client();
        let graph_id = client
            .new_graph(&0u64.to_be_bytes(), TestActions::Init(0), &mut sink)
            .expect("new_graph");
        extend_chain(&mut client, graph_id, 1..n);
        (client, graph_id)
    }

    /// Appends one action per value in `values` to `client`'s graph.
    fn extend_chain(client: &mut TestClient, graph_id: GraphId, values: core::ops::Range<u64>) {
        let mut sink = new_sink();
        let mut rt_buffers = RuntimeBuffers::new();
        for i in values {
            client
                .action(
                    graph_id,
                    &mut sink,
                    TestActions::SetValue(i, i),
                    &mut rt_buffers,
                    mem_spill,
                )
                .expect("action");
        }
    }

    /// The outcome of one request and its first reply.
    struct Exchange {
        /// Commands in the reply.
        sent: vec::Vec<CmdId>,
        /// How many of them the requester did not already hold.
        new: usize,
        /// The reply's sample.
        sample: vec::Vec<Address>,
    }

    /// Sends one request from `req` to `resp`, commits the first reply, and
    /// records it in `req_cache` the way a transport would.
    fn exchange(
        req: &mut TestClient,
        resp: &mut TestClient,
        graph_id: GraphId,
        req_cache: &mut PeerCache,
        resp_cache: &mut PeerCache,
    ) -> Exchange {
        let mut sink = new_sink();
        let mut rt_buffers = RuntimeBuffers::new();
        let mut requester = SyncRequester::new(graph_id, Rng);
        let mut responder = SyncResponder::new();

        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let (len, _) = requester
            .poll(&mut buffer, req.provider(), req_cache.session_heads(), &Rng)
            .expect("requester poll");
        match SyncIncoming::decode(&buffer[..len]).expect("decode") {
            SyncIncoming::Poll(poll) => responder.receive(poll).expect("responder receive"),
            _ => panic!("expected a poll message"),
        }
        let len = responder
            .poll(
                &mut buffer,
                resp.provider(),
                resp_cache,
                &mut rt_buffers.traversal,
                &Rng,
            )
            .expect("responder poll");
        let Some(reply) = requester
            .receive(&buffer[..len])
            .expect("requester receive")
        else {
            req_cache.reply_committed();
            return Exchange {
                sent: vec::Vec::new(),
                new: 0,
                sample: vec::Vec::new(),
            };
        };

        let mut trx = req.transaction(graph_id);
        let new = req
            .add_commands(
                &mut trx,
                &mut sink,
                reply.commands(),
                &mut rt_buffers,
                mem_spill,
            )
            .expect("add_commands");
        req.commit(trx, &mut sink, &mut rt_buffers, mem_spill)
            .expect("commit");
        req.update_heads(
            graph_id,
            reply.addresses(),
            req_cache,
            &mut rt_buffers.traversal.primary,
            &Rng,
        )
        .expect("update_heads");

        Exchange {
            sent: reply.commands().iter().map(Command::id).collect(),
            new,
            sample: reply.sample().to_vec(),
        }
    }

    /// Decodes the sample a request carries, given the requester's cache.
    fn request_sample(
        client: &mut TestClient,
        graph_id: GraphId,
        cache: &mut PeerCache,
    ) -> vec::Vec<Address> {
        let mut requester = SyncRequester::new(graph_id, Rng);
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let (len, _) = requester
            .poll(&mut buffer, client.provider(), cache.session_heads(), &Rng)
            .expect("requester poll");
        let SyncIncoming::Poll(poll) = SyncIncoming::decode(&buffer[..len]).expect("decode") else {
            panic!("expected a poll message");
        };
        let SyncRequestMessage::SyncRequest { commands, .. } = poll.message else {
            panic!("expected a sync request");
        };
        commands.to_vec()
    }

    /// On a 1000-command chain the sample is the head followed by random commands
    /// spaced `COMMAND_RESPONSE_MAX` apart, the first at least half a gap
    /// below the head, down to the root.
    #[test]
    fn request_random_commands_are_evenly_spaced() {
        let (mut a, graph_id) = client_with_commands(1000);
        for _ in 0..20 {
            let sample = request_sample(&mut a, graph_id, &mut PeerCache::new());
            let cuts: vec::Vec<u64> = sample.iter().map(|s| s.max_cut.get()).collect();
            assert_eq!(cuts[0], 999, "the head comes first: {cuts:?}");
            let random = &cuts[1..];
            assert!(
                (899..=949).contains(&random[0]),
                "first random command is 50 to 100 below the head: {cuts:?}"
            );
            for pair in random.windows(2) {
                assert_eq!(
                    pair[0] - pair[1],
                    100,
                    "random commands are one gap apart: {cuts:?}"
                );
            }
            assert!(
                *random.last().unwrap() <= 100,
                "random commands reach within one gap of the root: {cuts:?}"
            );
        }
    }

    /// A requester far ahead of the responder: the old tip-only sample
    /// found nothing, so the responder resent its whole graph. Random
    /// commands resolve in the shared history, so at most one gap is resent.
    #[test]
    fn requester_ahead_resends_less_than_one_gap() {
        let (mut a, graph_id) = client_with_commands(500);
        let mut b = new_client();
        for _ in 0..20 {
            if b.head_address(graph_id).ok() == a.head_address(graph_id).ok() {
                break;
            }
            run_full_session(&mut a, &mut b, graph_id);
        }
        assert_eq!(
            b.head_address(graph_id).expect("b head"),
            a.head_address(graph_id).expect("a head"),
        );
        extend_chain(&mut a, graph_id, 500..1000);

        let mut a_cache = PeerCache::new();
        let mut b_cache = PeerCache::new();
        let mut wasted = 0;
        for _ in 0..10 {
            let ex = exchange(&mut a, &mut b, graph_id, &mut a_cache, &mut b_cache);
            assert_eq!(ex.new, 0, "b has nothing a lacks");
            if ex.sent.is_empty() {
                break;
            }
            wasted += ex.sent.len();
        }
        assert!(
            wasted < COMMAND_RESPONSE_MAX,
            "resent {wasted} commands a already held"
        );
    }

    /// A reply carries a sample only when the uncovered region does not fit
    /// in it, and the sample leaves out commands the reply already carries.
    #[test]
    fn responder_sample_only_when_reply_overflows() {
        let (mut b, graph_id) = client_with_commands(300);
        let mut a = new_client();
        let ex = exchange(
            &mut a,
            &mut b,
            graph_id,
            &mut PeerCache::new(),
            &mut PeerCache::new(),
        );
        assert_eq!(ex.sent.len(), COMMAND_RESPONSE_MAX);
        assert!(!ex.sample.is_empty(), "a 300-command region needs a sample");
        assert!(
            ex.sample.len() <= COMMAND_SAMPLE_MAX,
            "sample fits its bound"
        );
        for addr in &ex.sample {
            assert!(
                !ex.sent.contains(&addr.id),
                "sample repeats a command in the reply: {addr:?}"
            );
        }

        let (mut c, graph_id) = client_with_commands(50);
        let mut d = new_client();
        let ex = exchange(
            &mut d,
            &mut c,
            graph_id,
            &mut PeerCache::new(),
            &mut PeerCache::new(),
        );
        assert_eq!(ex.sent.len(), 50);
        assert!(ex.sample.is_empty(), "a region that fits needs no sample");
    }

    /// The peer cache keeps at most `PEER_HEAD_MAX` concurrent heads, and a
    /// new head evicts an old one rather than being dropped.
    #[test]
    fn peer_cache_evicts_when_full() {
        let (mut root, graph_id) = client_with_commands(1);
        let mut branches = vec::Vec::new();
        for i in 0..PEER_HEAD_MAX as u64 + 5 {
            let mut branch = new_client();
            run_full_session(&mut root, &mut branch, graph_id);
            extend_chain(&mut branch, graph_id, 100 + i..101 + i);
            branches.push(branch);
        }
        let mut hub = new_client();
        let mut cache = PeerCache::new();
        let mut buffer = TraversalBuffer::new();
        for branch in &mut branches {
            run_full_session(branch, &mut hub, graph_id);
            let head = branch.head_address(graph_id).expect("branch head");
            let storage = hub.provider().get_storage(graph_id).expect("storage");
            cache
                .add_command(storage, head, &mut buffer, &Rng)
                .expect("add_command");
            assert!(
                cache.heads().iter().any(|h| h.address() == head),
                "the new head is kept"
            );
        }
        assert_eq!(cache.heads().len(), PEER_HEAD_MAX);
    }

    /// Decodes whether a request asks the responder to reset.
    fn request_resets(client: &mut TestClient, graph_id: GraphId, heads: SessionHeads<'_>) -> bool {
        let mut requester = SyncRequester::new(graph_id, Rng);
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let (len, _) = requester
            .poll(&mut buffer, client.provider(), heads, &Rng)
            .expect("requester poll");
        let SyncIncoming::Poll(poll) = SyncIncoming::decode(&buffer[..len]).expect("decode") else {
            panic!("expected a poll message");
        };
        let SyncRequestMessage::SyncRequest { reset, .. } = poll.message else {
            panic!("expected a sync request");
        };
        reset
    }

    /// A request resets while the requester's cache is empty or after a
    /// missing parent, until a reply is committed.
    #[test]
    fn request_resets_until_reply_commits() {
        let (mut b, graph_id) = client_with_commands(10);
        let mut a = new_client();
        let mut a_cache = PeerCache::new();
        let mut b_cache = PeerCache::new();

        assert!(
            request_resets(&mut a, graph_id, a_cache.session_heads()),
            "an empty cache resets"
        );
        exchange(&mut a, &mut b, graph_id, &mut a_cache, &mut b_cache);
        assert!(
            !request_resets(&mut a, graph_id, a_cache.session_heads()),
            "a populated cache does not reset"
        );

        a_cache.saw_missing_parent();
        assert!(request_resets(&mut a, graph_id, a_cache.session_heads()));
        assert!(
            request_resets(&mut a, graph_id, a_cache.session_heads()),
            "the reset is sent again until a reply arrives"
        );
        exchange(&mut a, &mut b, graph_id, &mut a_cache, &mut b_cache);
        assert!(!request_resets(&mut a, graph_id, a_cache.session_heads()));
    }

    /// Session heads sent in a transaction that is dropped make the next
    /// request outside it reset.
    #[test]
    fn dropped_session_resets() {
        let (mut b, graph_id) = client_with_commands(10);
        let mut a = new_client();
        let mut a_cache = PeerCache::new();
        exchange(
            &mut a,
            &mut b,
            graph_id,
            &mut a_cache,
            &mut PeerCache::new(),
        );
        extend_chain(&mut b, graph_id, 10..20);

        // Receive b's new commands into a transaction, then advertise them.
        let mut trx = a.transaction(graph_id);
        let mut requester = SyncRequester::new(graph_id, Rng);
        let mut responder = SyncResponder::new();
        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
        let (len, _) = requester
            .poll(&mut buffer, a.provider(), a_cache.session_heads(), &Rng)
            .expect("requester poll");
        let SyncIncoming::Poll(poll) = SyncIncoming::decode(&buffer[..len]).expect("decode") else {
            panic!("expected a poll message");
        };
        responder.receive(poll).expect("responder receive");
        let mut rt_buffers = RuntimeBuffers::new();
        let len = responder
            .poll(
                &mut buffer,
                b.provider(),
                &mut PeerCache::new(),
                &mut rt_buffers.traversal,
                &Rng,
            )
            .expect("responder poll");
        let reply = requester
            .receive(&buffer[..len])
            .expect("requester receive")
            .expect("reply");
        a.add_commands(
            &mut trx,
            &mut new_sink(),
            reply.commands(),
            &mut rt_buffers,
            mem_spill,
        )
        .expect("add_commands");
        trx.flush(a.provider().get_storage(graph_id).expect("storage"))
            .expect("flush");
        assert!(
            !request_resets(&mut a, graph_id, trx.session_heads(&mut a_cache)),
            "a request inside the transaction does not reset"
        );

        drop(trx);
        assert!(
            request_resets(&mut a, graph_id, a_cache.session_heads()),
            "a request after the dropped transaction resets"
        );
    }

    /// A reset makes the responder forget what it knew the requester held.
    #[test]
    fn responder_clears_cache_on_reset() {
        let (mut b, graph_id) = client_with_commands(300);
        let mut a = new_client();
        let stale = b.head_address(graph_id).expect("head");
        let mut b_cache = cache_holding(&mut b, graph_id, &[stale]);

        let ex = exchange(
            &mut a,
            &mut b,
            graph_id,
            &mut PeerCache::new(),
            &mut b_cache,
        );
        assert_eq!(
            ex.sent.len(),
            COMMAND_RESPONSE_MAX,
            "b resends from the root"
        );
        assert!(
            !b_cache.heads().iter().any(|h| h.address() == stale),
            "the stale head is gone"
        );
    }

    /// The responder's sample covers only the region above its floor for the
    /// requester.
    #[test]
    fn responder_sample_above_floor() {
        let (mut b, graph_id) = client_with_commands(1000);
        let mut a = new_client();
        let mut a_cache = PeerCache::new();
        let mut b_cache = PeerCache::new();
        for _ in 0..7 {
            exchange(&mut a, &mut b, graph_id, &mut a_cache, &mut b_cache);
        }
        let floor = a.head_address(graph_id).expect("a head").max_cut;
        assert!(floor.get() >= 600, "a holds most of the chain");

        let ex = exchange(&mut a, &mut b, graph_id, &mut a_cache, &mut b_cache);
        assert!(!ex.sample.is_empty(), "the rest does not fit in one reply");
        for addr in &ex.sample {
            assert!(
                addr.max_cut > floor,
                "sample command {addr:?} is at or below the floor {floor:?}"
            );
        }
    }

    /// Returns a cache recording that the peer holds `addrs`.
    fn cache_holding(client: &mut TestClient, graph_id: GraphId, addrs: &[Address]) -> PeerCache {
        let mut cache = PeerCache::new();
        let mut buffer = TraversalBuffer::new();
        let storage = client.provider().get_storage(graph_id).expect("storage");
        for &addr in addrs {
            cache
                .add_command(storage, addr, &mut buffer, &Rng)
                .expect("add_command");
        }
        cache
    }

    /// A requester a few commands ahead of its cache head on a long chain:
    /// the floor is the cache head, so the sample is only the heads.
    #[test]
    fn floor_at_cache_head_sends_only_heads() {
        let (mut a, graph_id) = client_with_commands(1000);
        let held = a.head_address(graph_id).expect("head");
        extend_chain(&mut a, graph_id, 1000..1005);
        let mut cache = cache_holding(&mut a, graph_id, &[held]);

        let sample = request_sample(&mut a, graph_id, &mut cache);
        let head = a.head_address(graph_id).expect("head");
        assert_eq!(sample, [held, head]);
    }

    /// Two writers each add a command on the same parent. After the
    /// requester receives the other's command it has two heads, their LCA
    /// is the shared parent, and that is the floor: only heads.
    #[test]
    fn floor_below_sibling_heads_sends_only_heads() {
        let (mut a, graph_id) = client_with_commands(1000);
        let mut b = new_client();
        for _ in 0..20 {
            if b.head_address(graph_id).ok() == a.head_address(graph_id).ok() {
                break;
            }
            run_full_session(&mut a, &mut b, graph_id);
        }
        let parent = a.head_address(graph_id).expect("head");
        extend_chain(&mut a, graph_id, 2000..2001);
        extend_chain(&mut b, graph_id, 3000..3001);
        let mine = a.head_address(graph_id).expect("a head");
        let theirs = b.head_address(graph_id).expect("b head");

        let mut a_cache = PeerCache::new();
        let ex = exchange(
            &mut a,
            &mut b,
            graph_id,
            &mut a_cache,
            &mut PeerCache::new(),
        );
        assert_eq!(ex.new, 1, "a receives b's command");

        let storage = a.provider().get_storage(graph_id).expect("storage");
        let heads = storage.get_heads().expect("heads");
        assert_eq!(heads.len(), 2, "a holds both siblings as heads");
        assert_eq!(heads.lca().max_cut, parent.max_cut, "LCA is the parent");

        let mut cache = cache_holding(&mut a, graph_id, &[theirs]);
        let mut sample = request_sample(&mut a, graph_id, &mut cache);
        sample.sort();
        let mut expected = vec![mine, theirs];
        expected.sort();
        assert_eq!(sample, expected, "heads only");
    }

    /// A branch from near the root that the peer has never seen: the heads'
    /// LCA is near the root, so random commands cover the whole graph even
    /// though the cache head is the main line's tip.
    #[test]
    fn unknown_branch_puts_floor_at_root() {
        let (mut a, graph_id) = client_with_commands(1);
        let mut b = new_client();
        run_full_session(&mut a, &mut b, graph_id);
        extend_chain(&mut a, graph_id, 1..1000);
        extend_chain(&mut b, graph_id, 5000..5500);
        let main_tip = a.head_address(graph_id).expect("a head");
        for _ in 0..20 {
            let ex = exchange(
                &mut a,
                &mut b,
                graph_id,
                &mut PeerCache::new(),
                &mut PeerCache::new(),
            );
            if ex.sent.is_empty() {
                break;
            }
        }
        let storage = a.provider().get_storage(graph_id).expect("storage");
        assert_eq!(storage.get_heads().expect("heads").len(), 2);

        let mut cache = cache_holding(&mut a, graph_id, &[main_tip]);
        let sample = request_sample(&mut a, graph_id, &mut cache);
        let lowest = sample.iter().map(|s| s.max_cut.get()).min().unwrap();
        assert!(
            sample.len() > 3 && lowest < 100,
            "random commands reach the root: {:?}",
            sample
                .iter()
                .map(|s| s.max_cut.get())
                .collect::<vec::Vec<_>>()
        );
    }
}
