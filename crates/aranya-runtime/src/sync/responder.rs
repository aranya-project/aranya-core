use buggy::{Bug, BugExt as _, bug};
use heapless::{Deque, Vec};
use serde::{Deserialize, Serialize};

use super::{
    COMMAND_SAMPLE_MAX, PEER_HEAD_MAX, SEGMENT_BUFFER_MAX, SyncError, requester::SyncRequestMessage,
};
use crate::{
    MaxCut, SegmentIndex, StorageError, SyncCommand, SyncType,
    command::{Address, CmdId, Command as _},
    rkyv_utils::BufferOverflow,
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
        storage: &S,
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
                || storage.is_ancestor(new_head, &req_head_seg)?
            {
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
pub struct SyncResponder {
    session_id: Option<u128>,
    graph_id: Option<GraphId>,
    state: SyncResponderState,
    bytes_sent: u64,
    next_send: usize,
    message_index: usize,
    has: Vec<Address, COMMAND_SAMPLE_MAX>,
    to_send: Lru<SegmentIndex, MaxCut, SEGMENT_BUFFER_MAX>,
}

impl SyncResponder {
    /// Create a new [`SyncResponder`].
    pub fn new() -> Self {
        Self {
            session_id: None,
            graph_id: None,
            state: SyncResponderState::New,
            bytes_sent: 0,
            next_send: 0,
            message_index: 0,
            has: Vec::new(),
            to_send: Lru::new(),
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

        let target = &mut Buf::new(target);
        match self.state {
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
                    if let Some(cmd_loc) = storage.get_location(*command)? {
                        response_cache.add_command(storage, *command, cmd_loc)?;
                    }
                }
                self.find_needed_segments(storage)?;

                self.get_next(target, provider)?;
            }
            S::Send => self.get_next(target, provider)?,
            S::Reset => {
                self.state = S::Stopped;
                target.serialize(&SyncResponseMessage::EndSession {
                    session_id: self.session_id()?,
                })?;
            }
        }
        Ok(target.written())
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
                self.to_send.clear();
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

    /// This (probably) returns a Vec of segment addresses where the head of each segment is
    /// not the ancestor of any samples we have been sent. If that is longer than
    /// SEGMENT_BUFFER_MAX, it contains the oldest segment heads where that holds.
    fn find_needed_segments(&mut self, storage: &impl Storage) -> Result<(), SyncError> {
        self.to_send.clear();

        // TODO(jdygert): Use `to_send` to also store heads?
        let mut heads: Deque<Location, SEGMENT_BUFFER_MAX> = Deque::new();
        heads
            .push_front(storage.get_head()?)
            .ok()
            .assume("heads not full")?;

        let mut have_locations = Vec::<Location, COMMAND_SAMPLE_MAX>::new();
        for &addr in &self.has {
            // Note: We could use things we don't have as a hint to
            // know we should perform a sync request.
            if let Some(loc) = storage.get_location(addr)? {
                have_locations.push(loc).ok().assume("not full")?;
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
                        || storage.is_ancestor(location_a, &segment_b)?
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

        'heads: while let Some(head) = heads.pop_front() {
            // TODO(jdygert): What is this doing?
            if have_locations.iter().any(|hl| hl.segment == head.segment) {
                self.to_send.insert(head.segment, head.max_cut);
                continue 'heads;
            }

            // If the segment is already in the result, skip it
            if self.to_send.iter().any(|&(seg, _)| seg == head.segment) {
                continue 'heads;
            }

            // Check if the current segment head is an ancestor of any location in have_locations.
            // If so, stop traversing backward from this point since the requester already has
            // this command and all its ancestors.
            for &have_location in &have_locations {
                let have_segment = storage.get_segment(have_location)?;
                if storage.is_ancestor(head, &have_segment)? {
                    continue 'heads;
                }
            }

            let segment = storage.get_segment(head)?;

            // If the requester has any commands in this segment, send from the next command
            if let Some(latest_loc) = have_locations
                .iter()
                .filter(|&&location| head.same_segment(location))
                .max_by_key(|&&location| location.max_cut)
            {
                let next_max_cut = latest_loc
                    .max_cut
                    .checked_add(1)
                    .assume("command + 1 mustn't overflow")?;
                let next_location = Location {
                    segment: head.segment,
                    max_cut: next_max_cut,
                };

                let head_loc = segment.head_location()?;
                if next_location.max_cut > head_loc.max_cut {
                    continue 'heads;
                }
                self.to_send
                    .insert(next_location.segment, next_location.max_cut);
                continue 'heads;
            }

            for p in segment.prior() {
                force_push_front(&mut heads, p)?;
            }

            let loc = segment.first_location();
            self.to_send.insert(loc.segment, loc.max_cut);
        }

        // Order segments to ensure that a segment isn't received before its
        // ancestor segments.
        self.to_send.sort_by_key();

        Ok(())
    }

    fn get_next(
        &mut self,
        target: &mut Buf<'_>,
        provider: &mut impl StorageProvider,
    ) -> Result<(), SyncError> {
        if self.next_send >= self.to_send.len() {
            self.state = SyncResponderState::Idle;
            target.serialize(&SyncResponseMessage::SyncEnd {
                session_id: self.session_id()?,
                max_index: self.message_index as u64,
                remaining: false,
            })?;
            return Ok(());
        }

        target.serialize(&SyncResponseMessage::SyncResponse {
            session_id: self.session_id()?,
            response_index: self.message_index as u64,
        })?;

        self.message_index = self
            .message_index
            .checked_add(1)
            .assume("message_index overflow")?;

        self.next_send = self.get_commands(target, provider)?;

        Ok(())
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

        let target = &mut Buf::new(target);

        target.serialize(&SyncType::Push {
            message: SyncResponseMessage::SyncResponse {
                session_id: self.session_id()?,
                response_index: self.message_index as u64,
            },
            graph_id: self.graph_id.assume("storage id must exist")?,
        })?;

        self.message_index = self
            .message_index
            .checked_add(1)
            .assume("message_index increment overflow")?;

        self.find_needed_segments(storage)?;
        self.next_send = self.get_commands(target, provider)?;

        // TODO: rewind if empty?

        Ok(target.written())
    }

    fn get_commands(
        &mut self,
        target: &mut Buf<'_>,
        provider: &mut impl StorageProvider,
    ) -> Result<usize, SyncError> {
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
        let mut index = self.next_send;
        let Some(sending) = self.to_send.iter_mut_from(self.next_send) else {
            self.state = SyncResponderState::Reset;
            bug!("send index OOB");
        };

        let mut ser = target.as_ser_cmd().map_err(|_| SyncError::BufferTooSmall)?;

        'outer: for (seg, max_cut) in sending {
            let location = Location::new(*seg, *max_cut);
            let segment = storage
                .get_segment(location)
                .inspect_err(|_| self.state = SyncResponderState::Reset)?;

            let found = segment.get_from(location);

            for command in found {
                let command = SyncCommand {
                    priority: command.priority(),
                    id: command.id(),
                    parent: command.parent(),
                    policy: command.policy(),
                    data: command.bytes(),
                    max_cut: command.max_cut()?,
                };
                match ser.push(&command) {
                    Ok(()) => {}
                    Err(BufferOverflow) => {
                        *max_cut = command.max_cut;
                        break 'outer;
                    }
                }
            }
            index = index.checked_add(1).assume("won't overflow")?;
        }

        ser.finish()?;

        Ok(index)
    }

    fn session_id(&self) -> Result<u128, SyncError> {
        Ok(self.session_id.assume("session id is set")?)
    }
}

fn force_push_front<T>(deque: &mut heapless::deque::DequeView<T>, value: T) -> Result<(), Bug> {
    if deque.is_full() {
        deque.pop_back();
    }
    deque
        .push_front(value)
        .ok()
        .assume("deque is not full after popping if full")
}

use buf::Buf;
mod buf {
    use buggy::BugExt as _;

    use crate::{
        ArchivedSyncCommand, SyncError,
        rkyv_utils::{BufferOverflow, PerfectSer},
    };

    pub struct Buf<'a> {
        slice: &'a mut [u8],
        written: usize,
    }

    impl<'data> Buf<'data> {
        pub fn new(slice: &'data mut [u8]) -> Self {
            Self { slice, written: 0 }
        }

        pub fn written(&self) -> usize {
            self.written
        }

        pub fn serialize<T: serde::Serialize>(&mut self, value: &T) -> Result<(), SyncError> {
            let len = postcard::to_slice(value, &mut self.slice[self.written..])?.len();
            self.written = self
                .written
                .checked_add(len)
                .assume("can't overflow if postcard behaves")?;
            Ok(())
        }

        pub fn as_ser_cmd<'buf>(
            &'buf mut self,
        ) -> Result<PerfectSer<'buf, ArchivedSyncCommand>, BufferOverflow> {
            PerfectSer::new(self.slice, &mut self.written)
        }
    }
}

use lru::Lru;
mod lru {
    use alloc::vec::Vec;

    pub struct Lru<K, V, const SIZE: usize> {
        data: Vec<(K, V)>,
    }

    impl<K, V, const SIZE: usize> Lru<K, V, SIZE> {
        pub const fn new() -> Self {
            Self { data: Vec::new() }
        }

        pub fn len(&self) -> usize {
            self.data.len()
        }

        pub fn clear(&mut self) {
            self.data.clear();
        }

        pub fn iter_mut_from(
            &mut self,
            start: usize,
        ) -> Option<impl Iterator<Item = (&K, &mut V)>> {
            self.data
                .get_mut(start..)
                .map(|xs| xs.iter_mut().map(|(k, v)| (&*k, v)))
        }

        pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
            self.data.iter()
        }
    }

    impl<K: Ord, V, const SIZE: usize> Lru<K, V, SIZE> {
        pub fn sort_by_key(&mut self) {
            self.data.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));
        }
    }

    impl<K: Eq, V, const SIZE: usize> Lru<K, V, SIZE> {
        pub fn insert(&mut self, k: K, v: V) {
            if let Some(pos) = self.data.iter().position(|(x, _)| *x == k) {
                self.data.remove(pos);
            } else if self.data.len() >= SIZE {
                self.data.remove(0);
            }
            self.data.push((k, v));
        }

        #[allow(dead_code, reason = "Might need to use?")]
        pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
            let pos = self.data.iter().position(|(x, _)| x == k)?;
            let old = self.data.remove(pos);
            self.data.push(old);
            let (_, v) = self.data.last_mut()?;
            Some(v)
        }
    }

    impl<K, V, const SIZE: usize> Default for Lru<K, V, SIZE> {
        fn default() -> Self {
            Self::new()
        }
    }
}
