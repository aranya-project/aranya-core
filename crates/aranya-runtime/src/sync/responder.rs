use buggy::{Bug, BugExt as _, bug};
use heapless::{Deque, Vec};
use serde::{Deserialize, Serialize};

use super::{
    COMMAND_SAMPLE_MAX, PEER_HEAD_MAX, SEGMENT_BUFFER_MAX, SyncError, requester::SyncRequestMessage,
};
use crate::{
    StorageError, SyncCommand, SyncType,
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
            if (new_head.same_segment(req_head_loc) && new_head.command <= req_head_loc.command)
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
    storage_id: Option<GraphId>,
    state: SyncResponderState,
    bytes_sent: u64,
    next_send: usize,
    message_index: usize,
    has: Vec<Address, COMMAND_SAMPLE_MAX>,
    to_send: Lru<usize, usize, SEGMENT_BUFFER_MAX>,
}

impl SyncResponder {
    /// Create a new [`SyncResponder`].
    pub fn new() -> Self {
        Self {
            session_id: None,
            storage_id: None,
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
                storage_id,
                max_bytes,
                commands,
                ..
            } => {
                self.state = SyncResponderState::Start;
                self.storage_id = Some(storage_id);
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
                        && location_a.command <= location_b.command
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
                self.to_send.insert(head.segment, head.command);
                continue 'heads;
            }

            let segment = storage.get_segment(head)?;

            // If the segment is already in the result, skip it
            if segment.contains_any(
                self.to_send
                    .iter()
                    .map(|&(seg, cmd)| Location::new(seg, cmd)),
            ) {
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

            // If the requester has any commands in this segment, send from the next command
            if let Some(latest_loc) = have_locations
                .iter()
                .filter(|&&location| segment.contains(location))
                .max_by_key(|&&location| location.command)
            {
                let next_command = latest_loc
                    .command
                    .checked_add(1)
                    .assume("command + 1 mustn't overflow")?;
                let next_location = Location {
                    segment: head.segment,
                    command: next_command,
                };

                let head_loc = segment.head_location();
                if next_location.command > head_loc.command {
                    continue 'heads;
                }
                self.to_send
                    .insert(next_location.segment, next_location.command);
                continue 'heads;
            }

            for p in segment.prior() {
                force_push_front(&mut heads, p)?;
            }

            let loc = segment.first_location();
            self.to_send.insert(loc.segment, loc.command);
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

        let target = &mut Buf::new(target);

        target.serialize(&SyncType::Push {
            message: SyncResponseMessage::SyncResponse {
                session_id: self.session_id()?,
                response_index: self.message_index as u64,
            },
            storage_id: self.storage_id.assume("storage id must exist")?,
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
        let mut index = self.next_send;
        let Some(sending) = self.to_send.iter_mut_from(self.next_send) else {
            self.state = SyncResponderState::Reset;
            bug!("send index OOB");
        };

        let mut ser = target.as_ser_cmd().unwrap();

        'outer: for (seg, cmd) in sending {
            let location = Location::new(*seg, *cmd);
            let segment = storage
                .get_segment(location)
                .inspect_err(|_| self.state = SyncResponderState::Reset)?;

            let found = segment.get_from(location);

            for (command, j) in found.iter().zip(*cmd..) {
                let command = SyncCommand {
                    priority: command.priority(),
                    id: command.id(),
                    parent: command.parent(),
                    policy: command.policy(),
                    data: command.bytes(),
                    max_cut: command.max_cut()?,
                };
                if ser.push(&command).is_err() {
                    *cmd = j;
                    break 'outer;
                }
            }
            index = index.checked_add(1).assume("won't overflow")?;
        }

        ser.finish();

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
    use rkyv::{
        Place,
        ser::WriterExt as _,
        vec::{ArchivedVec, VecResolver},
    };

    use crate::{ArchivedSyncCommand, SyncCommand, SyncError};

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

        pub fn as_ser_cmd<'buf>(&'buf mut self) -> Result<SerCmd<'buf>, Overflow> {
            // TODO: align here?
            let slice = &mut *self.slice;
            let og_end = unsafe { slice.as_mut_ptr().add(slice.len()) };
            let slice = slice
                .get_mut(self.written..slice.len() - VEC_SIZE)
                .ok_or(Overflow)?;
            Ok(SerCmd {
                buf: LentBuf {
                    slice,
                    written: &mut self.written,
                },
                og_end,
                count: 0,
            })
        }
    }

    struct LentBuf<'a> {
        /// Unwritten data.
        slice: &'a mut [u8],
        /// Updated with amount written but not an index into slice.
        written: &'a mut usize,
    }

    impl rkyv::rancor::Fallible for LentBuf<'_> {
        type Error = Overflow;
    }

    impl rkyv::ser::Positional for LentBuf<'_> {
        fn pos(&self) -> usize {
            *self.written
        }
    }

    impl rkyv::ser::Writer for LentBuf<'_> {
        fn write(&mut self, bytes: &[u8]) -> Result<(), <Self as rkyv::rancor::Fallible>::Error> {
            self.slice
                .split_off_mut(..bytes.len())
                .ok_or(Overflow)?
                .copy_from_slice(bytes);
            *self.written += bytes.len();
            Ok(())
        }
    }

    pub struct SerCmd<'a> {
        buf: LentBuf<'a>,
        /// The original end of the slice.
        og_end: *mut u8,
        count: usize,
    }

    #[derive(Copy, Clone, Debug)]
    pub struct Overflow;

    const VEC_SIZE: usize = size_of::<ArchivedVec<ArchivedSyncCommand<'static>>>();
    const CMD_SIZE: usize = size_of::<ArchivedSyncCommand<'static>>();

    impl<'data> SerCmd<'data> {
        pub fn push(&mut self, cmd: &SyncCommand<'_>) -> Result<(), Overflow> {
            let mut reserve = self.reserve_cmd()?;
            let resolver = match rkyv::traits::Serialize::serialize(cmd, &mut self.buf) {
                Ok(r) => r,
                Err(Overflow) => return Err(Overflow),
            };
            unsafe {
                reserve.resolve_aligned(cmd, resolver)?;
            }
            self.count += 1;
            Ok(())
        }

        pub fn finish(self) {
            // [extra] [empty] [cmd meta] [vec meta]
            //                                     ^ OG end
            //                            ^--------^ len VEC_SIZE
            //         ^------^ lent buf slice
            //         ^ start_pos

            let start_pos = *self.buf.written;

            let empty_start = self.buf.slice.as_mut_ptr();
            let cmd_meta_start = unsafe { empty_start.add(self.buf.slice.len()) };
            let vec_meta_start = unsafe { self.og_end.sub(VEC_SIZE) };

            let cmd_meta_len = unsafe { vec_meta_start.offset_from(cmd_meta_start) as usize };
            // Number of commands written
            let count = cmd_meta_len / CMD_SIZE;
            assert_eq!(cmd_meta_len % CMD_SIZE, 0);
            assert_eq!(count, self.count);

            // Shift and reverse.
            let (align_offset, new_vec_start) = adjust(
                unsafe {
                    core::slice::from_raw_parts_mut(
                        empty_start,
                        vec_meta_start.offset_from(empty_start) as usize,
                    )
                },
                self.buf.slice.len(),
            );

            let out = unsafe {
                Place::new_unchecked(
                    start_pos + new_vec_start.offset_from(empty_start) as usize,
                    new_vec_start,
                )
                .cast_unchecked::<ArchivedVec<ArchivedSyncCommand<'static>>>()
            };
            assert!(unsafe { out.ptr() }.is_aligned());
            ArchivedVec::<ArchivedSyncCommand<'static>>::resolve_from_len(
                count,
                VecResolver::from_pos(start_pos + align_offset),
                out,
            );

            *self.buf.written +=
                unsafe { new_vec_start.offset_from(empty_start) } as usize + VEC_SIZE;
        }

        fn reserve_cmd(&mut self) -> Result<Reserve<'data>, Overflow> {
            let end = self.buf.slice.len().checked_sub(CMD_SIZE).ok_or(Overflow)?;
            let slice = self.buf.slice.split_off_mut(end..).ok_or(Overflow)?;
            Ok(Reserve {
                slice,
                pos: *self.buf.written + end,
            })
        }
    }

    pub struct Reserve<'a> {
        slice: &'a mut [u8],
        pos: usize,
    }

    impl rkyv::rancor::Fallible for Reserve<'_> {
        type Error = Overflow;
    }

    impl rkyv::ser::Positional for Reserve<'_> {
        fn pos(&self) -> usize {
            self.pos
        }
    }

    impl rkyv::ser::Writer for Reserve<'_> {
        fn write(&mut self, bytes: &[u8]) -> Result<(), <Self as rkyv::rancor::Fallible>::Error> {
            assert!(
                self.slice
                    .as_ptr()
                    .cast::<ArchivedSyncCommand<'static>>()
                    .is_aligned()
            );
            self.slice
                .split_off_mut(..bytes.len())
                .ok_or(Overflow)?
                .copy_from_slice(bytes);
            self.pos += bytes.len();
            assert_eq!(self.slice.len(), 0);
            Ok(())
        }
    }

    /// Shift, reverse, and update archived sync commands.
    fn adjust(slice: &mut [u8], start: usize) -> (usize, *mut u8) {
        let align_offset = slice
            .as_ptr()
            .align_offset(align_of::<ArchivedSyncCommand<'static>>());
        let slice = &mut slice[align_offset..];
        let start = start - align_offset;

        // Shift
        slice.copy_within(start.., 0);

        // re-slice to contain just the items
        let len = slice.len() - start;
        let slice = &mut slice[..len];
        let new_end = unsafe { slice.as_mut_ptr().add(len) };
        let (chunks, _) = slice.as_chunks_mut::<CMD_SIZE>();

        // reverse the items
        chunks.reverse();

        let cmds = unsafe {
            core::slice::from_raw_parts_mut(
                chunks.as_mut_ptr().cast::<ArchivedSyncCommand<'static>>(),
                chunks.len(),
            )
        };
        let count = cmds.len();

        for (i, cmd) in cmds.iter_mut().enumerate() {
            let delta_index = count as isize - 1 - i as isize - i as isize;
            let offset = start as isize + delta_index * CMD_SIZE as isize;
            unsafe {
                cmd.data.adjust(offset);
            }
            if let Some(policy) = cmd.policy.as_mut() {
                unsafe {
                    policy.adjust(offset);
                }
            }
        }

        (align_offset, new_end)
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
