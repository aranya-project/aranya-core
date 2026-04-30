use buggy::BugExt as _;
use heapless::Vec;

use super::{
    SyncError, diff,
    hello::{HelloParams, HelloRequest},
    message::{
        CommandMeta, HelloNotifyData, HelloSubscribeData, HelloUnsubscribeData, SyncHeader, Tag,
    },
    types::{PeerCache, Received, SEGMENT_BUFFER_MAX, SyncRequest},
};
use crate::{
    command::{Address, Command},
    storage::{
        GraphId, Location, Segment, Storage, StorageError, StorageProvider, TraversalBuffers,
    },
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Mode {
    #[default]
    Idle,
    Sync,
    HelloAck,
}

#[derive(Default)]
pub struct SyncResponder<const MAX_SEGMENTS: usize = SEGMENT_BUFFER_MAX> {
    session_id: Option<u128>,
    graph_id: Option<GraphId>,
    to_send: Vec<Location, MAX_SEGMENTS>,
    next_send: usize,
    mode: Mode,
}

impl<const MAX_SEGMENTS: usize> SyncResponder<MAX_SEGMENTS> {
    /// Creates a new `SyncResponder`.
    const fn new() -> Self {
        Self {
            session_id: None,
            graph_id: None,
            to_send: Vec::new(),
            next_send: 0,
            mode: Mode::Idle,
        }
    }

    /// Resets the `SyncResponder` to set up for a new request.
    fn reset(&mut self) {
        self.mode = Mode::Idle;
        self.to_send.clear();
        self.next_send = 0;
    }

    fn receive<const MAX_SAMPLES: usize>(
        &mut self,
        data: &[u8],
        provider: &mut impl StorageProvider,
        cache: &mut PeerCache,
        traversal: &mut TraversalBuffers,
    ) -> Result<Received, SyncError> {
        // Assume we're starting a brand new request.
        self.reset();

        let (tag, rest): (Tag, &[u8]) = postcard::take_from_bytes(data)?;

        match tag {
            Tag::SyncRequest => self.receive_sync::<MAX_SAMPLES>(rest, provider, cache, traversal),
            Tag::HelloSubscribe => {
                self.mode = Mode::HelloAck;
                Self::parse_hello_subscribe(rest)
            }
            Tag::HelloUnsubscribe => {
                self.mode = Mode::HelloAck;
                Self::parse_hello_unsubscribe(rest)
            }
            Tag::HelloNotify => {
                self.mode = Mode::HelloAck;
                Self::parse_hello_notify(rest)
            }
            _ => Err(SyncError::UnexpectedMessage),
        }
    }

    fn respond(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<Option<usize>, SyncError> {
        match self.mode {
            Mode::Idle => Ok(None),
            Mode::HelloAck => {
                self.mode = Mode::Idle;
                let n = postcard::to_slice(&Tag::HelloAck, target)?.len();
                Ok(Some(n))
            }
            Mode::Sync => self.respond_sync(target, provider),
        }
    }

    fn receive_sync<const MAX_SAMPLES: usize>(
        &mut self,
        rest: &[u8],
        provider: &mut impl StorageProvider,
        cache: &mut PeerCache,
        traversal: &mut TraversalBuffers,
    ) -> Result<Received, SyncError> {
        let (hdr, mut body): (SyncHeader, &[u8]) = postcard::take_from_bytes(rest)?;

        self.session_id = Some(hdr.session_id);
        self.graph_id = Some(hdr.graph_id);
        self.mode = Mode::Sync;

        let storage = match provider.get_storage(hdr.graph_id) {
            Ok(s) => s,
            Err(StorageError::NoSuchStorage) => {
                return Ok(Received::Sync(SyncRequest {
                    graph_id: hdr.graph_id,
                }));
            }
            Err(e) => return Err(SyncError::Storage(e)),
        };

        let mut samples: Vec<Address, MAX_SAMPLES> = Vec::new();
        while !body.is_empty() {
            let (addr, tail): (Address, &[u8]) = postcard::take_from_bytes(body)?;
            body = tail;

            if let Some(loc) = storage.get_location(addr, &mut traversal.primary)? {
                cache.add_command(storage, addr, loc, &mut traversal.primary)?;
            }
            insert_keep_highest_addr(&mut samples, addr);
        }

        self.to_send =
            diff::find_needed_segments::<MAX_SAMPLES, MAX_SEGMENTS>(&samples, storage, traversal)?;

        Ok(Received::Sync(SyncRequest {
            graph_id: hdr.graph_id,
        }))
    }

    fn respond_sync(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<Option<usize>, SyncError> {
        if self.next_send >= self.to_send.len() {
            self.mode = Mode::Idle;
            return Ok(None);
        }

        // Write tag + header.
        let mut cursor = postcard::to_slice(&Tag::SyncResponse, target)?.len();
        let graph_id = self.graph_id.assume("graph_id must be set")?;
        let hdr = SyncHeader {
            session_id: self.session_id()?,
            graph_id,
        };
        cursor += postcard::to_slice(&hdr, &mut target[cursor..])?.len();
        let header_end = cursor;

        let storage = provider.get_storage(graph_id)?;

        while self.next_send < self.to_send.len() {
            let loc = self.to_send[self.next_send];
            let segment = storage.get_segment(loc)?;
            let seg_idx = loc.segment;
            let mut max_cut = loc.max_cut;
            let mut finished_segment = true;

            loop {
                let cmd_loc = Location::new(seg_idx, max_cut);
                let Some(command) = segment.get_command(cmd_loc) else {
                    break;
                };

                let policy = command.policy().unwrap_or(&[]);
                let data = command.bytes();
                let meta = CommandMeta {
                    id: command.id(),
                    priority: command.priority(),
                    parent: command.parent(),
                    policy_length: policy.len() as u32,
                    length: data.len() as u32,
                    max_cut: command.max_cut()?,
                };

                let meta_size = postcard::experimental::serialized_size(&meta)?;
                let needed = meta_size + policy.len() + data.len();

                if cursor + needed > target.len() {
                    // Buffer full. Update the plan so we resume from here.
                    self.to_send[self.next_send] = cmd_loc;
                    finished_segment = false;
                    break;
                }

                cursor += postcard::to_slice(&meta, &mut target[cursor..])?.len();

                target[cursor..cursor + policy.len()].copy_from_slice(policy);
                cursor += policy.len();

                target[cursor..cursor + data.len()].copy_from_slice(data);
                cursor += data.len();

                max_cut = match max_cut.checked_add(1) {
                    Some(next) => next,
                    None => break,
                };
            }

            if finished_segment {
                self.next_send = self
                    .next_send
                    .checked_add(1)
                    .assume("next_send + 1 mustn't overflow")?;
            } else {
                break;
            }
        }

        // If we only wrote the header and the buffer is too small to even send one command, error.
        if cursor == header_end && self.next_send < self.to_send.len() {
            return Err(SyncError::BufferTooSmall);
        }

        // If we finished sending everything, we're done on this sync.
        if self.next_send >= self.to_send.len() {
            self.mode = Mode::Idle;
        }

        Ok(Some(cursor))
    }

    fn parse_hello_subscribe(rest: &[u8]) -> Result<Received, SyncError> {
        let (data, _): (HelloSubscribeData, _) = postcard::take_from_bytes(rest)?;
        Ok(Received::Hello(HelloRequest::Subscribe {
            graph_id: data.graph_id,
            params: HelloParams::new(data.graph_change_delay, data.schedule_delay, data.duration),
        }))
    }

    fn parse_hello_unsubscribe(rest: &[u8]) -> Result<Received, SyncError> {
        let (data, _): (HelloUnsubscribeData, _) = postcard::take_from_bytes(rest)?;
        Ok(Received::Hello(HelloRequest::Unsubscribe {
            graph_id: data.graph_id,
        }))
    }

    fn parse_hello_notify(rest: &[u8]) -> Result<Received, SyncError> {
        let (data, _): (HelloNotifyData, _) = postcard::take_from_bytes(rest)?;
        Ok(Received::Hello(HelloRequest::Notification {
            graph_id: data.graph_id,
            head: data.head,
        }))
    }

    fn session_id(&self) -> Result<u128, SyncError> {
        Ok(self.session_id.assume("session_id is set")?)
    }
}

/// Insert into a bounded vec, keeping the highest `max_cut` entries.
///
/// When full, replaces the entry with the lowest `max_cut` if the new entry's `max_cut` is higher.
fn insert_keep_highest_addr<const N: usize>(v: &mut Vec<Address, N>, addr: Address) {
    if v.push(addr).is_err() {
        if let Some((min_idx, min_loc)) = v.iter().enumerate().min_by_key(|(_, l)| l.max_cut) {
            if addr.max_cut > min_loc.max_cut {
                v[min_idx] = addr;
            }
        }
    }
}
