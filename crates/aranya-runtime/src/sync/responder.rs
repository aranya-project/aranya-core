use buggy::{BugExt as _, bug};
use heapless::Vec;

use super::{
    COMMAND_RESPONSE_MAX, CommandMeta, MAX_SYNC_MESSAGE_SIZE, PEER_HEAD_MAX, SEGMENT_BUFFER_MAX,
    SyncError, diff,
    wire::{RequestMessage, ResponseMessage},
};
use crate::{
    command::{Address, Command as _},
    storage::{
        GraphId, Location, Segment as _, Storage, StorageError, StorageProvider, TraversalBuffer,
        TraversalBuffers,
    },
};

/// Tracks the set of graph heads a remote peer is known to have.
///
/// Used by both [`SyncExchange`](super::SyncExchange) (to produce tighter samples) and
/// [`SyncResponder`] (to avoid sending segments the peer already has).
#[derive(Default, Debug)]
pub(super) struct PeerCache<const MAX_HEADS: usize = PEER_HEAD_MAX> {
    heads: Vec<Address, MAX_HEADS>,
}

impl<const MAX_HEADS: usize> PeerCache<MAX_HEADS> {
    /// Create a new `PeerCache`.
    const fn new() -> Self {
        Self { heads: Vec::new() }
    }

    /// Returns the currently stored heads.
    pub(super) fn heads(&self) -> &[Address] {
        &self.heads
    }

    /// Add a new head command to the cache, pruning any heads that are now dominated by it.
    fn add_command<S: Storage>(
        &mut self,
        storage: &S,
        command: Address,
        cmd_loc: Location,
        buffer: &mut TraversalBuffer,
    ) -> Result<(), StorageError> {
        let mut add_command = true;

        let mut retain = |existing: &Address, new_loc: Location| {
            let new_seg = storage.get_segment(new_loc)?;
            let ex_loc = storage.get_location(*existing, buffer)?.assume("exists")?;
            let ex_seg = storage.get_segment(ex_loc)?;
            if existing.id == new_seg.get_command(new_loc).assume("exists")?.address()?.id {
                add_command = false;
            }
            // If the new head is an ancestor of the request head, don't add it.
            if (new_loc.same_segment(ex_loc) && new_loc.max_cut <= ex_loc.max_cut)
                || storage.is_ancestor(new_loc, &ex_seg, buffer)?
            {
                add_command = false;
            }
            Ok::<bool, StorageError>(!storage.is_ancestor(ex_loc, &new_seg, buffer)?)
        };

        self.heads
            .retain(|head| retain(head, cmd_loc).unwrap_or(false));

        if add_command && !self.heads.is_full() {
            self.heads.push(command).ok().assume("checked capacity")?;
        }

        Ok(())
    }
}

#[derive(Default)]
struct SyncResponder<const MAX_SEGMENTS: usize = SEGMENT_BUFFER_MAX> {
    session_id: Option<u128>,
    graph_id: Option<GraphId>,
    to_send: Vec<Location, MAX_SEGMENTS>,
    next_send: usize,
}

impl<const MAX_SEGMENTS: usize> SyncResponder<MAX_SEGMENTS> {
    const fn new() -> Self {
        Self {
            session_id: None,
            graph_id: None,
            to_send: Vec::new(),
            next_send: 0,
        }
    }

    fn receive(
        &mut self,
        request: &[u8],
        provider: &mut impl StorageProvider,
        response_cache: &mut PeerCache,
        traversal: &mut TraversalBuffers,
    ) -> Result<(), SyncError> {
        let msg: RequestMessage = postcard::from_bytes(request)?;

        // TODO(nikki): this is fragile, we need to re-think this approach in the broader system.
        let RequestMessage::Sync {
            session_id,
            graph_id,
            samples,
            ..
        } = msg
        else {
            bug!("SyncResponder::receive called with non-sync message");
        };

        self.session_id = Some(session_id);
        self.graph_id = Some(graph_id);
        self.next_send = 0;

        let storage = provider.get_storage(graph_id)?;
        for &addr in &samples {
            if let Some(loc) = storage.get_location(addr, &mut traversal.primary)? {
                response_cache.add_command(storage, addr, loc, &mut traversal.primary)?;
            }
        }

        self.to_send = diff::find_needed_segments(&samples, storage, traversal)?;
        Ok(())
    }

    fn respond(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<Option<usize>, SyncError> {
        if self.next_send >= self.to_send.len() {
            return Ok(None);
        }

        let (metas, cmd_data, new_next) = self.collect_commands_from(provider)?;
        self.next_send = new_next;

        if metas.is_empty() {
            return Ok(None);
        }

        let resp = ResponseMessage::Sync {
            session_id: self.session_id()?,
            commands: metas,
        };
        let header_len = postcard::to_slice(&resp, target)?.len();

        // Append raw command bytes after the header.
        let total = header_len
            .checked_add(cmd_data.len())
            .assume("response fits in target")?;
        target
            .get_mut(header_len..total)
            .assume("target large enough")?
            .copy_from_slice(&cmd_data);

        Ok(Some(total))
    }

    fn collect_commands_from(
        &self,
        provider: &mut impl StorageProvider,
    ) -> Result<
        (
            Vec<CommandMeta, COMMAND_RESPONSE_MAX>,
            Vec<u8, MAX_SYNC_MESSAGE_SIZE>,
            usize,
        ),
        SyncError,
    > {
        let graph_id = self.graph_id.assume("graph_id must be set")?;
        let storage = provider.get_storage(graph_id)?;

        let mut metas: Vec<CommandMeta, COMMAND_RESPONSE_MAX> = Vec::new();
        let mut data: Vec<u8, MAX_SYNC_MESSAGE_SIZE> = Vec::new();
        let mut index = self.next_send;

        for i in self.next_send..self.to_send.len() {
            if metas.is_full() {
                break;
            }

            index = index.checked_add(1).assume("index + 1 mustn't overflow")?;

            let &location = self.to_send.get(i).assume("send index in bounds")?;

            let segment = storage.get_segment(location)?;
            let found = segment.get_from(location);

            for command in &found {
                let mut policy_length = 0u32;
                if let Some(policy) = command.policy() {
                    policy_length = policy.len() as u32;
                    data.extend_from_slice(policy)
                        .ok()
                        .assume("command_data fits")?;
                }

                let bytes = command.bytes();
                data.extend_from_slice(bytes)
                    .ok()
                    .assume("command_data fits")?;

                let max_cut = command.max_cut()?;
                metas
                    .push(CommandMeta {
                        id: command.id(),
                        priority: command.priority(),
                        parent: command.parent(),
                        policy_length,
                        length: bytes.len() as u32,
                        max_cut,
                    })
                    .ok()
                    .assume("checked capacity at loop top")?;

                if metas.is_full() {
                    break;
                }
            }
        }

        Ok((metas, data, index))
    }

    fn session_id(&self) -> Result<u128, SyncError> {
        Ok(self.session_id.assume("session_id is set")?)
    }
}
