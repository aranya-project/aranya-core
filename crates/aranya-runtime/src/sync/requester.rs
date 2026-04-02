//! # Example Usage
//! A sync exchange is driven by the requester.
//! ```
//! let mut exchange = SyncExchange::new(graph_id, rng);
//!
//! while let Some(len) = exchange.request(buffer, provider, cache, traversal)? {
//!     stream.send(&buffer[..len]).await?;
//!     let n = stream.receive(buffer).await?;
//!     if let Some(cmds) = exchange.receive(&buffer[..n])? {
//!         self.commit_commands(peer, &cmds, &mut sink).await?;
//!     }
//! }
//! ```
use aranya_crypto::Csprng;
use buggy::BugExt as _;
use heapless::Vec;

use super::{
    COMMAND_RESPONSE_MAX, COMMAND_SAMPLE_MAX, CommandMeta, MAX_SYNC_MESSAGE_SIZE, PeerCache,
    SyncCommand, SyncError, diff,
    wire::{RequestMessage, ResponseMessage},
};
use crate::storage::{GraphId, StorageError, StorageProvider, TraversalBuffers};

struct SyncExchange {
    /// The current Session ID for tracking an exchange.
    session_id: u128,
    /// The current Graph ID being synced.
    graph_id: GraphId,
    /// Used in Sync v1 to flag whether we're done with a sync exchange.
    sent_request: bool,
}

impl SyncExchange {
    fn new<R: Csprng>(graph_id: GraphId, rng: R) -> Result<Self, SyncError> {
        let mut session_bytes = [0u8; 16];
        rng.fill_bytes(&mut session_bytes);
        Ok(Self {
            session_id: u128::from_le_bytes(session_bytes),
            graph_id,
            sent_request: false,
        })
    }

    fn graph_id(&self) -> GraphId {
        self.graph_id
    }

    fn request<const MAX_HEADS: usize>(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        peer_cache: &mut PeerCache<MAX_HEADS>,
        traversal: &mut TraversalBuffers,
    ) -> Result<Option<usize>, SyncError> {
        if self.sent_request {
            return Ok(None);
        }

        let samples = match provider.get_storage(self.graph_id) {
            Err(StorageError::NoSuchStorage) => Vec::new(),
            Err(e) => return Err(SyncError::Storage(e)),
            Ok(storage) => diff::sample_commands(storage, peer_cache, traversal)?,
        };

        let msg: RequestMessage<COMMAND_SAMPLE_MAX> = RequestMessage::Sync {
            session_id: self.session_id,
            graph_id: self.graph_id,
            max_bytes: MAX_SYNC_MESSAGE_SIZE as u64,
            samples,
        };

        let len = postcard::to_slice(&msg, target)?.len();
        self.sent_request = true;
        Ok(Some(len))
    }

    fn receive<'a>(
        &mut self,
        data: &'a [u8],
    ) -> Result<Option<Vec<SyncCommand<'a>, COMMAND_RESPONSE_MAX>>, SyncError> {
        let (msg, remaining): (ResponseMessage, &'a [u8]) = postcard::take_from_bytes(data)?;

        match msg {
            ResponseMessage::Sync {
                session_id,
                commands,
            } => {
                if session_id != self.session_id {
                    return Err(SyncError::SessionMismatch);
                }
                let cmds = Self::parse_commands(commands, remaining)?;
                if cmds.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(cmds))
                }
            }
            ResponseMessage::HelloAck => Ok(None),
        }
    }

    fn parse_commands<'a>(
        metas: Vec<CommandMeta, COMMAND_RESPONSE_MAX>,
        remaining: &'a [u8],
    ) -> Result<Vec<SyncCommand<'a>, COMMAND_RESPONSE_MAX>, SyncError> {
        let mut result = Vec::new();
        let mut offset: usize = 0;

        for meta in metas {
            let policy_len = meta.policy_length as usize;

            let policy = match policy_len == 0 {
                true => None,
                false => {
                    let end = offset
                        .checked_add(policy_len)
                        .assume("offset + policy_len mustn't overflow")?;
                    let policy = &remaining[offset..end];
                    offset = end;
                    Some(policy)
                }
            };

            let data_len = meta.length as usize;
            let end = offset
                .checked_add(data_len)
                .assume("offset + len mustn't overflow")?;
            let payload = &remaining[offset..end];
            offset = end;

            result
                .push(SyncCommand {
                    id: meta.id,
                    priority: meta.priority,
                    parent: meta.parent,
                    policy,
                    data: payload,
                    max_cut: meta.max_cut,
                })
                .ok()
                .assume("metas fits in result")?;
        }

        Ok(result)
    }
}
