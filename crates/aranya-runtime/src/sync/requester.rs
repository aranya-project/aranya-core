//! # Example
//!
//! ```ignore
//! let mut requester = SyncRequester::new(graph_id, rng)?;
//!
//! while let Some(len) = requester.request(&mut buffer, provider, cache.heads(), traversal)? {
//!     stream.send(&buffer[..len]).await?;
//!     let len = stream.receive(buffer).await?;
//!     if let Some(cmds) = requester.receive(&buffer[..len])? {
//!         for cmd in cmds {
//!             commit(cmd?);
//!         }
//!     }
//! }
//!
//! let len = requester.hello_subscribe(&mut buffer, &params)?;
//! stream.send(&buffer[..len]).await?;
//! let len = stream.receive(buffer).await?;
//! requester.receive(&buffer[..len])?;
//! ```
use aranya_crypto::Csprng;
use heapless::Vec;

use super::{
    SyncError, diff,
    hello::HelloParams,
    message::{HelloNotifyData, HelloSubscribeData, HelloUnsubscribeData, SyncHeader, Tag},
    types::{PEER_HEAD_MAX, SyncCommands},
};
use crate::{
    command::Address,
    storage::{GraphId, Location, StorageError, StorageProvider, TraversalBuffers},
};

pub struct SyncRequester {
    /// The current Session ID for tracking a conversation.
    session_id: u128,
    /// The current Graph ID being synced.
    graph_id: GraphId,
    /// Set by [`Self::receive`] when the conversation is complete.
    done: bool,
}

impl SyncRequester {
    /// Create a new `SyncRequester` for the given graph.
    pub fn new(graph_id: GraphId, rng: impl Csprng) -> Result<Self, SyncError> {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        Ok(Self {
            session_id: u128::from_le_bytes(buf),
            graph_id,
            done: false,
        })
    }

    /// The current Graph ID being synced.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }

    pub fn request<const MAX_HEADS: usize>(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
        peer_cache: &[Address],
        traversal: &mut TraversalBuffers,
    ) -> Result<Option<usize>, SyncError> {
        if self.done {
            return Ok(None);
        }

        // Write the initial message tag.
        let mut cursor = postcard::to_slice(&Tag::SyncRequest, target)?.len();

        // Write the needed header data for the sync request.
        let hdr = SyncHeader {
            session_id: self.session_id,
            graph_id: self.graph_id,
        };
        cursor += postcard::to_slice(&hdr, &mut target[cursor..])?.len();

        // Attempt to get the storage for the current Graph ID.
        match provider.get_storage(self.graph_id) {
            Err(StorageError::NoSuchStorage) => {}
            Err(e) => return Err(SyncError::Storage(e)),
            Ok(storage) => {
                // Write as many samples as we can fit inside the target buffer.
                let mut cache_buf: Vec<Location, PEER_HEAD_MAX> = Vec::new();
                let mut samples =
                    diff::CommandSampler::new(storage, traversal, peer_cache, &mut cache_buf)?;
                while let Some(addr) = samples.next()? {
                    match postcard::to_slice(&addr, &mut target[cursor..]) {
                        Ok(written) => cursor += written.len(),
                        Err(_) => break, // buffer is full
                    }
                }
            }
        }

        self.done = true;
        Ok(Some(cursor))
    }

    pub fn receive<'a>(&mut self, data: &'a [u8]) -> Result<Option<SyncCommands<'a>>, SyncError> {
        let (tag, rest): (Tag, &[u8]) = postcard::take_from_bytes(data)?;

        match tag {
            Tag::SyncResponse => {
                let (hdr, body): (SyncHeader, &[u8]) = postcard::take_from_bytes(rest)?;

                if hdr.session_id != self.session_id {
                    return Err(SyncError::SessionMismatch);
                }

                // NB: this currently acts as a single round trip. Eventually we'll want to add a "more coming" flag.
                self.done = true;

                if body.is_empty() {
                    return Ok(None);
                }
                Ok(Some(SyncCommands::new(body)))
            }
            Tag::HelloAck => Ok(None),
            _ => Err(SyncError::UnexpectedMessage),
        }
    }

    /// Write a hello-subscribe message into `target`.
    pub fn hello_subscribe(
        &self,
        target: &mut [u8],
        params: &HelloParams,
    ) -> Result<usize, SyncError> {
        let mut cursor = postcard::to_slice(&Tag::HelloSubscribe, target)?.len();
        let data = HelloSubscribeData {
            graph_id: self.graph_id,
            graph_change_delay: params.graph_change_delay,
            schedule_delay: params.schedule_delay,
            duration: params.duration,
        };
        cursor += postcard::to_slice(&data, &mut target[cursor..])?.len();
        Ok(cursor)
    }

    /// Write a hello-unsubscribe message into `target`.
    pub fn hello_unsubscribe(&self, target: &mut [u8]) -> Result<usize, SyncError> {
        let mut cursor = postcard::to_slice(&Tag::HelloUnsubscribe, target)?.len();
        let data = HelloUnsubscribeData {
            graph_id: self.graph_id,
        };
        cursor += postcard::to_slice(&data, &mut target[cursor..])?.len();
        Ok(cursor)
    }

    /// Write a hello-notify message into `target`.
    pub fn hello_notify(&self, target: &mut [u8], head: Address) -> Result<usize, SyncError> {
        let mut cursor = postcard::to_slice(&Tag::HelloNotify, target)?.len();
        let data = HelloNotifyData {
            graph_id: self.graph_id,
            head,
        };
        cursor += postcard::to_slice(&data, &mut target[cursor..])?.len();
        Ok(cursor)
    }
}
