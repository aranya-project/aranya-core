use buggy::BugExt as _;
use heapless::Vec;

use super::{SyncError, hello::HelloRequest, message::CommandMeta};
use crate::{
    CmdId, Prior,
    command::{Address, Command, Priority},
    storage::{GraphId, Location, MaxCut, Segment as _, Storage, StorageError, TraversalBuffer},
};

/// The maximum number of heads that will be cached for a given peer.
pub(super) const PEER_HEAD_MAX: usize = 10;

/// The maximum number of segments which can be stored to send
#[cfg(feature = "low-mem-usage")]
pub(super) const SEGMENT_BUFFER_MAX: usize = 10;
#[cfg(not(feature = "low-mem-usage"))]
pub(super) const SEGMENT_BUFFER_MAX: usize = 100;

/// Tracks the set of graph heads a remote peer is known to have.
///
/// Used by both [`SyncRequester`](super::SyncRequester) to produce tighter samples and
/// [`SyncResponder`](super::SyncResponder) to avoid sending segments the peer already has.
#[derive(Debug, Default)]
pub(super) struct PeerCache<const MAX_HEADS: usize = PEER_HEAD_MAX> {
    heads: Vec<Address, MAX_HEADS>,
}

impl<const MAX_HEADS: usize> PeerCache<MAX_HEADS> {
    /// Create a new `PeerCache`.
    pub(super) const fn new() -> Self {
        Self { heads: Vec::new() }
    }

    /// Returns the currently stored heads.
    pub(super) fn heads(&self) -> &[Address] {
        &self.heads
    }

    /// Add a new head command to the cache, pruning any heads that are now dominated by it.
    pub(super) fn add_command<S: Storage>(
        &mut self,
        storage: &S,
        command: Address,
        cmd_loc: Location,
        buffer: &mut TraversalBuffer,
    ) -> Result<(), StorageError> {
        let mut dominated_by_existing = false;

        self.heads.retain(|existing| {
            Self::should_retain(
                storage,
                existing,
                cmd_loc,
                buffer,
                &mut dominated_by_existing,
            )
            .unwrap_or(false)
        });

        if !dominated_by_existing && !self.heads.is_full() {
            self.heads.push(command).ok().assume("checked capacity")?;
        }

        Ok(())
    }

    fn should_retain<S: Storage>(
        storage: &S,
        existing: &Address,
        new_loc: Location,
        buffer: &mut TraversalBuffer,
        dominated: &mut bool,
    ) -> Result<bool, StorageError> {
        let new_seg = storage.get_segment(new_loc)?;

        let ex_loc = storage
            .get_location(*existing, buffer)?
            .assume("existing head must resolve")?;
        let ex_seg = storage.get_segment(ex_loc)?;

        // Check to see if we're referencing the same command.
        if let Some(cmd) = new_seg.get_command(new_loc) {
            if existing.id == cmd.address()?.id {
                *dominated = true;
            }
        }

        // If the new location is an ancestor of the existing one, don't add the new one.
        if (new_loc.same_segment(ex_loc) && new_loc.max_cut <= ex_loc.max_cut)
            || storage.is_ancestor(new_loc, &ex_seg, buffer)?
        {
            *dominated = true;
        }

        // If the existing location is an ancestor of the new one, remove the existing one.
        Ok(!storage.is_ancestor(ex_loc, &new_seg, buffer)?)
    }
}

/// Routing result from [`SyncResponder::receive`](super::SyncResponder::receive).
///
/// After calling `receive`, this contains the public details about the request. This is used for
/// things like verifying the Graph ID and registering a new hello subscription.
#[derive(Debug)]
#[non_exhaustive]
pub(super) enum Received {
    /// A sync request was processed.
    Sync(SyncRequest),
    /// A hello protocol message was received.
    Hello(HelloRequest),
}

/// Metadata extracted from an incoming sync request.
///
/// The `graph_id` is needed for authentication by the application.
#[derive(Debug)]
pub(super) struct SyncRequest {
    /// The graph the peer wants to sync.
    pub graph_id: GraphId,
}

/// A parsed sync command to be committed to graph.
#[derive(Debug)]
pub(super) struct SyncCommand<'a> {
    pub priority: Priority,
    pub id: CmdId,
    pub parent: Prior<Address>,
    pub policy: Option<&'a [u8]>,
    pub data: &'a [u8],
    pub max_cut: MaxCut,
}

impl<'a> Command for SyncCommand<'a> {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> CmdId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        self.parent
    }

    fn policy(&self) -> Option<&'a [u8]> {
        self.policy
    }

    fn bytes(&self) -> &'a [u8] {
        self.data
    }

    fn max_cut(&self) -> Result<MaxCut, buggy::Bug> {
        Ok(self.max_cut)
    }
}

pub(super) struct SyncCommands<'a> {
    remaining: &'a [u8],
}

impl<'a> SyncCommands<'a> {
    /// Create a new `SyncCommands` wrapper.
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }

    // Parse out a `SyncCommand` from the stored data.
    fn parse_command(&mut self) -> Result<SyncCommand<'a>, SyncError> {
        // Get the initial `CommandMeta` data.
        let (meta, rest): (CommandMeta, &'a [u8]) = postcard::take_from_bytes(self.remaining)?;

        // Verify that we actually have enough data to properly parse a command.
        let policy_length = meta.policy_length as usize;
        let data_length = meta.length as usize;
        let total = policy_length
            .checked_add(data_length)
            .assume("policy_length + length mustn't overflow")?;
        if rest.len() < total {
            return Err(SyncError::Serialize(
                postcard::Error::DeserializeUnexpectedEnd,
            ));
        }

        // Extract the policy and command data.
        let policy = (policy_length > 0).then(|| &rest[..policy_length]);
        let data = &rest[policy_length..total];
        self.remaining = &rest[total..];

        Ok(SyncCommand {
            id: meta.id,
            priority: meta.priority,
            parent: meta.parent,
            policy,
            data,
            max_cut: meta.max_cut,
        })
    }
}

impl<'a> Iterator for SyncCommands<'a> {
    type Item = Result<SyncCommand<'a>, SyncError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        match self.parse_command() {
            Ok(cmd) => Some(Ok(cmd)),
            Err(e) => {
                self.remaining = &[];
                Some(Err(e))
            }
        }
    }
}
