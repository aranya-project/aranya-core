//! Interface for syncing state between clients.

use core::convert::Infallible;

use buggy::Bug;
use postcard::Error as PostcardError;
use rkyv::rancor::ResultExt as _;
use serde::{Deserialize, Serialize};

use crate::{
    Address, Prior,
    command::{CmdId, Command, Priority},
    rkyv_utils::{self, ArchivedBytes, Bytes},
    storage::{MAX_COMMAND_LENGTH, StorageError},
};

mod dispatcher;
mod requester;
mod responder;

pub use dispatcher::{SubscribeResult, SyncHelloType, SyncType};
pub use requester::{SyncRequestMessage, SyncRequester};
pub use responder::{PeerCache, SyncResponder, SyncResponseMessage};

// TODO: These should all be compile time parameters

/// The maximum number of heads that will be stored for a peer.
pub const PEER_HEAD_MAX: usize = 10;

/// The maximum number of samples in a request
#[cfg(feature = "low-mem-usage")]
const COMMAND_SAMPLE_MAX: usize = 20;
#[cfg(not(feature = "low-mem-usage"))]
const COMMAND_SAMPLE_MAX: usize = 100;

/// The maximum number of missing segments that can be requested
/// in a single message
#[cfg(feature = "low-mem-usage")]
const REQUEST_MISSING_MAX: usize = 1;
#[cfg(not(feature = "low-mem-usage"))]
const REQUEST_MISSING_MAX: usize = 100;

/// The maximum number of segments which can be stored to send
#[cfg(feature = "low-mem-usage")]
const SEGMENT_BUFFER_MAX: usize = 10;
#[cfg(not(feature = "low-mem-usage"))]
const SEGMENT_BUFFER_MAX: usize = 100;

/// The maximum size of a sync message
// TODO(jdygert): Configurable and sent in request.
pub const MAX_SYNC_MESSAGE_SIZE: usize = 1024 + MAX_COMMAND_LENGTH * 100;

/// Represents high-level data of a command.
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandMeta {
    id: CmdId,
    priority: Priority,
    parent: Prior<Address>,
    policy_length: u32,
    length: u32,
    max_cut: usize,
}

impl CommandMeta {
    pub fn address(&self) -> Address {
        Address {
            id: self.id,
            max_cut: self.max_cut,
        }
    }
}

/// An error returned by the syncer.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync session ID does not match")]
    SessionMismatch,
    #[error("missing sync response")]
    MissingSyncResponse,
    #[error("syncer state not valid for this message")]
    SessionState,
    #[error("syncer not ready for operation")]
    NotReady,
    #[error("too many commands sent")]
    CommandOverflow,
    #[error("target buffer is too small")]
    BufferTooSmall,
    #[error("could not access commands with rkyv")]
    RkyvAccess(#[from] rkyv::rancor::Error),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("serialize error: {0}")]
    Serialize(#[from] PostcardError),
    #[error(transparent)]
    Bug(#[from] Bug),
}

/// Sync command to be committed to graph.
#[derive(Serialize, Deserialize, Debug, rkyv::Archive, rkyv::Serialize)]
pub struct SyncCommand<'a> {
    priority: Priority,
    id: CmdId,
    parent: Prior<Address>,
    #[rkyv(with = rkyv::with::MapNiche<Bytes>)]
    policy: Option<&'a [u8]>,
    #[rkyv(with = Bytes)]
    data: &'a [u8],
    max_cut: usize,
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

    fn max_cut(&self) -> Result<usize, Bug> {
        Ok(self.max_cut)
    }
}

impl<'a> Command for ArchivedSyncCommand<'a> {
    fn priority(&self) -> Priority {
        rkyv::api::low::deserialize::<_, Infallible>(&self.priority).always_ok()
    }

    fn id(&self) -> CmdId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        rkyv::api::low::deserialize::<_, Infallible>(&self.parent).always_ok()
    }

    fn policy(&self) -> Option<&'a [u8]> {
        self.policy.as_ref().map(ArchivedBytes::as_slice)
    }

    fn bytes(&self) -> &'a [u8] {
        self.data.as_slice()
    }

    fn max_cut(&self) -> Result<usize, Bug> {
        Ok(self.max_cut.to_native() as usize)
    }
}

unsafe impl rkyv_utils::Adjust for ArchivedSyncCommand<'_> {
    unsafe fn adjust(
        &mut self,
        amount: rkyv::primitive::FixedIsize,
    ) -> Result<(), rkyv_utils::AdjustOverflow> {
        unsafe {
            self.policy.adjust(amount)?;
            self.data.adjust(amount)?;
        }
        Ok(())
    }
}
