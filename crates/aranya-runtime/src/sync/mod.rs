//! Interface for syncing state between clients.

mod diff;
mod hello;
mod message;
mod requester;
mod responder;
mod types;

pub use self::{requester::SyncRequester, responder::SyncResponder};

/// An error returned by the syncer.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync session ID does not match")]
    SessionMismatch,
    #[error("syncer not ready for operation")]
    NotReady,
    #[error("unexpected message type")]
    UnexpectedMessage,
    #[error("buffer too small to fit any commands")]
    BufferTooSmall,
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("serialize error: {0}")]
    Serialize(#[from] postcard::Error),
    #[error(transparent)]
    Bug(#[from] buggy::Bug),
}
