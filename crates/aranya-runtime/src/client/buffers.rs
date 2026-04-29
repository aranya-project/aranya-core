//! Caller-supplied buffers for graph operations.
//!
//! Mirrors the [`TraversalBuffer`] / [`TraversalBuffers`] pattern from
//! `crate::storage`: the caller owns the buffer, hands `&mut` to an
//! operation, and the buffer's `get()` accessors clear on entry so the
//! caller never touches reset logic.

use crate::{
    Segment,
    client::{braiding::strand_heap::StrandHeap, convergence_map::ConvergenceStorage},
    storage::TraversalBuffer,
};

/// Reusable storage for one [`braid`](crate::client::braiding::braid) call.
///
/// Generic over the [`Segment`] type because [`StrandHeap`] caches
/// segments inline.
pub struct BraidBuffer<S> {
    pub strands: StrandHeap<S>,
    pub convergence: ConvergenceStorage,
}

impl<S: Segment> BraidBuffer<S> {
    pub const fn new() -> Self {
        Self {
            strands: StrandHeap::new(),
            convergence: ConvergenceStorage::new(),
        }
    }
}

impl<S: Segment> Default for BraidBuffer<S> {
    fn default() -> Self {
        Self::new()
    }
}

/// Bundle of buffers used by graph-mutating operations such as
/// [`add_commands`](crate::ClientState::add_commands).
///
/// Construct once per long-lived component and reuse across calls.
pub struct RuntimeBuffers<S> {
    pub traversal: TraversalBuffer,
    pub braid: BraidBuffer<S>,
}

impl<S: Segment> RuntimeBuffers<S> {
    pub const fn new() -> Self {
        Self {
            traversal: TraversalBuffer::new(),
            braid: BraidBuffer::new(),
        }
    }
}

impl<S: Segment> Default for RuntimeBuffers<S> {
    fn default() -> Self {
        Self::new()
    }
}
