//! Interfaces for an application to begin a runtime.
//!
//! An [`Engine`] stores policies for an application. A [`Policy`] is required
//! to process [`Command`]s and defines how the runtime's graph is constructed.

use buggy::Bug;
use serde::{Deserialize, Serialize};

use crate::{
    Address,
    command::{Command, CommandId},
    storage::{FactPerspective, Perspective},
};

/// An error returned by the runtime engine.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    #[error("read error")]
    Read,
    #[error("write error")]
    Write,
    #[error("check error")]
    Check,
    #[error("panic")]
    Panic,
    #[error("internal error")]
    InternalError,
    #[error(transparent)]
    Bug(#[from] Bug),
}

impl From<core::convert::Infallible> for EngineError {
    fn from(error: core::convert::Infallible) -> Self {
        match error {}
    }
}

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyId(usize);

impl PolicyId {
    pub fn new(id: usize) -> Self {
        Self(id)
    }
}

/// The [`Engine`] manages storing and retrieving [`Policy`].
pub trait Engine {
    type Policy: Policy<Effect = Self::Effect>;

    type Effect;

    /// Add a policy to this runtime.
    ///
    /// # Arguments
    ///
    /// * `policy` - Byte slice that holds a policy.
    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, EngineError>;

    /// Get a policy from this runtime.
    ///
    /// # Arguments
    ///
    /// * `policy` - Byte slice representing a [`PolicyId`].
    fn get_policy(&self, id: PolicyId) -> Result<&Self::Policy, EngineError>;
}

/// The [`Sink`] transactionally consumes effects from evaluating [`Policy`].
pub trait Sink<E> {
    fn begin(&mut self);
    fn consume(&mut self, effect: E);
    fn rollback(&mut self);
    fn commit(&mut self);
}

pub struct NullSink;

impl<E> Sink<E> for NullSink {
    fn begin(&mut self) {}

    fn consume(&mut self, _effect: E) {}

    fn rollback(&mut self) {}

    fn commit(&mut self) {}
}

/// The IDs to a merge command in sorted order.
pub struct MergeIds {
    // left < right
    left: Address,
    right: Address,
}

impl MergeIds {
    /// Create [`MergeIds`] by ordering two [`Address`]s and ensuring they are different.
    pub fn new(a: Address, b: Address) -> Option<Self> {
        use core::cmp::Ordering;
        match a.id.cmp(&b.id) {
            Ordering::Less => Some(Self { left: a, right: b }),
            Ordering::Equal => None,
            Ordering::Greater => Some(Self { left: b, right: a }),
        }
    }
}

impl From<MergeIds> for (CommandId, CommandId) {
    /// Convert [`MergeIds`] into an ordered pair of [`CommandId`]s.
    fn from(value: MergeIds) -> Self {
        (value.left.id, value.right.id)
    }
}

impl From<MergeIds> for (Address, Address) {
    /// Convert [`MergeIds`] into an ordered pair of [`Address`]s.
    fn from(value: MergeIds) -> Self {
        (value.left, value.right)
    }
}

/// Whether to execute a command's recall block on command failure
pub enum CommandRecall {
    /// Don't recall command
    None,
    /// Recall if the command fails with a [`aranya_policy_vm::ExitReason::Check`]
    OnCheck,
}

/// [`Policy`] evaluates actions and [`Command`]s on the graph, emitting effects
/// as a result.
pub trait Policy {
    type Action<'a>;
    type Effect;
    type Command<'a>: Command;

    /// Policies have a serial number which can be used to order them.
    /// This is used to support inband policy upgrades.
    fn serial(&self) -> u32;

    /// Evaluate a command at the given perspective. If the command is accepted, effects may
    /// be emitted to the sink and facts may be written to the perspective. Returns an error
    /// for a rejected command.
    fn call_rule(
        &self,
        command: &impl Command,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<Self::Effect>,
        recall: CommandRecall,
    ) -> Result<(), EngineError>;

    /// Process an action checking each published command against the policy and emitting
    /// effects to the sink. All published commands are handled transactionally where if any
    /// published command is rejected no commands are added to the storage.
    fn call_action(
        &self,
        action: Self::Action<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effect>,
    ) -> Result<(), EngineError>;

    /// Produces a merge message serialized to target. The `struct` representing the
    /// Command is returned.
    fn merge<'a>(
        &self,
        target: &'a mut [u8],
        ids: MergeIds,
    ) -> Result<Self::Command<'a>, EngineError>;
}
