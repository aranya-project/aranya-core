//! Interfaces for an application to begin a runtime.
//!
//! An [`Engine`] stores policies for an application. A [`Policy`] is required
//! to process [`Command`]s and defines how the runtime's graph is constructed.

use core::fmt;

use buggy::Bug;
use serde::{Deserialize, Serialize};

use crate::{
    command::{Command, CommandId},
    storage::{FactPerspective, Perspective},
};

/// An error returned by the runtime engine.
#[derive(Debug)]
pub enum EngineError {
    Read,
    Write,
    Check,
    InternalError,
    Bug(Bug),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read error"),
            Self::Write => write!(f, "write error "),
            Self::Check => write!(f, "check error"),
            Self::InternalError => write!(f, "internal error"),
            Self::Bug(b) => write!(f, "{b}"),
        }
    }
}

impl From<Bug> for EngineError {
    fn from(value: Bug) -> Self {
        EngineError::Bug(value)
    }
}

impl trouble::Error for EngineError {}

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyId(usize);

impl PolicyId {
    pub fn new(id: usize) -> Self {
        PolicyId(id)
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
    fn get_policy<'a>(&'a self, id: &PolicyId) -> Result<&'a Self::Policy, EngineError>;
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
    left: CommandId,
    right: CommandId,
}

impl MergeIds {
    /// Create [`MergeIds`] by ordering two [`CommandId`]s and ensuring they are different.
    pub fn new(a: CommandId, b: CommandId) -> Option<Self> {
        use core::cmp::Ordering;
        match a.cmp(&b) {
            Ordering::Less => Some(Self { left: a, right: b }),
            Ordering::Equal => None,
            Ordering::Greater => Some(Self { left: b, right: a }),
        }
    }
}

impl From<MergeIds> for (CommandId, CommandId) {
    /// Convert [`MergeIds`] into an ordered pair of [`CommandId`]s.
    fn from(value: MergeIds) -> Self {
        (value.left, value.right)
    }
}

/// [`Policy`] evaluates actions and [`Command`]s on the graph, emitting effects
/// as a result.
pub trait Policy {
    type Payload<'a>;
    type Action<'a>;
    type Effect;
    type Command<'a>: Command;

    /// Policies have a serial number which can be used to order them.
    /// This is used to support inband policy upgrades.
    fn serial(&self) -> u32;

    /// Evaluate a command at the given perspective. If the command is accepted,
    /// effects may be emitted to the sink and facts may be written to the
    /// perspective. Returns true for an accepted command and false for a
    /// rejected command.
    fn call_rule(
        &self,
        command: &impl Command,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<Self::Effect>,
    ) -> Result<bool, EngineError>;

    /// Process an action checking each emitted command against the policy and producing
    /// effects to the sink. All emitted commands are handled transactionally where if
    /// any emitted command is rejected no commands are added to the storage.
    fn call_action(
        &self,
        parent_id: &CommandId,
        action: Self::Action<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effect>,
    ) -> Result<bool, EngineError>;

    /// Produces an init message serialized to target. The `struct` representing the
    /// Command is returned.
    fn init<'a>(
        &self,
        target: &'a mut [u8],
        policy_data: &[u8],
        payload: Self::Payload<'_>,
    ) -> Result<Self::Command<'a>, EngineError>;

    /// Produces a merge message serialized to target. The `struct` representing the
    /// Command is returned.
    fn merge<'a>(
        &self,
        target: &'a mut [u8],
        ids: MergeIds,
    ) -> Result<Self::Command<'a>, EngineError>;
}
