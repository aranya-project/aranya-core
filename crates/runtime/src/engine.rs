//! Interfaces for an application to begin a runtime.
//!
//! An [`Engine`] stores policies for an application. A [`Policy`] is required
//! to process [`Command`]s and defines how the runtime's graph is constructed.

use core::fmt;

use buggy::Bug;
use serde::{Deserialize, Serialize};

use crate::{
    command::{Command, Id},
    storage::{FactPerspective, Perspective},
};

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

pub trait Engine {
    type Policy: Policy<Effects = Self::Effects>;

    type Effects;

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
    left: Id,
    right: Id,
}

impl MergeIds {
    /// Create [`MergeIds`] by ordering two [`Id`]s and ensuring they are different.
    pub fn new(a: Id, b: Id) -> Option<Self> {
        use core::cmp::Ordering;
        match a.cmp(&b) {
            Ordering::Less => Some(Self { left: a, right: b }),
            Ordering::Equal => None,
            Ordering::Greater => Some(Self { left: b, right: a }),
        }
    }
}

impl From<MergeIds> for (Id, Id) {
    /// Convert [`MergeIds`] into an ordered pair of [`Id`]s.
    fn from(value: MergeIds) -> Self {
        (value.left, value.right)
    }
}

pub trait Policy {
    type Payload<'a>;
    type Actions<'a>;
    type Effects;
    type Command<'a>: Command<'a>;

    /// Policies have a serial number which can be used to order them.
    /// This is used to support inband policy upgrades.
    fn serial(&self) -> u32;

    /// Evaluate a command at the given perspective. If the command is accepted,
    /// effects may be emitted to the sink and facts may be written to the
    /// perspective. Returns true for an accepted command and false for a
    /// rejected command.
    fn call_rule<'a>(
        &self,
        command: &impl Command<'a>,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError>;

    /// Process an action checking each emitted command against the policy and producing
    /// effects to the sink. All emitted commands are handled transactionally where if
    /// any emitted command is rejected no commands are added to the storage.
    fn call_action(
        &self,
        parent_id: &Id,
        action: Self::Actions<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError>;

    /// Deserialize a bytes in to a command
    fn read_command<'a>(&self, id: Id, data: &'a [u8]) -> Result<Self::Command<'a>, EngineError>;

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

    /// Produces a protocol message serialized to target. The `struct` representing the
    /// Command is returned.
    fn basic<'a>(
        &self,
        target: &'a mut [u8],
        parent: Id,
        payload: Self::Payload<'a>,
    ) -> Result<Self::Command<'a>, EngineError>;
}
