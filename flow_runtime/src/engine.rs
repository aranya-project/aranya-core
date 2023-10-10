//! Interfaces for an application to begin a runtime.
//!
//! An [`Engine`] stores policies for an application. A [`Policy`] is required
//! to process [`Command`]s and defines how the runtime's graph is constructed.

use crate::command::{Command, Id};
use crate::storage::Perspective;

#[derive(Debug)]
pub enum EngineError {
    Read,
    Write,
    Check,
    InternalError,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Copy)]
pub struct PolicyId(usize);

impl PolicyId {
    pub fn new(id: usize) -> Self {
        PolicyId(id)
    }
}

pub trait Engine {
    type Policy: Policy<Payload = Self::Payload, Effects = Self::Effects, Actions = Self::Actions>;

    type Payload;
    type Actions;
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

pub trait Policy {
    type Payload;
    type Actions;
    type Effects;
    type Command<'a>: Command<'a>;

    /// Policies have a serial number which can be used to order them.
    /// This is used to support inband policy upgrades.
    fn serial(&self) -> u32;

    /// Check if a command is accepted at the given perspective.
    /// Any effects are returned via the sink. Returns true for accepted
    /// commands false for rejected commands. If accepted command is
    /// added to the perspective.
    fn call_rule<'a>(
        &self,
        command: &impl Command<'a>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError>;

    /// Process an action checking each emmited command aginst the policy and producing
    /// effects to the sink. All emmited commands are handled transactionally where if
    /// any emmited command is rejected no commands are added to the storage.
    fn call_action(
        &self,
        id: &Id,
        action: &Self::Actions,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError>;

    /// Deserilise a bytes in to a command of type T
    fn read_command<'a>(&self, data: &'a [u8]) -> Result<Self::Command<'a>, EngineError>;

    /// Produces an init message serilized to target. The `struct` representing the
    /// Command is returned.
    fn init<'a>(
        &self,
        target: &'a mut [u8],
        policy_data: &[u8],
        payload: &Self::Payload,
    ) -> Result<Self::Command<'a>, EngineError>;

    /// Produces a merge message serilized to target. The `struct` representing the
    /// Command is returned.
    fn merge<'a>(
        &self,
        target: &'a mut [u8],
        left: Id,
        right: Id,
    ) -> Result<Self::Command<'a>, EngineError>;

    /// Produces a protocol message serilized to target. The `struct` representing the
    /// Command is returned.
    fn message<'a>(
        &self,
        target: &'a mut [u8],
        parent: Id,
        payload: &Self::Payload,
    ) -> Result<Self::Command<'a>, EngineError>;
}
