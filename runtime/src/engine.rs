//! Interfaces for an application to begin a runtime.
//!
//! An [`Engine`] stores policies for an application. A [`Policy`] is required
//! to process [`Command`]s and defines how the runtime's graph is constructed.
use crate::command::{Command, Id};
use crate::storage::Perspective;

/// Store and access a [`Policy`] for this runtime.
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
    fn get_policy(&self, id: &PolicyId) -> Result<&Self::Policy, EngineError>;
}

pub trait Sink<E> {
    fn consume(&mut self, effect: E);
}

/// Returned by the runtime [`Engine`].
#[derive(Debug)]
pub enum EngineError {
    Read,
    Write,
    Check,
    InternalError,
}

/// A [`Policy`] interprets [`Command`]s, keeping the message data opaque
/// to the runtime.
pub trait Policy {
    type Payload;
    type Actions;
    type Effects;
    type Command: Command;

    /// A policy may have a serial number, used for ordering.
    /// This supports in-band policy upgrades.
    fn serial(&self) -> u32;

    /// Check if the `command` is accepted following the given `facts`.
    /// If the `command` is accepted, this adds it to `facts` and returns
    /// `true`. Otherwise, returns `false`.
    ///
    /// # Arguments
    ///
    /// * `command` - Represents an effect on the graph.
    /// * `facts` - A mutable slice of the graph.
    /// * `sink` - Produces effects caused by the `command`; graph changes to
    ///   be consumed by the application.
    fn call_rule<'segment_storage>(
        &self,
        command: &impl Command,
        facts: &mut impl Perspective<'segment_storage>,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError>;

    /// Process an action to produce a command and its associated effects
    /// and store this data. If any produced command is rejected, no commands
    /// will be stored.
    ///
    /// # Arguments
    ///
    /// * `id` - Uniquely identifies the (serialized) command.
    /// * `action` - A policy-specific message that is evaluated by the
    ///   policy to produce commands.
    /// * `facts` - A mutable slice of the graph.
    /// * `sink` - Produces effects caused by the `command`s; graph changes to
    ///   be consumed by the application.
    fn call_action<'segment_storage>(
        &self,
        id: &Id,
        action: &Self::Actions,
        facts: &mut impl Perspective<'segment_storage>,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError>;

    /// Deserialize `data` into a command
    fn read_command(&self, data: &[u8]) -> Result<Self::Command, EngineError>;

    /// Produce an init command and serialize to `target`.
    ///
    /// # Arguments
    ///
    /// * `target` - A mutable buffer used by the policy for serialization.
    /// * `policy_data` - Byte slice that holds the policy that will
    ///   validate the command.
    /// * `payload` - The policy's associated [`Payload`] type.
    fn init(
        &self,
        target: &mut [u8],
        policy_data: &[u8],
        payload: &Self::Payload,
    ) -> Result<Self::Command, EngineError>;

    /// Produce a merge command serialized to target.
    ///
    /// # Arguments
    ///
    /// * `target` - A mutable buffer used by the policy for serialization.
    /// * `left` - Identifies the left branch for the merge; a 32-byte slice
    ///   that holds the beginning of the cryptographic hash of the serialized
    ///   command.
    /// * `right` - Idenfities the right branch for the merge; a 32-byte slice
    ///   that holds the beginning of the cryptographic hash of the serialized
    ///   command.
    fn merge(&self, target: &mut [u8], left: Id, right: Id) -> Result<Self::Command, EngineError>;

    /// Produce a user-defined command and serialize to target.
    ///
    /// # Arguments
    ///
    /// * `target` - A mutable buffer used by the policy for serialization.
    /// * `parent` - The command prior to the one to be created.
    /// * `payload` - The policy's associated [`Payload`] type.
    fn basic(
        &self,
        target: &mut [u8],
        parent: Id,
        payload: &Self::Payload,
    ) -> Result<Self::Command, EngineError>;
}

/// Identifies a [`Policy`].
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Copy)]
pub struct PolicyId(usize);

impl PolicyId {
    pub fn new(id: usize) -> Self {
        PolicyId(id)
    }
}
