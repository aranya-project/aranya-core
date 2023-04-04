use crate::command::{Command, Id};
use crate::storage::Perspective;

/// Runtime engine, which continuously applies a `policy` to commands
/// to produce state.
pub trait Engine<T, K, V>
where
    T: Command,
{
    type Policy: Policy<
        T,
        K,
        V,
        Payload = Self::Payload,
        PolicyData = Self::PolicyData,
        Effects = Self::Effects,
        Actions = Self::Actions,
    >;

    type PolicyData;
    type Payload;
    type Actions;
    type Effects;

    fn add_policy(&mut self, policy: &Self::PolicyData) -> Result<PolicyId, EngineError>;
    fn get_policy<'a>(&'a self, id: &PolicyId) -> Result<&'a Self::Policy, EngineError>;
}

pub trait Sink<E> {
    fn consume(&mut self, effect: E);
}

/// Returned by the runtime engine.
#[derive(Debug)]
pub enum EngineError {
    Read,
    Write,
    Check,
    InternalError,
}

/// Common functions for a `Policy`, which is a set of rules to define
/// how a command effects existing state. As commands are opaque to
/// the runtime, the `Policy` contains functions for command
/// serialization.
pub trait Policy<T, K, V>
where
    T: Command,
{
    type Payload;
    type PolicyData;
    type Actions;
    type Effects;

    fn serial(&self) -> u32;
    fn read_command(&self, data: &[u8]) -> Result<T, EngineError>;
    fn check<'a>(
        &self,
        command: &T,
        facts: &mut impl Perspective<'a, T, K, V>,
        sink: Option<&mut impl Sink<Self::Effects>>,
    ) -> Result<bool, EngineError>;

    fn action<'a>(
        &self,
        action: &Self::Actions,
        facts: &mut impl Perspective<'a, T, K, V>,
        sink: Option<&mut impl Sink<Self::Effects>>,
    ) -> Result<bool, EngineError>;

    /// Initialize state with the associated policy
    fn init(
        &self,
        target: &mut [u8],
        policy_data: &Self::PolicyData,
        payload: &Self::Payload,
    ) -> Result<T, EngineError>;

    /// Create a merge command from the specified branches
    fn merge(&self, target: &mut [u8], left: Id, right: Id) -> Result<T, EngineError>;

    /// Submit a user-specific command
    fn basic(
        &self,
        target: &mut [u8],
        parent: Id,
        payload: &Self::Payload,
    ) -> Result<T, EngineError>;
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Copy)]
pub struct PolicyId(usize);

impl PolicyId {
    pub fn new(id: usize) -> Self {
        PolicyId(id)
    }
}
