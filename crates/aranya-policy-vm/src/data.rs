pub use aranya_crypto::Id;
use aranya_crypto::UserId;

/// Context for actions
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionContext<'a> {
    /// The name of the action
    pub name: &'a str,
    /// The head of the graph
    pub head_id: Id,
}

/// Context for seal blocks
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealContext<'a> {
    /// The name of the command
    pub name: &'a str,
    /// The ID of the command at the head of the perspective
    pub head_id: Id,
}

/// Context for open blocks
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenContext<'a> {
    /// The name of the command
    pub name: &'a str,
}

/// Context for Policy and Recall blocks
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyContext<'a> {
    /// The name of the command
    pub name: &'a str,
    /// The ID of the command
    pub id: Id,
    /// The ID of the author of the command
    pub author: UserId,
    /// The ID of the version of policy and FFI module set
    pub version: Id,
}

/// Properties of policy execution available through FFI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandContext<'a> {
    /// Action
    Action(ActionContext<'a>),
    /// Seal operation
    Seal(SealContext<'a>),
    /// Open operation
    Open(OpenContext<'a>),
    /// Policy operation
    Policy(PolicyContext<'a>),
    /// Recall operation
    Recall(PolicyContext<'a>),
}
