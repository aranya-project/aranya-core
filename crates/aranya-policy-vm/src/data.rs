use aranya_crypto::DeviceId;
pub use aranya_crypto::Id;
use buggy::{bug, Bug};

// TODO(jdygert): Use Identifier?

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
    pub author: DeviceId,
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

impl<'a> CommandContext<'a> {
    /// Try to create a new command context with a new `head_id` that uses the same name as the original
    /// This method will fail if it's not called on an [`CommandContext::Action`]
    pub fn with_new_head(&self, new_head_id: Id) -> Result<CommandContext<'a>, Bug> {
        match &self {
            Self::Action(ref ctx) => Ok(Self::Action(ActionContext {
                name: ctx.name,
                head_id: new_head_id,
            })),
            _ => bug!("Unable to call CommandContext::with_new_head in a non-action context"),
        }
    }

    /// Try to create a new [`CommandContext::Seal`] with the same `head_id` as the current context.
    /// This method will fail if it's not called on an [`CommandContext::Action`]
    pub fn seal_from_action(&self, command_name: &'a str) -> Result<CommandContext<'a>, Bug> {
        if let CommandContext::Action(ActionContext {
            name: _,
            ref head_id,
        }) = self
        {
            Ok(CommandContext::Seal(SealContext {
                name: command_name,
                head_id: *head_id,
            }))
        } else {
            bug!("Trying to call CommandContext::seal_from_action on a variant that isn't CommandContext::Action")
        }
    }
}
