pub use aranya_crypto::BaseId;
use aranya_crypto::DeviceId;
use buggy::{Bug, bug};

use crate::Identifier;

/// Context for actions
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionContext {
    /// The name of the action
    pub name: Identifier,
    /// The head of the graph
    pub head_id: BaseId,
}

/// Context for seal blocks
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealContext {
    /// The name of the command
    pub name: Identifier,
    /// The ID of the command at the head of the perspective
    pub head_id: BaseId,
}

/// Context for open blocks
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenContext {
    /// The name of the command
    pub name: Identifier,
}

/// Context for Policy and Recall blocks
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyContext {
    /// The name of the command
    pub name: Identifier,
    /// The ID of the command
    pub id: BaseId,
    /// The ID of the author of the command
    pub author: DeviceId,
    /// The ID of the version of policy and FFI module set
    pub version: BaseId,
}

/// Properties of policy execution available through FFI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandContext {
    /// Action
    Action(ActionContext),
    /// Seal operation
    Seal(SealContext),
    /// Open operation
    Open(OpenContext),
    /// Policy operation
    Policy(PolicyContext),
    /// Recall operation
    Recall(PolicyContext),
}

impl CommandContext {
    /// Try to create a new command context with a new `head_id` that uses the same name as the original
    /// This method will fail if it's not called on an [`CommandContext::Action`]
    pub fn with_new_head(&self, new_head_id: BaseId) -> Result<CommandContext, Bug> {
        match &self {
            Self::Action(ctx) => Ok(Self::Action(ActionContext {
                name: ctx.name.clone(),
                head_id: new_head_id,
            })),
            _ => bug!("Unable to call CommandContext::with_new_head in a non-action context"),
        }
    }

    /// Try to create a new [`CommandContext::Seal`] with the same `head_id` as the current context.
    /// This method will fail if it's not called on an [`CommandContext::Action`]
    pub fn seal_from_action(&self, command_name: Identifier) -> Result<CommandContext, Bug> {
        if let CommandContext::Action(ActionContext { name: _, head_id }) = self {
            Ok(CommandContext::Seal(SealContext {
                name: command_name,
                head_id: *head_id,
            }))
        } else {
            bug!(
                "Trying to call CommandContext::seal_from_action on a variant that isn't CommandContext::Action"
            )
        }
    }
}
