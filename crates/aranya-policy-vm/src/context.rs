use aranya_crypto::{BaseId, DeviceId, policy::CmdId};
use buggy::{Bug, bug};

use crate::Identifier;

/// Context for actions
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionContext {
    /// The name of the action
    pub name: Identifier,
    /// The head of the graph
    pub head_id: CmdId,
}

/// Context for Policy and Recall blocks
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyContext {
    /// The name of the command
    pub name: Identifier,
    /// The ID of the command
    pub id: CmdId,
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
    /// Policy operation
    Policy(PolicyContext),
    /// Recall operation
    Recall(PolicyContext),
}

impl CommandContext {
    /// Try to create a new command context with a new `head_id` that uses the same name as the original
    /// This method will fail if it's not called on an [`CommandContext::Action`]
    pub fn with_new_head(&self, new_head_id: CmdId) -> Result<Self, Bug> {
        match &self {
            Self::Action(ctx) => Ok(Self::Action(ActionContext {
                name: ctx.name.clone(),
                head_id: new_head_id,
            })),
            _ => bug!("Unable to call CommandContext::with_new_head in a non-action context"),
        }
    }
}
