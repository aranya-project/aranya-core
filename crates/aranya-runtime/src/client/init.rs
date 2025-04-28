use buggy::{bug, Bug};
use serde::{Deserialize, Serialize};

use crate::{Address, Command, CommandId, GraphId, Prior, Priority};

#[derive(Serialize, Deserialize)]
/// Used for serializing init commands
pub(crate) struct InitCommand<'a> {
    storage_id: GraphId,
    id: CommandId,
    #[serde(borrow)]
    data: &'a [u8],
    #[serde(borrow)]
    policy: &'a [u8],
}

impl Command for InitCommand<'_> {
    fn priority(&self) -> Priority {
        Priority::Init
    }

    fn id(&self) -> CommandId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        Prior::None
    }

    fn policy(&self) -> Option<&[u8]> {
        Some(self.policy)
    }

    fn bytes(&self) -> &[u8] {
        self.data
    }
}

impl<'sc> InitCommand<'sc> {
    pub(crate) fn from_cmd(storage_id: GraphId, command: &'sc impl Command) -> Result<Self, Bug> {
        if !matches!(command.priority(), Priority::Init) {
            bug!("wrong command type")
        }

        if !matches!(command.parent(), Prior::None) {
            bug!("wrong command type")
        }

        Ok(InitCommand {
            storage_id,
            id: command.id(),
            policy: match command.policy() {
                Some(policy) => policy,
                None => bug!("init command should have a policy"),
            },
            data: command.bytes(),
        })
    }
}
