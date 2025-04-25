use buggy::{bug, Bug};
use serde::{Deserialize, Serialize};

use crate::{Address, Command, CommandId, GraphId, Prior, Priority};

#[derive(Serialize, Deserialize)]
/// Used for serializing init commands
pub(crate) struct InitCommand<'a> {
    storage_id: GraphId,
    #[serde(default = "Priority::init", skip)]
    priority: Priority,
    id: CommandId,
    #[serde(default = "Prior::none", skip)]
    parent: Prior<Address>,
    #[serde(borrow)]
    data: &'a [u8],
    #[serde(borrow)]
    policy: &'a [u8],
}

impl Command for InitCommand<'_> {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> CommandId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        self.parent
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
        Ok(InitCommand {
            storage_id,
            id: command.id(),
            priority: match command.priority() {
                p @ Priority::Init => p,
                _ => bug!("wrong command type"),
            },
            parent: match command.parent() {
                p @ Prior::None => p,
                _ => bug!("wrong command type"),
            },
            policy: match command.policy() {
                Some(policy) => policy,
                None => bug!("init command should have a policy"),
            },
            data: command.bytes(),
        })
    }
}

impl Priority {
    fn init() -> Self {
        Self::Init
    }
}

impl<T> Prior<T> {
    fn none() -> Self {
        Self::None
    }
}
