use core::fmt::{self, Display};

use aranya_policy_ast::Identifier;
use serde::{Deserialize, Serialize};

/// Types of Labels
#[derive(Debug, Clone, PartialOrd, Ord, Eq, PartialEq, Serialize, Deserialize)]
pub enum LabelType {
    /// This label represents the entry point of an action
    Action,
    /// This label represents the entry point of a command policy block
    CommandPolicy,
    /// This label represents the entry point of a command recall block
    CommandRecall,
    /// A command seal block
    CommandSeal,
    /// A command open block
    CommandOpen,
    /// This label is a temporary destination for implementing
    /// branching constructs.
    Temporary,
    /// Function entry point
    Function,
}

impl Display for LabelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelType::Action => write!(f, "action"),
            LabelType::CommandPolicy => write!(f, "policy"),
            LabelType::CommandRecall => write!(f, "recall"),
            LabelType::CommandSeal => write!(f, "seal"),
            LabelType::CommandOpen => write!(f, "open"),
            LabelType::Temporary => write!(f, "temp"),
            LabelType::Function => write!(f, "fn"),
        }
    }
}

/// Labels are branch targets and execution entry points.
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    /// The address of the label
    pub name: Identifier,
    /// The type of the label
    pub ltype: LabelType,
}

impl Label {
    /// Creates a new named label of the given type.
    pub fn new(name: Identifier, ltype: LabelType) -> Label {
        Label { name, ltype }
    }

    /// Creates a new temporary label. Used by the compiler.
    pub fn new_temp(name: Identifier) -> Label {
        Label {
            name,
            ltype: LabelType::Temporary,
        }
    }
}

impl Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ltype, self.name)
    }
}
