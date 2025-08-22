//! Serializable [`Machine`][super::machine::Machine] state.

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap};
use core::fmt::{self, Display};

use aranya_policy_ast::{self as ast, Identifier, Persistence, VType};
use ast::FactDefinition;
use serde::{Deserialize, Serialize};

use crate::{CodeMap, Instruction, Label, Value};

/// Identifies a [`Module`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Version {
    /// Version 0.
    V0,
}

impl Version {
    /// Returns the `Version` as a human-readable string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::V0 => "V0",
        }
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Unsupported [`Module`] version.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("unsupported module version")]
pub struct UnsupportedVersion(());

/// The serializable state of
/// a [`Machine`](../policy_vm/struct.Machine.html).
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Module {
    /// The module data
    pub data: ModuleData,
    // TODO(eric): add a checksum?
}

impl Module {
    /// Returns the module version.
    pub const fn version(&self) -> Version {
        match self.data {
            ModuleData::V0(_) => Version::V0,
        }
    }
}

/// Versioned [`Module`] data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum ModuleData {
    /// Version 0
    V0(ModuleV0),
}

/// The Version 0 module format
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleV0 {
    /// Program memory
    pub progmem: Box<[Instruction]>,
    /// Labels
    pub labels: BTreeMap<Label, usize>,
    /// Action definitions
    pub action_defs: BTreeMap<Identifier, ActionDef>,
    /// Command definitions
    pub command_defs: BTreeMap<Identifier, CommandDef>,
    /// Fact definitions
    pub fact_defs: BTreeMap<Identifier, FactDefinition>,
    /// Struct definitions
    pub struct_defs: BTreeMap<Identifier, StructDef>,
    /// Enum definitions
    pub enum_defs: BTreeMap<Identifier, EnumDef>,
    /// Code map
    pub codemap: Option<CodeMap>,
    /// Global static data
    pub globals: BTreeMap<Identifier, Value>,
}

/// An action definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionDef {
    /// The action's persistence.
    pub persistence: Persistence,
    /// The action's arguments.
    pub args: IndexMap<Identifier, VType>,
}

/// A command definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandDef {
    /// The command's persistence.
    pub persistence: Persistence,
    /// The command's attributes.
    pub attributes: IndexMap<Identifier, Value>,
    /// The command's fields.
    pub fields: IndexMap<Identifier, VType>,
}

/// An struct definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StructDef {
    /// The struct's fields.
    pub fields: IndexMap<Identifier, VType>,
}

/// An enum definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnumDef {
    /// The enum's variants.
    pub variants: IndexMap<Identifier, i64>,
}

type IndexMap<K, V> = indexmap::IndexMap<K, V, fnv::FnvBuildHasher>;
