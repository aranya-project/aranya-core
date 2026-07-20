//! Serializable [`Machine`][super::machine::Machine] state.

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::fmt::{self, Display};

use aranya_policy_ast::{self as ast, Identifier};
use serde::{Deserialize, Serialize};

use crate::{
    CodeMap, ConstValue, Field, Instruction, Label, Persistence, interface, named::named_item,
};

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
#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
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
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[serde(tag = "version")]
pub enum ModuleData {
    /// Version 0
    V0(ModuleV0),
}

/// The Version 0 module format
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[serde(deny_unknown_fields)]
pub struct ModuleV0 {
    /// Program memory
    pub progmem: Box<[Instruction]>,
    /// Labels
    pub labels: BTreeMap<Label, usize>,
    /// Action definitions
    pub action_defs: Vec<ActionDef>,
    /// Command definitions
    pub command_defs: Vec<CommandDef>,
    /// Fact definitions
    pub fact_defs: Vec<FactDef>,
    /// Struct definitions
    pub struct_defs: Vec<StructDef>,
    /// Enum definitions
    pub enum_defs: Vec<EnumDef>,
    /// Code map
    pub codemap: Option<CodeMap>,
    /// Global static data
    pub globals: BTreeMap<Identifier, ConstValue>,
}

/// An action definition.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct ActionDef {
    /// The name of the action.
    pub name: Identifier,
    /// The persistence of the action.
    pub persistence: Persistence,
    /// The parameters of the action.
    pub params: Vec<Field>,
}

named_item!(ActionDef);

impl From<interface::ActionDefinition> for ActionDef {
    fn from(value: interface::ActionDefinition) -> Self {
        Self {
            name: value.name.inner,
            persistence: value.persistence.into(),
            params: value.params.into_iter().map(ast::Param::into).collect(),
        }
    }
}

/// A command definition.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct CommandDef {
    /// The name of the command.
    pub name: Identifier,
    /// The persistence of the command.
    pub persistence: Persistence,
    /// The attributes of the command.
    pub attributes: Vec<Attribute>,
    /// The fields of the command.
    pub fields: Vec<Field>,
}

named_item!(CommandDef);

impl From<interface::CommandDefinition> for CommandDef {
    fn from(value: interface::CommandDefinition) -> Self {
        Self {
            name: value.name.inner,
            persistence: value.persistence.into(),
            attributes: value.attributes.into_iter().map(Attribute::from).collect(),
            fields: value.fields.into_iter().map(Field::from).collect(),
        }
    }
}

/// A command attribute.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct Attribute {
    /// The name of the attribute.
    pub name: Identifier,
    /// The value of the attribute.
    pub value: ConstValue,
}

impl From<interface::Attribute> for Attribute {
    fn from(value: interface::Attribute) -> Self {
        Self {
            name: value.name.inner,
            value: value.value,
        }
    }
}

/// A schema definition for a fact
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]

pub struct FactDef {
    /// The name of the fact
    pub name: Identifier,
    /// Types for all of the key fields
    pub key: Vec<Field>,
    /// Types for all of the value fields
    pub value: Vec<Field>,
    /// Is this fact immutable?
    pub immutable: bool,
}

named_item!(FactDef);

impl From<ast::FactDefinition> for FactDef {
    fn from(value: ast::FactDefinition) -> Self {
        Self {
            name: value.identifier.inner,
            key: value.key.into_iter().map(Field::from).collect(),
            value: value.value.into_iter().map(Field::from).collect(),
            immutable: value.immutable,
        }
    }
}

/// A schema definition for a struct
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct StructDef {
    /// The name of the struct
    pub name: Identifier,
    /// The fields of the struct and their types
    pub items: Vec<Field>,
}

named_item!(StructDef);

/// A schema definition for an enum
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct EnumDef {
    /// enum name
    pub name: Identifier,
    /// list of possible values
    pub variants: Vec<(Identifier, i64)>,
}

named_item!(EnumDef);

impl EnumDef {
    /// Get the integer associated with the variant name, if it exists. Otherwise return `None`.
    pub fn get(&self, name: impl AsRef<str>) -> Option<i64> {
        self.variants
            .iter()
            .find(|(n, _)| *n == name.as_ref())
            .map(|(_, v)| *v)
    }
}
