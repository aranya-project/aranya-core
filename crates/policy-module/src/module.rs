//! Serializable [`Machine`][super::machine::Machine] state.

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use core::fmt::{self, Display};

use ast::FactDefinition;
use policy_ast as ast;
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
#[derive(Debug, Eq, PartialEq)]
pub struct UnsupportedVersion(());

impl trouble::Error for UnsupportedVersion {}

impl Display for UnsupportedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unsupported module version")
    }
}

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
    /// Fact definitions
    pub fact_defs: BTreeMap<String, FactDefinition>,
    /// Struct definitions
    pub struct_defs: BTreeMap<String, Vec<ast::FieldDefinition>>,
    /// Code map
    pub codemap: Option<CodeMap>,
    /// Global static data
    pub globals: BTreeMap<String, Value>,
}