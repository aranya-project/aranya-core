//! Serializable [`Machine`][super::machine::Machine] state.

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use core::fmt::{self, Display};

use ast::FactDefinition;
use policy_ast as ast;
use serde::{Deserialize, Serialize};

use super::machine::Label;
use crate::{instructions::Instruction, CodeMap};

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

impl Display for UnsupportedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unsupported module version")
    }
}

/// The serializable state of
/// a [`Machine`][super::machine::Machine].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Module {
    pub(super) data: ModuleData,
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
pub(super) enum ModuleData {
    V0(ModuleV0),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModuleV0 {
    pub(super) progmem: Box<[Instruction]>,
    pub(super) labels: BTreeMap<Label, usize>,
    pub(super) fact_defs: BTreeMap<String, FactDefinition>,
    pub(super) struct_defs: BTreeMap<String, Vec<ast::FieldDefinition>>,
    pub(super) codemap: Option<CodeMap>,
}

#[cfg(test)]
mod tests {
    use ciborium as cbor;
    use policy_ast as ast;
    use policy_lang::lang::parse_policy_str;

    use super::*;
    use crate::{compile::Compiler, Machine};

    /// Tests serializing then deserializing a [`Module`].
    #[test]
    fn test_module_round_trip() {
        let policy = parse_policy_str(
            r#"
fact Foo[]=>{x int}

effect Update {
    value int
}

command Set {
    fields {
        a int,
    }
    seal { return None }
    open { return None }
    policy {
        let x = this.a
        finish {
            create Foo[]=>{x: x}
            emit Update{value: x}
        }
    }
}

command Clear {
    fields {}
    seal { return None }
    open { return None }
    policy {
        finish {
            delete Foo[]
        }
    }
}

command Increment {
    fields {}
    seal { return None }
    open { return None }
    policy {
        let r = unwrap query Foo[]=>{x: ?}
        let new_x = r.x + 1
        finish {
            update Foo[]=>{x: r.x} to {x: new_x}
            emit Update{value: new_x}
        }
    }
}
"#
            .trim(),
            ast::Version::V3,
        )
        .unwrap();

        let machine = Compiler::new(&policy).compile().unwrap();

        let want = machine.clone().into_module();
        let data = {
            let mut buf = Vec::new();
            cbor::into_writer(&want, &mut buf).unwrap();
            buf
        };
        let got: Module = cbor::from_reader(&data[..]).unwrap();
        assert_eq!(got, want);
        assert_eq!(Machine::from_module(got), Ok(machine));
    }
}
