use std::{collections::BTreeMap, fmt::Display};

use aranya_policy_ast as ast;
use aranya_policy_module::{CodeMap, Instruction, Label, Module, ModuleData, ModuleV0, Value};
use ast::FactDefinition;

/// This is a stripped down version of the VM `Machine` type, which exists to be a target
/// for compilation
#[derive(Debug)]
#[cfg_attr(test, derive(Clone, Eq, PartialEq))]
pub struct CompileTarget {
    // static state (things which do not change after compilation)
    /// The program memory
    pub progmem: Vec<Instruction>,
    /// Mapping of Label names to addresses
    pub labels: BTreeMap<Label, usize>,
    /// Action definitions
    pub action_defs: BTreeMap<String, Vec<ast::FieldDefinition>>,
    /// Command definitions (`fields`)
    pub command_defs: BTreeMap<String, BTreeMap<String, ast::VType>>,
    /// Fact schemas
    pub fact_defs: BTreeMap<String, FactDefinition>,
    /// Struct schemas
    pub struct_defs: BTreeMap<String, Vec<ast::FieldDefinition>>,
    /// Command attributes
    pub command_attributes: BTreeMap<String, BTreeMap<String, Value>>,
    /// Mapping between program instructions and original code
    pub codemap: Option<CodeMap>,
    /// Globally scoped variables
    pub globals: BTreeMap<String, Value>,
}

impl CompileTarget {
    /// Creates an empty `CompileTarget` with a given codemap. Used by the compiler.
    pub fn new(codemap: CodeMap) -> Self {
        CompileTarget {
            progmem: vec![],
            labels: BTreeMap::new(),
            action_defs: BTreeMap::new(),
            command_defs: BTreeMap::new(),
            fact_defs: BTreeMap::new(),
            struct_defs: BTreeMap::new(),
            command_attributes: BTreeMap::new(),
            codemap: Some(codemap),
            globals: BTreeMap::new(),
        }
    }

    /// Converts the `CompileTarget` into a `Module`.
    pub fn into_module(self) -> Module {
        Module {
            data: ModuleData::V0(ModuleV0 {
                progmem: self.progmem.into_boxed_slice(),
                labels: self.labels,
                action_defs: self.action_defs,
                command_defs: self.command_defs,
                fact_defs: self.fact_defs,
                struct_defs: self.struct_defs,
                command_attributes: self.command_attributes,
                codemap: self.codemap,
                globals: self.globals,
            }),
        }
    }
}

impl Display for CompileTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "Program memory:")?;
        for (addr, instr) in self.progmem.iter().enumerate() {
            writeln!(f, "  {:4}  {}", addr, instr)?;
        }
        writeln!(f, "Labels:")?;
        for (k, v) in &self.labels {
            writeln!(f, "  {}: {:?}", k, v)?;
        }
        writeln!(f, "Fact definitions:")?;
        for (k, v) in &self.fact_defs {
            writeln!(f, "  {}: {:?}", k, v)?;
        }
        writeln!(f, "Struct definitions:")?;
        for (k, v) in &self.struct_defs {
            writeln!(f, "  {}: {:?}", k, v)?;
        }
        Ok(())
    }
}
