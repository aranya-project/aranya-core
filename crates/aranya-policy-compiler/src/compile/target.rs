use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use aranya_policy_ast::{self as ast, Identifier, TypeKind};
use aranya_policy_module::{
    ActionDef, CodeMap, CommandDef, Instruction, Label, Module, ModuleData, ModuleV0, Value,
    named::NamedMap,
};
use ast::FactDefinition;
use indexmap::IndexMap;

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
    pub action_defs: NamedMap<ActionDef>,
    /// Command definitions (`fields`)
    pub command_defs: NamedMap<CommandDef>,
    /// Effect identifiers. The effect definitions can be found in `struct_defs`.
    pub effects: BTreeSet<Identifier>,
    /// Fact schemas
    pub fact_defs: BTreeMap<Identifier, FactDefinition>,
    /// Struct schemas
    pub struct_defs: BTreeMap<Identifier, Vec<ast::FieldDefinition>>,
    /// Enum definitions
    pub enum_defs: BTreeMap<Identifier, IndexMap<Identifier, i64>>,
    /// Mapping between program instructions and original code
    pub codemap: Option<CodeMap>,
    /// Globally scoped variables
    pub globals: BTreeMap<Identifier, Value>,
}

impl CompileTarget {
    /// Creates an empty `CompileTarget` with a given codemap. Used by the compiler.
    pub fn new(codemap: CodeMap) -> Self {
        Self {
            progmem: vec![],
            labels: BTreeMap::new(),
            action_defs: NamedMap::new(),
            command_defs: NamedMap::new(),
            effects: BTreeSet::new(),
            fact_defs: BTreeMap::new(),
            struct_defs: BTreeMap::new(),
            enum_defs: BTreeMap::new(),
            codemap: Some(codemap),
            globals: BTreeMap::new(),
        }
    }

    /// Converts the `CompileTarget` into a `Module`.
    pub fn into_module(self) -> Module {
        // Convert enum defs IndexMap into BTreeMap.
        let enum_defs = self
            .enum_defs
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect::<BTreeMap<_, _>>();

        Module {
            data: ModuleData::V0(ModuleV0 {
                progmem: self.progmem.into_boxed_slice(),
                labels: self.labels,
                action_defs: self.action_defs,
                command_defs: self.command_defs,
                fact_defs: self.fact_defs,
                struct_defs: self.struct_defs,
                enum_defs,
                codemap: self.codemap,
                globals: self.globals,
            }),
        }
    }

    pub(in crate::compile) fn cardinality(&self, kind: &TypeKind) -> Option<u64> {
        match kind {
            TypeKind::String | TypeKind::Bytes => None,
            // With 2^(32 * 8) choices, it's unlikely for someone to want to match against IDs exhaustively.
            TypeKind::Id => None,
            // TODO: This should really be 1 above the max.
            TypeKind::Int => Some(u64::MAX),
            TypeKind::Bool => Some(2),
            TypeKind::Optional(vtype) => {
                // Add 1 for the None case.
                self.cardinality(&vtype.kind).and_then(|c| c.checked_add(1))
            }
            TypeKind::Struct(ident) => {
                let defs = self.struct_defs.get(&ident.name)?;
                defs.iter()
                    .map(|def| self.cardinality(&def.field_type.kind))
                    .reduce(|acc, e| match e {
                        None => None,
                        Some(v) => acc.and_then(|w| v.checked_mul(w)),
                    })
                    .flatten()
            }
            TypeKind::Enum(ident) => {
                let defs = self.enum_defs.get(&ident.name)?;
                Some(defs.len() as u64)
            }
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
