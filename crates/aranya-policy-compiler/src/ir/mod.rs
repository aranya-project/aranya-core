//! Intermediate Representation (IR) for the Aranya policy compiler.
//!
//! This module provides an SSA-style IR that sits between the AST and bytecode,
//! enabling static analysis, dependency checking, and optimizations.

mod builder;
mod codegen;
mod dependency;
mod display;
mod error;
mod name_resolution;
mod types;
#[cfg(test)]
mod test_utils;

pub use builder::IRBuilder;
pub use codegen::compile_ir_to_bytecode;
pub use dependency::{DependencyAnalyzer, DependencyError};
pub use error::*;
pub use name_resolution::{NameResolver, NameError};
pub use types::*;

use std::collections::HashMap;
use aranya_policy_ast::Identifier;

/// The complete IR for a policy module.
#[derive(Debug, Clone)]
pub struct IR {
    /// All functions defined in the module.
    pub functions: HashMap<Identifier, Function>,
    
    /// All global variables defined in the module.
    pub globals: HashMap<Identifier, Global>,
    
    /// Metadata about the original policy.
    pub metadata: Metadata,
}

/// Metadata preserved from the original AST.
#[derive(Debug, Clone, Default)]
pub struct Metadata {
    /// FFI modules imported by the policy.
    pub ffi_imports: Vec<Identifier>,
    
    /// Source code mapping information.
    pub source_map: Option<SourceMap>,
}

/// Source mapping information for debugging and error reporting.
#[derive(Debug, Clone)]
pub struct SourceMap {
    /// Maps IR locations to source locations.
    pub locations: HashMap<Location, usize>,
}

/// A location in the IR (function + block + instruction).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Location {
    pub function: Identifier,
    pub block: BlockId,
    pub instruction: usize,
}

impl IR {
    /// Create a new empty IR.
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            globals: HashMap::new(),
            metadata: Metadata::default(),
        }
    }
    
    /// Run dependency analysis to detect recursion and circular dependencies.
    pub fn analyze_dependencies(&self) -> Result<(), Vec<DependencyError>> {
        let analyzer = DependencyAnalyzer::new(self);
        analyzer.analyze()
    }
    
    /// Compile this IR to bytecode instructions.
    pub fn compile_to_bytecode(&self) -> Result<Vec<aranya_policy_module::Instruction>, Vec<CodegenError>> {
        compile_ir_to_bytecode(self)
    }
}