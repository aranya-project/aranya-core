//! The symbol resolution stage.
//!
//! This stage builds a symbol table and resolves all identifier
//! references in the AST.

mod error;
mod resolver;
mod scope;
mod symbols;

#[cfg(test)]
mod tests;

use std::{collections::HashMap, rc::Rc};

use aranya_policy_ast::{Identifier, Policy};
use aranya_policy_module::ffi::ModuleSchema;
pub use error::SymbolResolutionError;
pub use resolver::FieldLike;
pub use symbols::{Symbol, SymbolKind};

use crate::symbol_resolution::resolver::Resolver;

/// Entry point for symbol resolution.
pub fn resolve<'a>(
    policy: &'a Policy,
    ffi_modules: &'a [ModuleSchema<'a>],
) -> Result<ResolvedAst<'a>, SymbolResolutionError> {
    let resolver = Resolver::new(policy, ffi_modules)?;
    resolver.resolve()
}

/// A wrapper around [`Policy`] with symbol resolution
/// information.
#[derive(Clone, Debug)]
pub struct ResolvedAst<'a> {
    /// The original AST.
    pub ast: &'a Policy,
    /// Map from identifier usage locations to their resolved
    /// symbols.
    pub identifier_resolutions: HashMap<usize, Identifier>,
    /// The symbol table.
    pub symbol_table: Rc<SymbolTable>,
}

impl ResolvedAst<'_> {
    /// Get the declaration that an identifier at the given location resolves to.
    pub fn get_resolution(&self, location: usize) -> Option<&Identifier> {
        self.identifier_resolutions.get(&location)
    }

    /// Helper function to create a test policy with the actual structure.
    #[cfg(test)]
    pub fn create_test_policy() -> Policy {
        todo!()
        // use aranya_policy_ast::Version;
        // Policy {
        //     version: Version::V2,
        //     ffi_imports: vec![],
        //     facts: vec![],
        //     actions: vec![],
        //     effects: vec![],
        //     structs: vec![],
        //     enums: vec![],
        //     commands: vec![],
        //     functions: vec![],
        //     finish_functions: vec![],
        //     global_lets: vec![],
        // }
    }
}
