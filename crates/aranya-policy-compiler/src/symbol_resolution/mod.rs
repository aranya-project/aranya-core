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

use std::collections::HashMap;

use aranya_policy_module::ffi::ModuleSchema;
pub use error::SymbolResolutionError;

pub use symbols::{Symbol, SymbolKind, SymbolId, Symbols};

use crate::{
    hir::{arena::AstNodes, hir::{Hir, IdentId}},
    symbol_resolution::{resolver::Resolver, scope::Scopes},
};

/// Entry point for symbol resolution.
pub fn resolve<'a>(
    hir: &'a Hir,
    ast_nodes: &'a AstNodes<'a>,
    ffi_modules: &'a [ModuleSchema<'a>],
) -> Result<ResolvedHir<'a>, SymbolResolutionError> {
    let resolver = Resolver::new(hir, ast_nodes, ffi_modules)?;
    resolver.resolve()
}

/// HIR with symbol resolution information.
#[derive(Clone, Debug)]
pub struct ResolvedHir<'a> {
    /// The HIR.
    pub hir: &'a Hir,
    /// The AST nodes for error location lookup.
    pub ast_nodes: &'a AstNodes<'a>,
    /// Map from identifier usage locations to their resolved symbols.
    pub identifier_resolutions: HashMap<IdentId, SymbolId>,
    /// The scope hierarchy.
    pub scopes: Scopes,
    /// The symbol arena.
    pub symbols: Symbols,
}

impl ResolvedHir<'_> {
    /// Get the symbol that an identifier resolves to.
    pub fn get_resolution(&self, ident_id: IdentId) -> Option<SymbolId> {
        self.identifier_resolutions.get(&ident_id).copied()
    }
    
    /// Get a symbol by its ID.
    pub fn get_symbol(&self, sym_id: SymbolId) -> Option<&Symbol> {
        self.symbols.get(sym_id)
    }
}
