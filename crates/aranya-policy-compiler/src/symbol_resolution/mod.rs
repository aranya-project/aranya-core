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

pub(crate) use error::SymbolResolutionError;
pub(crate) use symbols::{Symbol, SymbolId, Symbols};

use crate::{
    hir::{Hir, IdentId},
    symbol_resolution::{resolver::Resolver, scope::Scopes},
};

pub(crate) type Result<T, E = SymbolResolutionError> = std::result::Result<T, E>;

/// HIR with symbol resolution information.
#[derive(Clone, Debug)]
pub(crate) struct SymbolTable {
    /// Maps identifiers to their symbols.
    pub resolutions: HashMap<IdentId, SymbolId>,
    /// The scope hierarchy.
    pub scopes: Scopes,
    /// The symbol arena.
    pub symbols: Symbols,
}

impl SymbolTable {
    /// Creates a new symbol table.
    pub fn new(hir: &Hir<'_>) -> Result<Self> {
        Resolver::resolve(hir)
    }

    pub fn empty() -> Self {
        Self {
            resolutions: HashMap::new(),
            scopes: Scopes::new(),
            symbols: Symbols::new(),
        }
    }

    /// Get the symbol that an identifier resolves to.
    pub fn get_resolution(&self, ident_id: IdentId) -> Option<SymbolId> {
        self.resolutions.get(&ident_id).copied()
    }

    /// Get a symbol by its ID.
    pub fn get_symbol(&self, sym_id: SymbolId) -> Option<&Symbol> {
        self.symbols.get(sym_id)
    }
}
