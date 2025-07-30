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

use std::{collections::HashMap, ops::Deref};

pub(crate) use error::SymbolResolutionError;
pub(crate) use symbols::{Symbol, SymbolId, Symbols};

use crate::{
    hir::{Hir, IdentId},
    symbol_resolution::{resolver::Resolver, scope::Scopes},
};

/// Entry point for symbol resolution.
pub(crate) fn resolve<'a>(hir: &'a Hir) -> Result<ResolvedHir<'a>, SymbolResolutionError> {
    let resolver = Resolver::new(hir)?;
    resolver.resolve()
}

/// HIR with symbol resolution information.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedHir<'a> {
    /// The HIR.
    pub hir: &'a Hir,
    /// Maps identifiers to their symbols.
    pub resolutions: HashMap<IdentId, SymbolId>,
    /// The scope hierarchy.
    pub scopes: Scopes,
    /// The symbol arena.
    pub symbols: Symbols,
}

impl ResolvedHir<'_> {
    /// Get the symbol that an identifier resolves to.
    pub fn get_resolution(&self, ident_id: IdentId) -> Option<SymbolId> {
        self.resolutions.get(&ident_id).copied()
    }

    /// Get a symbol by its ID.
    pub fn get_symbol(&self, sym_id: SymbolId) -> Option<&Symbol> {
        self.symbols.get(sym_id)
    }
}

impl Deref for ResolvedHir<'_> {
    type Target = Hir;

    fn deref(&self) -> &Self::Target {
        self.hir
    }
}
