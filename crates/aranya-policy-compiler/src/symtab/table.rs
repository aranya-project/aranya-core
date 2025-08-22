use std::collections::{BTreeMap, BTreeSet};

use super::{
    Result,
    scope::{InvalidScopeId, ScopeId, ScopedId},
};
use crate::{
    hir::{Ident, IdentId, Span},
    symtab::{Scopes, Symbol, SymbolId, SymbolKind, Symbols, scope::InsertError},
};

/// Symbol resolution information.
#[derive(Clone, Debug)]
pub struct SymbolTable {
    /// Maps identifiers to their symbols.
    pub resolutions: BTreeMap<IdentId, SymbolId>,
    /// Identifiers that we skipped because they'll be "resolved"
    /// during while type checking. E.g., struct fields, enum
    /// variants, etc.
    pub skipped: BTreeSet<IdentId>,
    /// The scope hierarchy.
    pub scopes: Scopes,
    /// The symbol arena.
    pub symbols: Symbols,
    /// TODO
    #[cfg(test)]
    pub scopemap: ScopeMap,
}

impl SymbolTable {
    pub fn empty() -> Self {
        Self {
            resolutions: BTreeMap::new(),
            skipped: BTreeSet::new(),
            scopes: Scopes::new(),
            symbols: Symbols::new(),
            #[cfg(test)]
            scopemap: ScopeMap::new(),
        }
    }

    /// Retrieves a shared reference to a symbol by its ID.
    pub fn get(&self, id: SymbolId) -> Option<&Symbol> {
        self.symbols.get(id)
    }

    /// Sugar for creating a child scope of `scope`.
    pub(crate) fn create_child_scope(&mut self, scope: ScopeId) -> Result<ScopeId, InvalidScopeId> {
        self.scopes.create_child_scope(scope)
    }

    /// Adds a symbol created from `ident`, `kind`, and `span` to
    /// `scope`.
    pub(crate) fn add_symbol(
        &mut self,
        scope: ScopeId,
        ident: &Ident,
        kind: SymbolKind,
        span: Span,
    ) -> Result<(), InsertError> {
        let sym = Symbol {
            ident: ident.id,
            kind,
            scope,
            span,
        };
        let sym_id = self.symbols.insert(sym);
        self.resolutions.insert(ident.id, sym_id);
        self.scopes.try_insert(scope, ident.xref, sym_id)
    }
}

pub(crate) type ScopeMap = BTreeMap<ScopedId, ScopeId>;
