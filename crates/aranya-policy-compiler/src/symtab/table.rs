use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    scope::{InsertError, InvalidScopeId, ScopeId, ScopedId},
    Namespace, Scopes, Symbol, SymbolId, SymbolKind, Symbols,
};
use crate::hir::{Ident, IdentId, IdentRef, Span};

/// Symbol resolution information.
#[derive(Clone, Debug)]
pub struct SymbolTable {
    /// Maps item identifiers to their symbols.
    pub item_resolutions: BTreeMap<IdentId, SymbolId>,
    /// Maps type identifiers to their symbols.
    pub type_resolutions: BTreeMap<IdentId, SymbolId>,

    index: BTreeMap<ScopedKey, SymbolId>,

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
            item_resolutions: BTreeMap::new(),
            type_resolutions: BTreeMap::new(),
            index: BTreeMap::new(),
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
        let ns = kind.namespace();
        let sym = Symbol {
            ident: ident.id,
            kind,
            scope,
            span,
        };
        let sym_id = self.symbols.insert(sym);
        match kind {
            SymbolKind::Item(_) => self.item_resolutions.insert(ident.id, sym_id),
            SymbolKind::Type(_) => self.type_resolutions.insert(ident.id, sym_id),
        };
        self.scopes.try_insert(scope, ident.xref, sym_id)?;
        let scoped_key = ScopedKey {
            scope,
            ns,
            xref: ident.xref,
        };
        if let Some(existing) = self.index.insert(scoped_key, sym_id) {
            Err(InsertError::Duplicate(existing))
        } else {
            Ok(())
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
struct ScopedKey {
    scope: ScopeId,
    ns: Namespace,
    xref: IdentRef,
}

// TODO: delete?
pub type ScopeMap = BTreeMap<ScopedId, ScopeId>;
