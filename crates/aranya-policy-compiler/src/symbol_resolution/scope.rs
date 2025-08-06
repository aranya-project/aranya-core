use std::{
    collections::hash_map::{Entry, HashMap},
    fmt,
};

use buggy::{Bug, BugExt};

use crate::{
    arena::{self, Arena},
    diag::DiagMsg,
    hir::IdentRef,
    symbol_resolution::symbols::SymbolId,
};

/// A program scope (global or block).
// `pub(super)` only for tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Scope {
    /// Uniquely identifies this scope.
    // TODO(eric): Do we need this field?
    id: ScopeId,
    /// The parent scope, if any.
    // `pub(super)` only for tests.
    pub(super) parent: Option<ScopeId>,
    /// Symbols defined in this scope.
    pub(super) symbols: HashMap<IdentRef, SymbolId>,
}

arena::new_key_type!(
    /// Uniquely identifies a [`Scope`].
    pub(crate) struct ScopeId;
);

impl ScopeId {
    /// The global scope.
    pub const GLOBAL: Self = Self(0);
}

impl fmt::Display for ScopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A collection of [`Scope`]s.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scopes {
    // `pub(super)` only for tests.
    pub(super) scopes: Arena<ScopeId, Scope>,
}

impl Scopes {
    /// Creates an empty arena.
    pub(super) fn new() -> Self {
        let mut arena = Self {
            scopes: Arena::new(),
        };
        // Always create the global scope.
        let id = arena.create_scope();
        assert_eq!(id, ScopeId::GLOBAL);
        arena
    }

    /// Creates a new scope.
    fn create_scope(&mut self) -> ScopeId {
        self.scopes.insert_with_key(|id| Scope {
            id,
            parent: None,
            symbols: HashMap::new(),
        })
    }

    /// Creates a new child scope.
    pub(super) fn create_child_scope(
        &mut self,
        parent: ScopeId,
    ) -> Result<ScopeId, InvalidScopeId> {
        // Make sure the parent scope exists.
        self.scopes.get(parent).ok_or(InvalidScopeId(parent))?;

        let id = self.scopes.insert_with_key(|id| Scope {
            id,
            parent: Some(parent),
            symbols: HashMap::new(),
        });
        Ok(id)
    }

    /// Inserts a symbol into the specified scope.
    pub(super) fn try_insert(
        &mut self,
        scope: ScopeId,
        ident: IdentRef,
        sym: SymbolId,
    ) -> Result<(), InsertError> {
        let scope = self.scopes.get_mut(scope).ok_or(InvalidScopeId(scope))?;
        match scope.symbols.entry(ident) {
            Entry::Occupied(_) => Err(InsertError::Duplicate(DuplicateSymbolId(sym))),
            Entry::Vacant(entry) => {
                entry.insert(sym);
                Ok(())
            }
        }
    }

    /// Looks up a symbol given its name and scope.
    pub fn get(&self, id: ScopeId, ident: IdentRef) -> Result<Option<SymbolId>, LookupError> {
        let scope = self.scopes.get(id).ok_or(InvalidScopeId(id))?;
        if let Some(sym) = scope.symbols.get(&ident) {
            return Ok(Some(*sym));
        }
        let mut current = scope.parent;
        while let Some(id) = current {
            let scope = self
                .scopes
                .get(id)
                .assume("parent scope ID should be valid")?;
            if let Some(sym) = scope.symbols.get(&ident) {
                return Ok(Some(*sym));
            }
            current = scope.parent;
        }
        Ok(None)
    }
}

/// A [`ScopeId`] was invalid for a [`Scopes`].
#[derive(Clone, Debug, thiserror::Error)]
#[error("invalid scope id {0}")]
pub struct InvalidScopeId(ScopeId);

/// An error that can occur when inserting a symbol into a scope.
#[derive(Clone, Debug, thiserror::Error)]
pub enum InsertError {
    /// A symbol with the same identifier already exists in the
    /// scope.
    #[error("{0}")]
    Duplicate(#[from] DuplicateSymbolId),
    /// The scope ID is invalid.
    #[error("{0}")]
    InvalidScopeId(#[from] InvalidScopeId),
}

/// A duplicate symbol.
#[derive(Clone, Debug, thiserror::Error)]
#[error("duplicate symbol")]
pub struct DuplicateSymbolId(SymbolId);

/// TODO
#[derive(Clone, Debug, thiserror::Error)]
pub enum LookupError {
    /// TODO
    #[error("internal bug: {0}")]
    Bug(#[from] Bug),
    /// TODO
    #[error("{0}")]
    InvalidScopeId(#[from] InvalidScopeId),
}

impl From<LookupError> for DiagMsg {
    fn from(err: LookupError) -> Self {
        err.to_string().into()
    }
}
