use std::{
    collections::hash_map::{Entry, HashMap},
    fmt,
    hash::Hash,
};

use aranya_policy_ast::Identifier;
use buggy::{Bug, BugExt};

use crate::symbol_resolution::symbols::SymbolId;

/// Uniquely identifies a [`Scope`] in an [`Arena`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ScopeId(usize);

impl ScopeId {
    /// The global scope.
    pub const GLOBAL: Self = Self(0);
}

impl fmt::Display for ScopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A [`ScopeId`] was invalid for an [`Arena`].
#[derive(Clone, Debug, thiserror::Error)]
#[error("invalid scope id {0}")]
pub struct InvalidScopeId(ScopeId);

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

/// A program scope (e.g., global, function, block, etc.).
#[derive(Clone, Debug)]
pub struct Scope {
    id: ScopeId,
    parent: Option<ScopeId>,
    symbols: HashMap<Identifier, SymbolId>,
    // TODO: scope kind (e.g., function, block, etc.)
}

/// A collection of [`Scope`]s.
#[derive(Clone, Debug)]
pub struct Scopes {
    scopes: Vec<Scope>,
}

impl Scopes {
    /// Creates an empty arena.
    pub fn new() -> Self {
        let mut arena = Self { scopes: Vec::new() };
        // Always create the global scope.
        arena.create_scope();
        arena
    }

    /// Creates a new scope.
    fn create_scope(&mut self) -> ScopeId {
        let id = ScopeId(self.scopes.len());
        self.scopes.push(Scope {
            id,
            parent: None,
            symbols: HashMap::new(),
        });
        id
    }

    /// Creates a new child scope.
    pub fn create_child_scope(&mut self, parent: ScopeId) -> Result<ScopeId, InvalidScopeId> {
        // Make sure the parent scope exists.
        self.scopes.get(parent.0).ok_or(InvalidScopeId(parent))?;

        let id = ScopeId(self.scopes.len());
        self.scopes.push(Scope {
            id,
            parent: Some(parent),
            symbols: HashMap::new(),
        });
        Ok(id)
    }

    /// Inserts a symbol into the specified scope.
    pub fn insert(
        &mut self,
        scope: ScopeId,
        ident: Identifier,
        sym: SymbolId,
    ) -> Result<(), InsertError> {
        let scope = self.scopes.get_mut(scope.0).ok_or(InvalidScopeId(scope))?;
        match scope.symbols.entry(ident.clone()) {
            Entry::Occupied(_) => Err(InsertError::Duplicate(DuplicateSymbolId(sym))),
            Entry::Vacant(entry) => {
                entry.insert(sym);
                Ok(())
            }
        }
    }

    /// Looks up a symbol given its name and scope.
    pub fn get(&self, id: ScopeId, ident: &Identifier) -> Result<Option<SymbolId>, LookupError> {
        let scope = self.scopes.get(id.0).ok_or(InvalidScopeId(id))?;
        if let Some(sym) = scope.symbols.get(ident) {
            return Ok(Some(*sym));
        }
        let mut current = scope.parent;
        while let Some(id) = current {
            let scope = self
                .scopes
                .get(id.0)
                .assume("parent scope ID should be valid")?;
            if let Some(sym) = scope.symbols.get(ident) {
                return Ok(Some(*sym));
            }
            current = scope.parent;
        }
        Ok(None)
    }
}
