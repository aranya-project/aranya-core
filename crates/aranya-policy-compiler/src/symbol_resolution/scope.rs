use std::{
    collections::btree_map::{BTreeMap, Entry},
    fmt,
    hash::Hash,
};

use buggy::{Bug, BugExt};
use serde::{Deserialize, Serialize};

use super::symbols::{SymbolId, SymbolKind};
use crate::{
    arena::{self, Arena},
    diag::DiagMsg,
    hir::{ActionId, BlockId, FfiFuncId, FfiModuleId, FinishFuncId, FuncId, IdentRef},
};

/// A program scope (global or block).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Scope {
    /// Uniquely identifies this scope.
    // TODO(eric): Do we need this field?
    id: ScopeId,
    /// The parent scope, if any.
    pub(super) parent: Option<ScopeId>,
    /// Symbols defined in this scope.
    pub(super) symbols: BTreeMap<IdentRef, SymbolId>,
}

arena::new_key_type!(
    /// Uniquely identifies a [`Scope`].
    pub(crate) struct ScopeId;
);

impl ScopeId {
    /// The global scope.
    pub const GLOBAL: Self = Self(0);
}

/// A collection of [`Scope`]s.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scopes {
    pub(super) scopes: Arena<ScopeId, Scope>,
}

impl Scopes {
    /// Creates an empty arena.
    pub(super) fn new() -> Self {
        let mut arena = Self {
            scopes: Arena::new(),
        };
        // Always create the global scope.
        let id = arena.create_global_scope();
        assert_eq!(id, ScopeId::GLOBAL);
        arena
    }

    /// Creates a new scope without a parent.
    fn create_global_scope(&mut self) -> ScopeId {
        self.scopes.insert_with_key(|id| Scope {
            id,
            parent: None,
            symbols: BTreeMap::new(),
        })
    }

    /// Creates a new child scope of `parent`.
    pub(super) fn create_child_scope(
        &mut self,
        parent: ScopeId,
    ) -> Result<ScopeId, InvalidScopeId> {
        // Make sure the parent scope exists.
        if !self.scopes.contains(parent) {
            return Err(InvalidScopeId(parent));
        }
        let id = self.scopes.insert_with_key(|id| Scope {
            id,
            parent: Some(parent),
            symbols: BTreeMap::new(),
        });
        Ok(id)
    }

    /// Attempts to add the `ident` to `sym` mapping in the
    /// specified scope.
    ///
    /// It is an error if `ident` exists `scope` or any parent
    /// scopes up to (and including) the global scope.
    pub(super) fn try_insert(
        &mut self,
        scope: ScopeId,
        ident: IdentRef,
        sym: SymbolId,
    ) -> Result<(), InsertError> {
        if let Some(id) = self.get(scope, ident)? {
            return Err(InsertError::Duplicate(id));
        }
        let scope = self.scopes.get_mut(scope).ok_or(InvalidScopeId(scope))?;
        match scope.symbols.entry(ident) {
            Entry::Occupied(e) => Err(InsertError::Duplicate(*e.get())),
            Entry::Vacant(entry) => {
                entry.insert(sym);
                Ok(())
            }
        }
    }

    /// Resolves `ident` to a symbol in the specified scope or
    /// any parent scopes up to (and including) the global scope.
    ///
    /// It returns `None` if the symbol cannot be found.
    pub fn get(&self, scope: ScopeId, ident: IdentRef) -> Result<Option<SymbolId>, LookupError> {
        let scope = self.scopes.get(scope).ok_or(InvalidScopeId(scope))?;
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

    /// Reports whether `ident` exists in the specified scope or
    /// any parent scopes up to (and including) the global scope.
    pub fn contains(&self, scope: ScopeId, ident: IdentRef) -> Result<bool, LookupError> {
        self.get(scope, ident).map(|v| v.is_some())
    }

    /// Returns the parent scope of `scope`.
    pub fn get_parent(&self, scope: ScopeId) -> Result<Option<ScopeId>, LookupError> {
        let scope = self.scopes.get(scope).ok_or(InvalidScopeId(scope))?;
        Ok(scope.parent)
    }
}

/// A [`ScopeId`] was invalid for a [`Scopes`].
#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("invalid scope id {0}")]
pub struct InvalidScopeId(ScopeId);

/// An error that can occur when inserting a symbol into a scope.
#[derive(Clone, Debug, thiserror::Error)]
pub enum InsertError {
    /// An internal bug occurred.
    #[error("internal bug: {0}")]
    Bug(#[from] Bug),
    /// A symbol with the same identifier already exists in the
    /// scope.
    #[error("duplicate symbol: {0}")]
    Duplicate(SymbolId),
    /// The scope ID is invalid.
    #[error("{0}")]
    InvalidScopeId(#[from] InvalidScopeId),
}

impl From<LookupError> for InsertError {
    fn from(err: LookupError) -> Self {
        match err {
            LookupError::Bug(bug) => InsertError::Bug(bug),
            LookupError::InvalidScopeId(id) => InsertError::InvalidScopeId(id),
        }
    }
}

/// A duplicate symbol.
#[derive(Clone, Debug, thiserror::Error)]
#[error("duplicate symbol")]
pub struct DuplicateSymbolId(SymbolId);

/// An error occurred while looking up a symbol.
#[derive(Clone, Debug, thiserror::Error)]
pub enum LookupError {
    /// An internal bug occurred.
    #[error("internal bug: {0}")]
    Bug(#[from] Bug),
    /// The scope ID is invalid.
    #[error("{0}")]
    InvalidScopeId(#[from] InvalidScopeId),
}

impl From<LookupError> for DiagMsg {
    fn from(err: LookupError) -> Self {
        err.to_string().into()
    }
}

macro_rules! impl_scoped {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident($ty:ty)
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Copy,
            Clone,
            Debug,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Hash,
            Serialize,
            Deserialize,
        )]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant($ty),
            )*
        }

        $(impl From<$ty> for $name {
            fn from(id: $ty) -> Self {
                $name::$variant(id)
            }
        })*

        $(impl TryFrom<$name> for $ty {
            // TODO(eric): Better error type.
            type Error = ();
            fn try_from(value: $name) -> Result<Self, Self::Error> {
                if let $name::$variant(id) = value {
                    Ok(id)
                } else {
                    Err(())
                }
            }
        })*

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $($name::$variant(id) => write!(f, "{id}")),*
                }
            }
        }
    };
}
impl_scoped! {
    /// The ID of an item that has a scope.
    ///
    /// It's used by [`Scopes`] to more easily look up a thing's
    /// scope.
    pub(crate) enum ScopedId {
        Action(ActionId),
        Block(BlockId),
        FfiFunc(FfiFuncId),
        FfiModule(FfiModuleId),
        FinishFunc(FinishFuncId),
        Func(FuncId),
    }
}

impl ScopedId {
    pub(super) fn try_from_sym_kind(kind: SymbolKind) -> Option<Self> {
        let id = match kind {
            SymbolKind::Action(id) => Self::Action(id),
            SymbolKind::FfiFunc(id) => Self::FfiFunc(id),
            SymbolKind::FfiModule(id) => Self::FfiModule(id),
            SymbolKind::FinishFunc(id) => Self::FinishFunc(id),
            SymbolKind::Func(id) => Self::Func(id),
            _ => return None,
        };
        Some(id)
    }
}
