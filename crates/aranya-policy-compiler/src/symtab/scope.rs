#![expect(clippy::unwrap_used)]

use std::{
    collections::{
        BTreeSet, VecDeque,
        btree_map::{BTreeMap, Entry},
    },
    fmt,
    hash::Hash,
};

use buggy::{Bug, BugExt};
use serde::{Deserialize, Serialize};

use super::symbols::SymbolId;
use crate::{
    arena::{self, Arena},
    diag::DiagMsg,
    hir::{ActionId, BlockId, BodyId, FfiFuncId, FfiModuleId, FinishFuncId, FuncId, IdentRef},
};

/// A program scope (global or block).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Uniquely identifies this scope.
    // TODO(eric): Do we need this field?
    pub id: ScopeId,
    /// The parent scope, if any.
    pub parent: Option<ScopeId>,
    /// Symbols defined in this scope.
    pub symbols: BTreeMap<IdentRef, SymbolId>,
}

arena::new_key_type! {
    /// Uniquely identifies a [`Scope`].
    pub struct ScopeId;
}

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
        if let Some(id) = self.get_sym(scope, ident)? {
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

    /// Retrieves a shared reference to a scope.
    pub fn get(&self, scope: ScopeId) -> Result<&Scope, InvalidScopeId> {
        self.scopes.get(scope).ok_or(InvalidScopeId(scope))
    }

    /// Resolves `ident` to a symbol in the specified scope or
    /// any parent scopes up to (and including) the global scope.
    ///
    /// It returns `None` if the symbol cannot be found.
    pub fn get_sym(
        &self,
        scope: ScopeId,
        ident: IdentRef,
    ) -> Result<Option<SymbolId>, LookupError> {
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
        self.get_sym(scope, ident).map(|v| v.is_some())
    }

    /// Returns the parent scope of `scope`.
    pub fn get_parent(&self, scope: ScopeId) -> Result<Option<ScopeId>, LookupError> {
        let scope = self.scopes.get(scope).ok_or(InvalidScopeId(scope))?;
        Ok(scope.parent)
    }

    pub fn walk(&self, mut f: impl FnMut(&Self, ScopeId)) {
        let Graph { sorted, .. } = self.build_graph().unwrap();
        for id in sorted {
            f(self, id);
        }
    }

    fn build_graph(&self) -> Result<Graph, HasCycles> {
        let mut incoming = BTreeMap::<_, BTreeSet<ScopeId>>::new();
        let mut outgoing = BTreeMap::new();
        for (id, scope) in &self.scopes {
            if let Some(parent) = &scope.parent {
                outgoing.insert(id, *parent);
                incoming
                    .entry(*parent)
                    .and_modify(|v| {
                        v.insert(id);
                    })
                    .or_default();
            } else {
                // The global scope is the only scope without
                // a parent.
                assert_eq!(id, ScopeId::GLOBAL);
            }
        }
        let mut graph = Graph {
            incoming,
            outgoing,
            sorted: Vec::new(),
        };
        graph.sorted = graph.topo_sort()?;
        Ok(graph)
    }
}

#[derive(Clone, Debug)]
struct Graph {
    incoming: BTreeMap<ScopeId, BTreeSet<ScopeId>>,
    outgoing: BTreeMap<ScopeId, ScopeId>,
    sorted: Vec<ScopeId>,
}

impl Graph {
    fn topo_sort(&self) -> Result<Vec<ScopeId>, HasCycles> {
        let mut sorted = Vec::new();
        let (mut q, mut incoming): (VecDeque<_>, BTreeMap<_, _>) = self.incoming.iter().fold(
            (VecDeque::new(), BTreeMap::new()),
            |(mut q, mut edges), (id, incoming)| {
                if incoming.is_empty() {
                    q.push_back(*id);
                } else {
                    edges.insert(*id, incoming.clone());
                }
                (q, edges)
            },
        );
        let mut outgoing = self.outgoing.clone();
        while let Some(n) = q.pop_front() {
            sorted.push(n);
            let Some(m) = outgoing.remove(&n) else {
                continue;
            };
            let out = incoming.get_mut(&m).unwrap();
            out.remove(&n);
            if out.is_empty() {
                incoming.remove(&m);
                q.push_back(m);
            }
        }

        // TODO(eric): Reverse the edge direction instead.
        sorted.reverse();
        assert_eq!(sorted[0], ScopeId::GLOBAL);

        if incoming.is_empty() {
            Ok(sorted)
        } else {
            Err(HasCycles)
        }
    }
}

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("scope has cycles")]
struct HasCycles;

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

macro_rules! impl_scoped_id {
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

        // TODO: keep this impl?
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
impl_scoped_id! {
    /// The ID of an item that has a scope.
    ///
    /// It's used by [`Scopes`] to more easily look up a thing's
    /// scope.
    pub enum ScopedId {
        Action(ActionId),
        Block(BlockId),
        Body(BodyId),
        FfiFunc(FfiFuncId),
        FfiModule(FfiModuleId),
        FinishFunc(FinishFuncId),
        Func(FuncId),
    }
}
