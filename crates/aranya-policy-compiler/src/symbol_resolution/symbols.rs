//! Symbol table for storing declarations and their types.

use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::{
    hir::{IdentId, Span},
    symbol_resolution::scope::ScopeId,
};

/// Uniquely identifies a [`Symbol`] in a [`Symbols`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub(crate) struct SymbolId(usize);

/// A collection of [`Symbols`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Symbols {
    symbols: Vec<Symbol>,
}

impl Symbols {
    /// Creates an empty symbol arena.
    pub const fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    /// Get the underlying symbols vector (for testing only)
    #[cfg(test)]
    pub(crate) fn symbols(&self) -> &Vec<Symbol> {
        &self.symbols
    }

    /// Inserts a symbol into the arena and returns its ID.
    ///
    /// Each symbol is assigned a unique ID, even if the exact
    /// same symbol already exists inside the arena.
    pub fn insert(&mut self, sym: Symbol) -> SymbolId {
        let id = SymbolId(self.symbols.len());
        self.symbols.push(sym);
        id
    }

    /// Retrieves a shared reference to a symbol by its ID.
    pub fn get(&self, id: SymbolId) -> Option<&Symbol> {
        self.symbols.get(id.0)
    }

    /// Retrieves an exclusive reference to a symbol by its ID.
    pub fn get_mut(&mut self, id: SymbolId) -> Option<&mut Symbol> {
        self.symbols.get_mut(id.0)
    }
}

/// A symbol in the symbol table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Symbol {
    pub ident: IdentId,
    pub kind: SymbolKind,
    /// The scope that the symbol was defined in (a backref).
    ///
    /// For example, a top-level function will be defined in the
    /// global scope. That function's local variable declarations
    /// will be defined in a child scope of the global scope.
    pub scope: ScopeId,
    pub span: Option<Span>,
}

/// A symbol in the symbol table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SymbolKind {
    GlobalVar(SymGlobalVar),
    LocalVar(SymLocalVar),
    Fact(SymFact),
    Action(SymAction),
    Effect(SymEffect),
    Struct(SymStruct),
    Enum(SymEnum),
    Cmd(SymCmd),
    Func(SymFunc),
    FinishFunc(SymFinishFunc),
    FfiModule(SymFfiModule),
    FfiFunc(SymFfiFunc),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymFfiFunc {
    /// The scope that the FFI function was defined in.
    pub scope: ScopeId,
}

/// A global variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymGlobalVar {
    /// Expression local scope.
    pub scope: ScopeId,
}

/// A local variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymLocalVar {
    /// Expression local scope.
    pub scope: ScopeId,
}

/// A `fact` declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymFact {}

/// An `action` declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymAction {
    /// Action-local scope.
    pub scope: ScopeId,
}

/// An `effect` declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymEffect {}

/// A `struct` declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymStruct {}

/// An `enum` declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymEnum {}

/// A `command` declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymCmd {
    pub policy: PolicyBlock,
    pub recall: RecallBlock,
}

/// A `policy` block inside a [`SymCommand`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyBlock {
    /// Block-local scope.
    pub scope: ScopeId,
    pub finish: FinishBlock,
}

/// A `recall` block inside a [`SymCommand`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecallBlock {
    /// Block-local scope.
    pub scope: ScopeId,
    pub finish: FinishBlock,
}

/// A `finish` block inside a [`PolicyBlock`] or [`RecallBlock`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FinishBlock {
    /// Block-local scope.
    pub scope: ScopeId,
}

/// An FFI module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymFfiModule {
    /// Module-local scope.
    pub scope: ScopeId,
}

/// A `function` declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymFunc {
    /// Function-local scope.
    pub scope: ScopeId,
}

/// A `finish function` declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymFinishFunc {
    /// Function-local scope.
    pub scope: ScopeId,
}
