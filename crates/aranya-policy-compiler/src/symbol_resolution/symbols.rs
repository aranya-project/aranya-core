//! Symbol table for storing declarations and their types.

use std::hash::Hash;

use aranya_policy_ast::{Identifier, VType};

use crate::{
    hir::hir::{IdentId, VTypeId},
    symbol_resolution::scope::ScopeId,
};

/// Uniquely identifies a [`Symbol`] in a [`Symbols`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SymbolId(usize);

/// A collection of [`Symbols`].
#[derive(Clone, Debug)]
pub struct Symbols {
    symbols: Vec<Symbol>,
}

impl Symbols {
    /// Creates an empty symbol arena.
    pub const fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
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
#[derive(Clone, Debug)]
pub struct Symbol {
    pub ident: IdentId,
    pub kind: SymbolKind,
    /// The scope that the symbol was defined in.
    ///
    /// For example, a top-level function will be defined in the
    /// global scope. That function's local variable declarations
    /// will be defined in a child scope of the global scope.
    pub scope: ScopeId,
    pub location: Option<usize>,
}

/// A symbol in the symbol table.
#[derive(Clone, Debug)]
pub enum SymbolKind {
    GlobalVar(SymGlobalVar),
    LocalVar(SymLocalVar),
    Fact(SymFact),
    Action(SymAction),
    Effect(SymEffect),
    Struct(SymStruct),
    Enum(SymEnum),
    Command(SymCommand),
    Function(SymFunction),
    FinishFunction(SymFinishFunction),
    FfiModule(SymFfiModule),
}

/// A global variable.
#[derive(Clone, Debug)]
pub struct SymGlobalVar {
    /// The value of the global variable.
    pub vtype: SymType,
    /// Expression local scope.
    pub scope: ScopeId,
}

/// A local variable.
#[derive(Clone, Debug)]
pub struct SymLocalVar {
    /// The type of the local variable.
    pub vtype: SymType,
    /// Expression local scope.
    pub scope: ScopeId,
}

/// A `fact` declaration.
#[derive(Clone, Debug)]
pub struct SymFact {
    pub keys: Vec<(IdentId, SymType)>,
    pub values: Vec<(IdentId, SymType)>,
}

/// An `action` declaration.
#[derive(Clone, Debug)]
pub struct SymAction {
    pub params: Vec<(IdentId, SymType)>,
    /// Action-local scope.
    pub scope: ScopeId,
}

/// An `effect` declaration.
#[derive(Clone, Debug)]
pub struct SymEffect {
    pub fields: Status<Vec<(IdentId, SymType)>>,
}

/// A `struct` declaration.
#[derive(Clone, Debug)]
pub struct SymStruct {
    pub fields: Status<Vec<(IdentId, SymType)>>,
}

/// An `enum` declaration.
#[derive(Clone, Debug)]
pub struct SymEnum {
    pub variants: Vec<IdentId>,
}

/// A `command` declaration.
#[derive(Clone, Debug)]
pub struct SymCommand {
    pub fields: Status<Vec<(IdentId, SymType)>>,
    pub policy: Status<PolicyBlock>,
    pub finish: Status<FinishBlock>,
    pub recall: Status<RecallBlock>,
}

/// A `policy` block inside a [`SymCommand`].
#[derive(Clone, Debug)]
pub struct PolicyBlock {
    /// Block-local scope.
    pub scope: ScopeId,
    pub finish: FinishBlock,
}

/// A `recall` block inside a [`SymCommand`].
#[derive(Clone, Debug)]
pub struct RecallBlock {
    /// Block-local scope.
    pub scope: ScopeId,
    pub finish: FinishBlock,
}

/// A `finish` block inside a [`PolicyBlock`] or [`RecallBlock`].
#[derive(Clone, Debug)]
pub struct FinishBlock {
    /// Block-local scope.
    pub scope: ScopeId,
}

/// An FFI module.
#[derive(Clone, Debug)]
pub struct SymFfiModule {
    /// Module-local scope.
    pub scope: ScopeId,
}

/// A `function` declaration.
#[derive(Clone, Debug)]
pub struct SymFunction {
    pub params: Vec<(IdentId, SymType)>,
    pub result: SymType,
    /// Function-local scope.
    pub scope: ScopeId,
}

/// A `finish function` declaration.
#[derive(Clone, Debug)]
pub struct SymFinishFunction {
    pub params: Vec<(IdentId, SymType)>,
    /// Function-local scope.
    pub scope: ScopeId,
}

/// Has this field been resolved?
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Status<T> {
    /// Yes.
    Resolved(T),
    /// Nope.
    Unresolved,
}

/// A maybe resolved [`VTypeId`].
pub type SymType = Status<VTypeId>;

// Note: VTypeId resolution will be handled during symbol resolution
// All types start as Unresolved and are resolved later


