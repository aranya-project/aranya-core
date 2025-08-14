//! Symbol table for storing declarations and their types.

use serde::{Deserialize, Serialize};

use super::scope::ScopeId;
use crate::{
    arena::{self, Arena},
    hir::{
        ActionId, BlockId, CmdId, EffectId, EnumId, FactId, FfiEnumId, FfiFuncId, FfiImportId,
        FfiModuleId, FfiStructId, FinishFuncId, FuncId, GlobalId, IdentId, Span, StructId,
    },
};

/// A collection of [`Symbols`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Symbols {
    symbols: Arena<SymbolId, Symbol>,
}

impl Symbols {
    /// Creates an empty symbol arena.
    pub(super) const fn new() -> Self {
        Self {
            symbols: Arena::new(),
        }
    }

    /// Inserts a symbol into the arena and returns its ID.
    ///
    /// Each symbol is assigned a unique ID, even if the exact
    /// same symbol already exists inside the arena.
    pub(super) fn insert(&mut self, sym: Symbol) -> SymbolId {
        self.symbols.insert(sym)
    }

    /// Retrieves a shared reference to a symbol by its ID.
    pub fn get(&self, id: SymbolId) -> Option<&Symbol> {
        self.symbols.get(id)
    }

    /// Retrieves an exclusive reference to a symbol by its ID.
    pub fn get_mut(&mut self, id: SymbolId) -> Option<&mut Symbol> {
        self.symbols.get_mut(id)
    }

    /// Returns an iterator over the symbols in the arena.
    pub fn iter(&self) -> arena::Iter<'_, SymbolId, Symbol> {
        self.into_iter()
    }
}

impl<'a> IntoIterator for &'a Symbols {
    type Item = (SymbolId, &'a Symbol);
    type IntoIter = arena::Iter<'a, SymbolId, Symbol>;

    fn into_iter(self) -> Self::IntoIter {
        self.symbols.iter()
    }
}

/// A symbol in the symbol table.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Symbol {
    pub ident: IdentId,
    pub kind: SymbolKind,
    /// A back reference to the scope that the symbol was defined
    /// in.
    ///
    /// For example, a top-level function will be defined in the
    /// global scope. That function's local variable declarations
    /// will be defined in a child scope of the global scope.
    pub scope: ScopeId,
    /// TODO(eric): Keep this? We can compute it by using `kind`
    /// to look up the HIR node.
    pub span: Span,
}

arena::new_key_type! {
    /// Uniquely identifies a [`Symbol`] in a [`Symbols`].
    pub(crate) struct SymbolId;
}

macro_rules! impl_sym_kind {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident($id:ty),
            )*
        }
    ) => {
        $(#[$meta])*
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant($id),
            )*
        }
        $(impl From<$id> for $name {
            fn from(id: $id) -> Self {
                Self::$variant(id)
            }
        })*
    };
}

impl_sym_kind! {
    /// A symbol in the symbol table.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub(crate) enum SymbolKind {
        Action(ActionId),
        Cmd(CmdId),
        Effect(EffectId),
        Enum(EnumId),
        Fact(FactId),
        FfiEnum(FfiEnumId),
        FfiFunc(FfiFuncId),
        FfiImport(FfiImportId),
        FfiModule(FfiModuleId),
        FfiStruct(FfiStructId),
        FinishFunc(FinishFuncId),
        Func(FuncId),
        GlobalVar(GlobalId),
        LocalVar(Option<BlockId>),
        Struct(StructId),
    }
}
