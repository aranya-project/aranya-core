//! Symbol table for storing declarations and their types.

use std::hash::Hash;

use serde::{Deserialize, Serialize};

use super::scope::ScopeId;
use crate::{
    arena::{self, Arena},
    hir::{
        ActionId, BlockId, CmdId, EffectId, EnumId, FactId, FfiEnumId, FfiFuncId, FfiImportId,
        FfiModuleId, FfiStructId, FinishFuncId, FuncId, GlobalId, Hir, HirNode, IdentId, IdentRef,
        Named, Span, StructDef, StructId, StructOrigin,
    },
};

/// A collection of [`Symbols`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Symbols {
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
pub struct Symbol {
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
    pub struct SymbolId;
}

macro_rules! impl_enum {
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

/// Symbol table namespace.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Namespace {
    /// An item.
    Item,
    /// A type.
    Type,
}

impl_enum! {
    /// The kind of symbol.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
    pub enum SymbolKind {
        Item(ItemKind),
        Type(TypeKind),
    }
}

impl SymbolKind {
    /// Returns the namespace of this symbol kind.
    pub fn namespace(&self) -> Namespace {
        match self {
            Self::Item(_) => Namespace::Item,
            Self::Type(_) => Namespace::Type,
        }
    }
}

macro_rules! impl_inner_kind {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident($id:ty),
            )*
        }
    ) => {
        impl_enum! {
            $(#[$meta])*
            $vis enum $name {
                $(
                    $(#[$variant_meta])*
                    $variant($id),
                )*
            }
        }
        $(impl From<$id> for SymbolKind {
            fn from(id: $id) -> Self {
                Self::Item($name::$variant(id))
            }
        })*
    };
}

impl_inner_kind! {
    /// An item (i.e., a non-type).
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
    pub enum ItemKind {
        /// An action.
        Action(ActionId),
        /// A command.
        Cmd(CmdId),
        /// An effect.
        Effect(EffectId),
        /// A fact.
        Fact(FactId),
        /// An enum from an FFI module.
        FfiEnum(FfiEnumId),
        /// A function from an FFI module.
        FfiFunc(FfiFuncId),
        /// An FFI import (`use`).
        FfiImport(FfiImportId),
        /// An FFI module.
        FfiModule(FfiModuleId),
        /// A struct from an FFI module.
        /// TODO(eric): This should be a type.
        FfiStruct(FfiStructId),
        /// A finish function.
        FinishFunc(FinishFuncId),
        /// A function.
        Func(FuncId),
        /// A global variable.
        GlobalVar(GlobalId),
        /// A local variable.
        LocalVar(Option<BlockId>),
    }
}

/// A type (i.e., a non-item).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum TypeKind {
    /// A struct.
    Struct(StructId, TypeOrigin),
    /// An enum.
    Enum(EnumId),
}

impl From<(StructId, TypeOrigin)> for TypeKind {
    fn from((id, origin): (StructId, TypeOrigin)) -> Self {
        Self::Struct(id, origin)
    }
}
impl From<(StructId, TypeOrigin)> for SymbolKind {
    fn from((id, origin): (StructId, TypeOrigin)) -> Self {
        Self::Type(TypeKind::Struct(id, origin))
    }
}

impl From<EnumId> for TypeKind {
    fn from(id: EnumId) -> Self {
        Self::Enum(id)
    }
}
impl From<EnumId> for SymbolKind {
    fn from(id: EnumId) -> Self {
        Self::Type(TypeKind::Enum(id))
    }
}

/// The origin of a [`TypeKind::Struct`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum TypeOrigin {
    /// Explicitly defined in the source code.
    Explicit,
    /// Synthesized from a command.
    AutoCmd(CmdId),
    /// Synthesized from an effect.
    AutoEffect(EffectId),
    /// Synthesized from a fact.
    AutoFact(FactId),
}

/// Marker trait for HIR nodes that represent global symbols.
///
/// Global symbols are top-level symbols that can be referenced
/// from anywhere in the program (e.g., actions, structs, enums).
///
/// Keep impls of this trait in sync with
/// [`for_each_top_level_item`][crate::hir::visit::for_each_top_level_item].
pub trait GlobalSymbol: HirNode + Named {
    fn kind(&self) -> SymbolKind;
}

impl<T: GlobalSymbol> GlobalSymbol for &T {
    fn kind(&self) -> SymbolKind {
        (*self).kind()
    }
}

/// Macro to implement GlobalSymbol for HIR node types.
macro_rules! impl_global_symbol {
    ($($def:ident => $kind:ident($variant:ident)),* $(,)?) => {
        $(
            impl GlobalSymbol for crate::hir::$def {
                fn kind(&self) -> SymbolKind {
                    SymbolKind::from($kind::$variant(self.id))
                }
            }
        )*
    };
}

impl_global_symbol! {
    ActionDef => ItemKind(Action),
    CmdDef => ItemKind(Cmd),
    EffectDef => ItemKind(Effect),
    EnumDef => TypeKind(Enum),
    FactDef => ItemKind(Fact),
    FfiEnumDef => ItemKind(FfiEnum),
    FfiImportDef => ItemKind(FfiImport),
    FfiModuleDef => ItemKind(FfiModule),
    FfiStructDef => ItemKind(FfiStruct),
    FinishFuncDef => ItemKind(FinishFunc),
    FuncDef => ItemKind(Func),
    GlobalLetDef => ItemKind(GlobalVar),
}

impl GlobalSymbol for StructDef {
    fn kind(&self) -> SymbolKind {
        match self.origin {
            StructOrigin::Explicit => {
                SymbolKind::Type(TypeKind::Struct(self.id, TypeOrigin::Explicit))
            }
            StructOrigin::AutoCmd(id) => {
                SymbolKind::Type(TypeKind::Struct(self.id, TypeOrigin::AutoCmd(id)))
            }
            StructOrigin::AutoEffect(id) => {
                SymbolKind::Type(TypeKind::Struct(self.id, TypeOrigin::AutoEffect(id)))
            }
            StructOrigin::AutoFact(id) => {
                SymbolKind::Type(TypeKind::Struct(self.id, TypeOrigin::AutoFact(id)))
            }
        }
    }
}
