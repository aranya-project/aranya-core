use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
};

use indexmap::IndexSet;
use serde::{Deserialize, Serialize};

use crate::{
    hir::{ExprId, IdentRef, Span, VTypeId},
    intern::typed_interner,
    symtab::SymbolId,
};

/// Implements [`Eq`], [`PartialEq`], and [`Hash`] for a type or
/// item whose equality should be defined solely by its
/// [`SymbolId`].
macro_rules! impl_symbol_eq {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            pub symbol: SymbolId,
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field:ident: $ty:ty,
            )*
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            // TODO(eric): Rename to `id` or something.
            pub symbol: SymbolId,
            $($(#[$field_meta])* $field_vis $field: $ty,)*
        }

        impl Eq for $name {}
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                // Double check the invariant that we only need
                // to compare the symbols.
                if cfg!(debug_assertions) {
                    if self.symbol == other.symbol {
                        debug_assert!(
                            true $(&& self.$field == other.$field)*
                        );
                    } else {
                        debug_assert!(
                            true $(|| self.$field != other.$field)*
                        );
                    }
                }
                self.symbol == other.symbol
            }
        }

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.symbol.hash(state);
            }
        }
    };
}

/// A wrapper for a [`TypeKind`] and its xref.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Type<'cx> {
    pub xref: TypeRef,
    pub kind: &'cx TypeKind,
}

impl Eq for Type<'_> {}
impl PartialEq for Type<'_> {
    fn eq(&self, other: &Self) -> bool {
        if cfg!(debug_assertions) {
            if self.xref == other.xref {
                debug_assert_eq!(self.kind, other.kind);
            } else {
                debug_assert_ne!(self.kind, other.kind);
            }
        }
        self.xref == other.xref
    }
}

impl Hash for Type<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.xref.hash(state);
    }
}

typed_interner! {
    pub(crate) struct TypeInterner(TypeKind) => TypeRef;
}

/// A type.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum TypeKind {
    /// A UTF-8 encoded [string].
    ///
    /// [string]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#string
    String,
    /// An arbitrary [byte sequence].
    ///
    /// [byte sequence]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#bytes
    Bytes,
    /// A signed, 64-bit [integer].
    ///
    /// [integer]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#int
    Int,
    /// A [boolean] value, either `true` or `false`.
    ///
    /// [boolean]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#bool
    Bool,
    /// An opaque [id].
    ///
    /// [id]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#id
    Id,
    /// A [struct] type.
    ///
    /// [struct]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#structs
    Struct(TypeStruct),
    /// An [enumeration].
    ///
    /// [enumeration]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#enumerations
    Enum(TypeEnum),
    /// An [optional] type.
    ///
    /// [optional]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#optional-type
    Optional(TypeOptional),
    /// Type variable for inference.
    ///
    /// TODO: expand on this.
    TypeVar(TypeVar),
    // TODO: keep this?
    Unit,
    /// A type that is currently unknown and that we need to
    /// infer.
    ///
    /// This is currently only used as the return type for the
    /// [`deserialize`] intrinsic.
    ///
    /// [`deserialize`]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#serializedeserialize
    Infer,
    /// The type of a computation that can never occur.
    ///
    /// This is currently only used as the return type for the
    /// currently undocumented `todo` intrinsic.
    Never,
    /// A type that represents an type checking error.
    Error,
}

impl TypeKind {
    /// Returns the type's symbol ID, if it has one.
    pub fn symbol_id(&self) -> Option<SymbolId> {
        match self {
            Self::Struct(s) => Some(s.symbol),
            Self::Enum(e) => Some(e.symbol),
            _ => None,
        }
    }
}

impl_symbol_eq! {
    /// A struct.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct TypeStruct {
        pub symbol: SymbolId,
        pub fields: IndexSet<StructField>,
        pub origin: TypeStructOrigin,
    }
}

impl TypeStruct {
    /// Finds a particular field, if it exists.
    pub fn find_field(&self, xref: IdentRef) -> Option<&StructField> {
        self.fields.iter().find(|f| f.xref == xref)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) enum TypeStructOrigin {
    Explicit,
    Auto(ItemRef),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct StructField {
    // TODO(eric): aldo include `pub id: StructFieldId`?
    pub span: Span,
    pub xref: IdentRef,
    pub ty: TypeRef,
}

impl_symbol_eq! {
    /// An enumeration.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct TypeEnum {
        pub symbol: SymbolId,
        pub variants: IndexSet<EnumVariant>,
    }
}

impl TypeEnum {
    /// Reports whether the enum has a particular variant.
    pub fn has_variant(&self, xref: IdentRef) -> bool {
        self.variants.iter().any(|v| v.xref == xref)
    }

}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct EnumVariant {
    pub xref: IdentRef,
}

/// An optional type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct TypeOptional {
    /// The inner type, if known.
    ///
    /// If `inner` is [`None`], then it this struct represents
    ///
    /// ```policy
    /// let foo = None
    /// ```
    ///
    /// TODO(eric): Is this the righ way of doing it? We have
    /// [`Type::Infer`] we could use instead?
    pub inner: Option<TypeRef>,
}

/// An type inference variable.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct TypeVar {
    pub id: u32,
}

/// A wrapper for a [`ItemKind`] and its xref.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Item<'cx> {
    pub xref: ItemRef,
    pub kind: &'cx ItemKind,
}

impl Eq for Item<'_> {}
impl PartialEq for Item<'_> {
    fn eq(&self, other: &Self) -> bool {
        if cfg!(debug_assertions) {
            if self.xref == other.xref {
                debug_assert_eq!(self.kind, other.kind);
            } else {
                debug_assert_ne!(self.kind, other.kind);
            }
        }
        self.xref == other.xref
    }
}

impl Hash for Item<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.xref.hash(state);
    }
}

typed_interner! {
    pub(crate) struct ItemInterner(ItemKind) => ItemRef;
}

/// An item.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ItemKind {
    /// A [command].
    ///
    /// [command]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#commands
    Cmd(ItemCmd),
    /// An [effect].
    ///
    /// [effect]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#effects
    Effect(ItemEffect),
    /// A [fact].
    ///
    /// [fact]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#facts
    Fact(ItemFact),
    /// A [function].
    ///
    /// [function]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4d4f2370c9512104b89657d76ce667/docs/policy-v1.md#functions
    Func(ItemFunc),
    /// An [action].
    ///
    /// [action]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4f2370c9512104b89657d76ce667/docs/policy-v1.md#actions
    Action(ItemAction),
    /// A [finish function].
    ///
    /// [finish function]: https://github.com/aranya-project/aranya-docs/blob/c9701a0c7c4f2370c9512104b89657d76ce667/docs/policy-v1.md#finish-functions
    FinishFunc(ItemFinishFunc),
    /// An FFI function.
    FfiFunc(ItemFfiFunc),
    /// An FFI module.
    FfiModule(ItemFfiModule),
}

impl ItemKind {
    /// Returns the item's symbol ID.
    pub fn symbol_id(&self) -> SymbolId {
        match self {
            Self::Cmd(c) => c.symbol,
            Self::Effect(e) => e.symbol,
            Self::Fact(f) => f.symbol,
            Self::Func(f) => f.symbol,
            Self::Action(a) => a.symbol,
            Self::FinishFunc(f) => f.symbol,
            Self::FfiFunc(f) => f.symbol,
            Self::FfiModule(m) => m.symbol,
        }
    }
}

impl_symbol_eq! {
    /// A function.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct ItemFunc {
        pub symbol: SymbolId,
        pub params: IndexSet<TypeRef>,
        pub return_type: TypeRef,
    }
}

impl_symbol_eq! {
    /// An action.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct ItemAction {
        pub symbol: SymbolId,
        pub params: IndexSet<TypeRef>,
    }
}

impl_symbol_eq! {
    /// A finish function.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct ItemFinishFunc {
        pub symbol: SymbolId,
        pub params: IndexSet<TypeRef>,
        pub return_type: Option<TypeRef>,
    }
}

impl_symbol_eq! {
    /// A fact.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct ItemFact {
        pub symbol: SymbolId,
        pub keys: IndexSet<FactField>,
        pub vals: IndexSet<FactField>,
    }
}

impl ItemFact {
    /// Retrieves a particular key, if it exists.
    pub fn find_key(&self, xref: IdentRef) -> Option<&FactField> {
        self.keys.iter().find(|k| k.xref == xref)
    }

    /// Retrieves a particular value, if it exists.
    pub fn find_val(&self, xref: IdentRef) -> Option<&FactField> {
        self.vals.iter().find(|v| v.xref == xref)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct FactField {
    pub xref: IdentRef,
    pub ty: TypeRef,
}

impl_symbol_eq! {
    /// A command.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct ItemCmd {
        pub symbol: SymbolId,
        pub fields: IndexSet<StructField>,
    }
}

impl_symbol_eq! {
    /// An effect.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct ItemEffect {
        pub symbol: SymbolId,
        pub fields: IndexSet<StructField>,
    }
}

impl_symbol_eq! {
    /// An FFI function.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct ItemFfiFunc {
        pub symbol: SymbolId,
        pub params: IndexSet<TypeRef>,
        pub return_type: TypeRef,
    }
}

impl_symbol_eq! {
    /// An FFI module.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct ItemFfiModule {
        pub symbol: SymbolId,
    }
}

#[derive(Debug)]
pub(crate) struct TypeEnv {
    pub item_symbols: BTreeMap<SymbolId, ItemRef>,
    pub type_symbols: BTreeMap<SymbolId, TypeRef>,
    #[allow(dead_code)]
    pub exprs: BTreeMap<ExprId, TypeRef>,
    #[allow(dead_code)]
    pub vtypes: BTreeMap<VTypeId, TypeRef>,
}

impl TypeEnv {
    pub fn new() -> Self {
        Self {
            item_symbols: BTreeMap::new(),
            type_symbols: BTreeMap::new(),
            exprs: BTreeMap::new(),
            vtypes: BTreeMap::new(),
        }
    }
}

impl Default for TypeEnv {
    fn default() -> Self {
        Self::new()
    }
}

// TODO(eric): Rename to Common or something.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Builtins {
    pub string: TypeRef,
    pub bytes: TypeRef,
    pub int: TypeRef,
    pub bool: TypeRef,
    pub id: TypeRef,
    pub none: TypeRef,
    pub error: TypeRef,
    pub unit: TypeRef,
    pub infer: TypeRef,
    pub never: TypeRef,
}

impl Builtins {
    pub fn new(types: &TypeInterner) -> Self {
        let string = types.intern(TypeKind::String);
        let bytes = types.intern(TypeKind::Bytes);
        let int = types.intern(TypeKind::Int);
        let bool = types.intern(TypeKind::Bool);
        let id = types.intern(TypeKind::Id);
        let none = types.intern(TypeKind::Optional(TypeOptional { inner: None }));
        let error = types.intern(TypeKind::Error);
        let unit = types.intern(TypeKind::Unit);
        let infer = types.intern(TypeKind::Infer);
        let never = types.intern(TypeKind::Never);
        Self {
            string,
            bytes,
            int,
            bool,
            id,
            none,
            error,
            unit,
            infer,
            never,
        }
    }
}
