use std::{
    collections::BTreeMap,
    fmt,
    hash::{Hash, Hasher},
};

use serde::{Deserialize, Serialize};

use crate::{
    hir::{ExprId, IdentId, IdentRef, Span, VTypeId},
    intern::typed_interner,
    symtab::SymbolId,
};

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Type {
    String,
    Bytes,
    Int,
    Bool,
    Id,
    Struct(TypeStruct),
    Enum(TypeEnum),
    Optional(TypeOptional),
    Function(TypeFunc),
    Fact(TypeFact),
    /// A command type (to be synthesized as struct)
    Cmd(TypeCmd),
    /// An effect type (to be synthesized as struct)
    Effect(TypeEffect),
    /// Type variable for inference (future)
    TypeVar(u32),
    Error,
    Unit,
    Infer,
    Never,
}

/// A struct.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TypeStruct {
    pub symbol: SymbolId,
    pub fields: Vec<StructField>,
}

impl Eq for TypeStruct {}
impl PartialEq for TypeStruct {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            symbol: self_symbol,
            fields: _,
        } = self;
        let Self {
            symbol: other_symbol,
            fields: _,
        } = other;
        self_symbol == other_symbol
    }
}

impl Hash for TypeStruct {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.symbol.hash(state);
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct StructField {
    pub ident: IdentId,
    pub xref: IdentRef,
    pub ty: TypeRef,
}

/// An enumeration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TypeEnum {
    pub symbol: SymbolId,
    pub variants: Vec<EnumVariant>,
}

impl Eq for TypeEnum {}
impl PartialEq for TypeEnum {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            symbol: self_symbol,
            variants: _,
        } = self;
        let Self {
            symbol: other_symbol,
            variants: _,
        } = other;
        self_symbol == other_symbol
    }
}

impl Hash for TypeEnum {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.symbol.hash(state);
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct EnumVariant {
    pub ident: IdentId,
    pub xref: IdentRef,
}

/// An optional type.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct TypeOptional {
    pub inner: Option<TypeRef>,
}

/// A function, finish function, or action.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TypeFunc {
    pub symbol: SymbolId,
    pub params: Vec<TypeRef>,
    pub return_type: Option<TypeRef>,
}

impl Eq for TypeFunc {}
impl PartialEq for TypeFunc {
    fn eq(&self, other: &Self) -> bool {
        self.symbol == other.symbol
    }
}

impl Hash for TypeFunc {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.symbol.hash(state);
    }
}

/// A fact.
///
/// TODO(eric): keep this?
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TypeFact {
    pub symbol: SymbolId,
    pub keys: Vec<FactField>,
    pub vals: Vec<FactField>,
}

impl Eq for TypeFact {}
impl PartialEq for TypeFact {
    fn eq(&self, other: &Self) -> bool {
        self.symbol == other.symbol
    }
}

impl Hash for TypeFact {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.symbol.hash(state);
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct FactField {
    pub ident: IdentId,
    pub xref: IdentRef,
    pub ty: TypeRef,
}

/// A command.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TypeCmd {
    pub symbol: SymbolId,
    pub fields: Vec<StructField>,
}

impl Eq for TypeCmd {}
impl PartialEq for TypeCmd {
    fn eq(&self, other: &Self) -> bool {
        self.symbol == other.symbol
    }
}

impl Hash for TypeCmd {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.symbol.hash(state);
    }
}

/// An effect.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TypeEffect {
    pub symbol: SymbolId,
    pub fields: Vec<StructField>,
}

impl Eq for TypeEffect {}
impl PartialEq for TypeEffect {
    fn eq(&self, other: &Self) -> bool {
        self.symbol == other.symbol
    }
}

impl Hash for TypeEffect {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.symbol.hash(state);
    }
}

#[derive(Debug)]
pub(crate) struct TypeEnv {
    pub types: TypeInterner,
    pub symbols: BTreeMap<SymbolId, TypeRef>,
    pub exprs: BTreeMap<ExprId, TypeRef>,
    pub vtypes: BTreeMap<VTypeId, TypeRef>,
}

impl TypeEnv {
    pub fn new() -> Self {
        Self {
            types: TypeInterner::new(),
            symbols: BTreeMap::new(),
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

typed_interner! {
    pub(crate) struct TypeInterner(Type) => TypeRef;
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
        let string = types.intern(Type::String);
        let bytes = types.intern(Type::Bytes);
        let int = types.intern(Type::Int);
        let bool = types.intern(Type::Bool);
        let id = types.intern(Type::Id);
        let none = types.intern(Type::Optional(TypeOptional { inner: None }));
        let error = types.intern(Type::Error);
        let unit = types.intern(Type::Unit);
        let infer = types.intern(Type::Infer);
        let never = types.intern(Type::Never);
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
