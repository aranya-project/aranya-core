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
    Error,
    Unit,
}

impl Type {
    pub fn is_builtin(&self) -> bool {
        matches!(
            self,
            Self::String | Self::Bytes | Self::Int | Self::Bool | Self::Id
        )
    }
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

    pub fn new_none(&mut self) -> TypeRef {
        self.types
            .intern(Type::Optional(TypeOptional { inner: None }))
    }

    pub fn new_struct(&mut self, ty: TypeStruct) -> TypeRef {
        self.types.intern(Type::Struct(ty))
    }

    pub fn new_enum(&mut self, ty: TypeEnum) -> TypeRef {
        self.types.intern(Type::Enum(ty))
    }

    pub fn new_function(&mut self, ty: TypeFunc) -> TypeRef {
        self.types.intern(Type::Function(ty))
    }

    pub fn new_fact(&mut self, ty: TypeFact) -> TypeRef {
        self.types.intern(Type::Fact(ty))
    }

    pub fn new_optional(&mut self, inner_ty: Option<TypeRef>) -> TypeRef {
        self.types
            .intern(Type::Optional(TypeOptional { inner: inner_ty }))
    }

    pub fn new_error(&mut self) -> TypeRef {
        self.types.intern(Type::Error)
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
        Self {
            string,
            bytes,
            int,
            bool,
            id,
            none,
            error,
            unit,
        }
    }
}
