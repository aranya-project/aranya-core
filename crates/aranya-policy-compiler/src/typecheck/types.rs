use std::{
    collections::BTreeMap,
    fmt,
    hash::{Hash, Hasher},
};

use serde::{Deserialize, Serialize};

use crate::{
    hir::{ExprId, IdentId, IdentRef, Span, VTypeId},
    intern::typed_interner,
    symbol_resolution::SymbolId,
};

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Type {
    Builtin(TypeBuiltin),
    Struct(TypeStruct),
    Enum(TypeEnum),
    Optional(TypeOptional),
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin(ty) => write!(f, "{ty}"),
            Self::Struct(ty) => write!(f, "struct({ty:?})"),
            Self::Enum(ty) => write!(f, "enum({ty:?})"),
            Self::Optional(ty) => write!(f, "optional({ty:?})"),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) enum TypeBuiltin {
    String,
    Bytes,
    Int,
    Bool,
    Id,
}

impl fmt::Display for TypeBuiltin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Bytes => write!(f, "bytes"),
            Self::Int => write!(f, "int"),
            Self::Bool => write!(f, "bool"),
            Self::Id => write!(f, "id"),
        }
    }
}

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

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct TypeOptional {
    pub ty: Option<TypeRef>,
}

#[derive(Clone, Debug)]
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

    pub fn new_builtin(&mut self, ty: TypeBuiltin) -> TypeRef {
        self.types.intern(Type::Builtin(ty))
    }

    pub fn new_none(&mut self) -> TypeRef {
        self.types.intern(Type::Optional(TypeOptional { ty: None }))
    }

    pub fn new_struct(&mut self, ty: TypeStruct) -> TypeRef {
        self.types.intern(Type::Struct(ty))
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

/// Type checking error
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TypeError {
    pub kind: TypeErrorKind,
    pub span: Span,
}

impl TypeError {
    pub fn new(kind: TypeErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    pub fn type_mismatch(expected: Type, found: Type, span: Span) -> Self {
        Self::new(TypeErrorKind::TypeMismatch { expected, found }, span)
    }

    pub fn undefined_identifier(ident: IdentRef, span: Span) -> Self {
        Self::new(TypeErrorKind::UndefinedIdentifier(ident), span)
    }

    pub fn undefined_field(struct_name: IdentRef, field: IdentRef, span: Span) -> Self {
        Self::new(TypeErrorKind::UndefinedField { struct_name, field }, span)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TypeErrorKind {
    TypeMismatch {
        expected: Type,
        found: Type,
    },
    UndefinedIdentifier(IdentRef),
    UndefinedField {
        struct_name: IdentRef,
        field: IdentRef,
    },
    UndefinedEnumVariant {
        enum_name: IdentRef,
        variant: IdentRef,
    },
    ArgumentCountMismatch {
        expected: usize,
        found: usize,
    },
    InvalidUnaryOp {
        op: String,
        ty: Type,
    },
    InvalidBinaryOp {
        op: String,
        left: Type,
        right: Type,
    },
    NotAFunction(IdentRef),
    NotAStruct(Type),
    NotAnEnum(Type),
    NotAFact(Type),
    NotOptional(Type),
    RecursiveType(IdentRef),
    MissingReturnType,
    UnexpectedReturn,
    IncompatibleMatchArms,
    IncompatibleBranches {
        then_ty: Type,
        else_ty: Type,
    },
}

impl fmt::Display for TypeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeErrorKind::TypeMismatch { expected, found } => {
                write!(
                    f,
                    "type mismatch: expected {:?}, found {:?}",
                    expected.kind, found.kind
                )
            }
            TypeErrorKind::UndefinedIdentifier(ident) => {
                write!(f, "undefined identifier: {:?}", ident)
            }
            TypeErrorKind::UndefinedField { struct_name, field } => {
                write!(f, "undefined field {:?} in struct {:?}", field, struct_name)
            }
            TypeErrorKind::UndefinedEnumVariant { enum_name, variant } => {
                write!(f, "undefined variant {:?} in enum {:?}", variant, enum_name)
            }
            TypeErrorKind::ArgumentCountMismatch { expected, found } => {
                write!(
                    f,
                    "argument count mismatch: expected {}, found {}",
                    expected, found
                )
            }
            TypeErrorKind::InvalidUnaryOp { op, ty } => {
                write!(f, "invalid unary operation {} on type {:?}", op, ty.kind)
            }
            TypeErrorKind::InvalidBinaryOp { op, left, right } => {
                write!(
                    f,
                    "invalid binary operation {} between {:?} and {:?}",
                    op, left.kind, right.kind
                )
            }
            TypeErrorKind::NotAFunction(ident) => {
                write!(f, "{:?} is not a function", ident)
            }
            TypeErrorKind::NotAStruct(ty) => {
                write!(f, "expected struct type, found {:?}", ty.kind)
            }
            TypeErrorKind::NotAnEnum(ty) => {
                write!(f, "expected enum type, found {:?}", ty.kind)
            }
            TypeErrorKind::NotAFact(ty) => {
                write!(f, "expected fact type, found {:?}", ty.kind)
            }
            TypeErrorKind::NotOptional(ty) => {
                write!(f, "expected optional type, found {:?}", ty.kind)
            }
            TypeErrorKind::RecursiveType(ident) => {
                write!(f, "recursive type definition: {:?}", ident)
            }
            TypeErrorKind::MissingReturnType => {
                write!(f, "missing return statement in function with return type")
            }
            TypeErrorKind::UnexpectedReturn => {
                write!(f, "unexpected return statement in void context")
            }
            TypeErrorKind::IncompatibleMatchArms => {
                write!(f, "match arms have incompatible types")
            }
            TypeErrorKind::IncompatibleBranches { then_ty, else_ty } => {
                write!(
                    f,
                    "if branches have incompatible types: {:?} and {:?}",
                    then_ty.kind, else_ty.kind
                )
            }
        }
    }
}
