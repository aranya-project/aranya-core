use std::{collections::BTreeMap, fmt, hash::Hash};

use serde::{Deserialize, Serialize};

use crate::{
    arena::new_key_type,
    hir::{IdentId, IdentRef, Span},
    symbol_resolution::SymbolId,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct Type {
    pub id: TypeId,
    pub kind: TypeKind,
}

impl Type {
    pub fn new(id: TypeId, kind: TypeKind) -> Self {
        Self { id, kind }
    }

    pub fn is_numeric(&self) -> bool {
        matches!(self.kind, TypeKind::Int)
    }

    pub fn is_boolean(&self) -> bool {
        matches!(self.kind, TypeKind::Bool)
    }

    pub fn is_optional(&self) -> bool {
        matches!(self.kind, TypeKind::Optional(_))
    }
}

new_key_type! {
    pub(crate) struct TypeId;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) enum TypeKind {
    String,
    Bytes,
    Int,
    Bool,
    Id,
    Struct(SymbolId),
    Enum(SymbolId),
    Fact(SymbolId),
    Optional(TypeId),
    
    /// Type variable for inference
    TypeVar(TypeVarId),
    
    /// Unknown type (used during inference)
    Unknown,
    
    /// Error type (used when type checking fails)
    Error,
}

impl TypeKind {
    pub fn is_primitive(&self) -> bool {
        matches!(
            self,
            TypeKind::String | TypeKind::Bytes | TypeKind::Int | TypeKind::Bool | TypeKind::Id
        )
    }
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeKind::String => write!(f, "string"),
            TypeKind::Bytes => write!(f, "bytes"),
            TypeKind::Int => write!(f, "int"),
            TypeKind::Bool => write!(f, "bool"),
            TypeKind::Id => write!(f, "id"),
            TypeKind::Struct(id) => write!(f, "struct({:?})", id),
            TypeKind::Enum(id) => write!(f, "enum({:?})", id),
            TypeKind::Fact(id) => write!(f, "fact({:?})", id),
            TypeKind::Optional(ty) => write!(f, "optional({:?})", ty),
            TypeKind::TypeVar(id) => write!(f, "?{}", id.0),
            TypeKind::Unknown => write!(f, "unknown"),
            TypeKind::Error => write!(f, "error"),
        }
    }
}

new_key_type! {
    pub(crate) struct TypeVarId;
}

/// Type environment for managing type information during checking
#[derive(Clone, Debug, Default)]
pub(crate) struct TypeEnv {
    /// Maps identifiers to their types
    pub bindings: BTreeMap<IdentId, Type>,
    
    /// Type variable substitutions for inference
    pub substitutions: BTreeMap<TypeVarId, Type>,
    
    /// Parent environment for nested scopes
    pub parent: Option<Box<TypeEnv>>,
}

impl TypeEnv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_parent(parent: TypeEnv) -> Self {
        Self {
            bindings: BTreeMap::new(),
            substitutions: BTreeMap::new(),
            parent: Some(Box::new(parent)),
        }
    }

    pub fn bind(&mut self, id: IdentId, ty: Type) {
        self.bindings.insert(id, ty);
    }

    pub fn lookup(&self, id: IdentId) -> Option<Type> {
        self.bindings
            .get(&id)
            .copied()
            .or_else(|| self.parent.as_ref().and_then(|p| p.lookup(id)))
    }

    pub fn substitute(&mut self, var: TypeVarId, ty: Type) {
        self.substitutions.insert(var, ty);
    }

    pub fn resolve_type(&self, ty: Type) -> Type {
        match ty.kind {
            TypeKind::TypeVar(var) => self
                .substitutions
                .get(&var)
                .map(|t| self.resolve_type(*t))
                .unwrap_or(ty),
            TypeKind::Optional(_inner_id) => {
                // For Optional types, we'd need to resolve the inner type
                // This requires access to the type arena which we'll handle in check.rs
                ty
            }
            _ => ty,
        }
    }
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
        Self::new(
            TypeErrorKind::UndefinedField {
                struct_name,
                field,
            },
            span,
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TypeErrorKind {
    TypeMismatch { expected: Type, found: Type },
    UndefinedIdentifier(IdentRef),
    UndefinedField { struct_name: IdentRef, field: IdentRef },
    UndefinedEnumVariant { enum_name: IdentRef, variant: IdentRef },
    ArgumentCountMismatch { expected: usize, found: usize },
    InvalidUnaryOp { op: String, ty: Type },
    InvalidBinaryOp { op: String, left: Type, right: Type },
    NotAFunction(IdentRef),
    NotAStruct(Type),
    NotAnEnum(Type),
    NotAFact(Type),
    NotOptional(Type),
    RecursiveType(IdentRef),
    MissingReturnType,
    UnexpectedReturn,
    IncompatibleMatchArms,
    IncompatibleBranches { then_ty: Type, else_ty: Type },
}

impl fmt::Display for TypeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeErrorKind::TypeMismatch { expected, found } => {
                write!(f, "type mismatch: expected {:?}, found {:?}", expected.kind, found.kind)
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
                write!(f, "argument count mismatch: expected {}, found {}", expected, found)
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
