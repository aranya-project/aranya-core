extern crate alloc;

use alloc::{borrow::ToOwned as _, boxed::Box, collections::BTreeMap, format, string::String};
use core::fmt::{self, Display};

use aranya_policy_ast::{self as ast, Identifier, Text, WithSpanExt as _};
use serde::{Deserialize, Serialize};

/// Result type kind
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct ResultTypeKind {
    /// ok type
    pub ok: TypeKind,
    /// error type
    pub err: TypeKind,
}

impl From<ast::ResultTypeKind> for ResultTypeKind {
    fn from(value: ast::ResultTypeKind) -> Self {
        Self {
            ok: value.ok.inner.into(),
            err: value.err.inner.into(),
        }
    }
}

/// A [`Span`](ast::Span)-less version of [`ast::TypeKind`].
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(
    bounds(
        __C: rkyv::validation::ArchiveContext,
        __C::Error: rkyv::rancor::Source,
    )
))]
pub enum TypeKind {
    /// The unit, like `()` or `void`.
    Unit,
    /// A character (UTF-8) string
    String,
    /// A byte string
    Bytes,
    /// A signed 64-bit integer
    Int,
    /// A boolean
    Bool,
    /// A unique identifier
    Id,
    /// A named struct
    Struct(Identifier),
    /// Named enumeration
    Enum(Identifier),
    /// An optional type of some other type
    Optional(#[rkyv(omit_bounds)] Box<TypeKind>),
    /// A type which cannot be instantiated.
    Never,
    /// Result with value, or error
    Result(#[rkyv(omit_bounds)] Box<ResultTypeKind>),
}

impl From<ast::TypeKind> for TypeKind {
    fn from(value: ast::TypeKind) -> Self {
        match value {
            aranya_policy_ast::TypeKind::Unit => Self::Unit,
            aranya_policy_ast::TypeKind::String => Self::String,
            aranya_policy_ast::TypeKind::Bytes => Self::Bytes,
            aranya_policy_ast::TypeKind::Int => Self::Int,
            aranya_policy_ast::TypeKind::Bool => Self::Bool,
            aranya_policy_ast::TypeKind::Id => Self::Id,
            aranya_policy_ast::TypeKind::Struct(s) => Self::Struct(s.inner),
            aranya_policy_ast::TypeKind::Enum(e) => Self::Enum(e.inner),
            aranya_policy_ast::TypeKind::Optional(o) => Self::Optional(Box::new(o.inner.into())),
            aranya_policy_ast::TypeKind::Never => Self::Never,
            aranya_policy_ast::TypeKind::Result(r) => Self::Result(Box::new((*r).into())),
        }
    }
}

impl Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unit => write!(f, "unit"),
            Self::String => write!(f, "string"),
            Self::Bytes => write!(f, "bytes"),
            Self::Int => write!(f, "int"),
            Self::Bool => write!(f, "bool"),
            Self::Id => write!(f, "id"),
            Self::Struct(name) => write!(f, "struct {name}"),
            Self::Enum(name) => write!(f, "enum {name}"),
            Self::Optional(vtype) => write!(f, "option[{vtype}]"),
            Self::Never => write!(f, "never"),
            Self::Result(result_type) => {
                write!(f, "result[{}, {}]", result_type.ok, result_type.err)
            }
        }
    }
}
/// A constant or literal value used in policy.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(
    bounds(
        __C: rkyv::validation::ArchiveContext,
        __C::Error: rkyv::rancor::Source,
    )
))]
pub enum ConstValue {
    /// A Unit value.
    Unit,
    /// Integer (64-bit signed)
    Int(i64),
    /// Boolean
    Bool(bool),
    /// String (UTF-8)
    String(Text),
    /// Struct
    Struct(#[rkyv(omit_bounds)] ConstStruct),
    /// Enumeration value
    Enum(Identifier, i64),
    /// Optional value
    Option(#[rkyv(omit_bounds)] Option<Box<Self>>),
    /// Result value
    Result(#[rkyv(omit_bounds)] Result<Box<Self>, Box<Self>>),
}

impl ConstValue {
    /// Shorthand for `Self::Option(None)`.
    pub const NONE: Self = Self::Option(None);

    /// Get the associated [`TypeKind`].
    pub fn type_kind(&self) -> TypeKind {
        match self {
            Self::Unit => TypeKind::Unit,
            Self::Int(_) => TypeKind::Int,
            Self::Bool(_) => TypeKind::Bool,
            Self::String(_) => TypeKind::String,
            Self::Enum(name, _) => TypeKind::Enum(name.to_owned()),
            Self::Struct(s) => TypeKind::Struct(s.name.clone()),
            Self::Option(o) => {
                let inner_kind = match o {
                    Some(inner_value) => inner_value.type_kind(),
                    None => TypeKind::Never,
                };
                TypeKind::Optional(Box::new(inner_kind))
            }
            Self::Result(Ok(ok)) => {
                let ok_kind = ok.type_kind();
                TypeKind::Result(Box::new(ResultTypeKind {
                    ok: ok_kind,
                    err: TypeKind::Never,
                }))
            }
            Self::Result(Err(err)) => {
                let err_kind = err.type_kind();
                TypeKind::Result(Box::new(ResultTypeKind {
                    ok: TypeKind::Never,
                    err: err_kind,
                }))
            }
        }
    }

    /// Returns a string representing the value's type.
    pub fn type_name(&self) -> String {
        match self {
            Self::Unit => String::from("Unit"),
            Self::Int(_) => String::from("Int"),
            Self::Bool(_) => String::from("Bool"),
            Self::String(_) => String::from("String"),
            Self::Struct(s) => format!("Struct {}", s.name),
            Self::Enum(name, _) => format!("Enum {}", name),
            Self::Option(Some(inner)) => format!("Option[{}]", inner.type_name()),
            Self::Option(None) => String::from("Option[_]"),
            Self::Result(Ok(inner)) => format!("Result[_, {}]", inner.type_name()),
            Self::Result(Err(inner)) => format!("Result[{}, _]", inner.type_name()),
        }
    }

    /// Create a VType from this and externally-provided span data
    pub fn vtype(&self, span: ast::Span) -> ast::VType {
        ast::VType::new(
            match self {
                Self::Unit => ast::TypeKind::Unit,
                Self::Int(_) => ast::TypeKind::Int,
                Self::Bool(_) => ast::TypeKind::Bool,
                Self::String(_) => ast::TypeKind::String,
                Self::Struct(s) => ast::TypeKind::Struct(s.name.clone().at(span)),
                Self::Enum(identifier, _) => ast::TypeKind::Enum(identifier.clone().at(span)),
                Self::Option(v) => ast::TypeKind::Optional(Box::new(match v {
                    Some(v) => v.vtype(span),
                    None => ast::VType::new(ast::TypeKind::Never, span),
                })),
                Self::Result(v) => ast::TypeKind::Result(Box::new(match v {
                    Ok(v) => ast::ResultTypeKind {
                        ok: v.vtype(span),
                        err: ast::VType::new(ast::TypeKind::Never, span),
                    },
                    Err(v) => ast::ResultTypeKind {
                        ok: ast::VType::new(ast::TypeKind::Never, span),
                        err: v.vtype(span),
                    },
                })),
            },
            span,
        )
    }
}

impl Display for ConstValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unit => write!(f, "()"),
            Self::Int(i) => write!(f, "{}", i),
            Self::Bool(b) => write!(f, "{}", b),
            Self::String(s) => write!(f, "\"{}\"", s),
            Self::Struct(s) => s.fmt(f),
            Self::Enum(name, value) => write!(f, "{name}::{value}"),
            Self::Option(Some(v)) => write!(f, "Some({v})"),
            Self::Option(None) => write!(f, "None"),
            Self::Result(Ok(v)) => write!(f, "Ok({})", v),
            Self::Result(Err(v)) => write!(f, "Err({})", v),
        }
    }
}

/// A Struct value
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(
    bounds(
        __C: rkyv::validation::ArchiveContext,
        __C::Error: rkyv::rancor::Source,
    )
))]
pub struct ConstStruct {
    /// The name of the struct
    pub name: Identifier,
    /// the fields of the struct
    #[rkyv(omit_bounds)]
    pub fields: BTreeMap<Identifier, ConstValue>,
}

impl ConstStruct {
    /// Creates an empty struct.
    pub fn empty(name: Identifier) -> Self {
        Self {
            name,
            fields: BTreeMap::new(),
        }
    }
}

impl Display for ConstStruct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{{", self.name)?;
        let mut i = false;
        for (k, v) in &self.fields {
            if i {
                write!(f, ", ")?;
            }
            i = true;
            write!(f, "{}: {}", k, v)?;
        }
        write!(f, "}}")
    }
}

/// A [`Span`](ast::Span)-less version of [`ast::Persistence`]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub enum Persistence {
    /// Persisted on-graph (default behavior)
    Persistent,
    /// Not persisted on-graph (ephemeral)
    Ephemeral,
}

impl From<ast::Persistence> for Persistence {
    fn from(value: ast::Persistence) -> Self {
        match value {
            ast::Persistence::Persistent => Self::Persistent,
            ast::Persistence::Ephemeral(_) => Self::Ephemeral,
        }
    }
}

/// A [`Span`](ast::Span)-less version of [`ast::Param`] and [`ast::FieldDefinition`], used for both
/// function arguments and struct fields.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct Field {
    /// The name of the parameter.
    pub name: Identifier,
    /// The type of the parameter.
    pub ty: TypeKind,
}

impl From<ast::Param> for Field {
    fn from(value: ast::Param) -> Self {
        Self {
            name: value.name.inner,
            ty: value.ty.inner.into(),
        }
    }
}

impl From<ast::FieldDefinition> for Field {
    fn from(value: ast::FieldDefinition) -> Self {
        Self {
            name: value.identifier.inner,
            ty: value.field_type.inner.into(),
        }
    }
}
