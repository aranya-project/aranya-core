extern crate alloc;

use alloc::{
    borrow::ToOwned as _, boxed::Box, collections::BTreeMap, format, string::String, vec, vec::Vec,
};
use core::fmt::{self, Display};

use aranya_policy_ast::{Ident, Identifier, ResultTypeKind, Span, Text, TypeKind, VType};
use serde::{Deserialize, Serialize};

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
    pub fn vtype(&self) -> TypeKind {
        match self {
            Self::Int(_) => TypeKind::Int,
            Self::Bool(_) => TypeKind::Bool,
            Self::String(_) => TypeKind::String,
            Self::Enum(name, _) => TypeKind::Enum(Ident {
                name: name.to_owned(),
                span: Span::empty(),
            }),
            Self::Struct(s) => TypeKind::Struct(Ident {
                name: s.name.clone(),
                span: Span::empty(),
            }),
            Self::Option(o) => {
                let inner_kind = match o {
                    Some(inner_value) => inner_value.vtype(),
                    None => TypeKind::Never,
                };
                TypeKind::Optional(Box::new(VType {
                    kind: inner_kind,
                    span: Span::empty(),
                }))
            }
            Self::Result(Ok(ok)) => {
                let ok_kind = ok.vtype();
                TypeKind::Result(Box::new(ResultTypeKind {
                    ok: VType {
                        kind: ok_kind,
                        span: Span::empty(),
                    },
                    err: VType {
                        kind: TypeKind::Never,
                        span: Span::empty(),
                    },
                }))
            }
            Self::Result(Err(err)) => {
                let err_kind = err.vtype();
                TypeKind::Result(Box::new(ResultTypeKind {
                    ok: VType {
                        kind: TypeKind::Never,
                        span: Span::empty(),
                    },
                    err: VType {
                        kind: err_kind,
                        span: Span::empty(),
                    },
                }))
            }
        }
    }

    /// Returns a string representing the value's type.
    pub fn type_name(&self) -> String {
        match self {
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
}

impl Display for ConstValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
