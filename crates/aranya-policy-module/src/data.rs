extern crate alloc;

use alloc::{borrow::ToOwned as _, boxed::Box, collections::BTreeMap, format, string::String};
use core::fmt::{self, Display};

use aranya_policy_ast::{Ident, Identifier, Span, Text, TypeKind, VType};
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
}

impl ConstValue {
    /// Shorthand for `Self::Option(None)`.
    pub const NONE: Self = Self::Option(None);

    /// Get the associated [`TypeKind`].
    pub fn vtype(&self) -> Option<TypeKind> {
        match self {
            Self::Int(_) => Some(TypeKind::Int),
            Self::Bool(_) => Some(TypeKind::Bool),
            Self::String(_) => Some(TypeKind::String),
            Self::Enum(name, _) => Some(TypeKind::Enum(Ident {
                name: name.to_owned(),
                span: Span::empty(),
            })),
            Self::Struct(s) => Some(TypeKind::Struct(Ident {
                name: s.name.clone(),
                span: Span::empty(),
            })),
            Self::Option(o) => {
                let inner_kind = match o {
                    Some(inner_value) => inner_value.vtype()?,
                    None => TypeKind::Never,
                };
                Some(TypeKind::Optional(Box::new(VType {
                    kind: inner_kind,
                    span: Span::empty(),
                })))
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
