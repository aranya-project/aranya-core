use alloc::{borrow::ToOwned as _, boxed::Box, string::String, vec::Vec};
use core::{fmt, str::FromStr};

use serde_derive::{Deserialize, Serialize};

use crate::{
    Identifier, Span, Spanned, Text,
    span::{WithSpan, spanned},
};

/// An identifier.
pub type Ident = WithSpan<Identifier>;

impl Ident {
    /// Reports whether the identifiers are the same, ignoring
    /// spans.
    pub fn matches(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T> PartialEq<T> for Ident
where
    T: AsRef<str> + ?Sized,
{
    fn eq(&self, other: &T) -> bool {
        self.inner == other.as_ref()
    }
}

/// An invalid version string was provided to
/// [`Version::from_str`].
#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("invalid version string")]
pub struct InvalidVersion;

mod version {
    #![allow(deprecated)] // for serde

    use alloc::format;

    use super::{Deserialize, Serialize, String};

    /// Policy language version
    #[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
    pub enum Version {
        /// Version 1, the initial version of the "new" policy
        /// language.
        #[deprecated]
        V1,
        /// Version 2, the second version of the policy language
        #[default]
        V2,
    }

    impl Version {
        /// A help message that suggests updating to the latest version.
        pub fn help_message() -> String {
            let v = Self::default();
            format!("please update `policy-version` to {v}")
        }
    }
}
pub use version::Version;

// This supports the command-line tools, allowing automatic
// conversion between string arguments and the enum.
impl FromStr for Version {
    type Err = InvalidVersion;

    #[allow(deprecated)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "1" => Ok(Self::V1),
            "2" => Ok(Self::V2),
            _ => Err(InvalidVersion),
        }
    }
}

impl fmt::Display for Version {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => write!(f, "1"),
            Self::V2 => write!(f, "2"),
        }
    }
}

/// Persistence mode for commands and actions
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
    Ephemeral(Span),
}

impl Persistence {
    /// Reports whether both persistence modes are the same,
    /// ignoring spans.
    pub fn matches(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Persistent, Self::Persistent) | (Self::Ephemeral(_), Self::Ephemeral(_))
        )
    }

    /// Returns the span of the persistence mode, if available.
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::Persistent => None,
            Self::Ephemeral(span) => Some(*span),
        }
    }
}

impl fmt::Display for Persistence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Persistent => write!(f, "persistent"),
            Self::Ephemeral(_) => write!(f, "ephemeral"),
        }
    }
}

/// The type of a value
///
/// It is not called `Type` because that conflicts with reserved keywords.
pub type VType = WithSpan<TypeKind>;

impl VType {
    /// Reports whether the types are the same, ignoring spans.
    pub fn matches(&self, other: &Self) -> bool {
        self.inner.matches(&other.inner)
    }

    /// Checks if two types fit, where `Never` matches with any type.
    pub fn fits_type(&self, other: &Self) -> bool {
        self.inner.fits_type(&other.inner)
    }

    /// Gets the struct name if this type is a struct.
    pub fn as_struct(&self) -> Option<&Ident> {
        if let TypeKind::Struct(name) = &self.inner {
            Some(name)
        } else {
            None
        }
    }
}

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
pub struct ResultTypeKind {
    /// ok type
    pub ok: VType,
    /// error type
    pub err: VType,
}

/// The kind of a [`VType`].
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
#[rkyv(attr(doc = "The archived kind of a [`VType`]."))]
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
    Struct(Ident),
    /// Named enumeration
    Enum(Ident),
    /// An optional type of some other type
    Optional(#[rkyv(omit_bounds)] Box<VType>),
    /// A type which cannot be instantiated.
    Never,
    /// Result with value, or error
    Result(#[rkyv(omit_bounds)] Box<ResultTypeKind>),
}

impl TypeKind {
    /// Reports whether the kinds are the same, ignoring spans.
    pub fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unit, Self::Unit)
            | (Self::String, Self::String)
            | (Self::Bytes, Self::Bytes)
            | (Self::Int, Self::Int)
            | (Self::Bool, Self::Bool)
            | (Self::Id, Self::Id)
            | (Self::Never, Self::Never) => true,
            (Self::Struct(lhs), Self::Struct(rhs)) => lhs.inner == rhs.inner,
            (Self::Enum(lhs), Self::Enum(rhs)) => lhs.inner == rhs.inner,
            (Self::Optional(lhs), Self::Optional(rhs)) => lhs.inner.matches(&rhs.inner),
            (Self::Result(lhs), Self::Result(rhs)) => {
                lhs.ok.inner.matches(&rhs.ok.inner) && lhs.err.inner.matches(&rhs.err.inner)
            }
            _ => false,
        }
    }

    fn fits_type(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Never, _) => true,
            (_, Self::Never) => true,
            (Self::Unit, Self::Unit)
            | (Self::String, Self::String)
            | (Self::Bytes, Self::Bytes)
            | (Self::Int, Self::Int)
            | (Self::Bool, Self::Bool)
            | (Self::Id, Self::Id) => true,
            (Self::Struct(lhs), Self::Struct(rhs)) => lhs.inner == rhs.inner,
            (Self::Enum(lhs), Self::Enum(rhs)) => lhs.inner == rhs.inner,
            (Self::Optional(lhs), Self::Optional(rhs)) => lhs.inner.fits_type(&rhs.inner),
            (Self::Result(lhs), Self::Result(rhs)) => {
                lhs.ok.fits_type(&rhs.ok) && lhs.err.fits_type(&rhs.err)
            }
            _ => false,
        }
    }
}

impl fmt::Display for TypeKind {
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

spanned! {
/// An action or function parameter.
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
pub struct Param {
    /// The name of the parameter.
    pub name: Ident,
    /// The type of the parameter.
    pub ty: VType,
}
}

spanned! {
/// An identifier and its type
///
/// Field definitions are used in Command fields, fact
/// key/value fields, and action/function arguments.
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
pub struct FieldDefinition {
    /// the field's name
    pub identifier: Ident,
    /// the field's type
    pub field_type: VType,
}
}

impl FieldDefinition {
    /// Reports whether the field definitions are the same,
    /// ignoring spans.
    pub fn matches(&self, other: &Self) -> bool {
        self.identifier.matches(&other.identifier) && self.field_type.matches(&other.field_type)
    }
}

/// An identifier and its type and dynamic effect marker
///
/// A variant used exclusively for Effects
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectFieldDefinition {
    /// the field's name
    pub identifier: Ident,
    /// the field's type
    pub field_type: VType,
    /// Whether the field is marked "dynamic" or not
    pub dynamic: bool,
}

impl Spanned for EffectFieldDefinition {
    fn span(&self) -> Span {
        self.identifier.span.merge(self.field_type.span())
    }
}

/// Value part of a key/value pair for a fact field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FactField {
    /// Expression
    Expression(Expression),
    /// Bind value, e.g. "?"
    Bind(Span),
}

impl Spanned for FactField {
    fn span(&self) -> Span {
        match self {
            Self::Expression(expr) => expr.span(),
            Self::Bind(span) => *span,
        }
    }
}

spanned! {
/// A fact and its key/value field values.
///
/// It is used to create, read, update, and delete facts.
#[derive(Debug, Clone, PartialEq,Serialize,Deserialize)]
pub struct FactLiteral {
    /// the fact's name
    pub identifier: Ident,
    /// values for the fields of the fact key
    pub key_fields: Vec<(Ident, FactField)>,
    /// values for the fields of the fact value, which can be absent
    pub value_fields: Option<Vec<(Ident, FactField)>>,
}
}

spanned! {
/// A function call with a list of arguments.
///
/// Can only be used in expressions, not on its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionCall {
    /// the function's name
    pub identifier: Ident,
    /// values for the function's arguments
    pub arguments: Vec<Expression>,
}
}

spanned! {
/// A named struct literal
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamedStruct {
    /// the struct name - should refer to either a Effect or Command
    pub identifier: Ident,
    /// The fields, which are pairs of identifiers and expressions
    pub fields: Vec<(Ident, Expression)>,
    /// sources is a list of identifiers used in struct composition
    pub sources: Vec<Ident>,
}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Enumeration definition
pub struct EnumDefinition {
    /// enum name
    pub identifier: Ident,
    /// list of possible values
    pub variants: Vec<Ident>,
    /// The source location of this definition
    pub span: Span,
}

impl Spanned for EnumDefinition {
    fn span(&self) -> Span {
        self.span
    }
}

spanned! {
/// A reference to an enumeration, e.g. `Color::Red`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumReference {
    /// enum name
    pub identifier: Ident,
    /// name of value inside enum
    pub value: Ident,
}
}

/// How many facts to expect when counting
#[derive(Copy, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactCountType {
    /// Up to
    UpTo(Span),
    /// At least
    AtLeast(Span),
    /// At most
    AtMost(Span),
    /// Exactly
    Exactly(Span),
}

impl fmt::Display for FactCountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UpTo(_) => write!(f, "up_to"),
            Self::AtLeast(_) => write!(f, "at_least"),
            Self::AtMost(_) => write!(f, "at_most"),
            Self::Exactly(_) => write!(f, "exactly"),
        }
    }
}

impl Spanned for FactCountType {
    fn span(&self) -> Span {
        match self {
            Self::UpTo(span) | Self::AtLeast(span) | Self::AtMost(span) | Self::Exactly(span) => {
                *span
            }
        }
    }
}

/// Expression atoms with special rules or effects.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InternalFunction {
    /// A `query` expression
    Query(FactLiteral),
    /// An `exists` fact query
    Exists(FactLiteral),
    /// Counts the number of facts up to the given limit, and returns the lower of the two.
    // TODO(eric): make `i64` an expr or literal or something
    FactCount(FactCountType, i64, FactLiteral),
    /// An `if` expression
    If(Box<Expression>, Box<Expression>, Box<Expression>),
    /// Serialize function
    Serialize(Box<Expression>),
    /// Deserialize function
    Deserialize(Box<Expression>),
    /// Not yet implemented panic
    Todo(Span),
}

impl Spanned for InternalFunction {
    fn span(&self) -> Span {
        match self {
            Self::Query(fact) => fact.span(),
            Self::Exists(fact) => fact.span(),
            Self::FactCount(ty, _, fact) => ty.span().merge(fact.span()),
            Self::If(cond, then, else_) => cond.span.merge(then.span()).merge(else_.span()),
            Self::Serialize(expr) | Self::Deserialize(expr) => expr.span(),
            Self::Todo(span) => *span,
        }
    }
}

spanned! {
/// A foreign function call with a list of arguments.
///
/// Can only be used in expressions, not on its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForeignFunctionCall {
    /// the function's module name
    pub module: Ident,
    /// the function's name
    pub identifier: Ident,
    /// values for the function's arguments
    pub arguments: Vec<Expression>,
}
}

/// All of the things which can be in an expression.
pub type Expression = WithSpan<ExprKind>;

/// The kind of [`Expression`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExprKind {
    /// A Unit literal
    Unit,
    /// A 64-bit signed integer
    Int(i64),
    /// A text string
    String(Text),
    /// A boolean literal
    Bool(bool),
    /// An optional literal
    Optional(Option<Box<Expression>>),
    /// A Result Ok literal
    Ok(Box<Expression>),
    /// A Result Err literal
    Err(Box<Expression>),
    /// A named struct
    NamedStruct(NamedStruct),
    /// One of the [InternalFunction]s
    InternalFunction(InternalFunction),
    /// A function call
    FunctionCall(FunctionCall),
    /// A foreign function call
    ForeignFunctionCall(ForeignFunctionCall),
    /// A return expression. Valid only in functions.
    Return(Box<Expression>),
    /// A variable identifier
    Identifier(Ident),
    /// Enum reference, e.g. `Color::Red`
    EnumReference(EnumReference),
    /// expr && expr`
    And(Box<Expression>, Box<Expression>),
    /// expr || expr`
    Or(Box<Expression>, Box<Expression>),
    /// `expr or expr` — optional coalescing
    Coalesce(Box<Expression>, Box<Expression>),
    /// expr.expr`
    Dot(Box<Expression>, Ident),
    /// `expr` == `expr`
    Equal(Box<Expression>, Box<Expression>),
    /// `expr` != `expr`
    NotEqual(Box<Expression>, Box<Expression>),
    /// `expr` > `expr`
    GreaterThan(Box<Expression>, Box<Expression>),
    /// `expr` < `expr`
    LessThan(Box<Expression>, Box<Expression>),
    /// `expr` >= `expr`
    GreaterThanOrEqual(Box<Expression>, Box<Expression>),
    /// `expr` <= `expr`
    LessThanOrEqual(Box<Expression>, Box<Expression>),
    /// `!expr`
    Not(Box<Expression>),
    /// `unwrap expr`
    Unwrap(Box<Expression>),
    /// Similar to Unwrap, but exits with a Check, instead of a Panic
    CheckUnwrap(Box<Expression>),
    /// `expr is Some`, `expr is None`
    Is(Box<Expression>, bool),
    /// A block expression
    Block(Vec<Statement>, Box<Expression>),
    /// A substruct expression
    Substruct(Box<Expression>, Ident),
    /// Type cast expression
    Cast(Box<Expression>, Ident),
    /// Match expression
    Match(Box<MatchExpression>),
}

impl ExprKind {
    /// Compare two expression kinds for equality, ignoring spans.
    pub fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unit, Self::Unit) => true,

            // Simple types without spans - can use ==
            (Self::Int(a), Self::Int(b)) => a == b,
            (Self::String(a), Self::String(b)) => a == b,
            (Self::Bool(a), Self::Bool(b)) => a == b,

            // Optional types
            (Self::Optional(None), Self::Optional(None)) => true,
            (Self::Optional(Some(a)), Self::Optional(Some(b))) => a.inner.matches(&b.inner),

            // Result types
            (Self::Ok(a), Self::Ok(b)) => a.inner.matches(&b.inner),
            (Self::Err(a), Self::Err(b)) => a.inner.matches(&b.inner),

            // Identifier
            (Self::Identifier(a), Self::Identifier(b)) => a.matches(b),

            // Named struct
            (Self::NamedStruct(a), Self::NamedStruct(b)) => {
                a.identifier.matches(&b.identifier)
                    && a.fields.len() == b.fields.len()
                    && a.fields
                        .iter()
                        .zip(&b.fields)
                        .all(|((k1, v1), (k2, v2))| k1.matches(k2) && v1.inner.matches(&v2.inner))
                    && a.sources.len() == b.sources.len()
                    && a.sources
                        .iter()
                        .zip(&b.sources)
                        .all(|(s1, s2)| s1.matches(s2))
            }

            // Enum reference
            (Self::EnumReference(a), Self::EnumReference(b)) => {
                a.identifier.matches(&b.identifier) && a.value.matches(&b.value)
            }

            // Function call
            (Self::FunctionCall(a), Self::FunctionCall(b)) => {
                a.identifier.matches(&b.identifier)
                    && a.arguments.len() == b.arguments.len()
                    && a.arguments
                        .iter()
                        .zip(&b.arguments)
                        .all(|(e1, e2)| e1.inner.matches(&e2.inner))
            }

            // Foreign function call
            (Self::ForeignFunctionCall(a), Self::ForeignFunctionCall(b)) => {
                a.module.matches(&b.module)
                    && a.identifier.matches(&b.identifier)
                    && a.arguments.len() == b.arguments.len()
                    && a.arguments
                        .iter()
                        .zip(&b.arguments)
                        .all(|(e1, e2)| e1.inner.matches(&e2.inner))
            }

            // Internal functions
            (Self::InternalFunction(a), Self::InternalFunction(b)) => {
                match (a, b) {
                    (InternalFunction::Query(f1), InternalFunction::Query(f2))
                    | (InternalFunction::Exists(f1), InternalFunction::Exists(f2)) => {
                        f1.identifier.matches(&f2.identifier)
                            && f1.key_fields.len() == f2.key_fields.len()
                            && f1.key_fields.iter().zip(&f2.key_fields).all(
                                |((k1, v1), (k2, v2))| k1.matches(k2) && matches_fact_field(v1, v2),
                            )
                            && match (&f1.value_fields, &f2.value_fields) {
                                (None, None) => true,
                                (Some(vf1), Some(vf2)) => {
                                    vf1.len() == vf2.len()
                                        && vf1.iter().zip(vf2).all(|((k1, v1), (k2, v2))| {
                                            k1.matches(k2) && matches_fact_field(v1, v2)
                                        })
                                }
                                _ => false,
                            }
                    }
                    (
                        InternalFunction::FactCount(t1, n1, f1),
                        InternalFunction::FactCount(t2, n2, f2),
                    ) => {
                        t1 == t2
                            && n1 == n2
                            && f1.identifier.matches(&f2.identifier)
                            && f1.key_fields.len() == f2.key_fields.len()
                            && f1.key_fields.iter().zip(&f2.key_fields).all(
                                |((k1, v1), (k2, v2))| k1.matches(k2) && matches_fact_field(v1, v2),
                            )
                            && match (&f1.value_fields, &f2.value_fields) {
                                (None, None) => true,
                                (Some(vf1), Some(vf2)) => {
                                    vf1.len() == vf2.len()
                                        && vf1.iter().zip(vf2).all(|((k1, v1), (k2, v2))| {
                                            k1.matches(k2) && matches_fact_field(v1, v2)
                                        })
                                }
                                _ => false,
                            }
                    }
                    (InternalFunction::If(c1, t1, e1), InternalFunction::If(c2, t2, e2)) => {
                        c1.inner.matches(&c2.inner)
                            && t1.inner.matches(&t2.inner)
                            && e1.inner.matches(&e2.inner)
                    }
                    (InternalFunction::Serialize(e1), InternalFunction::Serialize(e2))
                    | (InternalFunction::Deserialize(e1), InternalFunction::Deserialize(e2)) => {
                        e1.inner.matches(&e2.inner)
                    }
                    (InternalFunction::Todo(_), InternalFunction::Todo(_)) => true,
                    _ => false,
                }
            }

            // Single expression variants
            (Self::Return(a), Self::Return(b))
            | (Self::Not(a), Self::Not(b))
            | (Self::Unwrap(a), Self::Unwrap(b))
            | (Self::CheckUnwrap(a), Self::CheckUnwrap(b)) => a.inner.matches(&b.inner),

            // Two expression variants
            (Self::And(a1, a2), Self::And(b1, b2))
            | (Self::Or(a1, a2), Self::Or(b1, b2))
            | (Self::Coalesce(a1, a2), Self::Coalesce(b1, b2))
            | (Self::Equal(a1, a2), Self::Equal(b1, b2))
            | (Self::NotEqual(a1, a2), Self::NotEqual(b1, b2))
            | (Self::GreaterThan(a1, a2), Self::GreaterThan(b1, b2))
            | (Self::LessThan(a1, a2), Self::LessThan(b1, b2))
            | (Self::GreaterThanOrEqual(a1, a2), Self::GreaterThanOrEqual(b1, b2))
            | (Self::LessThanOrEqual(a1, a2), Self::LessThanOrEqual(b1, b2)) => {
                a1.inner.matches(&b1.inner) && a2.inner.matches(&b2.inner)
            }

            // Expression with Ident
            (Self::Dot(e1, i1), Self::Dot(e2, i2))
            | (Self::Cast(e1, i1), Self::Cast(e2, i2))
            | (Self::Substruct(e1, i1), Self::Substruct(e2, i2)) => {
                e1.inner.matches(&e2.inner) && i1.matches(i2)
            }

            // Is expression
            (Self::Is(e1, b1), Self::Is(e2, b2)) => e1.inner.matches(&e2.inner) && b1 == b2,

            // Block expression
            (Self::Block(stmts1, expr1), Self::Block(stmts2, expr2)) => {
                stmts1.len() == stmts2.len()
                    && stmts1
                        .iter()
                        .zip(stmts2)
                        .all(|(s1, s2)| matches_statement(s1, s2))
                    && expr1.inner.matches(&expr2.inner)
            }

            // Match expression
            (Self::Match(m1), Self::Match(m2)) => matches_match_expression(m1, m2),

            // Different variants don't match
            _ => false,
        }
    }
}

/// Helper function to compare FactField instances, ignoring spans.
fn matches_fact_field(a: &FactField, b: &FactField) -> bool {
    match (a, b) {
        (FactField::Expression(e1), FactField::Expression(e2)) => e1.inner.matches(&e2.inner),
        (FactField::Bind(_), FactField::Bind(_)) => true,
        _ => false,
    }
}

/// Helper function to compare Statement instances, ignoring spans.
fn matches_statement(a: &Statement, b: &Statement) -> bool {
    use StmtKind::*;
    match (&a.inner, &b.inner) {
        (Let(l1), Let(l2)) => {
            l1.identifier.matches(&l2.identifier)
                && l1.expression.inner.matches(&l2.expression.inner)
        }
        (Check(c1), Check(c2)) => c1.expression.inner.matches(&c2.expression.inner),
        (Match(m1), Match(m2)) => {
            m1.expression.inner.matches(&m2.expression.inner)
                && m1.arms.len() == m2.arms.len()
                && m1.arms.iter().zip(&m2.arms).all(|(a1, a2)| {
                    matches_match_pattern(&a1.pattern, &a2.pattern)
                        && a1.statements.len() == a2.statements.len()
                        && a1
                            .statements
                            .iter()
                            .zip(&a2.statements)
                            .all(|(s1, s2)| matches_statement(s1, s2))
                })
        }
        (If(i1), If(i2)) => {
            i1.branches.len() == i2.branches.len()
                && i1
                    .branches
                    .iter()
                    .zip(&i2.branches)
                    .all(|((cond1, stmts1), (cond2, stmts2))| {
                        cond1.inner.matches(&cond2.inner)
                            && stmts1.len() == stmts2.len()
                            && stmts1
                                .iter()
                                .zip(stmts2)
                                .all(|(s1, s2)| matches_statement(s1, s2))
                    })
                && match (&i1.fallback, &i2.fallback) {
                    (None, None) => true,
                    (Some(f1), Some(f2)) => {
                        f1.len() == f2.len()
                            && f1.iter().zip(f2).all(|(s1, s2)| matches_statement(s1, s2))
                    }
                    _ => false,
                }
        }
        (Finish(f1), Finish(f2)) => {
            f1.len() == f2.len() && f1.iter().zip(f2).all(|(s1, s2)| matches_statement(s1, s2))
        }
        (Map(m1), Map(m2)) => {
            matches_fact_literal(&m1.fact, &m2.fact)
                && m1.identifier.matches(&m2.identifier)
                && m1.statements.len() == m2.statements.len()
                && m1
                    .statements
                    .iter()
                    .zip(&m2.statements)
                    .all(|(s1, s2)| matches_statement(s1, s2))
        }
        (Return(r1), Return(r2)) => r1.expression.inner.matches(&r2.expression.inner),
        (ActionCall(c1), ActionCall(c2)) | (FunctionCall(c1), FunctionCall(c2)) => {
            c1.identifier.matches(&c2.identifier)
                && c1.arguments.len() == c2.arguments.len()
                && c1
                    .arguments
                    .iter()
                    .zip(&c2.arguments)
                    .all(|(e1, e2)| e1.inner.matches(&e2.inner))
        }
        (Publish(e1), Publish(e2)) | (Emit(e1), Emit(e2)) | (DebugAssert(e1), DebugAssert(e2)) => {
            e1.inner.matches(&e2.inner)
        }
        (Create(c1), Create(c2)) => matches_fact_literal(&c1.fact, &c2.fact),
        (Delete(d1), Delete(d2)) => matches_fact_literal(&d1.fact, &d2.fact),
        (Update(u1), Update(u2)) => {
            matches_fact_literal(&u1.fact, &u2.fact)
                && u1.to.len() == u2.to.len()
                && u1
                    .to
                    .iter()
                    .zip(&u2.to)
                    .all(|((k1, v1), (k2, v2))| k1.matches(k2) && matches_fact_field(v1, v2))
        }
        _ => false,
    }
}

/// Helper function to compare FactLiteral instances, ignoring spans.
fn matches_fact_literal(a: &FactLiteral, b: &FactLiteral) -> bool {
    a.identifier.matches(&b.identifier)
        && a.key_fields.len() == b.key_fields.len()
        && a.key_fields
            .iter()
            .zip(&b.key_fields)
            .all(|((k1, v1), (k2, v2))| k1.matches(k2) && matches_fact_field(v1, v2))
        && match (&a.value_fields, &b.value_fields) {
            (None, None) => true,
            (Some(vf1), Some(vf2)) => {
                vf1.len() == vf2.len()
                    && vf1
                        .iter()
                        .zip(vf2)
                        .all(|((k1, v1), (k2, v2))| k1.matches(k2) && matches_fact_field(v1, v2))
            }
            _ => false,
        }
}

/// Helper function to compare MatchPattern instances, ignoring spans.
fn matches_match_pattern(a: &MatchPattern, b: &MatchPattern) -> bool {
    match (a, b) {
        (MatchPattern::Default(_), MatchPattern::Default(_)) => true,
        (MatchPattern::Values(v1), MatchPattern::Values(v2)) => {
            v1.len() == v2.len()
                && v1
                    .iter()
                    .zip(v2)
                    .all(|(e1, e2)| e1.inner.matches(&e2.inner))
        }
        _ => false,
    }
}

/// Helper function to compare MatchExpression instances, ignoring spans.
fn matches_match_expression(a: &MatchExpression, b: &MatchExpression) -> bool {
    a.scrutinee.inner.matches(&b.scrutinee.inner)
        && a.arms.len() == b.arms.len()
        && a.arms.iter().zip(&b.arms).all(|(a1, a2)| {
            matches_match_pattern(&a1.pattern, &a2.pattern)
                && a1.expression.inner.matches(&a2.expression.inner)
        })
}

spanned! {
/// Encapsulates both [FunctionDefinition] and [FinishFunctionDefinition] for the purpose
/// of parsing FFI function declarations.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct FunctionDecl {
    /// The identifier of the function
    pub identifier: Ident,
    /// A list of the arguments to the function, and their types
    pub arguments: Vec<Param>,
    /// The return type of the function, if any
    pub return_type: Option<VType>,
}
}

spanned! {
/// Define a variable with an expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LetStatement {
    /// The variable's name
    pub identifier: Ident,
    /// The variable's value
    pub expression: Expression,
}
}

spanned! {
/// Check that a boolean expression is true, and fail otherwise
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckStatement {
    /// The boolean expression being checked
    pub expression: Expression,
}
}

/// Match arm pattern
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MatchPattern {
    /// No values, default case
    Default(Span),
    /// List of values to match. E.g. `0 | 1 | 2 => ...`
    /// Can include Ok(x) and Err(e) for Result matching.
    Values(Vec<Expression>),
}

impl Spanned for MatchPattern {
    fn span(&self) -> Span {
        match self {
            Self::Default(span) => *span,
            Self::Values(values) => values.span(),
        }
    }
}

spanned! {
/// One arm of a match statement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchArm {
    /// The values to check against. Matches any value if the option is None.
    // TODO(chip): Restrict this to only literal values so we can do
    // exhaustive range checks.
    pub pattern: MatchPattern,
    /// The statements to execute if the value matches
    pub statements: Vec<Statement>,
}
}

spanned! {
/// Match a value and execute one possibility out of many
///
/// Match arms are tested in order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchStatement {
    /// The value to match against
    pub expression: Expression,
    /// All of the potential match arms
    pub arms: Vec<MatchArm>,
}
}

spanned! {
/// Match statement expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchExpression {
    /// Value to match against
    pub scrutinee: Expression,
    /// Match arms
    pub arms: Vec<MatchExpressionArm>,
}
}

/// A container for a statement or expression
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LanguageContext<A, B> {
    /// statement
    Statement(A),
    /// expression
    Expression(B),
}

impl<A, B> Spanned for LanguageContext<A, B>
where
    A: Spanned,
    B: Spanned,
{
    fn span(&self) -> Span {
        match self {
            Self::Statement(stmt) => stmt.span(),
            Self::Expression(expr) => expr.span(),
        }
    }
}

/// Match arm expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchExpressionArm {
    /// value to match against the match expression
    pub pattern: MatchPattern,
    /// Expression
    pub expression: Expression,
    /// The source location of this match arm
    pub span: Span,
}

impl Spanned for MatchExpressionArm {
    fn span(&self) -> Span {
        self.span
    }
}

spanned! {
/// Test a series of conditions and execute the statements for the first true condition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IfStatement {
    /// Each `if` and `else if` branch.
    pub branches: Vec<(Expression, Vec<Statement>)>,
    /// The `else` branch, if present.
    pub fallback: Option<Vec<Statement>>,
}
}

spanned! {
/// Iterate over the results of a query, and execute some statements for each one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MapStatement {
    /// Query
    pub fact: FactLiteral,
    /// Identifier of container struct
    pub identifier: Ident,
    /// Statements to execute for each fact
    pub statements: Vec<Statement>,
}
}

spanned! {
/// Create a fact
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateStatement {
    /// The fact to create
    pub fact: FactLiteral,
}
}

spanned! {
/// Update a fact
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateStatement {
    /// This fact has to exist as stated
    pub fact: FactLiteral,
    /// The value fields are updated to these values
    pub to: Vec<(Ident, FactField)>,
}
}

spanned! {
/// Delete a fact
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeleteStatement {
    /// The fact to delete
    pub fact: FactLiteral,
}
}

spanned! {
/// Return from a function
///
/// Only valid within functions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReturnStatement {
    /// The value to return
    pub expression: Expression,
}
}

/// Statements in the policy language.
///
/// Not all statements are valid in all contexts.
pub type Statement = WithSpan<StmtKind>;

/// The kind of [`Statement`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StmtKind {
    /// A [LetStatement]
    Let(LetStatement),
    /// A [CheckStatement]
    Check(CheckStatement),
    /// A [MatchStatement]
    Match(MatchStatement),
    /// An [IfStatement],
    If(IfStatement),
    /// A `finish` block containing [Statement]s
    /// Valid only in policy blocks
    Finish(Vec<Statement>),
    /// Map over a fact result set
    Map(MapStatement),
    /// A [ReturnStatement]. Valid only in functions.
    Return(ReturnStatement),
    /// Calls an action
    ActionCall(FunctionCall),
    /// Publishes an expression describing a command.
    /// Valid only in actions.
    Publish(Expression),
    /// A [CreateStatement]
    Create(CreateStatement),
    /// An [UpdateStatement]
    Update(UpdateStatement),
    /// A [DeleteStatement]
    Delete(DeleteStatement),
    /// An [Expression] shaped by an effect that's emitted
    Emit(Expression),
    /// A function call (only valid as a statement for finish functions)
    FunctionCall(FunctionCall),
    /// A `debug_assert` expression for development purposes
    DebugAssert(Expression),
}

/// A schema definition for a fact
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

pub struct FactDefinition {
    /// Is this fact immutable?
    pub immutable: bool,
    /// The name of the fact
    pub identifier: Ident,
    /// Types for all of the key fields
    pub key: Vec<FieldDefinition>,
    /// Types for all of the value fields
    pub value: Vec<FieldDefinition>,
    /// The source location of this definition
    pub span: Span,
}

impl FactDefinition {
    /// Returns an iterator of the [`Self::key`] and [`Self::value`] fields combined.
    pub fn fields(&self) -> impl Iterator<Item = &FieldDefinition> {
        self.key.iter().chain(self.value.iter())
    }
}

impl Spanned for FactDefinition {
    fn span(&self) -> Span {
        self.span
    }
}

/// An action definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionDefinition {
    /// The persistence mode of the action
    pub persistence: Persistence,
    /// The name of the action
    pub identifier: Ident,
    /// The arguments to the action
    pub arguments: Vec<Param>,
    /// The statements executed when the action is called
    pub statements: Vec<Statement>,
    /// The source location of this definition
    pub span: Span,
}

impl Spanned for ActionDefinition {
    fn span(&self) -> Span {
        self.span
    }
}

/// An effect definition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectDefinition {
    /// The name of the effect
    pub identifier: Ident,
    /// The fields of the effect and their types
    pub items: Vec<StructItem<EffectFieldDefinition>>,
    /// The source location of this definition
    pub span: Span,
}

impl Spanned for EffectDefinition {
    fn span(&self) -> Span {
        self.span
    }
}

/// A struct definition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructDefinition {
    /// The name of the struct
    pub identifier: Ident,
    /// The fields of the struct and their types
    pub items: Vec<StructItem<FieldDefinition>>,
    /// The source location of this definition
    pub span: Span,
}

impl Spanned for StructDefinition {
    fn span(&self) -> Span {
        self.span
    }
}

/// Struct field or insertion reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructItem<T> {
    /// Field definition
    Field(T),
    /// Named struct whose fields to add to the current struct
    StructRef(Ident),
}

impl<T> StructItem<T> {
    /// Get the field definition from this struct item
    pub fn field(&self) -> Option<&T> {
        match self {
            Self::Field(f) => Some(f),
            Self::StructRef(_) => None,
        }
    }
}

impl<T: Spanned> Spanned for StructItem<T> {
    fn span(&self) -> Span {
        match self {
            Self::Field(f) => f.span(),
            Self::StructRef(ident) => ident.span,
        }
    }
}

/// A command definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandDefinition {
    /// The persistence mode of the command
    pub persistence: Persistence,
    /// Optional attributes
    pub attributes: Vec<(Ident, Expression)>,
    /// The name of the command
    pub identifier: Ident,
    /// The fields of the command and their types
    pub fields: Vec<StructItem<FieldDefinition>>,
    /// Statements for sealing the command into an envelope
    pub seal: Vec<Statement>,
    /// Statements for opening the command envelope
    pub open: Vec<Statement>,
    /// The policy rule statements for this command
    pub policy: Vec<Statement>,
    /// The recall rule statements for this command
    pub recall: Vec<Statement>,
    /// The source location of this definition
    pub span: Span,
}

impl Spanned for CommandDefinition {
    fn span(&self) -> Span {
        self.span
    }
}

/// A function definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// The name of the function
    pub identifier: Ident,
    /// The argument names and types
    pub arguments: Vec<Param>,
    /// The return type
    pub return_type: VType,
    /// The policy rule statements
    pub statements: Vec<Statement>,
    /// The source location of this definition
    pub span: Span,
}

impl Spanned for FunctionDefinition {
    fn span(&self) -> Span {
        self.span
    }
}

/// A finish function definition. This is slightly different than a
/// regular function since it cannot return values and can only
/// execute finish block statements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinishFunctionDefinition {
    /// The name of the function
    pub identifier: Ident,
    /// The argument names and types
    pub arguments: Vec<Param>,
    /// The finish block statements
    pub statements: Vec<Statement>,
    /// The source location of this definition
    pub span: Span,
}

impl Spanned for FinishFunctionDefinition {
    fn span(&self) -> Span {
        self.span
    }
}

/// A globally scopped let statement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalLetStatement {
    /// The variable's name
    pub identifier: Ident,
    /// The variable's value
    pub expression: Expression,
    /// The source location of this statement
    pub span: Span,
}

impl Spanned for GlobalLetStatement {
    fn span(&self) -> Span {
        self.span
    }
}

/// The policy AST root
///
/// This contains all of the definitions that comprise a policy.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// The policy version.
    pub version: Version,
    /// FFI imports
    pub ffi_imports: Vec<Ident>,
    /// The policy's fact definitions.
    pub facts: Vec<FactDefinition>,
    /// The policy's action definitions.
    pub actions: Vec<ActionDefinition>,
    /// The policy's effect definitions.
    pub effects: Vec<EffectDefinition>,
    /// The policy's struct definitions.
    pub structs: Vec<StructDefinition>,
    /// The policy's enum definitions.
    pub enums: Vec<EnumDefinition>,
    /// The policy's command definitions.
    pub commands: Vec<CommandDefinition>,
    /// The policy's function definitions.
    pub functions: Vec<FunctionDefinition>,
    /// The policy's finish function definitions.
    pub finish_functions: Vec<FinishFunctionDefinition>,
    /// The policy's global let statements.
    pub global_lets: Vec<GlobalLetStatement>,
    /// The source text
    pub text: String,
}

impl Policy {
    /// Create a new `Policy` with the given source text.
    pub fn new(version: Version, text: &str) -> Self {
        Self {
            version,
            text: text.to_owned(),
            ..Default::default()
        }
    }
}
