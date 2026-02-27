use alloc::{borrow::ToOwned as _, boxed::Box, string::String, vec::Vec};
use core::{fmt, ops::Deref, str::FromStr};

use serde_derive::{Deserialize, Serialize};

use crate::{Identifier, Span, Spanned, Text, span::spanned};

/// An identifier.
#[derive(
    Clone, Eq, PartialEq, Serialize, Deserialize, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize,
)]
pub struct Ident {
    /// The identifier name
    pub name: Identifier,
    /// The source location of this identifier
    pub span: Span,
}

impl fmt::Debug for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)?;
        write!(f, " @ {:?}", self.span)?;
        Ok(())
    }
}

impl Ident {
    /// Reports whether the identifiers are the same, ignoring
    /// spans.
    pub fn matches(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Deref for Ident {
    type Target = Identifier;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

impl<T> PartialEq<T> for Ident
where
    T: AsRef<str> + ?Sized,
{
    fn eq(&self, other: &T) -> bool {
        self.name == other.as_ref()
    }
}

impl Spanned for Ident {
    fn span(&self) -> Span {
        self.span
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
#[must_use]
#[derive(
    Clone, Eq, PartialEq, Serialize, Deserialize, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize,
)]
pub struct VType {
    /// The type kind
    pub kind: TypeKind,
    /// The source location of this type
    pub span: Span,
}

impl fmt::Debug for VType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)?;
        write!(f, " @ {:?}", self.span)?;
        Ok(())
    }
}

impl VType {
    /// Reports whether the types are the same, ignoring spans.
    pub fn matches(&self, other: &Self) -> bool {
        self.kind.matches(&other.kind)
    }

    /// Checks if two types fit, where `Never` matches with any type.
    pub fn fits_type(&self, other: &Self) -> bool {
        self.kind.fits_type(&other.kind)
    }

    /// Gets the struct name if this type is a struct.
    pub fn as_struct(&self) -> Option<&Ident> {
        if let TypeKind::Struct(name) = &self.kind {
            Some(name)
        } else {
            None
        }
    }
}

impl fmt::Display for VType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

impl Spanned for VType {
    fn span(&self) -> Span {
        self.span
    }
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
pub enum TypeKind {
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
}

impl TypeKind {
    /// Reports whether the kinds are the same, ignoring spans.
    pub fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String, Self::String)
            | (Self::Bytes, Self::Bytes)
            | (Self::Int, Self::Int)
            | (Self::Bool, Self::Bool)
            | (Self::Id, Self::Id)
            | (Self::Never, Self::Never) => true,
            (Self::Struct(lhs), Self::Struct(rhs)) => lhs.name == rhs.name,
            (Self::Enum(lhs), Self::Enum(rhs)) => lhs.name == rhs.name,
            (Self::Optional(lhs), Self::Optional(rhs)) => lhs.kind.matches(&rhs.kind),
            _ => false,
        }
    }

    fn fits_type(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Never, _) => true,
            (_, Self::Never) => true,
            (Self::String, Self::String)
            | (Self::Bytes, Self::Bytes)
            | (Self::Int, Self::Int)
            | (Self::Bool, Self::Bool)
            | (Self::Id, Self::Id) => true,
            (Self::Struct(lhs), Self::Struct(rhs)) => lhs.name == rhs.name,
            (Self::Enum(lhs), Self::Enum(rhs)) => lhs.name == rhs.name,
            (Self::Optional(lhs), Self::Optional(rhs)) => lhs.kind.fits_type(&rhs.kind),
            _ => false,
        }
    }
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Bytes => write!(f, "bytes"),
            Self::Int => write!(f, "int"),
            Self::Bool => write!(f, "bool"),
            Self::Id => write!(f, "id"),
            Self::Struct(name) => write!(f, "struct {name}"),
            Self::Enum(name) => write!(f, "enum {name}"),
            Self::Optional(vtype) => write!(f, "option[{vtype}]"),
            Self::Never => write!(f, "never"),
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
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Expression {
    /// The expression kind
    pub kind: ExprKind,
    /// The source location of this expression
    pub span: Span,
}

impl fmt::Debug for Expression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)?;
        write!(f, " @ {:?}", self.span)?;
        Ok(())
    }
}

impl Spanned for Expression {
    fn span(&self) -> Span {
        self.span
    }
}

/// The kind of [`Expression`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExprKind {
    /// A 64-bit signed integer
    Int(i64),
    /// A text string
    String(Text),
    /// A boolean literal
    Bool(bool),
    /// An optional literal
    Optional(Option<Box<Expression>>),
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
    /// List of values to match
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
/// Not all statements are valid in all contexts.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Statement {
    /// The statement kind
    pub kind: StmtKind,
    /// The source location of this statement
    pub span: Span,
}

impl fmt::Debug for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)?;
        write!(f, " @ {:?}", self.span)?;
        Ok(())
    }
}

impl Spanned for Statement {
    fn span(&self) -> Span {
        self.span
    }
}

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
