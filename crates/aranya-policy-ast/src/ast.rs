use alloc::{borrow::ToOwned, boxed::Box, string::String, vec::Vec};
use core::{fmt, ops::Deref, str::FromStr};

use serde_derive::{Deserialize, Serialize};

use crate::{Identifier, Text};

/// A span representing a range in source text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    /// The start position in the source text
    pub start: usize,
    /// The end position in the source text
    pub end: usize,
}

impl Span {
    /// Create a new span
    pub fn new(start: usize, end: usize) -> Self {
        debug_assert!(
            start <= end,
            "Invalid span: start ({}) must be <= end ({})",
            start,
            end
        );
        Span { start, end }
    }

    /// Check if this span contains another span
    pub fn contains(&self, other: &Span) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// Merge two spans into one encompassing both
    /// Takes the minimum start and maximum end to handle any ordering
    pub fn merge(&self, other: &Span) -> Span {
        Span::new(self.start.min(other.start), self.end.max(other.end))
    }

    /// Get the length of the span
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Check if span is empty (zero-width)
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Create a span for a single position (zero-width)
    pub fn point(pos: usize) -> Self {
        Span::new(pos, pos)
    }
}

/// An identifier with source location information
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ident {
    /// The identifier name
    pub name: Identifier,
    /// The source location of this identifier
    pub span: Span,
}

impl Ident {
    /// Create a new identifier with span
    pub fn new(name: Identifier, span: Span) -> Self {
        Ident { name, span }
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

/// An invalid version string was provided to
/// [`Version::from_str`].
#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("invalid version string")]
pub struct InvalidVersion;

/// Policy language version
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Version {
    /// Version 1, the initial version of the "new" policy
    /// language.
    #[deprecated]
    V1,
    /// Version 2, the second version of the policy language
    #[default]
    V2,
}

// This supports the command-line tools, allowing automatic
// conversion between string arguments and the enum.
impl FromStr for Version {
    type Err = InvalidVersion;

    #[allow(deprecated)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "1" => Ok(Version::V1),
            "2" => Ok(Version::V2),
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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Persistence {
    /// Persisted on-graph (default behavior)
    Persistent,
    /// Not persisted on-graph (ephemeral)
    Ephemeral,
}

impl fmt::Display for Persistence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Persistent => write!(f, "persistent"),
            Self::Ephemeral => write!(f, "ephemeral"),
        }
    }
}

impl Default for Persistence {
    fn default() -> Self {
        Self::Persistent
    }
}

/// The type of a value
///
/// It is not called `Type` because that conflicts with reserved keywords.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VType {
    /// The type kind
    pub kind: TypeKind,
    /// The source location of this type
    pub span: Span,
}

impl VType {
    /// Create a new type with span
    pub fn new(kind: TypeKind, span: Span) -> Self {
        VType { kind, span }
    }
}

impl fmt::Display for VType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

/// The kind of type
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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
    Struct(Identifier),
    /// Named enumeration
    Enum(Identifier),
    /// An optional type of some other type
    Optional(Box<VType>),
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
            Self::Optional(vtype) => write!(f, "optional {vtype}"),
        }
    }
}

/// An identifier and its type
///
/// Field definitions are used in Command fields, fact
/// key/value fields, and action/function arguments.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldDefinition {
    /// the field's name
    pub identifier: Ident,
    /// the field's type
    pub field_type: VType,
}

/// An identifier and its type and dynamic effect marker
///
/// A variant used exclusively for Effects
#[derive(Debug, Clone, PartialEq)]
pub struct EffectFieldDefinition {
    /// the field's name
    pub identifier: Ident,
    /// the field's type
    pub field_type: VType,
    /// Whether the field is marked "dynamic" or not
    pub dynamic: bool,
}

/// Value part of a key/value pair for a fact field.
#[derive(Debug, Clone, PartialEq)]
pub enum FactField {
    /// Expression
    Expression(Expression),
    /// Bind value, e.g. "?"
    Bind,
}

/// A fact and its key/value field values.
///
/// It is used to create, read, update, and delete facts.
#[derive(Debug, Clone, PartialEq)]
pub struct FactLiteral {
    /// the fact's name
    pub identifier: Ident,
    /// values for the fields of the fact key
    pub key_fields: Vec<(Ident, FactField)>,
    /// values for the fields of the fact value, which can be absent
    pub value_fields: Option<Vec<(Ident, FactField)>>,
}

/// A function call with a list of arguments.
///
/// Can only be used in expressions, not on its own.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionCall {
    /// the function's name
    pub identifier: Ident,
    /// values for the function's arguments
    pub arguments: Vec<Expression>,
}

/// A named struct literal
#[derive(Debug, Clone, PartialEq)]
pub struct NamedStruct {
    /// the struct name - should refer to either a Effect or Command
    pub identifier: Ident,
    /// The fields, which are pairs of identifiers and expressions
    pub fields: Vec<(Ident, Expression)>,
}

#[derive(Debug, Clone, PartialEq)]
/// Enumeration definition
pub struct EnumDefinition {
    /// enum name
    pub identifier: Ident,
    /// list of possible values
    pub variants: Vec<Ident>,
    /// The source location of this definition
    pub span: Span,
}

/// A reference to an enumeration, e.g. `Color::Red`.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumReference {
    /// enum name
    pub identifier: Ident,
    /// name of value inside enum
    pub value: Ident,
}

/// How many facts to expect when counting
#[derive(Debug, Clone, PartialEq)]
pub enum FactCountType {
    /// Up to
    UpTo,
    /// At least
    AtLeast,
    /// At most
    AtMost,
    /// Exactly
    Exactly,
}

impl fmt::Display for FactCountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UpTo => write!(f, "up_to"),
            Self::AtLeast => write!(f, "at_least"),
            Self::AtMost => write!(f, "at_most"),
            Self::Exactly => write!(f, "exactly"),
        }
    }
}

/// Expression atoms with special rules or effects.
#[derive(Debug, Clone, PartialEq)]
pub enum InternalFunction {
    /// A `query` expression
    Query(FactLiteral),
    /// An `exists` fact query
    Exists(FactLiteral),
    /// Counts the number of facts up to the given limit, and returns the lower of the two.
    FactCount(FactCountType, i64, FactLiteral),
    /// An `if` expression
    If(Box<Expression>, Box<Expression>, Box<Expression>),
    /// Serialize function
    Serialize(Box<Expression>),
    /// Deserialize function
    Deserialize(Box<Expression>),
    /// Not yet implemented panic
    Todo,
}

/// A foreign function call with a list of arguments.
///
/// Can only be used in expressions, not on its own.
#[derive(Debug, Clone, PartialEq)]
pub struct ForeignFunctionCall {
    /// the function's module name
    pub module: Ident,
    /// the function's name
    pub identifier: Ident,
    /// values for the function's arguments
    pub arguments: Vec<Expression>,
}

/// All of the things which can be in an expression.
#[derive(Debug, Clone, PartialEq)]
pub struct Expression {
    /// The expression kind
    pub kind: ExprKind,
    /// The source location of this expression
    pub span: Span,
}

impl Expression {
    /// Create a new expression with span
    pub fn new(kind: ExprKind, span: Span) -> Self {
        Expression { kind, span }
    }
}

/// The kind of expression
#[derive(Debug, Clone, PartialEq)]
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
    /// A variable identifier
    Identifier(Identifier),
    /// Enum reference, e.g. `Color::Red`
    EnumReference(EnumReference),
    /// `expr + expr`
    Add(Box<Expression>, Box<Expression>),
    /// `expr - expr`
    Subtract(Box<Expression>, Box<Expression>),
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
    /// `-expr`
    Negative(Box<Expression>),
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
    /// Match expression
    Match(Box<MatchExpression>),
}

/// Encapsulates both [FunctionDefinition] and [FinishFunctionDefinition] for the purpose
/// of parsing FFI function declarations.
#[derive(Debug, PartialEq)]
pub struct FunctionDecl {
    /// The identifier of the function
    pub identifier: Identifier,
    /// A list of the arguments to the function, and their types
    pub arguments: Vec<FieldDefinition>,
    /// The return type of the function, if any
    pub return_type: Option<VType>,
}

/// Define a variable with an expression
#[derive(Debug, Clone, PartialEq)]
pub struct LetStatement {
    /// The variable's name
    pub identifier: Identifier,
    /// The variable's value
    pub expression: Expression,
}

/// Check that a boolean expression is true, and fail otherwise
#[derive(Debug, Clone, PartialEq)]
pub struct CheckStatement {
    /// The boolean expression being checked
    pub expression: Expression,
}

/// Match arm pattern
#[derive(Debug, Clone, PartialEq)]
pub enum MatchPattern {
    /// No values, default case
    Default,
    /// List of values to match
    Values(Vec<Expression>),
}

/// One arm of a match statement
#[derive(Debug, Clone, PartialEq)]
pub struct MatchArm {
    /// The values to check against. Matches any value if the option is None.
    // TODO(chip): Restrict this to only literal values so we can do
    // exhaustive range checks.
    pub pattern: MatchPattern,
    /// The statements to execute if the value matches
    pub statements: Vec<Statement>,
}

/// Match a value and execute one possibility out of many
///
/// Match arms are tested in order.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchStatement {
    /// The value to match against
    pub expression: Expression,
    /// All of the potential match arms
    pub arms: Vec<MatchArm>,
}

/// Match expression
#[derive(Debug, Clone, PartialEq)]
pub struct MatchExpression {
    /// Value to match against
    pub scrutinee: Expression,
    /// Match arms
    pub arms: Vec<MatchExpressionArm>,
}

/// A container for a statement or expression
#[derive(Debug, Clone, PartialEq)]
pub enum LanguageContext<A, B> {
    /// statement
    Statement(A),
    /// expression
    Expression(B),
}

/// Match arm expression
#[derive(Debug, Clone, PartialEq)]
pub struct MatchExpressionArm {
    /// value to match against the match expression
    pub pattern: MatchPattern,
    /// Expression
    pub expression: Expression,
    /// Span of this arm
    pub span: Span,
}

/// Test a series of conditions and execute the statements for the first true condition.
#[derive(Debug, Clone, PartialEq)]
pub struct IfStatement {
    /// Each `if` and `else if` branch.
    pub branches: Vec<(Expression, Vec<Statement>)>,
    /// The `else` branch, if present.
    pub fallback: Option<Vec<Statement>>,
}

/// Iterate over the results of a query, and execute some statements for each one.
#[derive(Debug, Clone, PartialEq)]
pub struct MapStatement {
    /// Query
    pub fact: FactLiteral,
    /// Identifier of container struct
    pub identifier: Identifier,
    /// Statements to execute for each fact
    pub statements: Vec<Statement>,
}

/// Create a fact
#[derive(Debug, Clone, PartialEq)]
pub struct CreateStatement {
    /// The fact to create
    pub fact: FactLiteral,
}

/// Update a fact
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateStatement {
    /// This fact has to exist as stated
    pub fact: FactLiteral,
    /// The value fields are updated to these values
    pub to: Vec<(Ident, FactField)>,
}

/// Delete a fact
#[derive(Debug, Clone, PartialEq)]
pub struct DeleteStatement {
    /// The fact to delete
    pub fact: FactLiteral,
}

/// Return from a function
///
/// Only valid within functions.
#[derive(Debug, Clone, PartialEq)]
pub struct ReturnStatement {
    /// The value to return
    pub expression: Expression,
}

/// Statements in the policy language.
/// Not all statements are valid in all contexts.
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    /// The statement kind
    pub kind: StmtKind,
    /// The source location of this statement
    pub span: Span,
}

impl Statement {
    /// Create a new statement with span
    pub fn new(kind: StmtKind, span: Span) -> Self {
        Statement { kind, span }
    }
}

/// The kind of statement
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FactDefinition {
    /// Is this fact immutable?
    pub immutable: bool,
    /// The name of the fact
    pub identifier: Identifier,
    /// Types for all of the key fields
    pub key: Vec<FieldDefinition>,
    /// Types for all of the value fields
    pub value: Vec<FieldDefinition>,
    /// The source location of this definition
    pub span: Span,
}

/// An action definition
#[derive(Debug, Clone, PartialEq)]
pub struct ActionDefinition {
    /// The persistence mode of the action
    pub persistence: Persistence,
    /// The name of the action
    pub identifier: Identifier,
    /// The arguments to the action
    pub arguments: Vec<FieldDefinition>,
    /// The statements executed when the action is called
    pub statements: Vec<Statement>,
    /// The source location of this definition
    pub span: Span,
}

/// An effect definition
#[derive(Debug, Clone, PartialEq)]
pub struct EffectDefinition {
    /// The name of the effect
    pub identifier: Identifier,
    /// The fields of the effect and their types
    pub items: Vec<StructItem<EffectFieldDefinition>>,
    /// The source location of this definition
    pub span: Span,
}

/// A struct definition
#[derive(Debug, Clone, PartialEq)]
pub struct StructDefinition {
    /// The name of the struct
    pub identifier: Identifier,
    /// The fields of the struct and their types
    pub items: Vec<StructItem<FieldDefinition>>,
    /// The source location of this definition
    pub span: Span,
}

/// Struct field or insertion reference
#[derive(Debug, Clone, PartialEq)]
pub enum StructItem<T> {
    /// Field definition
    Field(T),
    /// Named struct from whose fields to add to the current struct
    StructRef(Identifier),
}

impl<T> StructItem<T> {
    /// Get the field definition from this struct item
    pub fn field(&self) -> Option<&T> {
        match self {
            StructItem::Field(f) => Some(f),
            StructItem::StructRef(_) => None,
        }
    }
}

/// A command definition
#[derive(Debug, Clone, PartialEq)]
pub struct CommandDefinition {
    /// The persistence mode of the command
    pub persistence: Persistence,
    /// Optional attributes
    pub attributes: Vec<(Identifier, Expression)>,
    /// The name of the command
    pub identifier: Identifier,
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

/// A function definition
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDefinition {
    /// The name of the function
    pub identifier: Identifier,
    /// The argument names and types
    pub arguments: Vec<FieldDefinition>,
    /// The return type
    pub return_type: VType,
    /// The policy rule statements
    pub statements: Vec<Statement>,
    /// The source location of this definition
    pub span: Span,
}

/// A finish function definition. This is slightly different than a
/// regular function since it cannot return values and can only
/// execute finish block statements.
#[derive(Debug, Clone, PartialEq)]
pub struct FinishFunctionDefinition {
    /// The name of the function
    pub identifier: Identifier,
    /// The argument names and types
    pub arguments: Vec<FieldDefinition>,
    /// The finish block statements
    pub statements: Vec<Statement>,
    /// The source location of this definition
    pub span: Span,
}

/// A globally scopped let statement
#[derive(Debug, Clone, PartialEq)]
pub struct GlobalLetStatement {
    /// The variable's name
    pub identifier: Identifier,
    /// The variable's value
    pub expression: Expression,
    /// The source location of this statement
    pub span: Span,
}

/// The policy AST root
///
/// This contains all of the definitions that comprise a policy.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Policy {
    /// The policy version.
    pub version: Version,
    /// FFI imports
    pub ffi_imports: Vec<Identifier>,
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
    pub fn new(version: Version, text: &str) -> Policy {
        Policy {
            version,
            text: text.to_owned(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_new_validation() {
        // Valid span
        let span = Span::new(0, 10);
        assert_eq!(span.start, 0);
        assert_eq!(span.end, 10);

        // Equal start and end (empty span)
        let empty = Span::new(5, 5);
        assert!(empty.is_empty());
    }

    #[test]
    #[should_panic(expected = "Invalid span")]
    #[cfg(debug_assertions)]
    fn test_span_new_invalid() {
        // This should panic in debug mode
        Span::new(10, 5);
    }

    #[test]
    fn test_span_contains() {
        let outer = Span::new(0, 100);
        let inner = Span::new(10, 20);
        let overlapping = Span::new(50, 150);

        assert!(outer.contains(&inner));
        assert!(!inner.contains(&outer));
        assert!(!outer.contains(&overlapping));

        // Test edge cases
        let same = Span::new(10, 20);
        assert!(same.contains(&same));

        let point = Span::point(15);
        assert!(outer.contains(&point));
        assert!(!point.contains(&outer));
    }

    #[test]
    fn test_span_merge() {
        let span1 = Span::new(10, 20);
        let span2 = Span::new(30, 40);
        let merged = span1.merge(&span2);

        assert_eq!(merged.start, 10);
        assert_eq!(merged.end, 40);

        // Test merge with overlapping spans
        let span3 = Span::new(15, 35);
        let merged2 = span1.merge(&span3);
        assert_eq!(merged2.start, 10);
        assert_eq!(merged2.end, 35);

        // Test merge order doesn't matter
        let merged3 = span2.merge(&span1);
        assert_eq!(merged3, merged);

        // Test merging with self
        let self_merge = span1.merge(&span1);
        assert_eq!(self_merge, span1);

        // Test merging points
        let point1 = Span::point(5);
        let point2 = Span::point(50);
        let point_merge = point1.merge(&point2);
        assert_eq!(point_merge.start, 5);
        assert_eq!(point_merge.end, 50);
    }

    #[test]
    fn test_span_len() {
        assert_eq!(Span::new(0, 10).len(), 10);
        assert_eq!(Span::new(5, 5).len(), 0);
        assert_eq!(Span::new(100, 150).len(), 50);

        // Test with point span
        assert_eq!(Span::point(42).len(), 0);
    }

    #[test]
    fn test_span_is_empty() {
        assert!(!Span::new(0, 10).is_empty());
        assert!(Span::new(5, 5).is_empty());
        assert!(Span::point(100).is_empty());
    }

    #[test]
    fn test_span_point() {
        let point = Span::point(42);
        assert_eq!(point.start, 42);
        assert_eq!(point.end, 42);
        assert!(point.is_empty());
        assert_eq!(point.len(), 0);
    }
}
