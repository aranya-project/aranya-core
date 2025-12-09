//! Typed High-level Intermediate Representation

use alloc::{boxed::Box, vec::Vec};

use serde_derive::{Deserialize, Serialize};

use crate::{FactCountType, Ident, Span, Spanned, Text, VType, span::spanned};

spanned! {
/// A fact and its key/value field values.
///
/// It is used to create, read, update, and delete facts.
#[derive(Debug, Clone, PartialEq,Serialize,Deserialize)]
pub struct FactLiteral {
    /// the fact's name
    pub identifier: Ident,
    /// values for the fields of the fact key
    pub key_fields: Vec<(Ident, Expression)>,
    /// values for the fields of the fact value, which can be absent
    pub value_fields: Option<Vec<(Ident, Expression)>>,
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

/// A reference to an enumeration, e.g. `Color::Red`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumReference {
    /// enum name
    pub identifier: Ident,
    /// variant value
    pub value: i64,
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

/// A foreign function call with a list of arguments.
///
/// Can only be used in expressions, not on its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForeignFunctionCall {
    /// the function's module name
    pub module: Ident,
    /// the function's name
    pub identifier: Ident,
    /// The module and procedure ID.
    ///
    /// This is `None` if `stub_ffi` is enabled.
    pub ids: Option<(usize, usize)>,
    /// values for the function's arguments
    pub arguments: Vec<Expression>,
}

/// All of the things which can be in an expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Expression {
    /// The expression kind
    pub kind: ExprKind,
    /// The expression's type
    pub vtype: VType,
    /// The source location of this expression
    pub span: Span,
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
    /// Return expression
    Return(Box<Expression>),
    /// Result Ok variant
    ResultOk(Box<Expression>),
    /// Result Err variant
    ResultErr(Box<Expression>),
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

/// Result pattern for matching Ok/Err in Result types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResultPattern {
    /// Match Ok(identifier)
    Ok(Ident),
    /// Match Err(identifier)
    Err(Ident),
}

impl Spanned for ResultPattern {
    fn span(&self) -> Span {
        match self {
            Self::Ok(ident) | Self::Err(ident) => ident.span(),
        }
    }
}

/// Match arm pattern
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MatchPattern {
    /// No values, default case
    Default(Span),
    /// List of values to match
    Values(Vec<Expression>),
    /// Result pattern (Ok or Err)
    ResultPattern(ResultPattern),
}

impl Spanned for MatchPattern {
    fn span(&self) -> Span {
        match self {
            Self::Default(span) => *span,
            Self::Values(values) => values.span(),
            Self::ResultPattern(pattern) => pattern.span(),
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
    pub to: Vec<(Ident, Expression)>,
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

/// Statements in the policy language.
/// Not all statements are valid in all contexts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Statement {
    /// The statement kind
    pub kind: StmtKind,
    /// The source location of this statement
    pub span: Span,
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
    /// An expression used as a statement (for return expressions, etc.)
    Expr(Expression),
}
