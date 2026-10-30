//! Typed High-level Intermediate Representation

use alloc::{boxed::Box, vec::Vec};

use crate::{FactCountType, Ident, IntLiteral, Span, Spanned, Text, VType};

/// A fact and its key/value field values.
///
/// It is used to create, read, update, and delete facts.
#[derive(Debug, Clone)]
pub struct FactLiteral {
    /// the fact's name
    pub name: Ident,
    /// values for the fields of the fact key
    pub key_fields: Vec<(Ident, Expression)>,
    /// values for the fields of the fact value, which can be absent
    pub value_fields: Option<Vec<(Ident, Expression)>>,
}

/// A function call with a list of arguments.
///
/// Can only be used in expressions, not on its own.
#[derive(Debug, Clone)]
pub struct FunctionCall {
    /// the function's name
    pub name: Ident,
    /// values for the function's arguments
    pub arguments: Vec<Expression>,
}

/// Call to a command's recall block.
#[derive(Debug, Clone)]
pub struct RecallCall {
    /// the command being recalled
    pub command_name: Ident,
    /// the name of the recall block
    pub recall_name: Ident,
    /// recall arguments
    pub arguments: Vec<Expression>,
}

/// A named struct literal
#[derive(Debug, Clone)]
pub struct NamedStruct {
    /// the struct name - should refer to either a Effect or Command
    pub name: Ident,
    /// The fields, which are pairs of identifiers and expressions
    pub fields: Vec<(Ident, Expression)>,
    /// sources is a list of identifiers used in struct composition
    pub sources: Vec<Ident>,
}

/// A reference to an enumeration, e.g. `Color::Red`.
#[derive(Debug, Clone)]
pub struct EnumReference {
    /// enum name
    pub enumeration: Ident,
    /// variant value
    pub value: i64,
}

/// Expression atoms with special rules or effects.
#[derive(Debug, Clone)]
pub enum InternalFunction {
    /// A `query` expression
    Query(FactLiteral),
    /// An `exists` fact query
    Exists(FactLiteral),
    /// Counts the number of facts up to the given limit, and returns the lower of the two.
    // TODO(eric): make `i64` an expr or literal or something
    FactCount(FactCountType, IntLiteral, FactLiteral),
    /// An `if` expression
    If(Box<Expression>, Box<Expression>, Box<Expression>),
    /// Not yet implemented panic
    Todo(Span),
    /// Panics with an optional message, for expressing test expectations
    TestFail(Option<Text>, Span),
}

/// A foreign function call with a list of arguments.
///
/// Can only be used in expressions, not on its own.
#[derive(Debug, Clone)]
pub struct ForeignFunctionCall {
    /// the function's module name
    pub module: Ident,
    /// the function's name
    pub function: Ident,
    /// The module and procedure ID.
    ///
    /// This is `None` if `stub_ffi` is enabled.
    pub ids: Option<(usize, usize)>,
    /// values for the function's arguments
    pub arguments: Vec<Expression>,
}

/// All of the things which can be in an expression.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub enum ExprKind {
    /// A unit literal
    Unit,
    /// A 64-bit signed integer
    Int(IntLiteral),
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
    /// Calls an action, evaluating to the action's return value.
    ActionCall(FunctionCall),
    /// A return expression. Valid only in functions.
    Return(Box<Expression>),
    /// A `recall name(args)` expression with type `Never`. Valid only in `policy` blocks.
    Recall(RecallCall),
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
    /// Result Ok variant
    Ok(Box<Expression>),
    /// Result Err variant
    Err(Box<Expression>),
    /// Unwrap a `result[T, E]`, propagating `Err` to the caller.
    Try(Box<Expression>),
}

/// Define a variable with an expression
#[derive(Debug, Clone)]
pub struct LetStatement {
    /// The variable's name
    pub name: Ident,
    /// The variable's value
    pub value: Expression,
}

/// Check that a boolean expression is true, and fail otherwise
#[derive(Debug, Clone)]
pub struct CheckStatement {
    /// The boolean expression being checked
    pub condition: Expression,
    /// Expression to evaluate if the check fails.
    pub else_expression: Expression,
}

/// Match arm pattern
#[derive(Debug, Clone)]
pub enum MatchPattern {
    /// No values, default case
    Default(Span),
    /// List of values to match
    /// Can include Ok(x) and Err(e) for Result matching.
    Values(Vec<Expression>),
}

/// One arm of a match statement
#[derive(Debug, Clone)]
pub struct MatchArm {
    /// The values to check against. Matches any value if the option is None.
    // TODO(chip): Restrict this to only literal values so we can do
    // exhaustive range checks.
    pub pattern: MatchPattern,
    /// The statements to execute if the value matches
    pub body: Vec<Statement>,
}

/// Match a value and execute one possibility out of many
///
/// Match arms are tested in order.
#[derive(Debug, Clone)]
pub struct MatchStatement {
    /// The value to match against
    pub scrutinee: Expression,
    /// All of the potential match arms
    pub arms: Vec<MatchArm>,
}

/// Match statement expression
#[derive(Debug, Clone)]
pub struct MatchExpression {
    /// Value to match against
    pub scrutinee: Expression,
    /// Match arms
    pub arms: Vec<MatchExpressionArm>,
}

/// Match arm expression
#[derive(Debug, Clone)]
pub struct MatchExpressionArm {
    /// value to match against the match expression
    pub pattern: MatchPattern,
    /// Expression
    pub body: Expression,
    /// The source location of this match arm
    pub span: Span,
}

/// Test a series of conditions and execute the statements for the first true condition.
#[derive(Debug, Clone)]
pub struct IfStatement {
    /// Each `if` and `else if` branch.
    pub branches: Vec<(Expression, Vec<Statement>)>,
    /// The `else` branch, if present.
    pub fallback: Option<Vec<Statement>>,
}

/// Iterate over the results of a query, and execute some statements for each one.
#[derive(Debug, Clone)]
pub struct MapStatement {
    /// Query
    pub fact: FactLiteral,
    /// Identifier of container struct
    pub identifier: Ident,
    /// Statements to execute for each fact
    pub body: Vec<Statement>,
}

/// Create a fact
#[derive(Debug, Clone)]
pub struct CreateStatement {
    /// The fact to create
    pub fact: FactLiteral,
}

/// Update a fact
#[derive(Debug, Clone)]
pub struct UpdateStatement {
    /// This fact has to exist as stated
    pub fact: FactLiteral,
    /// The value fields are updated to these values
    pub to: Vec<(Ident, Expression)>,
}

/// Delete a fact
#[derive(Debug, Clone)]
pub struct DeleteStatement {
    /// The fact to delete
    pub fact: FactLiteral,
}

/// Return from a function
///
/// Only valid within functions.
#[derive(Debug, Clone)]
pub struct ReturnStatement {
    /// The value to return
    pub value: Expression,
}

/// Statements in the policy language.
/// Not all statements are valid in all contexts.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
    /// Calls an non-returning action. For returning actions, see [`ExprKind::ActionCall`].
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
    /// A `recall name(args)` statement. Valid only in `policy` blocks.
    Recall(RecallCall),
}
