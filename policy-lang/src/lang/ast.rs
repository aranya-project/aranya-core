use crate::lang::Version;

/// The type of a value
///
/// It is not called `Type` because that conflicts with reserved keywords.
#[derive(Debug, Clone, PartialEq)]
pub enum VType {
    /// a character (UTF-8) string
    String,
    /// A byte string
    Bytes,
    /// a signed 64-bit integer
    Int,
    /// a boolean
    Bool,
    /// a Flow3 identifier
    ID,
    /// A named struct
    Struct(String),
    /// an optional type of some other type
    Optional(Box<VType>),
}

/// An identifier and its type
///
/// Field definitions are used in Command fields, fact
/// key/value fields, and action/function arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDefinition {
    /// the field's name
    pub identifier: String,
    /// the field's type
    pub field_type: VType,
}

/// An identifier and its type and dynamic effect marker
///
/// A variant used exclusively for Effects
#[derive(Debug, Clone, PartialEq)]
pub struct EffectFieldDefinition {
    /// the field's name
    pub identifier: String,
    /// the field's type
    pub field_type: VType,
    /// Whether the field is marked "dynamic" or not
    pub dynamic: bool,
}

/// Convert from EffectFieldDefinition to FieldDefinition, losing the
/// dynamic information.
impl From<&EffectFieldDefinition> for FieldDefinition {
    fn from(value: &EffectFieldDefinition) -> Self {
        FieldDefinition {
            identifier: value.identifier.clone(),
            field_type: value.field_type.clone(),
        }
    }
}

/// A fact and its key/value field values.
///
/// It is used to create, read, update, and delete facts.
#[derive(Debug, Clone, PartialEq)]
pub struct FactLiteral {
    /// the fact's name
    pub identifier: String,
    /// values for the fields of the fact key
    pub key_fields: Vec<(String, Expression)>,
    /// values for the fields of the fact value, which can be absent
    pub value_fields: Option<Vec<(String, Expression)>>,
}

/// A function call with a list of arguments.
///
/// Can only be used in expressions, not on its own.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionCall {
    /// the function's name
    pub identifier: String,
    /// values for the function's arguments
    pub arguments: Vec<Expression>,
}

/// A named struct literal
#[derive(Debug, Clone, PartialEq)]
pub struct NamedStruct {
    /// the struct name - should refer to either a Effect or Command
    pub identifier: String,
    /// The fields, which are pairs of identifiers and expressions
    pub fields: Vec<(String, Expression)>,
}

/// Expression atoms with special rules or effects.
#[derive(Debug, Clone, PartialEq)]
pub enum InternalFunction {
    /// A `query` expression
    Query(FactLiteral),
    /// An `exists` fact query
    Exists(FactLiteral),
    /// An `if` expression
    If(Box<Expression>, Box<Expression>, Box<Expression>),
    /// Return the ID of the command
    Id(Box<Expression>),
    /// Return the ID of the author of a command
    AuthorId(Box<Expression>),
}

/// All of the things which can be in an expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    /// A 64-bit signed integer
    Int(i64),
    /// A text string
    String(String),
    /// A boolean literal
    Bool(bool),
    /// An optional literal
    Optional(Option<Box<Expression>>),
    /// A named struct
    NamedStruct(NamedStruct),
    /// A query bind marker
    Bind,
    /// One of the [InternalFunction]s
    InternalFunction(InternalFunction),
    /// A function call
    FunctionCall(FunctionCall),
    /// A variable identifier
    Identifier(String),
    /// `(expr)`
    Parentheses(Box<Expression>),
    /// `expr + expr`
    Add(Box<Expression>, Box<Expression>),
    /// `expr - expr`
    Subtract(Box<Expression>, Box<Expression>),
    /// expr && expr`
    And(Box<Expression>, Box<Expression>),
    /// expr || expr`
    Or(Box<Expression>, Box<Expression>),
    /// expr.expr`
    Dot(Box<Expression>, String),
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
    /// `expr is Some`, `expr is None`
    Is(Box<Expression>, bool),
}

/// Define a variable with an expression
#[derive(Debug, Clone, PartialEq)]
pub struct LetStatement {
    /// The variable's name
    pub identifier: String,
    /// The variable's value
    pub expression: Expression,
}

/// Check that a boolean expression is true, and fail otherwise
#[derive(Debug, Clone, PartialEq)]
pub struct CheckStatement {
    /// Is this an origin check?
    pub origin: bool,
    /// The boolean expression being checked
    pub expression: Expression,
}

/// One arm of a match statement
#[derive(Debug, Clone, PartialEq)]
pub struct MatchArm {
    /// The value to check against. Matches any value if the option is None.
    // TODO(chip): Restrict this to only literal values so we can do
    // exhaustive range checks.
    pub value: Option<Expression>,
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

/// Test an expression and execute a set of substatements if it is true.
#[derive(Debug, Clone, PartialEq)]
pub struct WhenStatement {
    /// The value to match against
    pub expression: Expression,
    /// All of the potential match arms
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
    pub to: Vec<(String, Expression)>,
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

/// Statements alowed within an action, a policy block, or a function.
/// Not all statements are valid in all contexts.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    /// A [LetStatement]
    Let(LetStatement),
    /// A [CheckStatement]
    Check(CheckStatement),
    /// A [MatchStatement]
    Match(MatchStatement),
    /// A [WhenStatement],
    When(WhenStatement),
    /// A `finish` block containing [FinishStatement]s
    /// Valid only in policy blocks
    Finish(Vec<FinishStatement>),
    /// A [ReturnStatement]
    /// Valid only in functions
    Return(ReturnStatement),
    /// Creates a new command based on an expression describing a
    /// command
    /// Valid only in actions
    Emit(Expression),
}

/// Statements allowed within a finish block
#[derive(Debug, Clone, PartialEq)]
pub enum FinishStatement {
    /// A [CreateStatement]
    Create(CreateStatement),
    /// An [UpdateStatement]
    Update(UpdateStatement),
    /// A [DeleteStatement]
    Delete(DeleteStatement),
    /// An [Expression]
    Effect(Expression),
    /// A function call (only for finish functions)
    FunctionCall(FunctionCall),
}

/// A schema definition for a fact
#[derive(Debug, Clone, PartialEq)]
pub struct FactDefinition {
    /// The name of the fact
    pub identifier: String,
    /// Types for all of the key fields
    pub key: Vec<FieldDefinition>,
    /// Types for all of the value fields
    pub value: Vec<FieldDefinition>,
}

/// An action definition
#[derive(Debug, Clone, PartialEq)]
pub struct ActionDefinition {
    /// The name of the action
    pub identifier: String,
    /// The arguments to the action
    pub arguments: Vec<FieldDefinition>,
    /// The statements executed when the action is called
    pub statements: Vec<Statement>,
}

/// An effect definition
#[derive(Debug, Clone, PartialEq)]
pub struct EffectDefinition {
    /// The name of the effect
    pub identifier: String,
    /// The fields of the effect and their types
    pub fields: Vec<EffectFieldDefinition>,
}

/// A struct definition
#[derive(Debug, Clone, PartialEq)]
pub struct StructDefinition {
    /// The name of the struct
    pub identifier: String,
    /// The fields of the struct and their types
    pub fields: Vec<FieldDefinition>,
}

/// A command definition
#[derive(Debug, Clone, PartialEq)]
pub struct CommandDefinition {
    /// The name of the command
    pub identifier: String,
    /// The fields of the command and their types
    pub fields: Vec<FieldDefinition>,
    /// The policy rule statements for this command
    pub policy: Vec<Statement>,
    /// The recall rule statements for this command
    pub recall: Vec<Statement>,
}

/// A function definition
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDefinition {
    /// The name of the function
    pub identifier: String,
    /// The argument names and types
    pub arguments: Vec<FieldDefinition>,
    /// The return type
    pub return_type: VType,
    /// The policy rule statements
    pub statements: Vec<Statement>,
}

/// A finish function definition. This is slightly different than a
/// regular function since it cannot return values and can only
/// execute finish block statements.
#[derive(Debug, Clone, PartialEq)]
pub struct FinishFunctionDefinition {
    /// The name of the function
    pub identifier: String,
    /// The argument names and types
    pub arguments: Vec<FieldDefinition>,
    /// The finish block statements
    pub statements: Vec<FinishStatement>,
}

/// The policy AST root
///
/// This contains all of the definitions that comprise a policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub version: Version,
    pub facts: Vec<FactDefinition>,
    pub actions: Vec<ActionDefinition>,
    pub effects: Vec<EffectDefinition>,
    pub structs: Vec<StructDefinition>,
    pub commands: Vec<CommandDefinition>,
    pub functions: Vec<FunctionDefinition>,
    pub finish_functions: Vec<FinishFunctionDefinition>,
}

/// Describes a foreign function, with its name and arguments.
pub struct FfiFunctionDefinition {
    pub name: String,
    pub args: Vec<FieldDefinition>,
    pub color: FfiFunctionColor,
}

/// Describes the context in which the function can be called.
pub enum FfiFunctionColor {
    /// Function is valid outside of finish blocks, and returns a value.
    Pure(VType),

    /// Function is valid inside finish blocks, and does not return a value.
    Finish,
}
