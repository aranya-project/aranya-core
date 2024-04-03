extern crate alloc;

use alloc::{borrow::ToOwned, boxed::Box, string::String, vec::Vec};
use core::{fmt, ops::Deref, str::FromStr};

use serde::{Deserialize, Serialize};

/// An invalid version string was provided to
/// [`Version::from_str`].
#[derive(Copy, Clone, Debug)]
pub struct InvalidVersion;

impl fmt::Display for InvalidVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid version string")
    }
}

impl trouble::Error for InvalidVersion {}

/// Policy language version
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Version {
    /// Version 3, the initial version of the "new" policy
    /// language.
    #[default]
    V3,
}

// This supports the command-line tools, allowing automatic
// conversion between string arguments and the enum.
impl FromStr for Version {
    type Err = InvalidVersion;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "v3" => Ok(Version::V3),
            _ => Err(InvalidVersion),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V3 => write!(f, "v3"),
        }
    }
}

/// An AST node with location information
#[derive(Debug, Clone, PartialEq)]
pub struct AstNode<T> {
    /// The AST element contained within
    pub inner: T,
    /// The locator for where this AST element occurred in the source text
    pub locator: usize,
}

impl<T> AstNode<T> {
    /// Create a new `AstNode` from a node and locator
    pub fn new(inner: T, locator: usize) -> AstNode<T> {
        AstNode { inner, locator }
    }
}

impl<T> Deref for AstNode<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// The type of a value
///
/// It is not called `Type` because that conflicts with reserved keywords.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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
    Id,
    /// A named struct
    Struct(String),
    /// an optional type of some other type
    Optional(Box<VType>),
}

impl fmt::Display for VType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Bytes => write!(f, "bytes"),
            Self::Int => write!(f, "int"),
            Self::Bool => write!(f, "bool"),
            Self::Id => write!(f, "id"),
            Self::Struct(name) => write!(f, "struct {name}"),
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
    /// Serialize function
    Serialize(Box<Expression>),
    /// Deserialize function
    Deserialize(Box<Expression>),
}

/// A foreign function call with a list of arguments.
///
/// Can only be used in expressions, not on its own.
#[derive(Debug, Clone, PartialEq)]
pub struct ForeignFunctionCall {
    /// the function's module name
    pub module: String,
    /// the function's name
    pub identifier: String,
    /// values for the function's arguments
    pub arguments: Vec<Expression>,
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
    /// A foreign function call
    ForeignFunctionCall(ForeignFunctionCall),
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
    /// Similar to Unwrap, but exits with a Check, instead of a Panic
    CheckUnwrap(Box<Expression>),
    /// `expr is Some`, `expr is None`
    Is(Box<Expression>, bool),
}

/// Encapsulates both [FunctionDefinition] and [FinishFunctionDefinition] for the purpose
/// of parsing FFI function declarations.
#[derive(Debug, PartialEq)]
pub struct FunctionDecl {
    /// The identifier of the function
    pub identifier: String,
    /// A list of the arguments to the function, and their types
    pub arguments: Vec<FieldDefinition>,
    /// The return type of the function, if any
    pub return_type: Option<VType>,
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
    pub statements: Vec<AstNode<Statement>>,
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
    pub statements: Vec<AstNode<Statement>>,
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

/// Statements in the policy language.
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
    /// A `finish` block containing [Statement]s
    /// Valid only in policy blocks
    Finish(Vec<AstNode<Statement>>),
    /// A [ReturnStatement]. Valid only in functions.
    Return(ReturnStatement),
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
    pub statements: Vec<AstNode<Statement>>,
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
    /// Statements for sealing the command into an envelope
    pub seal: Vec<AstNode<Statement>>,
    /// Statements for opening the command envelope
    pub open: Vec<AstNode<Statement>>,
    /// The policy rule statements for this command
    pub policy: Vec<AstNode<Statement>>,
    /// The recall rule statements for this command
    pub recall: Vec<AstNode<Statement>>,
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
    pub statements: Vec<AstNode<Statement>>,
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
    pub statements: Vec<AstNode<Statement>>,
}

/// A list of (position, size) pairs for text ranges
pub type TextRanges = Vec<(usize, usize)>;

/// The policy AST root
///
/// This contains all of the definitions that comprise a policy.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Policy {
    /// The policy version.
    pub version: Version,
    /// The policy's fact definitions.
    pub facts: Vec<AstNode<FactDefinition>>,
    /// The policy's action definitions.
    pub actions: Vec<AstNode<ActionDefinition>>,
    /// The policy's effect definitions.
    pub effects: Vec<AstNode<EffectDefinition>>,
    /// The policy's struct definitions.
    pub structs: Vec<AstNode<StructDefinition>>,
    /// The policy's command definitions.
    pub commands: Vec<AstNode<CommandDefinition>>,
    /// The policy's function definitions.
    pub functions: Vec<AstNode<FunctionDefinition>>,
    /// The policy's finish function definitions.
    pub finish_functions: Vec<AstNode<FinishFunctionDefinition>>,
    /// The source text
    pub text: String,
    /// Text ranges for various nodes (start, end)
    /// Start is also the locator
    pub ranges: TextRanges,
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
