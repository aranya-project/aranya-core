use std::fmt;

use aranya_policy_ast::{self as ast, Identifier};
use aranya_policy_module::CodeMap;
use buggy::Bug;

use crate::compile::StatementContext;

/// Describes the call color in an [CompileErrorType::InvalidCallColor].
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum InvalidCallColor {
    /// The call is a pure function
    #[error("pure function not allowed in finish context")]
    Pure,
    /// The call is a finish function
    #[error("finish function not allowed in expression")]
    Finish,
}

/// Errors that can occur during compilation.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum CompileErrorType {
    /// Invalid statement - a statement was used in an invalid context.
    #[error("invalid statement in {0} context")]
    InvalidStatement(StatementContext),
    /// Invalid expression - the expression does not make sense in context.
    #[error("invalid expression: {0:?}")]
    InvalidExpression(ast::Expression),
    /// Invalid type
    #[error("invalid type: {0}")]
    InvalidType(String),
    /// Invalid call color - Tried to make a function call to the wrong type of function.
    #[error(transparent)]
    InvalidCallColor(#[from] InvalidCallColor),
    /// Resolution of branch targets failed to find a valid target
    #[error("bad branch target: {0}")]
    BadTarget(Identifier),
    /// An argument to a function or an item in an expression did not
    /// make sense
    #[error("bad argument: {0}")]
    BadArgument(String),
    /// A thing referenced is not defined
    #[error("not defined: {0}")]
    NotDefined(String),
    /// A thing by that name has already been defined
    #[error("already defined: {0}")]
    AlreadyDefined(String),
    /// A definition is recursive.
    #[error("invalid recursive definition: {0:?}")]
    RecursiveDefinition(Vec<Identifier>),
    /// Fact literal doesn't match definition
    #[error("fact literal does not match definition: {0}")]
    InvalidFactLiteral(String),
    /// A pure function has no return statement
    #[error("function has no return statement")]
    NoReturn,
    /// A validation step failed
    #[error("validation failed")]
    Validation,
    /// Source structs in struct composition have overlapping fields
    #[error("Struct {0} and Struct {1} have at least 1 field with the same name")]
    DuplicateSourceFields(Identifier, Identifier),
    /// The source struct is not a subset of the base struct
    #[error("Struct {0} must be a subset of Struct {1}")]
    SourceStructNotSubsetOfBase(Identifier, Identifier),
    /// It is an error to add a composed struct when all fields are directly specified
    #[error(
        "A struct literal has all its fields explicitly specified while also having 1 or more struct compositions"
    )]
    NoOpStructComp,
    /// Invalid Substruct operation - The struct on the RHS of the substruct
    /// operator is not a subset of the struct on the LHS of the substruct operator
    #[error("invalid substruct operation: `Struct {0}` must be a strict subset of `Struct {1}`")]
    InvalidSubstruct(Identifier, Identifier),
    /// Todo found
    #[error("todo found")]
    TodoFound,
    /// Invalid cast - LHS cannot be converted to RHS
    #[error("invalid cast: `{0}` cannot be converted to `{1}`")]
    InvalidCast(Identifier, Identifier),
    /// An implementation bug
    #[error("bug: {0}")]
    Bug(#[from] Bug),
    /// All other errors
    #[error("unknown error: {0}")]
    Unknown(String),
}

// TODO(chip): this is identical to MachineErrorSource and could
// probably be merged with it. I'm keeping it separate for now as I
// expect the compiler will be moved out of the VM crate.
/// The source location and text of an error
#[derive(Debug, PartialEq)]
struct ErrorSource {
    /// Line and column of where the error is
    linecol: (usize, usize),
    /// The text of the error
    text: String,
}

/// An error produced by the compiler. May contain the textual source of
/// an error.
#[derive(Debug, PartialEq)]
pub struct CompileError(Box<CompileErrorImpl>);

#[derive(Debug, PartialEq)]
struct CompileErrorImpl {
    /// The type of the error
    err_type: CompileErrorType,
    /// The source code information, if available
    source: Option<ErrorSource>,
}

impl CompileError {
    /// Creates a `CompileError`.
    pub(crate) fn new(err_type: CompileErrorType) -> CompileError {
        CompileError(Box::new(CompileErrorImpl {
            err_type,
            source: None,
        }))
    }

    pub(crate) fn from_locator(
        err_type: CompileErrorType,
        locator: usize,
        codemap: Option<&CodeMap>,
    ) -> CompileError {
        let source = codemap.and_then(|codemap| {
            codemap
                .span_from_locator(locator)
                .ok()
                .map(|span| ErrorSource {
                    linecol: span.start_linecol(),
                    text: span.as_str().to_owned(),
                })
        });

        CompileError(Box::new(CompileErrorImpl { err_type, source }))
    }

    pub fn err_type(self) -> CompileErrorType {
        self.0.err_type
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0.source {
            Some(source) => write!(
                f,
                "{} at line {} col {}:\n\t{}",
                self.0.err_type, source.linecol.0, source.linecol.1, source.text
            ),
            None => write!(f, "{}", self.0.err_type),
        }
    }
}

// Implementing Display and deriving Debug implements
// error::Error with default behavior by declaring this empty
// implementation.
impl core::error::Error for CompileError {}

impl From<Bug> for CompileError {
    fn from(bug: Bug) -> Self {
        CompileError::new(CompileErrorType::Bug(bug))
    }
}

// impl From<SortError> for CompileError {
//     fn from(err: SortError) -> Self {
//         match err {
//             SortError::Bug(bug) => bug.into(),
//             SortError::Cycle(_cycle) => {
//                 // TODO: Convert NodeIdx cycle to identifiers for error message
//                 CompileError::new(CompileErrorType::RecursiveDefinition(vec![]))
//             }
//         }
//     }
// }

// impl From<InvalidNodeIdx> for CompileError {
//     fn from(_err: InvalidNodeIdx) -> Self {
//         CompileError::new(CompileErrorType::Bug(Bug::new(
//             "invalid node index in dependency graph",
//         )))
//     }
// }
