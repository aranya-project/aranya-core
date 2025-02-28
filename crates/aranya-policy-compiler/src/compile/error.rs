use std::fmt;

use aranya_policy_ast as ast;
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
    BadTarget(String),
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
    /// A keyword collision occurs with that identifier
    #[error("reserved identifier: {0}")]
    ReservedIdentifier(String),
    /// Expected value was missing
    #[error("missing: {0}")]
    Missing(String),
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
    DuplicateSourceFields(String, String),
    /// The source struct is not a subset of the base struct
    #[error("Struct {0} must be subset of Struct {1}")]
    SourceStructTooManyFields(String, String),
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
pub struct CompileError {
    /// The type of the error
    pub err_type: CompileErrorType,
    /// The source code information, if available
    source: Option<ErrorSource>,
}

impl CompileError {
    /// Creates a `CompileError`.
    pub(crate) fn new(err_type: CompileErrorType) -> CompileError {
        CompileError {
            err_type,
            source: None,
        }
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

        CompileError { err_type, source }
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(
                f,
                "{} at line {} col {}:\n\t{}",
                self.err_type, source.linecol.0, source.linecol.1, source.text
            ),
            None => write!(f, "{}", self.err_type),
        }
    }
}

// Implementing Display and deriving Debug implements
// error::Error with default behavior by declaring this empty
// implementation.
impl core::error::Error for CompileError {}

impl From<CompileErrorType> for CompileError {
    fn from(value: CompileErrorType) -> Self {
        CompileError::new(value)
    }
}

impl From<Bug> for CompileError {
    fn from(bug: Bug) -> Self {
        CompileError::new(CompileErrorType::Bug(bug))
    }
}
