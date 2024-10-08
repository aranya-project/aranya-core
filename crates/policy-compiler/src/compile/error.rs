use std::fmt;

use aranya_buggy::Bug;
use policy_ast as ast;
use policy_module::CodeMap;

use crate::compile::StatementContext;

/// Describes the call color in an [CompileErrorType::InvalidCallColor].
#[derive(Debug, PartialEq)]
pub enum CallColor {
    /// The call is a pure function
    Pure,
    /// The call is a finish function
    Finish,
}

/// Errors that can occur during compilation.
#[derive(Debug, PartialEq)]
pub enum CompileErrorType {
    /// Invalid statement - a statement was used in an invalid context.
    InvalidStatement(StatementContext),
    /// Invalid expression - the expression does not make sense in context.
    InvalidExpression(ast::Expression),
    /// Invalid type
    InvalidType(String),
    /// Invalid call color - Tried to make a function call to the wrong type of function.
    InvalidCallColor(CallColor),
    /// Resolution of branch targets failed to find a valid target
    BadTarget(String),
    /// An argument to a function or an item in an expression did not
    /// make sense
    BadArgument(String),
    /// A thing referenced is not defined
    NotDefined(String),
    /// A thing by that name has already been defined
    AlreadyDefined(String),
    /// A keyword collision occurs with that identifier
    ReservedIdentifier(String),
    /// Expected value was missing
    Missing(String),
    /// Fact literal doesn't match definition
    InvalidFactLiteral(String),
    /// A pure function has no return statement
    NoReturn,
    /// A validation step failed
    Validation,
    /// An implementation bug
    Bug(Bug),
    /// All other errors
    Unknown(String),
}

impl fmt::Display for CompileErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStatement(c) => write!(f, "Invalid statement in {} context", c),
            Self::InvalidExpression(e) => write!(f, "Invalid expression: {:?}", e),
            Self::InvalidType(s) => write!(f, "Invalid type: {}", s),
            Self::InvalidCallColor(cc) => match cc {
                CallColor::Pure => write!(f, "Pure function not allowed in finish context"),
                CallColor::Finish => write!(f, "Finish function not allowed in expression"),
            },
            Self::BadTarget(s) => write!(f, "Bad branch target: {}", s),
            Self::BadArgument(s) => write!(f, "Bad argument: {}", s),
            Self::NotDefined(s) => write!(f, "Not defined: {}", s),
            Self::AlreadyDefined(s) => write!(f, "Already defined: {}", s),
            Self::ReservedIdentifier(s) => write!(f, "Reserved identifier: {}", s),
            Self::Missing(s) => write!(f, "Missing: {}", s),
            Self::InvalidFactLiteral(s) => write!(f, "Fact literal does not match definition: {s}"),
            Self::NoReturn => write!(f, "Function has no return statement"),
            Self::Validation => write!(f, "Validation failed"),
            Self::Bug(bug) => write!(f, "Bug: {}", bug),
            Self::Unknown(s) => write!(f, "Unknown error: {}", s),
        }
    }
}

impl From<Bug> for CompileErrorType {
    fn from(value: Bug) -> Self {
        CompileErrorType::Bug(value)
    }
}

impl core::error::Error for CompileErrorType {}

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
