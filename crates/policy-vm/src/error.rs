extern crate alloc;

use alloc::{borrow::ToOwned, string::String};
use core::{convert::Infallible, fmt};

use buggy::Bug;
use policy_module::{CodeMap, ValueConversionError};

use crate::io::MachineIOError;

/// Possible machine errors.
// TODO(chip): These should be elaborated with additional data, and/or
// more fine grained types.
#[derive(Debug, PartialEq)]
pub enum MachineErrorType {
    /// Stack underflow - an operation tried to consume a value from an
    /// empty stack.
    StackUnderflow,
    /// Stack overflow - an operation tried to push a value onto a full
    /// stack. N.B. that there are currently no size limits on the
    /// stack, so this cannot be reached.
    StackOverflow,
    /// Name already defined - an attempt was made to define a name
    /// that was already defined. Parameter is the name.
    AlreadyDefined(String),
    /// Name not defined - an attempt was made to access a name that
    /// has not been defined. Parameter is the name.
    NotDefined(String),
    /// Invalid type - An operation was given a value of the wrong
    /// type. E.g. addition with strings.
    InvalidType,
    /// Invalid struct member - An attempt to access a member not
    /// present in a struct. Parameter is the key name.
    InvalidStructMember(String),
    /// Invalid fact - An attempt was made to use a fact in a way
    /// that does not match the Fact schema.
    InvalidFact,
    /// Invalid schema - An attempt to publish a Command struct or emit
    /// an Effect that does not match its definition.
    InvalidSchema,
    /// Unresolved target - A branching instruction attempted to jump
    /// to a target whose address has not yet been resolved.
    UnresolvedTarget,
    /// Invalid address - An attempt to execute an instruction went
    /// beyond instruction bounds, or an action/command lookup did not
    /// find an address for the given name.
    InvalidAddress(String),
    /// Bad state - Some internal state is invalid and execution cannot
    /// continue.
    BadState,
    /// IntegerOverflow occurs when an instruction wraps an integer above
    /// the max value or below the min value.
    IntegerOverflow,
    /// Invalid instruction - An instruction was used in the wrong
    /// context, or some information encoded into an instruction is
    /// invalid. E.g. a Swap(0)
    InvalidInstruction,
    /// An instruction has done something wrong with the call stack, like
    /// `Return`ed without a `Call`.
    CallStack,
    /// IO Error - Some machine I/O operation caused an error
    IO(MachineIOError),
    /// FFI module name not found.
    FfiModuleNotDefined(usize),
    /// FFI module was found, but the procedure index is invalid.
    FfiProcedureNotDefined(String, usize),
    /// An implementation bug
    Bug(Bug),
    /// Unknown - every other possible problem
    Unknown(String),
}

impl fmt::Display for MachineErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachineErrorType::StackUnderflow => write!(f, "stack underflow"),
            MachineErrorType::StackOverflow => write!(f, "stack overflow"),
            MachineErrorType::AlreadyDefined(s) => write!(f, "name `{}` already defined", s),
            MachineErrorType::NotDefined(s) => write!(f, "name `{}` not defined", s),
            MachineErrorType::InvalidType => write!(f, "invalid type for operation"),
            MachineErrorType::InvalidStructMember(k) => write!(f, "invalid struct member `{}`", k),
            MachineErrorType::InvalidFact => write!(f, "invalid fact"),
            MachineErrorType::InvalidSchema => write!(f, "invalid schema"),
            MachineErrorType::UnresolvedTarget => write!(f, "unresolved branch/jump target"),
            MachineErrorType::InvalidAddress(label) => write!(f, "invalid address: {}", label),
            MachineErrorType::BadState => write!(f, "Bad state"),
            MachineErrorType::IntegerOverflow => write!(f, "integer wrap"),
            MachineErrorType::InvalidInstruction => write!(f, "bad state"),
            MachineErrorType::CallStack => write!(f, "call stack"),
            MachineErrorType::IO(e) => write!(f, "IO: {}", e),
            MachineErrorType::FfiModuleNotDefined(module) => {
                write!(f, "FFI module not defined: {}", module)
            }
            MachineErrorType::FfiProcedureNotDefined(module, proc) => {
                write!(f, "FFI proc {} not defined in module {}", proc, module)
            }
            MachineErrorType::Bug(bug) => write!(f, "Bug: {}", bug),
            MachineErrorType::Unknown(reason) => write!(f, "unknown error: {}", reason),
        }
    }
}

impl trouble::Error for MachineErrorType {}

impl From<Infallible> for MachineErrorType {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

impl From<ValueConversionError> for MachineErrorType {
    fn from(value: ValueConversionError) -> Self {
        match value {
            ValueConversionError::InvalidType => MachineErrorType::InvalidType,
            ValueConversionError::InvalidStructMember(s) => {
                MachineErrorType::InvalidStructMember(s)
            }
            ValueConversionError::OutOfRange => MachineErrorType::InvalidType,
            ValueConversionError::BadState => MachineErrorType::BadState,
        }
    }
}

/// The source location and text of an error
#[derive(Debug, PartialEq)]
struct MachineErrorSource {
    /// Line and column of where the error is
    linecol: (usize, usize),
    /// The text of the error
    text: String,
}

/// An error returned by [`Machine`][crate::machine::Machine].
#[derive(Debug, PartialEq)]
pub struct MachineError {
    /// The type of the error
    pub err_type: MachineErrorType,
    /// The source code information, if it exists
    source: Option<MachineErrorSource>,
}

impl MachineError {
    /// Creates a `MachineError`.
    pub fn new(err_type: MachineErrorType) -> MachineError {
        MachineError {
            err_type,
            source: None,
        }
    }

    pub(crate) fn from_position(
        err_type: MachineErrorType,
        pc: usize,
        codemap: Option<&CodeMap>,
    ) -> Self {
        Self {
            err_type,
            source: None,
        }
        .with_position(pc, codemap)
    }

    pub(crate) fn with_position(mut self, pc: usize, codemap: Option<&CodeMap>) -> Self {
        if self.source.is_none() {
            if let Some(codemap) = codemap {
                self.source =
                    codemap
                        .span_from_instruction(pc)
                        .ok()
                        .map(|span| MachineErrorSource {
                            linecol: span.start_linecol(),
                            text: span.as_str().to_owned(),
                        });
            }
        }
        self
    }
}

impl fmt::Display for MachineError {
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
impl trouble::Error for MachineError {}

impl From<MachineErrorType> for MachineError {
    fn from(value: MachineErrorType) -> Self {
        MachineError::new(value)
    }
}

impl From<Infallible> for MachineError {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

impl From<Bug> for MachineError {
    fn from(bug: Bug) -> Self {
        MachineError::new(MachineErrorType::Bug(bug))
    }
}
