extern crate alloc;

use alloc::{borrow::ToOwned, string::String};
use core::{convert::Infallible, fmt};

use aranya_policy_module::{CodeMap, Label, ValueConversionError};
use buggy::Bug;

use crate::io::MachineIOError;

/// Possible machine errors.
// TODO(chip): These should be elaborated with additional data, and/or more fine grained types.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum MachineErrorType {
    /// Stack underflow - an operation tried to consume a value from an empty stack.
    #[error("stack underflow")]
    StackUnderflow,
    /// Stack overflow - an operation tried to push a value onto a full stack.
    #[error("stack overflow")]
    StackOverflow,
    /// Name already defined - an attempt was made to define a name that was already defined.
    /// Parameter is the name.
    #[error("name `{0}` already defined")]
    AlreadyDefined(String),
    /// Name not defined - an attempt was made to access a name that has not been defined.
    /// Parameter is the name.
    #[error("name `{0}` not defined")]
    NotDefined(String),
    /// Invalid type - An operation was given a value of the wrong type, e.g. addition with
    /// strings.
    #[error("expected type {want}, but got {got}: {msg}")]
    InvalidType {
        /// Expected type name
        want: String,
        /// Received type name
        got: String,
        /// Extra information
        msg: String,
    },
    /// Invalid struct member - An attempt to access a member not present in a struct. Parameter is
    /// the key name.
    #[error("invalid struct member `{0}`")]
    InvalidStructMember(String),
    /// Invalid fact - An attempt to use a fact in a way that doesn't match the Fact schema.
    #[error("invalid fact: {0}")]
    InvalidFact(String),
    /// Invalid schema - An attempt to publish a Command struct or emit an Effect that does not
    /// match its definition.
    #[error("invalid schema: {0}")]
    InvalidSchema(String),
    /// Unresolved target - A branching instruction attempted to jump to a target whose address has
    /// not yet been resolved.
    #[error("unresolved branch/jump target: {0}")]
    UnresolvedTarget(Label),
    /// Invalid address - An attempt to execute an instruction went beyond instruction bounds, or
    /// an action/command lookup did not find an address for the given name.
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    /// Bad state - Some internal state is invalid and execution cannot continue.
    #[error("bad state: {0}")]
    BadState(&'static str),
    /// IntegerOverflow occurs when an instruction wraps an integer above the max value or below
    /// the min value.
    #[error("integer wrap")]
    IntegerOverflow,
    /// Invalid instruction - An instruction was used in the wrong context, or some information
    /// encoded into an instruction is invalid, e.g. a Swap(0)
    #[error("invalid instruction")]
    InvalidInstruction,
    /// An instruction has done something bad with the call stack, like `Return`ed without a
    /// `Call`.
    #[error("call stack")]
    CallStack,
    /// IO Error - Some machine I/O operation caused an error
    #[error("IO: {0}")]
    IO(MachineIOError),
    /// FFI module name not found.
    #[error("FFI module not defined: {0}")]
    FfiModuleNotDefined(usize),
    /// FFI module was found, but the procedure index is invalid.
    #[error("FFI proc {0} not defined in module {1}")]
    FfiProcedureNotDefined(String, usize),
    /// An implementation bug
    #[error("bug: {0}")]
    Bug(Bug),
    /// Unknown - every other possible problem
    #[error("unknown error: {0}")]
    Unknown(String),
}

impl MachineErrorType {
    /// Constructs an `InvalidType` error
    pub fn invalid_type(
        want: impl Into<String>,
        got: impl Into<String>,
        msg: impl Into<String>,
    ) -> Self {
        Self::InvalidType {
            want: want.into(),
            got: got.into(),
            msg: msg.into(),
        }
    }
}

impl From<Infallible> for MachineErrorType {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

impl From<ValueConversionError> for MachineErrorType {
    fn from(value: ValueConversionError) -> Self {
        match value {
            ValueConversionError::InvalidType { want, got, msg } => {
                MachineErrorType::InvalidType { want, got, msg }
            }
            ValueConversionError::InvalidStructMember(s) => {
                MachineErrorType::InvalidStructMember(s)
            }
            ValueConversionError::OutOfRange => MachineErrorType::InvalidType {
                want: "Int".to_owned(),
                got: "Int".to_owned(),
                msg: "out of range".to_owned(),
            },
            ValueConversionError::BadState => MachineErrorType::BadState("value conversion error"),
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
#[derive(Debug, PartialEq, thiserror::Error)]
pub struct MachineError {
    /// The type of the error
    #[source]
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
