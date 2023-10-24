use core::fmt;

use cfg_if::cfg_if;

use crate::io::MachineIOError;

cfg_if! {
    if #[cfg(feature = "std")] {
        use std::error;
    } else if #[cfg(feature = "error_in_core")] {
        use core::error;
    }
}

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
    /// that was already defined.
    AlreadyDefined,
    /// Name not defined - an attempt was made to access a name that
    /// has not been defined.
    NotDefined,
    /// Invalid type - An operation was given a value of the wrong
    /// type. E.g. addition with strings.
    InvalidType,
    /// Invalid struct - An attempt to access a member not present in a
    /// struct, or an attempt to emit a Command struct that does not
    /// match its definition.
    InvalidStruct,
    /// Invalid fact - An attempt was made to access a fact in a way
    /// that does not match the Fact schema.
    InvalidFact,
    /// Unresolved target - A branching instruction attempted to jump
    /// to a target whose address has not yet been resolved.
    UnresolvedTarget,
    /// Invalid address - An attempt to execute an instruction went
    /// beyond instruction bounds, or an action/command lookup did not
    /// find an address for the given name.
    InvalidAddress,
    /// Bad state - Some internal state is invalid and execution cannot
    /// continue.
    BadState,
    /// IntegerOverflow occurs when an instruction wraps an integer above
    /// the max value or below the min value.
    IntegerOverflow,
    /// IO Error - Some machine I/O operation caused an error
    IO(MachineIOError),
    /// Unknown - every other possible problem
    Unknown,
}

impl fmt::Display for MachineErrorType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MachineErrorType::StackUnderflow => write!(f, "stack underflow"),
            MachineErrorType::StackOverflow => write!(f, "stack overflow"),
            MachineErrorType::AlreadyDefined => write!(f, "name already defined"),
            MachineErrorType::NotDefined => write!(f, "name not defined"),
            MachineErrorType::InvalidType => write!(f, "invalid type for operation"),
            MachineErrorType::InvalidStruct => write!(f, "invalid struct"),
            MachineErrorType::InvalidFact => write!(f, "invalid fact"),
            MachineErrorType::UnresolvedTarget => write!(f, "unresolved branch/jump target"),
            MachineErrorType::InvalidAddress => write!(f, "invalid address"),
            MachineErrorType::BadState => write!(f, "Bad state"),
            MachineErrorType::IntegerOverflow => write!(f, "integer wrap"),
            MachineErrorType::IO(e) => write!(f, "IO: {}", e),
            MachineErrorType::Unknown => write!(f, "unknown error"),
        }
    }
}

/// An error returned by [`Machine`][crate::machine::Machine].
#[derive(Debug, PartialEq)]
pub struct MachineError {
    /// The type of the error
    pub err_type: MachineErrorType,
    /// The line and column of the error, if it exists
    instruction: Option<usize>,
}

impl MachineError {
    /// Creates a `MachineError`.
    pub fn new(err_type: MachineErrorType) -> MachineError {
        MachineError {
            err_type,
            instruction: None,
        }
    }

    pub(crate) fn new_with_position(err_type: MachineErrorType, pc: usize) -> MachineError {
        MachineError {
            err_type,
            instruction: Some(pc),
        }
    }
}

impl fmt::Display for MachineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.instruction {
            Some(pc) => write!(f, "{} at PC {}", self.err_type, pc),
            None => write!(f, "{}", self.err_type),
        }
    }
}

// Implementing Display and deriving Debug implements
// error::Error with default behavior by declaring this empty
// implementation.
#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for MachineError {}

impl From<MachineErrorType> for MachineError {
    fn from(value: MachineErrorType) -> Self {
        MachineError::new(value)
    }
}
