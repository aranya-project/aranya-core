use std::fmt;

use aranya_policy_module::Label;

pub enum TraceErrorType {
    BadLabel(Label),
    Bug, // TODO(chip) use actual Bug
}

impl fmt::Display for TraceErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLabel(l) => write!(f, "bad label: {l}"),
            Self::Bug => write!(f, "bug"),
        }
    }
}

pub struct TraceError {
    pub etype: TraceErrorType,
    pub instruction_path: Box<[usize]>,
}

impl TraceError {
    pub fn new(etype: TraceErrorType, instruction_path: Vec<usize>) -> Self {
        Self {
            etype,
            instruction_path: instruction_path.into(),
        }
    }
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, instruction trace: {:?}",
            self.etype, self.instruction_path
        )
    }
}
