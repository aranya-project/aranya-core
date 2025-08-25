use core::fmt;

use aranya_policy_ast::Identifier;
use serde::{Deserialize, Serialize};

/// Compiler Tracer metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Meta {
    /// A variable has been defined
    Let(Identifier),
    /// A varible has been retrieved
    Get(Identifier),
    /// Set finish state
    Finish(bool),
    /// Mark an FFI call (module name, procedure name)
    FFI(Identifier, Identifier),
}

impl fmt::Display for Meta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Let(n) => write!(f, "Set `{n}`"),
            Self::Get(n) => write!(f, "Get `{n}`"),
            Self::Finish(b) => {
                if *b {
                    write!(f, "finish enabled")
                } else {
                    write!(f, "finish disabled")
                }
            }
            Self::FFI(module, procedure) => write!(f, "FFI call `{module}.{procedure}"),
        }
    }
}
