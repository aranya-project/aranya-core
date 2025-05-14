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
            Meta::Let(n) => write!(f, "Set `{n}`"),
            Meta::Get(n) => write!(f, "Get `{n}`"),
            Meta::Finish(b) => {
                if *b {
                    write!(f, "finish enabled")
                } else {
                    write!(f, "finish disabled")
                }
            }
            Meta::FFI(module, procedure) => write!(f, "FFI call `{module}.{procedure}"),
        }
    }
}
