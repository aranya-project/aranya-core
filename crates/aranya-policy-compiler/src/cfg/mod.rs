//! Control flow graph construction and dataflow analyses.

mod graph;
mod unused;

pub use graph::{Cfg, CfgBlock, CfgEdge};
pub use unused::{UnusedVarDiagnostic, unused_vars};
