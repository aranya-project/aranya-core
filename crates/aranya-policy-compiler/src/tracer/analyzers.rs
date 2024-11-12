mod finish_analyzer;
mod function_analyzer;
mod value_analyzer;

use aranya_policy_module::{Instruction, ModuleV0};
pub use finish_analyzer::*;
pub use function_analyzer::*;
pub use value_analyzer::*;

use super::{TraceError, TraceFailure};

// Workaround for not being able to clone `Box<dyn T>`. See
// https://stackoverflow.com/questions/30353462/how-to-clone-a-struct-storing-a-boxed-trait-object/30353928#30353928
pub trait AnalyzerClone {
    fn clone_box(&self) -> Box<dyn Analyzer>;
}

impl<T> AnalyzerClone for T
where
    T: 'static + Analyzer + Clone,
{
    fn clone_box(&self) -> Box<dyn Analyzer> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn Analyzer> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

pub trait Analyzer: AnalyzerClone {
    /// Optionally initialize the analyzer using some information from the compile target.
    fn init(&mut self, _ct: &ModuleV0) {}

    /// Analyzes the current instruction. This may modify its own internal state, modify the
    /// `reqs` reference, and optionally return a string describing a failure at the current
    /// PC.
    fn analyze_instruction(
        &mut self,
        pc: usize,
        i: &Instruction,
        m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError>;

    /// Optionally post-analyze any produced failures using branch information.
    fn post_analyze(
        &mut self,
        _failures: &mut [TraceFailure],
        _successful_branches: &[Vec<usize>],
    ) {
    }
}

/// Status returned from analyzers
#[derive(Debug)]
pub enum AnalyzerStatus {
    /// Analysis proceeding normally.
    Ok,
    /// An error has been detected, but analysis should continue.
    Failed(String),
    /// An error has been detected, and analysis should not continue along this path.
    Halted(String),
}

impl AnalyzerStatus {
    /// Convenience constructor for [`AnalyzerStatus::Failed`].
    pub fn fail(s: &str) -> AnalyzerStatus {
        AnalyzerStatus::Failed(s.to_string())
    }

    /// Convenience constructor for [`AnalyzerStatus::Halted`].
    pub fn halt(s: &str) -> AnalyzerStatus {
        AnalyzerStatus::Halted(s.to_string())
    }
}
