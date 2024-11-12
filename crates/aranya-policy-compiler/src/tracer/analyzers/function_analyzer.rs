use aranya_policy_module::{Instruction, ModuleV0};

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::TraceError;

/// Ensures that all function branches return a value.
#[derive(Clone, Default)]
pub struct FunctionAnalyzer {
    have_return: bool,
}

impl FunctionAnalyzer {
    pub fn new() -> FunctionAnalyzer {
        FunctionAnalyzer::default()
    }
}

impl Analyzer for FunctionAnalyzer {
    fn analyze_instruction(
        &mut self,
        _pc: usize,
        i: &Instruction,
        _m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError> {
        match i {
            Instruction::Return => self.have_return = true,
            Instruction::Exit(_) => {
                if !self.have_return {
                    // Branches without returns are potential errors; it depends on whether there is a return following the branch.
                    return Ok(AnalyzerStatus::Failed("no return".to_string()));
                }
            }
            _ => (),
        }
        Ok(AnalyzerStatus::Ok)
    }
}
