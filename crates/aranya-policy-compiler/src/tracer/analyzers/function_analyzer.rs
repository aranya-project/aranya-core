use aranya_policy_module::{Instruction, ModuleV0};

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::{TraceError, TraceFailure};

/// Ensures that all function branches return a value.
#[derive(Clone, Default)]
pub struct FunctionAnalyzer {
    have_return: bool,
    unreachable_code: bool,
    first_unreachable_pc: Option<usize>,
}

impl FunctionAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Analyzer for FunctionAnalyzer {
    fn analyze_instruction(
        &mut self,
        pc: usize,
        i: &Instruction,
        _m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError> {
        match i {
            Instruction::Return => {
                self.have_return = true;
            }
            Instruction::Exit(_) => {
                if !self.have_return {
                    // Branches without returns are potential errors; it depends on whether there is a return following the branch.
                    return Ok(AnalyzerStatus::Failed("no return".to_string()));
                }
                if self.unreachable_code {
                    return Ok(AnalyzerStatus::Failed("unreachable code".to_string()));
                }
            }
            _ => {
                if self.have_return && !self.unreachable_code {
                    self.unreachable_code = true;
                    self.first_unreachable_pc = Some(pc);
                }
            }
        }
        Ok(AnalyzerStatus::Ok)
    }

    fn post_analyze(&mut self, failures: &mut [TraceFailure], _successful_branches: &[Vec<usize>]) {
        // Update the responsible_instruction for unreachable code failures
        // to point to the first unreachable instruction instead of the Exit
        if let Some(first_pc) = self.first_unreachable_pc {
            for failure in failures.iter_mut() {
                if failure.message == "unreachable code" {
                    failure.responsible_instruction = first_pc;
                }
            }
        }
    }
}
