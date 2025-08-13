use aranya_policy_module::{Instruction, ModuleV0};

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::TraceError;

/// Ensures that all branches publish a command.
#[derive(Clone, Default)]
pub struct ActionAnalyzer {
    have_publish: bool,
}

impl ActionAnalyzer {
    pub fn new() -> ActionAnalyzer {
        ActionAnalyzer::default()
    }
}

impl Analyzer for ActionAnalyzer {
    fn analyze_instruction(
        &mut self,
        _pc: usize,
        i: &Instruction,
        _m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError> {
        match i {
            Instruction::Publish => self.have_publish = true,
            Instruction::Return => {
                if !self.have_publish {
                    return Ok(AnalyzerStatus::Failed("no publish".to_string()));
                }
            }
            _ => (),
        }
        Ok(AnalyzerStatus::Ok)
    }
}
