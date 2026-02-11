use aranya_policy_module::{ExitReason, Instruction, Meta, ModuleV0};

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::{TraceError, TraceIssue};

/// Ensures that all branches enter a finish block before exiting.
#[derive(Clone, Default)]
pub struct FinishAnalyzer {
    finish: bool,
}

impl FinishAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Analyzer for FinishAnalyzer {
    fn analyze_instruction(
        &mut self,
        _pc: usize,
        i: &Instruction,
        _m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError> {
        match i {
            Instruction::Meta(Meta::Finish(s)) => {
                self.finish = *s;
            }
            Instruction::Exit(ExitReason::Normal) => {
                if !self.finish {
                    return Ok(AnalyzerStatus::fail("Exit without Finish"));
                }
            }
            _ => (),
        }
        Ok(AnalyzerStatus::Ok)
    }

    /// This attempts to find the branch point where we veered onto the failure path. It
    /// compares each failure's execution trace with the list of successful branches to find
    /// the last common address. This last common ancestor should be the point at which the
    /// decision was made to go down a path that did not have a finish block.
    fn post_analyze(&mut self, failures: &mut [TraceIssue], successful_branches: &[Vec<usize>]) {
        for f in failures {
            let mut longest_common_path = 0;
            let mut last_addr = None;
            for sb in successful_branches {
                let mut len: usize = 0;
                let mut subseq_addr = 0;
                for (i, addr) in sb.iter().enumerate() {
                    if !f.instruction_path.iter().any(|i| i == addr) {
                        break;
                    }
                    len = i.saturating_add(1);
                    subseq_addr = *addr;
                }
                if len > longest_common_path {
                    longest_common_path = len;
                    last_addr = Some(subseq_addr);
                }
            }
            if let Some(la) = last_addr {
                f.responsible_instruction = la;
            }
            // If we didn't find a longest common path, something weird must be going on,
            // and we leave the TraceFailure as-is.
        }
    }
}
