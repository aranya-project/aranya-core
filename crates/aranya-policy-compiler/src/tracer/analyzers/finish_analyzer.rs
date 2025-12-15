use aranya_policy_module::{ExitReason, Instruction, Meta, ModuleV0};

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::{TraceError, TraceFailure};

/// Ensures that all branches enter a finish block before exiting.
#[derive(Clone, Default)]
pub struct FinishAnalyzer;

impl FinishAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for FinishAnalyzer {
    fn analyze_instruction(
        &mut self,
        _pc: usize,
        _i: &Instruction,
        _m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError> {
        Ok(AnalyzerStatus::Ok)
    }

    /// Checks each successful path to ensure it enters a finish block before exiting.
    /// Also attempts to find the branch point where we veered onto the failure path.
    fn post_analyze(
        &mut self,
        failures: &mut [TraceFailure],
        successful_branches: &[Vec<usize>],
        successful_instruction_paths: &[Vec<usize>],
        m: &ModuleV0,
    ) -> Vec<TraceFailure> {
        // First, check each successful path for finish block requirement
        let new_failures: Vec<TraceFailure> = successful_instruction_paths
            .iter()
            .filter_map(|path| {
                let mut call_depth: usize = 0;
                let mut has_statements = false; // Does path have any statements? (Empty policy/recall blocks don't require finish.)
                let mut entered_finish = false;

                for &pc in path {
                    let instruction = m
                        .progmem
                        .get(pc)
                        .expect("PC should be valid in successful path");

                    match instruction {
                        Instruction::Call(_) => {
                            call_depth = call_depth.saturating_add(1);
                        }
                        Instruction::Return => {
                            if call_depth > 0 {
                                call_depth = call_depth.saturating_sub(1);
                            }
                        }
                        Instruction::Meta(Meta::Finish(in_finish)) => {
                            if call_depth == 0 && *in_finish {
                                entered_finish = true;
                            }
                        }
                        Instruction::Meta(Meta::FunctionEnd)
                        | Instruction::Exit(ExitReason::Normal) => {
                            // Empty blocks don't require finish blocks
                            if call_depth == 0 && !entered_finish && has_statements {
                                return Some(TraceFailure {
                                    instruction_path: path.clone(),
                                    responsible_instruction: pc,
                                    message: "Exit without Finish".to_string(),
                                });
                            }
                        }
                        // Track if we have any statements (not just metadata/control flow)
                        Instruction::Meta(_) | Instruction::Def(_) => {}
                        _ => {
                            if call_depth == 0 {
                                has_statements = true;
                            }
                        }
                    }
                }
                None
            })
            .collect();

        // For existing failures, find the branch point where we veered onto the failure path
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

        new_failures
    }
}
