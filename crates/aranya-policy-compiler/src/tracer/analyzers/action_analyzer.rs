use aranya_policy_module::{Instruction, ModuleV0};

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::{TraceError, TraceFailure};

/// Ensures that all branches publish a command.
/// The check is done in `post_analyze`, after we've visited all branches. So we don't need `analyze_instruction`.

#[derive(Clone, Default)]
pub struct ActionAnalyzer;

impl ActionAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for ActionAnalyzer {
    fn analyze_instruction(
        &mut self,
        _pc: usize,
        _i: &Instruction,
        _m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError> {
        Ok(AnalyzerStatus::Ok)
    }

    fn post_analyze(
        &mut self,
        _failures: &mut [TraceFailure],
        _successful_branches: &[Vec<usize>],
        successful_instruction_paths: &[Vec<usize>],
        m: &ModuleV0,
    ) -> Vec<TraceFailure> {
        // Check each successful path to ensure it has a Publish before Return/Exit
        successful_instruction_paths
            .iter()
            .filter_map(|path| {
                let mut have_publish = false;
                let mut call_depth: usize = 0;

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
                            } else {
                                // Returning from the top-level action
                                if !have_publish {
                                    return Some(TraceFailure {
                                        instruction_path: path.clone(),
                                        responsible_instruction: pc,
                                        message: "no publish".to_string(),
                                    });
                                }
                            }
                        }
                        Instruction::Exit(_) => {
                            // Exiting the action
                            if !have_publish {
                                return Some(TraceFailure {
                                    instruction_path: path.clone(),
                                    responsible_instruction: pc,
                                    message: "no publish".to_string(),
                                });
                            }
                        }
                        Instruction::Publish => {
                            if call_depth == 0 {
                                have_publish = true;
                            }
                        }
                        _ => {}
                    }
                }
                None
            })
            .collect()
    }
}
