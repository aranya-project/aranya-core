use aranya_policy_module::{Instruction, Meta, ModuleV0};

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::{TraceError, TraceFailure};

/// Ensures that all function branches return a value.
#[derive(Clone, Default)]
pub struct FunctionAnalyzer {
    have_return: bool,
}

impl FunctionAnalyzer {
    pub fn new() -> Self {
        Self::default()
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
            Instruction::Return => {
                self.have_return = true;
            }
            Instruction::Meta(Meta::FunctionEnd) => {
                // Check for missing return only at the function end marker
                if !self.have_return {
                    return Ok(AnalyzerStatus::Failed("no return".to_string()));
                }
            }
            _ => {}
        }
        Ok(AnalyzerStatus::Ok)
    }

    fn post_analyze(
        &mut self,
        _failures: &mut [TraceFailure],
        _successful_branches: &[Vec<usize>],
        successful_instruction_paths: &[Vec<usize>],
        m: &ModuleV0,
    ) -> Vec<TraceFailure> {
        use std::collections::{HashMap, HashSet};

        // Path-based unreachable code detection
        // For each PC, track which paths reach it before vs after a return
        let mut pc_before_return: HashMap<usize, usize> = HashMap::new();
        let mut pc_after_return: HashMap<usize, usize> = HashMap::new();

        for path in successful_instruction_paths {
            let mut found_return = false;
            let mut call_depth: usize = 0;

            for &pc in path.iter().take_while(|&&pc| {
                !matches!(
                    m.progmem.get(pc),
                    Some(Instruction::Meta(Meta::FunctionEnd))
                )
            }) {
                let instruction = m
                    .progmem
                    .get(pc)
                    .expect("PC should be valid in successful path");

                // Track call depth to distinguish between returns in the current function
                // vs returns in nested function calls
                match instruction {
                    Instruction::Call(_) => {
                        call_depth += 1;
                        continue;
                    }
                    Instruction::Return => {
                        if call_depth > 0 {
                            call_depth = call_depth.saturating_sub(1);
                        } else {
                            found_return = true;
                        }
                        continue;
                    }
                    _ => {}
                }

                // Skip control flow and metadata instructions so we don't track them as unreachable
                if matches!(
                    instruction,
                    Instruction::Block
                        | Instruction::End
                        | Instruction::Branch(_)
                        | Instruction::Jump(_)
                        | Instruction::Next
                        | Instruction::Last
                        | Instruction::Meta(_)
                ) {
                    continue;
                }

                if found_return {
                    pc_after_return
                        .entry(pc)
                        .and_modify(|count| *count = count.saturating_add(1))
                        .or_insert(1);
                } else {
                    pc_before_return
                        .entry(pc)
                        .and_modify(|count| *count = count.saturating_add(1))
                        .or_insert(1);
                }
            }
        }

        // A PC is unreachable if it's only ever reached after a return,
        // never before a return in any path.
        let unreachable_pcs: HashSet<usize> = pc_after_return
            .keys()
            .filter(|&pc| !pc_before_return.contains_key(pc))
            .copied()
            .collect();

        // Create failures for unreachable PCs
        successful_instruction_paths
            .iter()
            .filter_map(|path| {
                // Find the first unreachable PC in this path (if any)
                path.iter()
                    .find(|&&pc| unreachable_pcs.contains(&pc))
                    .map(|&pc| TraceFailure {
                        instruction_path: path.clone(),
                        responsible_instruction: pc,
                        message: "unreachable code".to_string(),
                    })
            })
            .collect()
    }
}
