use aranya_policy_module::{Instruction, LabelType, Meta, ModuleV0, Target};

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::TraceError;

/// Ensures that each branch does one of the following:
/// - publishes a command
/// - returns an `Err`
/// - calls another action. This allows actions to delegate publishing to other actions.
#[derive(Clone, Default)]
pub struct ActionAnalyzer {
    // Set if action meets criteria
    satisfied: bool,
    call_depth: usize,
    // Set if the next `Return` returns an `Err`
    returning_err: bool,
}

impl ActionAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Analyzer for ActionAnalyzer {
    fn analyze_instruction(
        &mut self,
        _pc: usize,
        i: &Instruction,
        m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError> {
        match i {
            Instruction::Publish => self.satisfied = true,
            Instruction::Call(c) => {
                self.call_depth = self.call_depth.saturating_add(1);
                // Calling another action is enough; since each action must
                // publish or call another, this guarantees a publish eventually.
                if calls_action(c, m) {
                    self.satisfied = true;
                }
            }
            Instruction::Meta(Meta::ReturnErr) => self.returning_err = true,
            Instruction::Return => {
                let returning_err = core::mem::take(&mut self.returning_err);
                if self.call_depth > 0 {
                    // Returning from a callee, not from the action itself. A
                    // nested action's `publish` still counts for the caller.
                    self.call_depth = self.call_depth.saturating_sub(1);
                    return Ok(AnalyzerStatus::Ok);
                }
                // If bailing with Err, don't need publish; otherwise, should
                // have published.
                if !self.satisfied && !returning_err {
                    return Ok(AnalyzerStatus::Failed("no publish".to_string()));
                }
            }
            _ => (),
        }
        Ok(AnalyzerStatus::Ok)
    }
}

/// True if `target` is the entry point of an action.
fn calls_action(target: &Target, m: &ModuleV0) -> bool {
    match target {
        Target::Unresolved(l) => l.ltype == LabelType::Action,
        Target::Resolved(addr) => m
            .labels
            .iter()
            .any(|(l, a)| a == addr && l.ltype == LabelType::Action),
    }
}
