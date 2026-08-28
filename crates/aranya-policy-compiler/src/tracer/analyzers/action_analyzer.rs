use aranya_policy_module::{Instruction, ModuleV0, WrapType};

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::TraceError;

/// Ensures that each branch does one of the following:
/// - publishes a command
/// - returns an `Err`
/// - calls another action. This allows actions do delegate publishing to other actions.
#[derive(Clone, Default)]
pub struct ActionAnalyzer {
    have_publish: bool,
    call_depth: usize,
}

impl ActionAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Analyzer for ActionAnalyzer {
    fn analyze_instruction(
        &mut self,
        pc: usize,
        i: &Instruction,
        m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError> {
        match i {
            Instruction::Publish => self.have_publish = true,
            Instruction::Call(_) => {
                self.call_depth = self.call_depth.saturating_add(1);
            }
            Instruction::Return => {
                if self.call_depth > 0 {
                    // Returning from a callee, not from the action itself. A
                    // nested action's `publish` still counts for the caller.
                    self.call_depth = self.call_depth.saturating_sub(1);
                    return Ok(AnalyzerStatus::Ok);
                }
                // If bailing with Err, don't need publish; if returning with
                // Ok, should have published.
                if !self.have_publish && !returns_err(pc, m) {
                    return Ok(AnalyzerStatus::Failed("no publish".to_string()));
                }
            }
            _ => (),
        }
        Ok(AnalyzerStatus::Ok)
    }
}

/// True if the `Return` at `pc` returns an `Err`.
///
/// An explicit return pushes the returned value, then restores the stack pointer, so the
/// wrap which made it an `Err` sits two instructions back. A `Return` not preceded by
/// `RestoreSP` is the implicit one at the end of an action, which returns nothing.
fn returns_err(pc: usize, m: &ModuleV0) -> bool {
    let Some(restore_pc) = pc.checked_sub(1) else {
        return false;
    };
    if !matches!(m.progmem.get(restore_pc), Some(Instruction::RestoreSP)) {
        return false;
    }
    let Some(wrap_pc) = restore_pc.checked_sub(1) else {
        return false;
    };
    matches!(
        m.progmem.get(wrap_pc),
        Some(Instruction::Wrap(WrapType::Err))
    )
}
