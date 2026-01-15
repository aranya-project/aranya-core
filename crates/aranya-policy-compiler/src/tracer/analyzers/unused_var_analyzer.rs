use aranya_policy_ast::{Identifier, ident};
use aranya_policy_module::{Instruction, ModuleV0};
use indexmap::IndexSet;

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::TraceError;

/// Ensures that all defined variables are used.
#[derive(Clone)]
pub struct UnusedVarAnalyzer {
    /// Stack of scopes, each containing variables that must be used (created by Def)
    scope_stack: Vec<IndexSet<Identifier>>,
    /// Predefined variables that are allowed to be unused (like 'this' and 'envelope')
    predefined_vars: IndexSet<Identifier>,
}

impl Default for UnusedVarAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl UnusedVarAnalyzer {
    pub fn new() -> Self {
        let mut predefined_vars = IndexSet::new();
        predefined_vars.insert(ident!("this"));
        predefined_vars.insert(ident!("envelope"));

        Self {
            scope_stack: vec![IndexSet::new()],
            predefined_vars,
        }
    }

    /// Get the current scope (the top of the stack)
    fn current_scope(&mut self) -> &mut IndexSet<Identifier> {
        self.scope_stack
            .last_mut()
            .expect("scope stack should never be empty")
    }

    /// Remove a variable from all scopes (searching from innermost to outermost)
    fn remove_from_scopes(&mut self, ident: &Identifier) {
        for scope in self.scope_stack.iter_mut().rev() {
            if scope.shift_remove(ident) {
                return;
            }
        }
    }
}

impl Analyzer for UnusedVarAnalyzer {
    fn analyze_instruction(
        &mut self,
        _pc: usize,
        i: &Instruction,
        _m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError> {
        match i {
            // Push a new scope
            Instruction::Block => {
                self.scope_stack.push(IndexSet::new());
            }

            // Pop scope and check for unused variables in that scope
            Instruction::End => {
                let Some(scope) = self.scope_stack.pop() else {
                    return Ok(AnalyzerStatus::Ok);
                };
                if !scope.is_empty() {
                    return Ok(AnalyzerStatus::Failed(format!(
                        "unused variable(s): `{}`",
                        scope
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<_>>()
                            .join("`, `")
                    )));
                }
            }

            // Def creates a must-use obligation (unless it's a predefined variable)
            Instruction::Def(ident) => {
                if !self.predefined_vars.contains(ident) {
                    self.current_scope().insert(ident.clone());
                }
            }

            // Get satisfies the must-use obligation (searching from innermost scope outward)
            Instruction::Get(ident) => {
                self.remove_from_scopes(ident);
            }

            // At function exit points, check that all obligations in all scopes are satisfied
            Instruction::Return | Instruction::Exit(_) => {
                for scope in &self.scope_stack {
                    if let Some(var) = scope.iter().next() {
                        return Ok(AnalyzerStatus::Failed(format!(
                            "unused variable: `{}`",
                            var
                        )));
                    }
                }
            }
            _ => {}
        }

        Ok(AnalyzerStatus::Ok)
    }
}
