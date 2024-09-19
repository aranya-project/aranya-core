use std::collections::BTreeSet;

use policy_module::{Instruction, Meta, ModuleV0};

use super::{Analyzer, AnalyzerStatus};
use crate::tracer::TraceError;

/// Ensures that all values that are read have first been defined.
#[derive(Clone)]
pub struct ValueAnalyzer {
    globals: BTreeSet<String>,
    value_sets: Vec<BTreeSet<String>>,
}

impl ValueAnalyzer {
    /// `predefined` is a list of words that are understood to have been defined before
    /// execution starts. Usually used to add things like `this` or global values.
    pub fn new(
        globals: impl IntoIterator<Item = String>,
        predefined: impl IntoIterator<Item = String>,
    ) -> ValueAnalyzer {
        let initial_set = predefined.into_iter().collect();
        ValueAnalyzer {
            globals: globals.into_iter().collect(),
            value_sets: vec![initial_set],
        }
    }

    fn contains(&self, name: &str) -> bool {
        let current_set = self.value_sets.last().expect("no current value set");
        current_set.contains(name) || self.globals.contains(name)
    }

    fn insert(&mut self, name: &str) -> bool {
        self.value_sets
            .last_mut()
            .expect("no current value set")
            .insert(name.to_string())
    }
}

impl Analyzer for ValueAnalyzer {
    fn analyze_instruction(
        &mut self,
        _pc: usize,
        i: &Instruction,
        _m: &ModuleV0,
    ) -> Result<AnalyzerStatus, TraceError> {
        match i {
            Instruction::Call(_) => {
                self.value_sets.push(BTreeSet::new());
            }
            Instruction::Return => {
                self.value_sets.pop();
            }
            Instruction::Meta(Meta::Let(s)) => {
                if !self.insert(s) {
                    return Ok(AnalyzerStatus::Failed(format!("Value `{s}` is set twice")));
                }
            }
            Instruction::Meta(Meta::Get(s)) => {
                if !self.contains(s) {
                    return Ok(AnalyzerStatus::Failed(format!("Value `{s}` is not set")));
                }
            }
            _ => (),
        }
        Ok(AnalyzerStatus::Ok)
    }
}
