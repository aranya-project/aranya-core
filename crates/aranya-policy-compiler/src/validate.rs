use aranya_policy_ast::Identifier;
use aranya_policy_module::{LabelType, Module, ModuleData};

use crate::{
    ActionAnalyzer, FailureLevel, FinishAnalyzer, FunctionAnalyzer, TraceAnalyzerBuilder,
    UnusedVarAnalyzer, ValueAnalyzer,
};

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub num_warnings: usize,
    pub num_errors: usize,
}

impl ValidationResult {
    /// Returns true if there are no errors, and (if `include_warnings` is true) no warnings.
    pub fn is_valid(&self, include_warnings: bool) -> bool {
        self.num_errors == 0 && (!include_warnings || self.num_warnings == 0)
    }
}

/// Post-compilation validation. Ensure:
/// - action branches publish a command
/// - variables are assigned before use
/// - no unused variables
/// - all function code paths return values
/// - commands enter a finish block
pub fn validate(module: &Module) -> ValidationResult {
    let ModuleData::V0(ref m) = module.data;
    let mut result = ValidationResult {
        num_warnings: 0,
        num_errors: 0,
    };

    // Get all global variable names
    let global_names: Vec<Identifier> = m.globals.keys().cloned().collect();

    for l in m.labels.keys() {
        let mut tracer = TraceAnalyzerBuilder::new(m);
        match l.ltype {
            LabelType::Action => tracer = tracer.add_analyzer(ActionAnalyzer::new()),
            LabelType::CommandPolicy | LabelType::CommandRecall => {
                tracer = tracer.add_analyzer(FinishAnalyzer::new());
            }
            LabelType::CommandSeal | LabelType::CommandOpen => {
                // TODO: Add function analyzer once panics are handled correctly.
            }
            LabelType::Function => tracer = tracer.add_analyzer(FunctionAnalyzer::new()),
            LabelType::Temporary => unreachable!("Shouldn't have gotten this label type"),
        }
        let tracer = tracer
            .add_analyzer(ValueAnalyzer::new(global_names.clone()))
            .add_analyzer(UnusedVarAnalyzer::new());
        let tracer = tracer.build();

        match tracer.trace(l) {
            Ok(issues) => {
                for issue in issues {
                    let level = match issue.level {
                        FailureLevel::Warning => "warning",
                        FailureLevel::Error => "error",
                    };
                    print!("{} in `{} {}`", level, l.ltype, l.name);
                    if let Some(codemap) = &m.codemap {
                        match codemap.span_from_instruction(issue.responsible_instruction) {
                            Ok(span) => {
                                let (line, col) = span.start_linecol();
                                print!(" at row {} col {}", line, col);
                                println!(": {}", issue.message);
                                println!("{}", span.as_str());
                            }
                            Err(e) => {
                                println!();
                                print!(": {}", issue.message);
                                println!(
                                    "  address {} is out of range in codemap: {}",
                                    issue.responsible_instruction, e
                                );
                            }
                        }
                    }
                    println!();
                    match issue.level {
                        FailureLevel::Warning => {
                            result.num_warnings = result.num_warnings.saturating_add(1);
                        }
                        FailureLevel::Error => {
                            result.num_errors = result.num_errors.saturating_add(1);
                        }
                    }
                }
            }
            Err(e) => {
                println!("{e}");
                result.num_errors = result.num_errors.saturating_add(1);
                return result;
            }
        }
    }

    result
}
