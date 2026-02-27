use aranya_policy_ast::Identifier;
use aranya_policy_module::{LabelType, Module, ModuleData};

use crate::{
    ActionAnalyzer, FailureLevel, FinishAnalyzer, FunctionAnalyzer, TraceAnalyzerBuilder,
    UnusedVarAnalyzer, ValueAnalyzer,
};

/// Result of policy validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// No warnings or errors
    Success,
    /// One or more warnings, but no errors
    Warning,
    /// One or more errors
    Failure,
}

/// Post-compilation validation. Ensure:
/// - action branches publish a command
/// - variables are assigned before use
/// - functions code paths return values
/// - no unused variables
/// - all function code paths return values
/// - commands enter a finish block
pub fn validate(module: &Module) -> ValidationResult {
    let ModuleData::V0(ref m) = module.data;
    let mut result = ValidationResult::Success;

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
                            result = ValidationResult::Warning;
                        }
                        FailureLevel::Error => {
                            result = ValidationResult::Failure;
                        }
                    }
                }
            }
            Err(e) => {
                println!("{e}");
                return ValidationResult::Failure;
            }
        }
    }

    result
}
