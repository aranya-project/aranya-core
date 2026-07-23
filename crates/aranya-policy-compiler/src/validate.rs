use std::collections::BTreeSet;

use aranya_policy_ast::{Identifier, ident};
use aranya_policy_module::{LabelType, Module, ModuleData};

use crate::{
    ActionAnalyzer, FailureLevel, FinishAnalyzer, FunctionAnalyzer, TraceAnalyzerBuilder,
    ValueAnalyzer,
    cfg::{self, Cfg},
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
/// - commands enter a finish block
/// - no unused variables (via CFG-based reachability, reported as warnings)
pub fn validate(module: &Module) -> ValidationResult {
    let ModuleData::V0(ref m) = module.data;
    let mut result = ValidationResult::Success;

    // Get all global variable names
    let global_names: Vec<Identifier> = m.globals.keys().cloned().collect();

    for l in m.labels.keys() {
        // --- Tracer-based analyzers (return, publish, finish, use-before-def). ---
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
            .build();

        match tracer.trace(l) {
            Ok(issues) => {
                for issue in issues {
                    let level = match issue.level {
                        FailureLevel::Warning => "warning",
                        FailureLevel::Error => "error",
                    };
                    print!("{} in `{} {}`", level, l.ltype, l.name);
                    report_span(m, issue.responsible_instruction, &issue.message);
                    match issue.level {
                        FailureLevel::Warning => {
                            if result == ValidationResult::Success {
                                result = ValidationResult::Warning;
                            }
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

        // --- CFG-based validation checks (warnings only). ---
        let entry_addr = *m.labels.get(l).expect("label present");
        let cfg = Cfg::build(m, entry_addr);
        let predefined = match l.ltype {
            LabelType::CommandPolicy
            | LabelType::CommandRecall
            | LabelType::CommandSeal
            | LabelType::CommandOpen => BTreeSet::from([ident!("this"), ident!("envelope")]),
            _ => BTreeSet::new(),
        };
        for d in cfg::unused_vars(&cfg, m, &predefined) {
            print!("warning in `{} {}`", l.ltype, l.name);
            let msg = format!("unused variable: `{}`", d.name);
            report_span(m, d.address, &msg);
            if result == ValidationResult::Success {
                result = ValidationResult::Warning;
            }
        }
    }

    result
}

fn report_span(m: &aranya_policy_module::ModuleV0, address: usize, message: &str) {
    if let Some(codemap) = &m.codemap {
        match codemap.span_from_instruction(address) {
            Ok(span) => {
                let (line, col) = span.start_linecol();
                print!(" at row {} col {}", line, col);
                println!(": {}", message);
                println!("{}", span.as_str());
                return;
            }
            Err(e) => {
                println!();
                println!(": {}", message);
                println!("  address {} is out of range in codemap: {}", address, e);
                return;
            }
        }
    }
    println!(": {}", message);
}
