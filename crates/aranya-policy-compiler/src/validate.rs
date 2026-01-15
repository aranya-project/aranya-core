use aranya_policy_ast::Identifier;
use aranya_policy_module::{LabelType, Module, ModuleData};

use crate::{
    ActionAnalyzer, FinishAnalyzer, FunctionAnalyzer, TraceAnalyzerBuilder, TraceFailure,
    UnusedVarAnalyzer, ValueAnalyzer,
};

/// Post-compilation validation. Ensure:
/// - action branches publish a command
/// - variables are assigned before use
/// - function code paths return values
/// - commands enter a finish block
pub fn validate(module: &Module) -> bool {
    let ModuleData::V0(ref m) = module.data;
    let mut failed = false;

    // Get all global variable names
    let global_names: Vec<Identifier> = m.globals.keys().cloned().collect();

    for l in m.labels.keys() {
        let mut tracer = TraceAnalyzerBuilder::new(m);
        match l.ltype {
            LabelType::Action => {
                tracer = tracer.add_analyzer(ActionAnalyzer::new());
            }
            LabelType::CommandPolicy | LabelType::CommandRecall => {
                tracer = tracer.add_analyzer(FinishAnalyzer::new());
            }
            LabelType::CommandSeal | LabelType::CommandOpen => {
                // TODO: Add function analyzer once panics are handled correctly.
            }
            LabelType::Function => {
                tracer = tracer.add_analyzer(FunctionAnalyzer::new());
            }
            LabelType::Temporary => unreachable!("Shouldn't have gotten this label type"),
        }
        let tracer = tracer.add_analyzer(ValueAnalyzer::new(global_names.clone()));
        let tracer = tracer.build();

        match tracer.trace(l) {
            Ok(failures) => {
                for TraceFailure {
                    responsible_instruction,
                    message,
                    ..
                } in failures
                {
                    print!("Trace `{}` policy: {}", l.name, message);
                    if let Some(codemap) = &m.codemap {
                        match codemap.span_from_instruction(responsible_instruction) {
                            Ok(span) => {
                                let (line, col) = span.start_linecol();
                                println!(" at row {} col {}:", line, col);
                                println!("{}", span.as_str());
                            }
                            Err(e) => {
                                println!();
                                println!(
                                    "  address {} is out of range in codemap: {}",
                                    responsible_instruction, e
                                );
                            }
                        }
                    }
                    println!();
                    failed = true;
                }
            }
            Err(e) => {
                println!("{e}");
                return false;
            }
        }
    }

    failed
}
