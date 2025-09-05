use aranya_policy_ast::{Identifier, ident};
use aranya_policy_module::{LabelType, Module, ModuleData};

use crate::{
    ActionAnalyzer, FinishAnalyzer, FunctionAnalyzer, TraceAnalyzerBuilder, TraceFailure,
    ValueAnalyzer,
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

    for (l, _) in m.labels.iter() {
        let mut predefined_names = vec![];
        match l.ltype {
            LabelType::CommandPolicy | LabelType::CommandRecall => {
                predefined_names.push(ident!("this"));
                predefined_names.push(ident!("envelope"));
            }
            LabelType::CommandSeal => {
                predefined_names.push(ident!("this"));
            }
            LabelType::CommandOpen => {
                predefined_names.push(ident!("envelope"));
            }
            LabelType::Function | LabelType::Action => {}
            _ => continue,
        };

        let tracer = TraceAnalyzerBuilder::new(m);
        let tracer = match l.ltype {
            LabelType::Action => tracer
                .add_analyzer(ActionAnalyzer::new())
                .add_analyzer(ValueAnalyzer::new(global_names.clone(), predefined_names)),
            LabelType::CommandSeal | LabelType::CommandOpen => {
                tracer.add_analyzer(ValueAnalyzer::new(global_names.clone(), predefined_names))
            }
            LabelType::CommandPolicy | LabelType::CommandRecall => tracer
                .add_analyzer(ValueAnalyzer::new(global_names.clone(), predefined_names))
                .add_analyzer(FinishAnalyzer::new()),
            LabelType::Function => tracer.add_analyzer(FunctionAnalyzer::new()),
            _ => unreachable!("Shouldn't have gotten this label type"),
        };
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
                        };
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
