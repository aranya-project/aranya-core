use aranya_policy_compiler::{FinishAnalyzer, TraceAnalyzerBuilder, TraceFailure, ValueAnalyzer};
use aranya_policy_module::{LabelType, Module, ModuleData};

pub fn validate(module: &Module) -> bool {
    let ModuleData::V0(ref m) = module.data;
    let mut failed = false;

    // Get all global variable names
    let global_names: Vec<String> = m.globals.keys().cloned().collect();

    for (l, _) in m
        .labels
        .iter()
        .filter(|(l, _)| l.ltype == LabelType::CommandPolicy)
    {
        let mut predefined_names = vec![];
        match l.ltype {
            LabelType::Action => {
                let mut function_args = m
                    .action_defs
                    .get(&l.name)
                    .expect("no action")
                    .iter()
                    .map(|fd| &fd.identifier)
                    .cloned()
                    .collect();
                predefined_names.append(&mut function_args);
            }
            LabelType::CommandPolicy | LabelType::CommandRecall => {
                predefined_names.push("this".to_string());
                predefined_names.push("envelope".to_string());
            }
            LabelType::CommandSeal => {
                predefined_names.push("this".to_string());
            }
            LabelType::CommandOpen => {
                predefined_names.push("envelope".to_string());
            }
            _ => continue,
        };

        let tracer = TraceAnalyzerBuilder::new(m);

        let tracer = match l.ltype {
            LabelType::Action | LabelType::CommandSeal | LabelType::CommandOpen => {
                tracer.add_analyzer(ValueAnalyzer::new(global_names.clone(), predefined_names))
            }
            LabelType::CommandPolicy | LabelType::CommandRecall => tracer
                .add_analyzer(ValueAnalyzer::new(global_names.clone(), predefined_names))
                .add_analyzer(FinishAnalyzer::new()),
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
