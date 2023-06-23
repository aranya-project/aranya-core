use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::io::{stdin, Read};

use clap::{ArgGroup, Parser, ValueEnum};

use flow3_policy_lang::lang::{parse_policy_document, parse_policy_str, Version};
use flow3_policy_lang::machine::*;

#[derive(Debug, Copy, Clone, PartialEq, ValueEnum)]
enum Mode {
    Exec,
    Debug,
    Compile,
}

#[derive(Parser, Debug)]
#[command(name = "machine explorer", version)]
#[command(about = "VM compiler and step-debugger for policy language")]
#[command(group(ArgGroup::new("mode").required(true).args(["exec", "debug", "compile"])))]
#[command(group(ArgGroup::new("call").conflicts_with("compile").args(["action", "command"])))]
struct Args {
    /// The policy version. If this is set the policy is treated as raw.
    /// Valid values are v3.
    #[arg(short, long)]
    raw_policy_version: Option<Version>,
    /// Execute the action or command and show the machine state.
    #[arg(short, long)]
    exec: bool,
    /// Step through the execution of policy instructions one-by-one,
    /// showing the state after each step. One instruction is executed
    /// for each newline read from stdin.
    #[arg(short, long)]
    debug: bool,
    /// Show only the compiled instructions and exit.
    #[arg(short, long)]
    compile: bool,
    /// The file to read from. If omitted, the document is read from stdin.
    file: String,
    /// Call an action. Command-line arguments are positional arguments
    /// to the function.
    #[arg(short, long)]
    action: Option<String>,
    /// Call a command policy block. Command-line arguments are
    /// key:value pairs that form the `self` struct.
    #[arg(short = 'm', long)]
    command: Option<String>,
    /// Any arguments to called functions.
    args: Vec<String>,
}

fn debug_loop<M>(rs: &mut RunState<M>) -> anyhow::Result<()>
where
    M: MachineIO,
{
    let mut buf = String::new();
    let mut status = MachineStatus::Executing;
    while status == MachineStatus::Executing {
        println!("{}", rs);
        stdin().read_line(&mut buf)?;
        status = rs.step()?;
    }
    println!("Execution stopped: {}", status);
    Ok(())
}

/// Parse string arguments as Value types
fn convert_arg_value(a: String) -> Value {
    if a == "true" {
        Value::Bool(true)
    } else if a == "false" {
        Value::Bool(false)
    } else if let Ok(i) = a.parse::<i64>() {
        Value::Int(i)
    } else {
        Value::String(a)
    }
}

type MachExpFactKey = (String, Vec<(String, HashableValue)>);
type MachExpFactValue = Vec<(String, Value)>;

struct MachExpIO {
    facts: HashMap<MachExpFactKey, MachExpFactValue>,
    emits: Vec<(String, Vec<(String, Value)>)>,
    effects: Vec<(String, Vec<(String, Value)>)>,
}

impl MachExpIO {
    fn new() -> MachExpIO {
        MachExpIO {
            facts: HashMap::new(),
            emits: vec![],
            effects: vec![],
        }
    }
}

impl MachineIO for MachExpIO {
    fn fact_insert(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = (String, HashableValue)>,
        value: impl IntoIterator<Item = (String, Value)>,
    ) -> Result<(), MachineError> {
        let key = key.into_iter().collect();
        let value = value.into_iter().collect();
        self.facts.insert((name, key), value);
        Ok(())
    }

    fn fact_delete(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = (String, HashableValue)>,
    ) -> Result<(), MachineError> {
        let key = key.into_iter().collect();
        let k = (name, key);
        self.facts.remove(&k);
        Ok(())
    }

    fn fact_query<'a>(
        &self,
        _name: String,
        _key: impl IntoIterator<Item = (String, HashableValue)>,
    ) -> Result<FactIterator<'a>, MachineError> {
        todo!()
    }

    fn emit(&mut self, name: String, fields: impl IntoIterator<Item = (String, Value)>) {
        let fields = fields.into_iter().collect();
        self.emits.push((name, fields))
    }

    fn effect(&mut self, name: String, fields: impl IntoIterator<Item = (String, Value)>) {
        let fields = fields.into_iter().collect();
        self.effects.push((name, fields))
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let s = {
        let mut buf = vec![];
        let mut f = OpenOptions::new()
            .read(true)
            .open(&args.file)
            .expect("Could not open");
        f.read_to_end(&mut buf).expect("Could not read file");
        String::from_utf8(buf)?
    };

    let policy = if let Some(v) = args.raw_policy_version {
        parse_policy_str(&s, v)?
    } else {
        parse_policy_document(&s)?
    };

    let machine: Machine = Machine::compile_from_policy(&policy).expect("Could not compile");
    let mut io = MachExpIO::new();
    let mut rs = machine.create_run_state(&mut io);

    let mode = if args.exec {
        Mode::Exec
    } else if args.debug {
        Mode::Debug
    } else {
        Mode::Compile
    };

    // This actually provides a pretty poor example of how you'd use
    // the VM in practice. Normally you would just call
    // `machine.call_command_policy()` or `machine.call_action()`,
    // which will return the commands or effects produced.
    match mode {
        Mode::Exec | Mode::Debug => {
            if let Some(action) = &args.action {
                let call_args: Vec<Value> = args.args.into_iter().map(convert_arg_value).collect();
                rs.setup_action(action, &call_args)?;
            } else if let Some(command) = args.command {
                let fields: BTreeMap<String, Value> = args
                    .args
                    .into_iter()
                    .map(|a| {
                        let v: Vec<_> = a.split(':').collect();
                        (v[0].to_owned(), convert_arg_value(v[1].to_owned()))
                    })
                    .collect();
                let self_data = Struct {
                    name: command.clone(),
                    fields,
                };
                rs.setup_command_policy(&command, &self_data)?;
            } else {
                return Err(anyhow::anyhow!("Neither action nor command specified"));
            }

            if mode == Mode::Exec {
                rs.run()?;
            } else {
                match debug_loop(&mut rs) {
                    Ok(()) => (),
                    Err(e) => println!("execution stopped: {}", e),
                }
            }
            println!("Facts:");
            for (k, v) in &io.facts {
                print!("  {}[", k.0);
                for (k, v) in &k.1 {
                    print!("{}: {}", k, v);
                }
                print!("]=>{{");
                for (k, v) in v {
                    print!("{}: {}", k, v);
                }
                println!("}}");
            }
            println!("Effects:");
            for e in &io.effects {
                println!("  {} {{", e.0);
                for (k, v) in &e.1 {
                    println!("    {}: {}", k, v);
                }
                println!("  }}");
            }
            println!("Emitted Commands:");
            for e in &io.emits {
                println!("  {} {{", e.0);
                for (k, v) in &e.1 {
                    println!("    {}: {}", k, v);
                }
                println!("  }}");
            }
        }
        Mode::Compile => {
            println!("{}", machine);
        }
    }

    Ok(())
}
