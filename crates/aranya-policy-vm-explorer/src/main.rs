#![warn(clippy::arithmetic_side_effects)]

use std::{
    cell::RefCell,
    collections::{hash_map, BTreeMap, HashMap},
    fs::OpenOptions,
    io::{stdin, Read},
};

use aranya_crypto::Id;
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::{parse_policy_document, parse_policy_str, Version};
use aranya_policy_vm::{
    ActionContext, CommandContext, ExitReason, FactKey, FactKeyList, FactValue, FactValueList,
    KVPair, LabelType, Machine, MachineError, MachineErrorType, MachineIO, MachineIOError,
    MachineStack, MachineStatus, PolicyContext, RunState, Stack, Struct, Value,
};
use clap::{arg, ArgGroup, Parser, ValueEnum};

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
    /// Valid values are v1.
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

fn debug_loop<M>(rs: &mut RunState<'_, M>) -> anyhow::Result<()>
where
    M: MachineIO<MachineStack>,
{
    let mut buf = String::new();
    let mut status = MachineStatus::Executing;
    while status == MachineStatus::Executing {
        println!("{}", rs);
        stdin().read_line(&mut buf)?;
        status = rs.step()?;
    }
    if let MachineStatus::Exited(reason) = status {
        print_machine_status(reason, rs);
    }

    Ok(())
}

fn print_machine_status<M>(reason: ExitReason, rs: &RunState<'_, M>)
where
    M: MachineIO<MachineStack>,
{
    print!("Exited({})", reason);
    if let Some(loc) = rs.source_location() {
        println!(" {}", loc);
    } else {
        println!();
    }
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

/// Returns true if the k/v pairs in a exist in b, otherwise false.
fn subset_key_match(a: &[FactKey], b: &[FactKey]) -> bool {
    for entry in a {
        if !b.iter().any(|e| e == entry) {
            return false;
        }
    }
    true
}

struct MachExpIO {
    facts: HashMap<(String, FactKeyList), FactValueList>,
    commands: Vec<(String, Vec<KVPair>)>,
    effects: Vec<(String, Vec<KVPair>)>,
}

impl MachExpIO {
    fn new() -> Self {
        MachExpIO {
            facts: HashMap::new(),
            commands: vec![],
            effects: vec![],
        }
    }
}

struct MachExpQueryIterator {
    name: String,
    key: FactKeyList,
    iter: hash_map::IntoIter<(String, FactKeyList), FactValueList>,
}

impl Iterator for MachExpQueryIterator {
    type Item = Result<(FactKeyList, FactValueList), MachineIOError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .filter(|((n, k), _)| *n == self.name && subset_key_match(k, &self.key))
            .map(|((_, k), v)| Ok((k.clone(), v.clone())))
    }
}

impl<S> MachineIO<S> for MachExpIO
where
    S: Stack,
{
    type QueryIterator = MachExpQueryIterator;

    fn fact_insert(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
        value: impl IntoIterator<Item = FactValue>,
    ) -> Result<(), MachineIOError> {
        let key = key.into_iter().collect();
        let value = value.into_iter().collect();
        match self.facts.entry((name, key)) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(value);
                Ok(())
            }
            hash_map::Entry::Occupied(_) => Err(MachineIOError::FactExists),
        }
    }

    fn fact_delete(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<(), MachineIOError> {
        let key = key.into_iter().collect();
        match self.facts.entry((name, key)) {
            hash_map::Entry::Vacant(_) => Err(MachineIOError::FactNotFound),
            hash_map::Entry::Occupied(entry) => {
                entry.remove();
                Ok(())
            }
        }
    }

    fn fact_query(
        &self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator, MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        Ok(MachExpQueryIterator {
            name,
            key,
            // TODO(jdygert): Worth removing clone?
            iter: self.facts.clone().into_iter(),
        })
    }

    fn publish(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>) {
        let fields = fields.into_iter().collect();
        self.commands.push((name, fields))
    }

    fn effect(
        &mut self,
        name: String,
        fields: impl IntoIterator<Item = KVPair>,
        _command: Id,
        _recalled: bool,
    ) {
        let fields = fields.into_iter().collect();
        self.effects.push((name, fields))
    }

    fn call(
        &self,
        module: usize,
        _procedure: usize,
        _stack: &mut S,
        _ctx: &CommandContext<'_>,
    ) -> Result<(), MachineError> {
        Err(MachineError::new(MachineErrorType::FfiModuleNotDefined(
            module,
        )))
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

    let machine: Machine = match Compiler::new(&policy).compile() {
        Ok(m) => Machine::from_module(m)?,
        Err(e) => {
            anyhow::bail!("Compilation failed: {e}");
        }
    };
    let io = RefCell::new(MachExpIO::new());

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
            let name;
            let mut rs;
            let ctx;

            if let Some(action) = &args.action {
                name = action.clone();
                ctx = CommandContext::Action(ActionContext {
                    name: &name,
                    head_id: Id::default(),
                });
                rs = machine.create_run_state(&io, ctx);
                let call_args = args.args.into_iter().map(convert_arg_value);
                rs.setup_action(action, call_args)?;
            } else if let Some(command) = args.command {
                name = command.clone();
                ctx = CommandContext::Policy(PolicyContext {
                    name: &name,
                    id: Id::default(),
                    author: Id::default().into(),
                    version: Id::default(),
                });
                rs = machine.create_run_state(&io, ctx);
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
                rs.setup_command(&command, LabelType::CommandPolicy, &self_data)?;
            } else {
                return Err(anyhow::anyhow!("Neither action nor command specified"));
            }

            if mode == Mode::Exec {
                let status = rs.run()?;
                print_machine_status(status, &rs);
            } else {
                match debug_loop(&mut rs) {
                    Ok(()) => (),
                    Err(e) => println!("execution stopped: {}", e),
                }
            }

            drop(rs);

            println!("Facts:");
            for ((name, k), v) in &io.borrow().facts {
                print!("  {}[", name);
                for e in k {
                    print!("{}", e);
                }
                print!("]=>{{");
                for e in v {
                    print!("{}", e);
                }
                println!("}}");
            }
            println!("Effects:");
            for (name, fields) in &io.borrow().effects {
                println!("  {} {{", name);
                for f in fields {
                    println!("    {}", f);
                }
                println!("  }}");
            }
            println!("Published Commands:");
            for (name, fields) in &io.borrow().commands {
                println!("  {} {{", name);
                for f in fields {
                    println!("    {}", f);
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
