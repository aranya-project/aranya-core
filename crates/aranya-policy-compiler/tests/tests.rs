#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use aranya_policy_ast::{Version, ident};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::{
    Instruction, Label, Module, ModuleData, arg,
    ffi::{self, ModuleSchema},
    flavor,
};
use tryfn::{Case, Data, Harness};

const TEST_SCHEMAS: &[ModuleSchema<'static>] = &[
    ModuleSchema {
        name: ident!("test"),
        functions: &[ffi::Func {
            name: ident!("doit"),
            args: &[ffi::Arg {
                name: ident!("x"),
                vtype: ffi::Type::Int,
            }],
            return_type: ffi::Type::Bool,
        }],
        structs: &[],
        enums: &[],
    },
    ModuleSchema {
        name: ident!("cyclic_types"),
        functions: &[],
        structs: &[
            ffi::Struct {
                name: ident!("FFIFoo"),
                fields: &[ffi::Arg {
                    name: ident!("bar"),
                    vtype: ffi::Type::Struct(ident!("FFIBar")),
                }],
            },
            ffi::Struct {
                name: ident!("FFIBar"),
                fields: &[ffi::Arg {
                    name: ident!("foo"),
                    vtype: ffi::Type::Struct(ident!("FFIFoo")),
                }],
            },
        ],
        enums: &[],
    },
];

const TEST_FLAVORS: &flavor::Flavors = &flavor::Flavors {
    flavors: &[
        (
            ident!("null"),
            flavor::Flavor {
                envelope: flavor::Struct {
                    name: ident!("NullEnvelope"),
                    fields: &[],
                },
            },
        ),
        (
            ident!("init"),
            flavor::Flavor {
                envelope: flavor::Struct {
                    name: ident!("InitEnvelope"),
                    fields: &[arg!("test_field", Int)],
                },
            },
        ),
        (
            ident!("basic"),
            flavor::Flavor {
                envelope: flavor::Struct {
                    name: ident!("BasicEnvelope"),
                    fields: &[],
                },
            },
        ),
        (
            ident!("ephemeral"),
            flavor::Flavor {
                envelope: flavor::Struct {
                    name: ident!("EphemeralEnvelope"),
                    fields: &[],
                },
            },
        ),
    ],
};

/// Wraps [`aranya_policy_module::Module`] to provide a Debug impl
/// that only prints data worth viewing.
struct ModuleSnapshotWrapper(Module);

impl fmt::Debug for ModuleSnapshotWrapper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (
            version,
            labels,
            action_defs,
            command_defs,
            fact_defs,
            struct_defs,
            enum_defs,
            globals,
        ) = match &self.0.data {
            ModuleData::V0(m) => (
                "0",
                &m.labels,
                &m.action_defs,
                &m.command_defs,
                &m.fact_defs,
                &m.struct_defs,
                &m.enum_defs,
                &m.globals,
            ),
            ModuleData::V1(m) => (
                "1",
                &m.program.labels,
                &m.contract.actions,
                &m.contract.commands,
                &m.contract.facts,
                &m.contract.structs,
                &m.contract.enums,
                &m.program.globals,
            ),
        };

        f.debug_struct("Module")
            .field("version", &version)
            .field("labels", labels)
            .field("action_defs", action_defs)
            .field("command_defs", command_defs)
            .field("fact_defs", fact_defs)
            .field("struct_defs", struct_defs)
            .field("enum_defs", enum_defs)
            .field("globals", globals)
            .finish_non_exhaustive()?;

        writeln!(f, "\n---")?;

        write_instructions(&self.0, f)?;

        Ok(())
    }
}

fn write_instructions(m: &Module, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
    let (progmem, m_labels) = match &m.data {
        ModuleData::V0(m) => (&m.progmem, &m.labels),
        ModuleData::V1(m) => (&m.program.progmem, &m.program.labels),
    };

    let mut labels: HashMap<usize, Vec<&Label>> = HashMap::new();
    let mut targets: HashSet<usize> = HashSet::new();

    for (label, &addr) in m_labels {
        labels.entry(addr).or_default().push(label);
    }

    for ins in progmem {
        if let Instruction::Branch(t) | Instruction::Jump(t) = ins {
            let addr = t.resolved().expect("unresolved target");
            targets.insert(addr);
        }
    }

    for (i, ins) in progmem.iter().enumerate() {
        if let Some(label_vec) = labels.get(&i) {
            for label in label_vec {
                writeln!(f, "{label:?}:")?;
            }
        }
        if targets.contains(&i) {
            writeln!(f, "<{i}>:")?;
        }

        writeln!(
            f,
            "    {}",
            core::fmt::from_fn(|f| {
                match ins {
                    // Show target label for calls.
                    Instruction::Call(t) => {
                        let label = labels
                            .get(&t.resolved().expect("unresolved target"))
                            .expect("missing target label")
                            .first()
                            .unwrap();
                        write!(f, "call {label:?}")
                    }
                    Instruction::Recall(t) => {
                        let label = labels
                            .get(&t.resolved().expect("unresolved target"))
                            .expect("missing target label")
                            .first()
                            .unwrap();
                        write!(f, "recall {label:?}")
                    }
                    // Fall back to display impl.
                    _ => write!(f, "{ins}"),
                }
            })
        )?;
    }

    Ok(())
}

fn main() {
    Harness::new("tests/data", setup, test)
        .select(["*.policy"])
        .test();
}

fn setup(path: PathBuf) -> Case {
    let name = get_name(&path).unwrap();
    let expected = Data::read_from(&path.with_extension("snap"), None).raw();
    Case {
        name,
        fixture: path,
        expected,
    }
}

fn test(path: &Path) -> Result<String> {
    let should_pass = should_pass(path)?;
    let debug = !path.starts_with("tests/data/unused/");

    let mut text = std::fs::read_to_string(path).context("could not read source file")?;
    if text.contains("StubBase") {
        text.push_str("\n\nbase[null] StubBase { get_key { return None } }");
    }
    let ast = parse_policy_str(&text, Version::V2).context("could not parse policy text")?;

    let res = Compiler::new(&ast)
        .ffi_modules(TEST_SCHEMAS)
        .flavors(TEST_FLAVORS)
        .debug(debug)
        .compile();

    Ok(match (res, should_pass) {
        (Ok(module), true) => format!("{:#?}", ModuleSnapshotWrapper(module)),
        (Err(error), false) => format!("{error}\n"),
        (Ok(_), false) => bail!("module compiled unexpectedly"),
        (Err(error), true) => bail!("unexpected compile error:\n{error}"),
    })
}

fn get_name(path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix("tests/data/")?
        .with_extension("")
        .to_string_lossy()
        .into_owned())
}

fn should_pass(path: &Path) -> Result<bool> {
    let filename = path
        .file_name()
        .context("no filename present")?
        .to_str()
        .context("filename is not valid unicode")?;
    let ext = filename
        .split_once(".")
        .context("filename does not contain '.'")?
        .1;
    match ext {
        "pass.policy" => Ok(true),
        "fail.policy" => Ok(false),
        _ => bail!(
            "Test file '{}', must end in '.pass.policy' or '.fail.policy'.",
            path.display()
        ),
    }
}
