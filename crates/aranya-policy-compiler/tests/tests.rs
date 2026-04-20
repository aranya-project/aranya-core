#![allow(clippy::panic)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::PathBuf,
};

use aranya_policy_ast::{Version, ident};
use aranya_policy_compiler::{CompileError, Compiler};
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::{
    Instruction, Label, Module, ModuleData, ModuleV0,
    RefOrBox::Ref,
    ffi::{self, ModuleSchema},
};

const TEST_SCHEMAS: &[ModuleSchema<'static>] = &[
    ModuleSchema {
        name: ident!("test"),
        functions: Ref(&[ffi::Func {
            name: ident!("doit"),
            args: Ref(&[ffi::Arg {
                name: ident!("x"),
                vtype: ffi::Type::Int,
            }]),
            return_type: ffi::Type::Bool,
        }]),
        structs: Ref(&[]),
        enums: Ref(&[]),
    },
    ModuleSchema {
        name: ident!("cyclic_types"),
        functions: Ref(&[]),
        structs: Ref(&[
            ffi::Struct {
                name: ident!("FFIFoo"),
                fields: Ref(&[ffi::Arg {
                    name: ident!("bar"),
                    vtype: ffi::Type::Struct(ident!("FFIBar")),
                }]),
            },
            ffi::Struct {
                name: ident!("FFIBar"),
                fields: Ref(&[ffi::Arg {
                    name: ident!("foo"),
                    vtype: ffi::Type::Struct(ident!("FFIFoo")),
                }]),
            },
        ]),
        enums: Ref(&[]),
    },
];

#[track_caller]
fn compile(text: &str) -> Result<Module, CompileError> {
    let policy = match parse_policy_str(text, Version::V2) {
        Ok(p) => p,
        Err(err) => panic!("{err}"),
    };
    Compiler::new(&policy)
        .ffi_modules(TEST_SCHEMAS)
        .debug(true)
        .compile()
}

// Helper function which parses and compiles policy expecting success.
#[track_caller]
fn compile_pass(text: &str) -> Module {
    match compile(text) {
        Ok(m) => m,
        Err(err) => panic!("{err}"),
    }
}

// Helper function which parses and compiles policy expecting compile failure.
#[track_caller]
fn compile_fail(text: &str) -> CompileError {
    match compile(text) {
        Ok(_) => panic!("policy compilation should have failed - src: {text}"),
        Err(err) => err,
    }
}

/// Wraps [`aranya_policy_module::Module`] to provide a Debug impl
/// that only prints data worth viewing.
struct ModuleSnapshotWrapper(Module);

impl fmt::Debug for ModuleSnapshotWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ModuleData::V0(ModuleV0 {
            labels,
            action_defs,
            command_defs,
            fact_defs,
            struct_defs,
            enum_defs,
            globals,
            ..
        }) = &self.0.data;

        f.debug_struct("Module")
            .field("version", &"0")
            .field("labels", &labels)
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

fn write_instructions(m: &Module, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
    let ModuleData::V0(m) = &m.data;

    let mut labels: HashMap<usize, &Label> = HashMap::new();
    let mut targets: HashSet<usize> = HashSet::new();

    for (label, &addr) in &m.labels {
        let old = labels.insert(addr, label);
        assert!(old.is_none(), "labels shouldn't point to same place");
    }

    for ins in &m.progmem {
        if let Instruction::Branch(t) | Instruction::Jump(t) = ins {
            let addr = t.resolved().expect("unresolved target");
            targets.insert(addr);
        }
    }

    for (i, ins) in m.progmem.iter().enumerate() {
        if let Some(label) = labels.get(&i) {
            writeln!(f, "{label:?}:")?;
        }
        if targets.contains(&i) {
            writeln!(f, "<{i}>:")?;
        }

        writeln!(
            f,
            "    {}",
            fmt_fn(|f| {
                match ins {
                    // Show target label for calls.
                    Instruction::Call(t) => {
                        let label = labels
                            .get(&t.resolved().expect("unresolved target"))
                            .expect("missing target label");
                        write!(f, "call {label:?}")
                    }
                    // Fall back to display impl.
                    _ => write!(f, "{ins}"),
                }
            })
        )?;
    }

    Ok(())
}

/// Display based on supplied function.
///
/// Adapted from [`core::fmt::from_fn`] (1.93+).
fn fmt_fn(f: impl Fn(&mut fmt::Formatter<'_>) -> fmt::Result) -> impl fmt::Display {
    struct FmtFn<F>(F);
    impl<F> fmt::Display for FmtFn<F>
    where
        F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            (self.0)(f)
        }
    }

    FmtFn(f)
}

#[rstest::rstest]
fn test_policy(#[files("tests/data/**/*.policy")] src: PathBuf) {
    let base = src.parent().expect("can't get parent");
    let name = src
        .file_stem()
        .expect("can't get filename stem")
        .to_str()
        .expect("filename not utf8");
    let text = std::fs::read_to_string(src.as_path()).expect("could not read source file");

    if name.ends_with(".pass") {
        let module = ModuleSnapshotWrapper(compile_pass(&text));

        insta::with_settings!({ prepend_module_to_snapshot => false, snapshot_path => base }, {
            insta::assert_debug_snapshot!(name, module);
        });
    } else if name.ends_with(".fail") {
        let error = compile_fail(&text);

        insta::with_settings!({ prepend_module_to_snapshot => false, snapshot_path => base }, {
            insta::assert_snapshot!(name, error);
        });
    } else {
        panic!(
            "Test file '{}', must end in '.pass.policy' or '.fail.policy'.",
            src.display()
        )
    }
}
