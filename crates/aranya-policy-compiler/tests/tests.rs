#![allow(clippy::panic)]

use std::path::PathBuf;

use aranya_policy_ast::{Version, ident};
use aranya_policy_compiler::{CompileError, Compiler};
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::{
    Module, ModuleData, ModuleV0,
    ffi::{self, ModuleSchema},
};

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

/// Wraps [`aranya_policy_module::Module`] to provide a Display impl
/// that only prints data worth viewing.
struct ModuleSnapshotWrapper(Module);

impl std::fmt::Display for ModuleSnapshotWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ModuleData::V0(ModuleV0 {
            labels,
            action_defs,
            command_defs,
            fact_defs,
            struct_defs,
            enum_defs,
            globals,
            progmem,
            ..
        }) = &self.0.data;

        writeln!(f, "Module (version 0)")?;

        writeln!(f, "\nlabels:")?;
        for (label, offset) in labels {
            writeln!(f, "\t{label} -> {offset}")?;
        }

        writeln!(f, "\naction_defs:")?;
        for action in action_defs.iter() {
            writeln!(f, "\t{}:", action.name)?;
            writeln!(f, "\t\tpersistence: {}", action.persistence)?;
            writeln!(f, "\t\tparams:")?;
            for param in action.params.iter() {
                writeln!(f, "\t\t\t{}: {}", param.name, param.ty)?;
            }
        }

        writeln!(f, "\ncommand_defs:")?;
        for cmd in command_defs.iter() {
            writeln!(f, "\t{}:", cmd.name)?;
            writeln!(f, "\t\tpersistence: {}", cmd.persistence)?;
            writeln!(f, "\t\tattributes:")?;
            for attr in cmd.attributes.iter() {
                writeln!(f, "\t\t\t{}: {}", attr.name, attr.value)?;
            }
            writeln!(f, "\t\tfields:")?;
            for field in cmd.fields.iter() {
                writeln!(f, "\t\t\t{}: {}", field.name, field.ty)?;
            }
        }

        writeln!(f, "\nfact_defs:")?;
        for (name, fact) in fact_defs {
            let mutability = if fact.immutable {
                "immutable"
            } else {
                "mutable"
            };
            writeln!(f, "\t{name} ({mutability})")?;
            writeln!(f, "\t\tkey:")?;
            for field in &fact.key {
                writeln!(f, "\t\t\t{}: {}", field.identifier, field.field_type)?;
            }
            writeln!(f, "\t\tvalue:")?;
            for field in &fact.value {
                writeln!(f, "\t\t\t{}: {}", field.identifier, field.field_type)?;
            }
        }

        writeln!(f, "\nstruct_defs:")?;
        for (name, fields) in struct_defs {
            writeln!(f, "\t{name}:")?;
            for field in fields {
                writeln!(f, "\t\t{}: {}", field.identifier, field.field_type)?;
            }
        }

        writeln!(f, "\nenum_defs:")?;
        for (name, variants) in enum_defs {
            writeln!(f, "\t{name}:")?;
            for (variant, value) in variants {
                writeln!(f, "\t\t{variant} = {value}")?;
            }
        }

        writeln!(f, "\nglobals:")?;
        for (name, value) in globals {
            writeln!(f, "\t{name} = {value}")?;
        }

        writeln!(f, "\nprogram memory:")?;
        for instr in progmem.iter() {
            writeln!(f, "\t{instr}")?;
        }

        Ok(())
    }
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
            insta::assert_snapshot!(name, module);
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
