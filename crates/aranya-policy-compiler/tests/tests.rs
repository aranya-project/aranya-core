use std::path::PathBuf;

use aranya_policy_ast::{Version, ident};
use aranya_policy_compiler::{CompileError, Compiler};
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::{
    Module,
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

#[rstest::rstest]
fn test_policy(#[files("tests/data/**/*.policy")] src: PathBuf) {
    let base = src.parent().expect("can't get parent");
    let name = src
        .file_stem()
        .expect("can't get filename stem")
        .to_str()
        .expect("filename not utf8");
    let text = std::fs::read_to_string(src.as_path()).expect("could not read source file");

    if name.contains("pass") {
        let module = compile_pass(&text);

        insta::with_settings!({ prepend_module_to_snapshot => false, snapshot_path => base }, {
            insta::assert_yaml_snapshot!(name, module, {
                // Redact the "text" field from the code map to clean up the snapshots a bit
                ".data.codemap.text" => "[source code]",
            })
        });
    } else if name.contains("fail") {
        let error = compile_fail(&text);

        insta::with_settings!({ prepend_module_to_snapshot => false, snapshot_path => base }, {
            insta::assert_snapshot!(name, error)
        });
    } else {
        panic!("Test file '{name}', must contain 'pass' or 'fail' in the file name.")
    }
}
