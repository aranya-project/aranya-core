#![cfg(test)]

use std::collections::BTreeMap;

use aranya_policy_ast::{self as ast, FieldDefinition, TypeKind, VType, Version, ident, text};
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::{
    ConstStruct, ConstValue, Label, LabelType, Module, ModuleData,
    ffi::{self, ModuleSchema},
};

use crate::{CompileError, CompileErrorType, Compiler, InvalidCallColor, validate::validate};

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
fn compile_fail(text: &str) -> CompileErrorType {
    match compile(text) {
        Ok(_) => panic!("policy compilation should have failed - src: {text}"),
        Err(err) => err.err_type(),
    }
}

#[test]
fn test_compile() {
    let text = r#"
        command Foo {
            fields {
                a int,
                b int
            }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }
        action foo(b int) {
            let i = 4
            let x = if b == 0 { :saturating_add(4, i) } else { :3 }
            let y = Foo{
                a: x,
                b: 4
            }
        }
    "#;

    compile_pass(text);
}

#[test]
fn test_undefined_struct() {
    let text = r#"
        action foo() {
            let v = Bar {}
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::NotDefined(String::from("Struct `Bar` not defined")),
    );
}

#[test]
fn test_function_no_return() {
    let text = r#"
        function f(x int) int {
            let y = saturating_add(x, 1)
            // no return value
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::NoReturn);
}

#[test]
fn test_function_not_defined() {
    let text = r#"
        function f(x int) int {
            return g()
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::NotDefined(String::from("g")));
}

#[test]
fn test_function_already_defined() {
    let text = r#"
        function f(x int) int {
            return 1
        }

        function f() int {}
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::AlreadyDefined(String::from("f")));
}

#[test]
fn test_function_wrong_number_arguments() {
    let text = r#"
        function f(x int) int {
            return 1
        }

        function g() int {
            return f()
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::BadArgument(String::from(
            "call to `f` has 0 arguments and it should have 1"
        ))
    );
}

#[test]
fn test_function_duplicate_arg_names() {
    let text = r#"
        function f(x int, x int) int {
            return 1
        }

        function g() int {
            return f(1, 2)
        }
    "#;

    let err = compile_fail(text);
    assert!(matches!(err, CompileErrorType::AlreadyDefined(_)));
}

#[test]
fn test_function_wrong_color_pure() {
    let text = r#"
        function f(x int) int {
            return x
        }

        finish function g() {
            f()
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::InvalidCallColor(InvalidCallColor::Pure)
    );
}

#[test]
fn test_function_wrong_color_finish() {
    let text = r#"
        finish function f(x int) {
            emit Foo {}
        }

        function g() int {
            return f()
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::InvalidCallColor(InvalidCallColor::Finish)
    );
}

#[test]
fn test_seal_open_command() {
    let text = r#"
        command Foo {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }
    "#;

    let module = compile_pass(text);
    let ModuleData::V0(module) = module.data;

    assert!(
        module
            .labels
            .iter()
            .any(|l| *l.0 == Label::new(ident!("Foo"), LabelType::CommandSeal))
    );
    assert!(
        module
            .labels
            .iter()
            .any(|l| *l.0 == Label::new(ident!("Foo"), LabelType::CommandOpen))
    );
}

#[test]
fn test_command_with_no_return_in_seal_block() {
    let text = r#"
        command Foo {
            fields {}
            seal { let x = 3 }
            open { return todo() }
            policy {
                finish {}
            }
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::NoReturn);
}

#[test]
fn test_command_with_no_return_in_open_block() {
    let text = r#"
        command Foo {
            fields {}
            seal { return todo() }
            open { let x = 3 }
            policy {
                finish {}
            }
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::NoReturn);
}

#[test]
fn test_command_attributes() {
    let text = r#"
        enum Priority { Low, High }
        command A {
            attributes {
                i: 5,
                s: "abc",
                priority: Priority::High
            }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }
    "#;

    let m = compile_pass(text);
    match m.data {
        ModuleData::V0(m) => {
            let attrs = &m
                .command_defs
                .get("A")
                .expect("should find command attribute map")
                .attributes;
            assert_eq!(attrs.len(), 3);
            assert_eq!(
                attrs.get("i").expect("should find 1st value").value,
                ConstValue::Int(5)
            );
            assert_eq!(
                attrs.get("s").expect("should find 2nd value").value,
                ConstValue::String(text!("abc"))
            );
            assert_eq!(
                attrs.get("priority").expect("should find 3nd value").value,
                ConstValue::Enum(ident!("Priority"), 1)
            );
        }
    }
}

#[test]
fn test_command_attributes_should_be_unique() {
    let text = r#"
    command F {
        attributes {
            a: 5,
            a: "five"
        }
        seal { return todo() }
        open { return todo() }
        policy {
            finish {}
        }
    }
    "#;
    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::AlreadyDefined("a".to_string()));
}

#[test]
fn test_command_attributes_must_be_literals() {
    let texts = [
        r#"
        command A {
            attributes { i: saturating_add(2, 1) }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }"#,
        r#"
        function f() int { return 3 }
        command A {
            attributes { i: f() }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }
    "#,
    ];

    for text in texts {
        let err = compile_fail(text);
        assert!(matches!(err, CompileErrorType::InvalidExpression(_)));
    }
}

#[test]
fn test_command_with_struct_field_insertion() -> anyhow::Result<()> {
    let text = r#"
        struct Bar { a int }
        struct Baz { +Bar, b string }
        command Foo {
            fields {
                +Baz,
                c bool
            }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }
    "#;

    let module = compile_pass(text);
    let ModuleData::V0(module) = module.data;

    let want = [
        (
            ident!("a"),
            VType {
                kind: TypeKind::Int,
                span: ast::Span::empty(),
            },
        ),
        (
            ident!("b"),
            VType {
                kind: TypeKind::String,
                span: ast::Span::empty(),
            },
        ),
        (
            ident!("c"),
            VType {
                kind: TypeKind::Bool,
                span: ast::Span::empty(),
            },
        ),
    ];
    let got = module.command_defs.get("Foo").unwrap();
    assert!(
        got.fields
            .iter()
            .map(|f| (&f.name.name, &f.ty))
            .eq(want.iter().map(|(k, v)| (k, v)))
    );

    Ok(())
}

#[test]
fn test_invalid_command_field_insertion() -> anyhow::Result<()> {
    let cases = [
        (
            r#"
            command Foo {
                fields {
                    +Bar, // Bar is not defined
                    b string
                }
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
            }
            "#,
            CompileErrorType::NotDefined(String::from("Bar")),
        ),
        (
            r#"
            struct Bar { a int }
            command Foo {
                fields {
                    +Bar,
                    a bool // Duplicate field `a`
                }
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
            }
            "#,
            CompileErrorType::AlreadyDefined(String::from("a")),
        ),
    ];

    for (text, expected_error) in cases {
        let err = compile_fail(text);
        assert_eq!(err, expected_error);
    }

    Ok(())
}

#[test]
fn test_command_duplicate_fields() -> anyhow::Result<()> {
    let cases = [
        (
            r#"
        command Foo {
            fields {
                a int,
                a string
            }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }
        "#,
            CompileErrorType::AlreadyDefined(String::from("a")),
        ),
        (
            r#"
        struct Bar { a int }
        command Foo {
            fields {
                +Bar,
                a string
            }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }
        "#,
            CompileErrorType::AlreadyDefined(String::from("a")),
        ),
    ];

    for (text, e) in cases {
        let err = compile_fail(text);
        assert_eq!(err, e);
    }

    Ok(())
}

#[test]
fn test_autodefine_struct() {
    let text = r#"
        fact Foo[a int]=>{b int}

        function get_foo(a int) struct Foo {
            let foo = unwrap query Foo[a: a]=>{b: ?}

            return foo
        }
    "#;

    let module = compile_pass(text);
    let ModuleData::V0(module) = module.data;

    let want = vec![
        FieldDefinition {
            identifier: ast::Ident {
                name: ident!("a"),
                span: ast::Span::new(18, 19),
            },
            field_type: VType {
                kind: TypeKind::Int,
                span: ast::Span::new(20, 23),
            },
        },
        FieldDefinition {
            identifier: ast::Ident {
                name: ident!("b"),
                span: ast::Span::new(27, 28),
            },
            field_type: VType {
                kind: TypeKind::Int,
                span: ast::Span::new(29, 32),
            },
        },
    ];
    let got = module.struct_defs.get("Foo").unwrap();
    assert_eq!(got, &want);
}

#[test]
fn test_duplicate_struct_fact_names() {
    let texts = &[
        r#"
            // Should give an "already defined" error.
            struct Foo {}
            fact Foo[]=>{}
        "#,
        r#"
            fact Foo[]=>{}
            struct Foo {}
        "#,
    ];

    for text in texts {
        let err = compile_fail(text);
        assert!(matches!(err, CompileErrorType::AlreadyDefined(_)));
    }
}

#[test]
fn test_struct_field_insertion_errors() {
    let cases = [
        (
            "struct Foo { +Bar }",
            CompileErrorType::NotDefined("Bar".to_string()),
        ),
        (
            r#"struct Bar { a int }
            struct Foo { +Bar, a string }"#,
            CompileErrorType::AlreadyDefined("a".to_string()),
        ),
        (
            r#"struct Foo { +Foo }"#,
            CompileErrorType::Unknown(
                "Found cyclic dependencies when compiling structs:\n- [Foo]".to_string(),
            ),
        ),
    ];
    for (text, err_type) in cases {
        let err = compile_fail(text);
        assert_eq!(err, err_type, "{text}");
    }
}

#[test]
fn test_struct_field_insertion() {
    let cases = vec![
        (
            r#"
            struct Bar { a int }
            struct Foo { +Bar, b string }
            "#,
            vec![
                FieldDefinition {
                    identifier: ast::Ident {
                        name: ident!("a"),
                        span: ast::Span::empty(),
                    },
                    field_type: VType {
                        kind: TypeKind::Int,
                        span: ast::Span::empty(),
                    },
                },
                FieldDefinition {
                    identifier: ast::Ident {
                        name: ident!("b"),
                        span: ast::Span::empty(),
                    },
                    field_type: VType {
                        kind: TypeKind::String,
                        span: ast::Span::empty(),
                    },
                },
            ],
        ),
        (
            r#"
            struct Bar { a int }
            struct Baz { c bool }
            struct Foo { +Bar, b string, +Baz }
            "#,
            vec![
                FieldDefinition {
                    identifier: ast::Ident {
                        name: ident!("a"),
                        span: ast::Span::empty(),
                    },
                    field_type: VType {
                        kind: TypeKind::Int,
                        span: ast::Span::empty(),
                    },
                },
                FieldDefinition {
                    identifier: ast::Ident {
                        name: ident!("b"),
                        span: ast::Span::empty(),
                    },
                    field_type: VType {
                        kind: TypeKind::String,
                        span: ast::Span::empty(),
                    },
                },
                FieldDefinition {
                    identifier: ast::Ident {
                        name: ident!("c"),
                        span: ast::Span::empty(),
                    },
                    field_type: VType {
                        kind: TypeKind::Bool,
                        span: ast::Span::empty(),
                    },
                },
            ],
        ),
    ];

    for (text, want) in cases {
        let result = compile_pass(text);
        let ModuleData::V0(module) = result.data;

        let got = module.struct_defs.get("Foo").unwrap();
        assert_eq!(got, &want);
    }
}

#[test]
fn test_effect_with_field_insertion() {
    let text = r#"
        struct Bar { b bool }
        effect Foo { +Bar, s string }
        effect Baz { i int, +Foo }
    "#;

    let m = compile_pass(text);
    let ModuleData::V0(module) = m.data;

    let foo_want = vec![
        FieldDefinition {
            identifier: ast::Ident {
                name: ident!("b"),
                span: ast::Span::empty(),
            },
            field_type: VType {
                kind: TypeKind::Bool,
                span: ast::Span::empty(),
            },
        },
        FieldDefinition {
            identifier: ast::Ident {
                name: ident!("s"),
                span: ast::Span::empty(),
            },
            field_type: VType {
                kind: TypeKind::String,
                span: ast::Span::empty(),
            },
        },
    ];
    let foo_got = module.struct_defs.get("Foo").unwrap();
    assert_eq!(foo_got, &foo_want);

    let baz_want = vec![
        FieldDefinition {
            identifier: ast::Ident {
                name: ident!("i"),
                span: ast::Span::empty(),
            },
            field_type: VType {
                kind: TypeKind::Int,
                span: ast::Span::empty(),
            },
        },
        FieldDefinition {
            identifier: ast::Ident {
                name: ident!("b"),
                span: ast::Span::empty(),
            },
            field_type: VType {
                kind: TypeKind::Bool,
                span: ast::Span::empty(),
            },
        },
        FieldDefinition {
            identifier: ast::Ident {
                name: ident!("s"),
                span: ast::Span::empty(),
            },
            field_type: VType {
                kind: TypeKind::String,
                span: ast::Span::empty(),
            },
        },
    ];
    let baz_got = module.struct_defs.get("Baz").unwrap();
    assert_eq!(baz_got, &baz_want);
}

#[test]
fn test_enum_identifiers_are_unique() {
    let text = r#"
        enum Drink {
            Water, Coffee
        }

        enum Drink {
            Coke
        }

    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::AlreadyDefined(String::from("Drink")));
}

#[test]
fn test_enum_values_are_unique() {
    let text = r#"
        enum Drink {
            Water, Tea, Water
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::AlreadyDefined(String::from("Drink::Water"))
    );
}

#[test]
fn test_enum_reference_undefined_enum() {
    let text = r#"
        action test() {
            let n = Drink::Coffee
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::NotDefined(String::from("Drink")));
}

#[test]
fn test_enum_reference_undefined_value() {
    let text = r#"
        enum Drink { Water, Coffee }
        action test() {
            let n = Drink::Tea
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::NotDefined(String::from("Drink::Tea"))
    );
}

#[test]
fn test_enum_reference() {
    let text = r#"
        enum Result { OK, Err }
        action test() {
            let ok = Result::OK
            check ok == Result::OK
            check ok != Result::Err

            match ok {
                Result::OK => {}
                Result::Err => {}
            }
        }
    "#;

    compile_pass(text);
}

#[test]
fn test_undefined_fact() {
    let text = r#"
        action test() {
            check exists Foo[]
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::NotDefined(String::from("Foo")));
}

#[test]
fn test_fact_invalid_key_name() {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[k: 1]
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral(String::from("Invalid key: expected i, got k"))
    );
}

#[test]
fn test_fact_incomplete_key() {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[]
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral(String::from("Fact keys don't match definition"))
    );
}

#[test]
fn test_fact_nonexistent_key() {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[i:0, j:1]
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral(String::from("Fact keys don't match definition"))
    );
}

#[test]
fn test_fact_invalid_key_type() {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[i: "1"]
        }
    "#;

    let err = compile_fail(text);
    assert!(matches!(err, CompileErrorType::InvalidType(_)));
}

#[test]
fn test_fact_duplicate_key() {
    let text = r#"
        fact Foo[i int, j int] => {a string}
        action test() {
            check exists Foo[i: 1, i: 2]
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral(String::from("Invalid key: expected j, got i"))
    );
}

#[test]
fn test_fact_invalid_value_name() {
    let text = r#"
    fact Foo[k int]=>{x int}
    action test() {
        check exists Foo[k: saturating_add(1, 1)]=>{y: 5}
    }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral(String::from("Expected value x, got y"))
    );
}

#[test]
fn test_fact_invalid_value_type() {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[i: 1] => {a: true}
        }
    "#;

    let err = compile_fail(text);
    assert!(matches!(err, CompileErrorType::InvalidType(_)));
}

#[test]
fn test_fact_bind_value_type() {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[i: 1] => {a: ?}
        }
    "#;

    compile_pass(text);
}

#[test]
fn test_fact_query_disallow_leading_binds() {
    let text = r#"
    fact Foo[x int, y int] => {}
    action test() {
        check exists Foo[x: ?, y: 42] => {}
    }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral("leading bind values not allowed".to_string())
    );
}

#[test]
fn test_fact_expression_value_type() {
    let text = r#"
        fact Foo[i int] => {a int}
        action test() {
            check exists Foo[i: 1] => {a: saturating_add(1, 1)}
        }
    "#;

    compile_pass(text);
}

#[test]
fn test_fact_update_invalid_to_type() {
    let text = r#"
        fact Foo[i int] => {a string}
        command test {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    update Foo[i: 1]=>{a: 1} to {a: 0}
                }
            }
        }
    "#;

    let err = compile_fail(text);
    assert!(matches!(err, CompileErrorType::InvalidType(_)));
}

#[test]
fn test_fact_update() {
    let text = r#"
        fact Foo[i int] => {a string}
        command Test {
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    update Foo[i: 1] to {a: "updated"}
                    update Foo[i: 1]=>{a:"apple"} to {a: "orange"}
                }
            }
        }
    "#;

    compile_pass(text);
}

#[test]
fn test_immutable_fact_can_be_created_and_deleted() {
    let text = r#"
        immutable fact Foo[i int] => {a string}
        command test {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    create Foo[i: 1]=>{a: ""}
                    delete Foo[i: 1]=>{a: ""}
                }
            }
        }
    "#;

    compile_pass(text);
}

#[test]
fn test_immutable_fact_cannot_be_updated() {
    let text = r#"
        immutable fact Foo[i int] => {a string}
        command test {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    update Foo[i: 1]=>{a: 1} to {a: 0}
                }
            }
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::Unknown(String::from("fact is immutable"))
    );
}

#[test]
fn test_serialize_deserialize() {
    let text = r#"
        struct Envelope {
            payload bytes
        }
        command Foo {
            fields {}
            seal {
                return Envelope {
                    payload: serialize(this),
                }
            }
            open {
                return deserialize(envelope.payload)
            }
            policy {
                finish {}
            }
        }
    "#;

    compile_pass(text);
}

#[test]
fn finish_block_should_exit() {
    let text = r#"
        fact Blah[] => {}
        command Foo {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                check true
                finish {
                    delete Blah[]
                } // finish must be the last statement in policy
                finish {
                    delete Blah[]
                }
                let a = 5
            }
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::Unknown("`finish` must be the last statement in the block".to_owned())
    );
}

#[test]
fn test_should_not_allow_bind_key_in_fact_creation() {
    let text = r#"
        fact F[i int] => {s string}

        command CreateBindKey {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    create F[i:?] => {s: "abc"}
                }
            }
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::BadArgument("Cannot create fact with bind values".to_owned())
    );
}

#[test]
fn test_should_not_allow_bind_value_in_fact_creation() {
    let text = r#"
        fact F[i int] => {s string}

        command CreateBindValue {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    create F[i:1] => {s:?}
                }
            }
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::BadArgument("Cannot create fact with bind values".to_owned())
    );
}

#[test]
fn test_should_not_allow_bind_key_in_fact_delete() {
    let text = r#"
        fact F[i int] => {}
        command C {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    delete F[i:?]
                }
            }
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::BadArgument("Cannot delete fact with wildcard keys".to_owned())
    );
}

#[test]
fn test_should_not_allow_bind_key_in_fact_update() {
    let text = r#"
        fact F[i int] => {}
        command C {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    update F[i:?] => {} to {}
                }
            }
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::BadArgument("Cannot update fact with wildcard keys".to_owned())
    );
}

#[test]
fn test_should_not_allow_bind_value_in_fact_update() {
    let text = r#"
        fact F[] => {s string}

        command CreateBindValue {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    update F[] => {s: ""} to {s: ?}
                }
            }
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::BadArgument("Cannot update fact to a bind value".to_owned())
    );
}

#[test]
fn test_fact_duplicate_field_names() {
    let cases = [
        ("i", "fact F[i int, i string] => {a string}"),
        ("a", "fact F[i int] => {a int, a bool}"),
        ("i", "fact F[i int] => {i int}"),
    ];
    for (identifier, case) in cases {
        let err = compile_fail(case);
        assert_eq!(
            err,
            CompileErrorType::AlreadyDefined(String::from(identifier))
        );
    }
}

#[test]
fn test_fact_create_too_few_values() {
    {
        let err = compile_fail(
            r#"
        fact Device[device_id int]=>{name string, email string}

        finish function too_few() {
            create Device[device_id:1]=>{name: "bob"}
        }
        "#,
        );

        assert_eq!(
            err,
            CompileErrorType::InvalidFactLiteral("incorrect number of values".to_owned())
        );
    }

    {
        let err = compile_fail(
            r#"
        fact Device[device_id int]=>{name string, email string}

        finish function too_few() {
            create Device[device_id:1]
        }
        "#,
        );

        assert_eq!(
            err,
            CompileErrorType::InvalidFactLiteral("fact literal requires value".to_owned())
        );
    }
}

#[test]
fn test_fact_create_too_many_values() {
    let text = r#"
        fact Device[device_id int]=>{name string}

        finish function too_many() {
            create Device[device_id:1]=>{name: "bob", email: "bob@email.com"}
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral("incorrect number of values".to_owned())
    );
}

#[test]
fn test_match_duplicate() {
    let policy_str = [
        (r#"
            command Result {
                fields {
                    x int
                }
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
            }

            action foo(x int) {
                match x {
                    5 => {
                        publish Result { x: x }
                    }
                    6 => {
                        publish Result { x: x }
                    }
                    5 => {
                        publish Result { x: x }
                    }
                }
            }
        "#),
        (r#"
            action foo(i int) {
                match i {
                    1 => {}
                    _ => {}
                    _ => {}
                }
            }
        "#),
    ];

    for str in policy_str {
        let err = compile_fail(str);
        assert!(matches!(err, CompileErrorType::AlreadyDefined(_)));
    }
}

#[test]
fn test_match_alternation_duplicates() {
    let policy_str = r#"
        command Result {
            fields {
                x int
            }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }

        action foo(x int) {
            match x {
                5 | 6 => {
                    publish Result { x: x }
                }
                1 | 5 | 3  => {
                    publish Result { x: x }
                }
            }
        }
    "#;
    let err = compile_fail(policy_str);
    assert_eq!(
        err,
        CompileErrorType::AlreadyDefined(String::from("duplicate match arm value"))
    );
}

#[test]
fn test_match_default_not_last() {
    let policy_str = r#"
        command Result {
            fields {
                x int
            }
            seal { return todo() }
            open { return todo() }
            policy { }
        }

        action foo(x int) {
            match x {
                5 => {
                    publish Result { x: x }
                }
                _ => {
                    publish Result { x: 0 }
                }
                6 => {
                    publish Result { x: x }
                }
            }
        }
    "#;
    let err = compile_fail(policy_str);
    assert!(matches!(err, CompileErrorType::Unknown(_)));
}

#[test]
fn test_match_arm_should_be_limited_to_literals() {
    let policies = vec![
        r#"
            action foo(x int) {
                match x {
                    saturating_add(0, 1)=> {}
                    _ => {}
                }
            }
        "#,
        r#"
        function f() int { return 0 }
        action foo(x int) {
            match x {
                f() => {}
                _ => {}
            }
        }
        "#,
        r#"
            struct Foo {
                x int,
                y string,
            }
            struct Bar {
                y string
            }
            action foo(x struct Foo) {
                let b = Bar { y: "y" }
                match x {
                    Foo { x: 10, ...b } => {}
                    _ => {}
                }
            }
        "#,
    ];

    for text in policies {
        let err = compile_fail(text);
        assert_eq!(
            err,
            CompileErrorType::InvalidType(String::from(
                "match pattern 1 is not a literal expression"
            ))
        );
    }
}

#[test]
fn test_match_expression() {
    let invalid_cases = vec![
        (
            // arms expressions have different types
            r#"action foo(a int) {
                let x = match a {
                    1 => { :"one" }
                    _ => { :false }
                }
            }
            "#,
            CompileErrorType::InvalidType(
                "match arm expression 2 has type bool, expected string".into(),
            ),
        ),
        (
            r#"action f(n int) {
                let x = match n {
                    0 => todo()
                    1 => 1
                    _ => false
                }
            }"#,
            CompileErrorType::InvalidType(
                "match arm expression 3 has type bool, expected int".into(),
            ),
        ),
        (
            // all match patterns are not listed
            r#"
            enum LightColor {
                Red, Yellow, Green
            }

            struct Light {
                color enum LightColor,
                go bool
            }

            action f(traffic struct Light) {
                let x = match traffic {
                    Light {  color: LightColor::Red, go: false } => 0
                    Light {  color: LightColor::Yellow, go: false } => 2
                    Light {  color: LightColor::Yellow, go: true } => 3
                    Light {  color: LightColor::Green, go: false } => 4
                    Light {  color: LightColor::Green, go: true } => 5
                }
            }"#,
            CompileErrorType::MissingDefaultPattern,
        ),
        (
            // all match patterns are not listed
            r#"
            action f(maybe_bool option[bool]) {
                let x = match maybe_bool {
                    None => 0
                    Some(false) => 2
                }
            }"#,
            CompileErrorType::MissingDefaultPattern,
        ),
        (
            // all match patterns are not listed (can't exhaustively match on strings)
            r#"
            enum LightColor {
                Red, Yellow, Green
            }

            struct ColorName {
                color enum LightColor,
                name string
            }

            action f(c struct ColorName) {
                let x = match c {
                    ColorName {  color: LightColor::Red, name: "red" } => 0
                    ColorName {  color: LightColor::Yellow, name: "yellow" } => 1
                    ColorName {  color: LightColor::Green, name: "green" } => 2
                }
            }"#,
            CompileErrorType::MissingDefaultPattern,
        ),
        (
            // all match patterns are not listed (can't exhaustively match on ints)
            r#"
            function foo(c int) int {
                let x = match c {
                    0 => 0
                    1 => 1
                    2 => 2
                }

                return x
            }"#,
            CompileErrorType::MissingDefaultPattern,
        ),
        (
            r#"function f() int {
                return match None {
                    Some(true) => 0
                }
            }"#,
            CompileErrorType::MissingDefaultPattern,
        ),
        (
            r#"function f() int {
                return match None {
                    Some(true) => 0
                    None => 1
                }
            }"#,
            CompileErrorType::MissingDefaultPattern,
        ),
    ];
    for (src, expected) in invalid_cases {
        let actual = compile_fail(src);
        assert_eq!(actual, expected, "{src}");
    }

    let valid_cases = vec![
        // match expression type is that of first arm
        r#"action f(n int) {
            let b = match n {
                0 => false
                _ => true
            }
            check b
        }"#,
        // match expression type is optional
        r#"action f(n int) {
            let x = match n {
                0 => None
                _ => Some(0)
            }
        }"#,
        // exhaustively matches on structs
        r#"
        enum LightColor {
            Red, Yellow, Green
        }

        struct Light {
            color enum LightColor,
            go bool
        }

        action f(traffic struct Light) {
            let x = match traffic {
                Light {  color: LightColor::Red, go: false } => 0
                Light {  color: LightColor::Red, go: true } => 1
                Light {  color: LightColor::Yellow, go: false } => 2
                Light {  color: LightColor::Yellow, go: true } => 3
                Light {  color: LightColor::Green, go: false } => 4
                Light {  color: LightColor::Green, go: true } => 5
            }
        }"#,
        // exhaustively matches on optionals
        r#"
        action f(maybe_bool option[bool]) {
            let x = match maybe_bool {
                None => 0
                Some(true) => 1
                Some(false) => 2
            }
        }"#,
        // alternate patterns
        r#"
        action f(maybe_bool option[bool]) {
            let x = match maybe_bool {
                None | Some(false) => 0
                Some(true) => 1
            }
        }"#,
        r#"function f() int {
            return match None {
                None => 0
                Some(true) => 1
                Some(false) => 2
            }
        }"#,
    ];
    for src in valid_cases {
        compile_pass(src);
    }
}

// Note: this test is not exhaustive
#[test]
fn test_bad_statements() {
    let texts = &[
        r#"
            action foo() {
                create Foo[]=>{}
            }
        "#,
        r#"
            finish function foo() {
                let x = 3
            }
        "#,
        r#"
            function foo(x int) int {
                publish Bar{}
            }
        "#,
    ];

    for text in texts {
        let err = compile_fail(text);
        assert!(matches!(err, CompileErrorType::InvalidStatement(_)));
    }
}

#[test]
fn test_global_let_valid_expressions() {
    let cases = &[
        ("None", ConstValue::Option(None)),
        (
            "Some(42)",
            ConstValue::Option(Some(Box::new(ConstValue::Int(42)))),
        ),
        (
            "Some(None)",
            ConstValue::Option(Some(Box::new(ConstValue::NONE))),
        ),
    ];

    for (input, output) in cases {
        let module = compile_pass(&format!("let global = {input}"));
        let ModuleData::V0(data) = module.data;
        assert_eq!(data.globals["global"], *output);
    }
}

#[test]
fn test_global_let_invalid_expressions() {
    let texts = &[
        r#"
            struct Bar {
                a bool,
            }
            let x = serialize( Bar { a: true, } )
        "#,
        r#"
            fact Foo[]=>{x int}
            let x = Foo
        "#,
        r#"
            let x = envelope::author_id(envelope)
        "#,
        r#"
            // Globals cannot depend on other global variables
            let x = 42

            struct Far {
                a int,
            }

            let e = Far {
                a: x
            }
        "#,
    ];

    for text in texts {
        let err = compile_fail(text);
        assert!(matches!(err, CompileErrorType::InvalidExpression(_)));
    }
}

#[test]
fn test_global_let_duplicates() {
    let text = r#"
        let x = 10
        action foo() {
            let x = saturating_add(x, 15)
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::AlreadyDefined("x".into()));

    let text = r#"
        let x = 10
        let x = 5
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::AlreadyDefined("x".into()));
}

#[test]
fn test_field_collision() {
    let text = r#"
    struct Bar {
        x int,
        x int
    }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::AlreadyDefined(String::from("x")));
}

#[test]
fn test_invalid_finish_expressions() {
    let invalid_expression = &r#"
            fact Foo[]=>{x int}
            command Test {
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {
                        create Foo[]=>{x: saturating_add(1, 2)}
                    }
                }
            }
        "#;
    let err = compile_fail(invalid_expression);
    assert!(matches!(err, CompileErrorType::InvalidExpression(_)));
}

#[test]
fn test_count_up_to() {
    let test = r#"
        fact Foo[i int]=>{}
        function f() int {
            let x = count_up_to 0 Foo[i:?]
            return 0
        }
    "#;

    let err = compile_fail(test);
    assert_eq!(
        err,
        CompileErrorType::BadArgument("count limit must be greater than zero".to_string())
    );
}

#[test]
fn test_map_valid_in_action() {
    // map is valid only in actions
    let test = r#"
        function pets() int {
            map Pet[name:?]=>{} as p {}
            return 0
        }
    "#;
    let err = compile_fail(test);
    assert!(matches!(err, CompileErrorType::InvalidStatement(..)));

    let test = r#"
        fact Pet[name string]=>{age int}
        action pets() {
            map Pet[name:?] as p {
                let age = p.age
            }
        }
    "#;

    compile_pass(test);
}

#[test]
fn test_map_identifier_scope() {
    // Var should be available inside the `map` block
    {
        let test = r#"
            fact Pet[name string]=>{age int}
            action pets() {
                let n = 42
                map Pet[name:?] as p {
                    check p.age > 0
                    check n == 42
                }
            }
        "#;
        compile_pass(test);
    }

    let failures = [
        // `as` var should not be available before `map` block
        (
            r#"
            fact Pet[name string]=>{age int}
            action pets() {
                check p == None
                map Pet[name:?] as p {}
            }
        "#,
            CompileErrorType::NotDefined(String::from("Unknown identifier `p`")),
        ),
        // `as` should not be available after `map` block
        (
            r#"
            fact Pet[name string]=>{age int}
            action pets() {
                map Pet[name:?] as p {}
                check p == None
            }
        "#,
            CompileErrorType::NotDefined(String::from("Unknown identifier `p`")),
        ),
        // vars defined inside map should not be accessible outside it
        (
            r#"
            fact Pet[name string]=>{age int}
            action pets() {
                map Pet[name:?] as p {
                    let n = 42
                }
                check n == 42 // should not be accessible outside the block
            }
        "#,
            CompileErrorType::NotDefined(String::from("Unknown identifier `n`")),
        ),
    ];

    for (test, expected) in failures {
        let actual = compile_fail(test);
        assert_eq!(actual, expected);
    }
}

#[test]
fn test_if_match_block_scope() {
    let cases = vec![
        (
            r#"
            function foo() int {
                if true { let x = 5 }
                return x // x should not exist in the outer scope
            }"#,
            CompileErrorType::NotDefined("Unknown identifier `x`".to_string()),
        ),
        (
            r#"
            function foo() int {
                if true {}
                else { let y = 0 }
                return y
            }"#,
            CompileErrorType::NotDefined("Unknown identifier `y`".to_string()),
        ),
        (
            r#"
            function foo(b bool) int {
                match b {
                    true => { let x = 0 }
                    false => { let y = 1 }
                }
                return y
            }"#,
            CompileErrorType::NotDefined("Unknown identifier `y`".to_string()),
        ),
        (
            r#"
            function foo(b bool) int {
                match b {
                    true => { let x = 0 }
                    _ => { let y = 1 }
                }
                return y
            }"#,
            CompileErrorType::NotDefined("Unknown identifier `y`".to_string()),
        ),
    ];
    for (text, expected) in cases {
        let actual = compile_fail(text);
        assert_eq!(actual, expected);
    }
}

#[test]
fn test_type_errors() {
    struct Case {
        t: &'static str,
        e: &'static str,
    }
    let cases = [
        Case {
            t: r#"
                function f(x int) bool {
                    return saturating_add(x, "foo")
                }
            "#,
            e: "Argument 2 (`y`) in call to `saturating_add` found `string`, expected `int`",
        },
        Case {
            t: r#"
                function f() int {
                    return if 0 { :3 } else { :4 }
                }
            "#,
            e: "if condition must be a boolean expression, was type int",
        },
        Case {
            t: r#"
                function g() int {
                    return saturating_add("3", "4")
                }
            "#,
            e: "Argument 1 (`x`) in call to `saturating_add` found `string`, expected `int`",
        },
        Case {
            t: r#"
                function g() bool {
                    return 3 || 4
                }
            "#,
            e: "invalid binary operation", // TODO
        },
        Case {
            t: r#"
                function g(x int) bool {
                    return x.y
                }
            "#,
            e: "Expression left of `.` is not a struct",
        },
        Case {
            t: r#"
                struct Foo {}
                function g(x struct Foo) bool {
                    return x.y
                }
            "#,
            e: "Struct `Foo` has no member `y`",
        },
        Case {
            t: r#"
                struct Foo {a int}
                function g(x struct Foo) bool {
                    return Foo{a: false}
                }
            "#,
            e: "`Struct Foo` field `a` is not int",
        },
        Case {
            t: r#"
                function g(x string) bool {
                    return x < "test"
                }
            "#,
            e: "invalid binary operation", // TODO
        },
        Case {
            t: r#"
                function g(x int) bool {
                    return !x
                }
            "#,
            e: "cannot invert non-boolean expression of type int",
        },
        Case {
            t: r#"
                function g(x int) bool {
                    return x.y
                }
            "#,
            e: "Expression left of `.` is not a struct",
        },
        Case {
            t: r#"
                function g(x int) bool {
                    return unwrap x
                }
            "#,
            e: "Cannot unwrap non-option expression",
        },
        Case {
            t: r#"
                function g(x int) bool {
                    return x is None
                }
            "#,
            e: "`is` must operate on an optional expression",
        },
        Case {
            t: r#"
                command Foo {
                    seal { return todo() }
                    open { return todo() }
                    policy {
                        check 0
                    }
                }
            "#,
            e: "check must have boolean expression",
        },
        Case {
            t: r#"
                function f() bool {
                    return 0
                }
            "#,
            e: "Return value of `f()` must be bool",
        },
        Case {
            t: r#"
                command Foo {
                    seal { return todo() }
                    open { return todo() }
                    policy {
                        finish {
                            emit 0
                        }
                    }
                }
            "#,
            e: "Cannot emit `int`, must be an effect struct",
        },
        Case {
            t: r#"
                command Foo {
                    seal { return serialize(3) }
                    open { return todo() }
                    policy {}
                }
            "#,
            e: "serializing int, expected struct Foo",
        },
        Case {
            t: r#"
                command Foo {
                    seal {
                        return todo()
                    }
                    open {
                      return deserialize(3)
                    }
                    policy {}
                }
            "#,
            e: "deserializing int, expected bytes",
        },
        Case {
            t: r#"
                function bar(x int) bool {
                    return false
                }
                function foo() bool {
                    return bar(Some(3))
                }
            "#,
            e: "Argument 1 (`x`) in call to `bar` found `option[int]`, expected `int`",
        },
        Case {
            t: r#"
                use test
                function foo() bool {
                    return test::doit(Some(3))
                }
            "#,
            e: "Argument 1 (`x`) in FFI call to `test::doit` found `option[int]`, not `int`",
        },
        Case {
            t: r#"
                function foo(x int) bool {
                    match x {
                        "foo" => {
                        }
                        _ => {}
                    }
                }
            "#,
            e: "match pattern 1 has type string, expected type int",
        },
        Case {
            t: r#"
                function foo(x int) bool {
                    if 3 {
                    }
                }
            "#,
            e: "if condition must be a boolean expression, was type int",
        },
        Case {
            t: r#"
                action foo() {
                    publish 3
                }
            "#,
            e: "Cannot publish `int`, must be a command struct",
        },
        Case {
            t: r#"
                struct Foo {}
                action foo() {
                    publish Foo {}
                }
            "#,
            e: "Struct `Foo` is not a Command struct",
        },
        Case {
            t: r#"
                fact Foo[x int]=>{y bool}
                command MangleFoo {
                    seal { return todo() }
                    open { return todo() }
                    policy {
                        finish {
                            update Foo[x: 0]=>{y: ?} to {y: 3}
                        }
                    }
                }
            "#,
            e: "Fact `Foo` value field `y` found `int`, not `bool`",
        },
        Case {
            t: r#"
                action foo() {
                    debug_assert(3)
                }
            "#,
            e: "debug assertion must be a boolean expression, was type int",
        },
        Case {
            t: r#"
                struct Foo { x int, y bool }
                struct Bar { x string }
                function baz(b struct Bar) struct Foo {
                    let new_foo = Foo {
                        y: true,
                        ...b
                    }

                    return new_foo
                }
            "#,
            e: "Expected field `x` of `b` to be a `int`",
        },
        Case {
            t: r#"
                struct Foo { x int, y bool }
                function baz(b bool) struct Foo {
                    let new_foo = Foo {
                        y: true,
                        ...b
                    }

                    return new_foo
                }
            "#,
            e: "Expected `b` to be a struct, but it's a(n) bool",
        },
        Case {
            t: r#"
                struct Foo { x int, y bool }
                struct Bar { x string }
                function baz(b struct Bar) struct Foo {
                    let maybe_bar = if true {
                        :Some(b)
                    } else {
                        :None
                    }


                    let new_foo = Foo {
                        y: true,
                        ...maybe_bar
                    }

                    return new_foo
                }
            "#,
            e: "Expected `maybe_bar` to be a struct, but it's a(n) option[struct Bar]",
        },
        Case {
            t: r#"
                struct Baz {
                    y int,
                }
                action foo(x bool) {
                    let new_struct = x substruct Baz
                    publish new_struct
                }
            "#,
            e: "Expression to the left of the substruct operator is not a struct",
        },
        Case {
            t: r#"
                action foo() {
                    match None {
                        Some(42) => {}
                        Some("foo") => {}
                        _ => {}
                    }
                }
            "#,
            e: "match pattern 2 has type string, expected type int",
        },
    ];

    for (i, c) in cases.iter().enumerate() {
        let err = compile_fail(c.t);
        let CompileErrorType::InvalidType(s) = err else {
            panic!("Did not get InvalidType for case {i}: {err:?} ({err})");
        };
        assert_eq!(s, c.e);
    }
}

#[test]
fn test_struct_composition() {
    struct Case {
        t: &'static str,
        e: Option<&'static str>,
    }

    let valid_cases = [Case {
        t: r#"
                struct Foo { x int, y bool }
                struct Bar { x int, y bool, z string }
                function baz(foo struct Foo) struct Bar {
                    return Bar {
                        z: "z",
                        ...foo
                    }
                }
            "#,
        e: None,
    }];

    let invalid_cases = [
        Case {
            t: r#"
                struct Foo { x int, y bool }
                struct Bar { x int, y bool, z string}
                function baz(b struct Bar) struct Foo {
                    let new_foo = Foo {
                        y: true,
                        ...b
                    }

                    return new_foo
                }
            "#,
            e: Some("Struct Bar must be a subset of Struct Foo"),
        },
        Case {
            t: r#"
                struct Foo { x int, y bool }
                struct Bar { x int, y bool }
                struct Thud { x int }
                function baz(b struct Bar, t struct Thud) struct Foo {
                    let new_foo = Foo {
                        y: true,
                        ...b,
                        ...t
                    }

                    return new_foo
                }
            "#,
            e: Some("Struct Thud and Struct Bar have at least 1 field with the same name"),
        },
        Case {
            t: r#"
                struct Foo { x int, y bool }
                function baz(f struct Foo) struct Foo {
                    let new_foo = Foo {
                        x: 3,
                        y: true,
                        ...f
                    }

                    return new_foo
                }
            "#,
            e: Some(
                "A struct literal has all its fields explicitly specified while also having 1 or more struct compositions",
            ),
        },
        Case {
            t: r#"
                struct Foo { x int, y bool }

                function baz() struct Foo {
                    let new_foo = Foo {
                        ...x
                    }

                    return new_foo
                }
            "#,
            e: Some("not defined: x"),
        },
    ];

    for c in valid_cases {
        let _ = compile_pass(c.t);
    }

    for (i, c) in invalid_cases.iter().enumerate() {
        let err = compile_fail(c.t);
        match compile_fail(c.t) {
            CompileErrorType::DuplicateSourceFields(_, _) => {}
            CompileErrorType::SourceStructNotSubsetOfBase(_, _) => {}
            CompileErrorType::NotDefined(_) => {}
            CompileErrorType::NoOpStructComp => {}
            err => {
                panic!(
                    "Did not get DuplicateSourceFields, SourceStructNotSubsetOfBase, NoOpStructComp, or NotDefined for case {i}: {err:?} ({err})"
                );
            }
        }

        assert_eq!(err.to_string(), c.e.expect("Failure case"), "#{i}");
    }
}

#[test]
fn test_struct_composition_global_let_and_command_attributes() {
    let policy_str = r#"
        struct Foo {
            x int,
            y int
        }

        let foo = Foo { x: 10, y: 20 }
        let foo2 = Foo { x: 1000, ...foo }

        command Bar {
            attributes {
                foo_attr: Foo { ...foo2 },
            }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }
    "#;

    let ModuleData::V0(mod_data) = compile_pass(policy_str).data;

    let expected = ConstValue::Struct(ConstStruct {
        name: ident!("Foo"),
        fields: BTreeMap::from([
            (ident!("x"), ConstValue::Int(1000)),
            (ident!("y"), ConstValue::Int(20)),
        ]),
    });

    assert_eq!(*mod_data.globals.get("foo2").unwrap(), expected);
    assert_eq!(
        mod_data
            .command_defs
            .get("Bar")
            .unwrap()
            .attributes
            .get("foo_attr")
            .unwrap()
            .value,
        expected
    );
}

#[test]
fn test_struct_literal_duplicate_field() {
    let text = r#"
        struct S {
            x int
        }
        function f() struct S {
            return S {
                x: 1,
                x: 2,
            }
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::AlreadyDefined(String::from("x")));
}

#[test]
fn test_optional_types() {
    let cases = [
        "unwrap None",
        "42 == unwrap Some(42)",
        "None is Some",
        "None is None",
        "(Some(42)) is Some",
        "(Some(42)) is None",
    ];

    for c in cases {
        let policy_text = format!(
            r#"
            function f() bool {{
                return {c}
            }}"#
        );
        compile_pass(&policy_text);
    }
}

#[test]
fn test_duplicate_definitions() {
    struct Case {
        t: &'static str,
        e: Option<CompileErrorType>,
    }
    let cases = [
        Case {
            t: r#"
                function f() int {
                    let x = {
                        let x = 1
                        : x
                    }

                    return x
                }
            "#,
            e: None,
        },
        Case {
            t: r#"
                function f(y int) bool {
                    match y {
                        1 => { let x = 3 }
                        2 => { let x = 4 }
                        _ => {}
                    }
                    return false
                }
            "#,
            e: None,
        },
        Case {
            t: r#"
                function f(y int) bool {
                    if y == 0 {
                        let x = 3
                    }
                    else {
                        let x = 4
                    }

                    return false
                }
            "#,
            e: None,
        },
        Case {
            t: r#"
                function f() bool {
                    let x = 3
                    let x = 4
                    return false
                }
            "#,
            e: Some(CompileErrorType::AlreadyDefined(String::from('x'))),
        },
        Case {
            t: r#"
                function f() bool {
                    let x = 3
                    let x = todo()
                    return false
                }
            "#,
            e: Some(CompileErrorType::AlreadyDefined(String::from('x'))),
        },
        Case {
            t: r#"
                function f() bool {
                    let x = 3
                    let x = "foo"
                    return false
                }
            "#,
            e: Some(CompileErrorType::AlreadyDefined(String::from('x'))),
        },
        Case {
            t: r#"
                action foo(n int) {
                    let n = n
                }
            "#,
            e: Some(CompileErrorType::AlreadyDefined(String::from('n'))),
        },
        Case {
            t: r#"
                function f(b bool) int {
                    let x = 4
                    if (b) {
                        let x = 4
                        return x
                    } else {
                        return x
                    }
                }
            "#,
            e: Some(CompileErrorType::AlreadyDefined(String::from('x'))),
        },
        Case {
            t: r#"
                function f(b bool) int {
                    let x = 4
                    if (b) {
                        return x
                    } else {
                        let x = 4
                        return x
                    }
                }
            "#,
            e: Some(CompileErrorType::AlreadyDefined(String::from('x'))),
        },
    ];

    for c in cases {
        if let Some(expected) = c.e {
            let actual = compile_fail(c.t);
            assert_eq!(actual, expected);
        } else {
            compile_pass(c.t);
        }
    }
}

#[test]
fn test_action_duplicate_name() {
    let text = r#"
        action foo() {}
        action bar() {}
        action foo() {}
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::AlreadyDefined("foo".to_string()));
}

#[test]
fn test_action_call_invalid_name() {
    let text = r#"
        action foo() {
            action bad()
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::NotDefined("bad".to_string()));
}

#[test]
fn test_action_call_without_action_keyword() {
    let text = r#"
        action bar() {}
        action foo() {
            bar()
        }
    "#;

    let err = compile_fail(text);
    assert!(matches!(err, CompileErrorType::InvalidStatement(_)));
}

#[test]
fn test_action_call_not_in_action_context() {
    let text = r#"
        action bar() {}
        function foo() int {
            action bar()
            return 0
        }
    "#;

    let err = compile_fail(text);
    assert!(matches!(err, CompileErrorType::InvalidStatement(_)));
}

#[test]
fn test_action_call_wrong_args() {
    let texts = [
        (
            r#"
        action bar(n int) {}
        action foo() {
            action bar()
        }
        "#,
            CompileErrorType::BadArgument(
                "call to `bar` has 0 arguments, but it should have 1".to_string(),
            ),
        ),
        (
            r#"
        action bar(n int) {}
        action foo() {
            action bar(false)
        }
        "#,
            CompileErrorType::BadArgument(
                "invalid argument type for `n`: expected `int`, but got `bool`".to_string(),
            ),
        ),
    ];

    for (text, expected) in texts {
        let err = compile_fail(text);
        assert_eq!(err, expected);
    }
}

#[test]
fn test_action_call() {
    let text = r#"
        action bar(n int, s string) {}
        action foo() {
            action bar(1, "abc")
        }
    "#;

    compile_pass(text);
}

#[test]
fn test_validate_return() {
    let valid = [
        r#"function a() int {
            return 0 // ok
        }"#,
        r#"function c() int {
            if true {
                // no return - ok
            }
            return 6
        }"#,
        r#"function d() int {
            let n = 0
            if n > 0 {
                // ok, return at end
            }
            else {
                return 0
            }
            return 1
        }"#,
        r#"function f() int {
            if true {
                return 1
            }
            else {
                return 0
            }
            // ok
        }"#,
        r#"function g(n int) int {
            match n {
                0 => { return 0 }
                _ => { return n }
            }
        }"#,
    ];

    let invalid = [
        r#"function b() int {
            if false {
                return 0
            }
            // missing return - fail
        }"#,
        r#"function e() int {
            let n = 0
            if n > 0 {

            }
            else {
                return 0
            }
            // missing return - fail
        }"#,
    ];

    for p in valid {
        let m = compile_pass(p);
        assert!(!validate(&m));
    }

    for p in invalid {
        let m = compile_pass(p);
        assert!(validate(&m));
    }
}

#[test]
fn test_validate_publish() {
    let concat = |text| {
        let base = r#"
            command Foo {
                fields {
                    a int
                }
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
                recall {
                    finish {}
                }
            }
        "#;
        format!("{base}{text}")
    };

    let valid = [
        concat(
            r#"
            action a() {
                publish Foo { a: 0 } // ok
            }
        "#,
        ),
        concat(
            r#"
            action b() {
                if true {}

                publish Foo { a: 0 } // ok
            }
        "#,
        ),
        concat(
            r#"
            action c() {
                if true {}
                else {
                    publish Foo { a: 0 }
                }
                publish Foo { a: 1 }
            }
        "#,
        ),
        concat(
            r#"
            action d() {
                if true {
                    publish Foo { a: 0 }
                }
                else {
                    publish Foo { a: 1 }
                }
            }
        "#,
        ),
        concat(
            r#"
            action e() {
                let n = 0
                match n {
                    0 => { publish Foo { a: 0 } }
                    _ => { publish Foo { a: 1 } }
                }
            }
        "#,
        ),
    ];

    let invalid = [
        concat(
            r#"
            action f() {
                if true {
                    publish Foo { a: 0 }
                }
            }
        "#,
        ),
        concat(
            r#"
            action g() {
                if true {
                }
                else if false {
                }
                else {
                    publish Foo { a: 0 }
                }
            }
        "#,
        ),
    ];

    for p in valid {
        let m = compile_pass(&p);
        assert!(!validate(&m), "Expected case to be valid: {}", p);
    }

    for p in invalid {
        let m = compile_pass(&p);
        assert!(validate(&m), "Expected case to be invalid: {}", p);
    }
}

#[test]
fn test_return_type_not_defined() {
    let cases = [
        (
            r#"
            struct Foo {}
            function get_foo() struct Nonexistent {
                return Foo {}
            }
            "#,
            CompileErrorType::NotDefined("struct Nonexistent".to_string()),
        ),
        (
            r#"
            function f() enum Blah {
                return Blah::Foo
            }
            "#,
            CompileErrorType::NotDefined("enum Blah".to_string()),
        ),
        (
            r#"
            function f() option[struct Foo] {
                return Some(Foo {})
            }
            "#,
            CompileErrorType::NotDefined("struct Foo".to_string()),
        ),
    ];

    for (text, expected) in cases {
        let err = compile_fail(text);
        assert_eq!(err, expected);
    }
}

#[test]
fn test_function_arguments_with_undefined_types() {
    let cases = [
        (
            r#"
            function foo(x struct UndefinedStruct) int {
                return 0
            }
            "#,
            CompileErrorType::NotDefined("struct UndefinedStruct".to_string()),
        ),
        (
            r#"
            function bar(x enum UndefinedEnum) bool {
                return false
            }
            "#,
            CompileErrorType::NotDefined("enum UndefinedEnum".to_string()),
        ),
        (
            r#"
            function baz(x option[struct UndefinedStruct]) bool {
                return true
            }
            "#,
            CompileErrorType::NotDefined("struct UndefinedStruct".to_string()),
        ),
    ];

    for (text, expected) in cases {
        let err = compile_fail(text);
        assert_eq!(err, expected);
    }
}

#[test]
fn test_structs_with_undefined_types() {
    let cases = [
        (
            r#"
            fact Foo[]=>{ s struct Unknown }
            "#,
            CompileErrorType::NotDefined("struct Unknown".to_string()),
        ),
        (
            r#"
            fact Foo[]=>{ s option[struct Unknown] }
            "#,
            CompileErrorType::NotDefined("struct Unknown".to_string()),
        ),
        (
            r#"
            fact Foo[]=>{ e enum Unknown }
            "#,
            CompileErrorType::NotDefined("enum Unknown".to_string()),
        ),
        (
            r#"
            struct Bar { s struct Unknown }
            "#,
            CompileErrorType::NotDefined("struct Unknown".to_string()),
        ),
        (
            r#"
            struct Bar { e enum Unknown }
            "#,
            CompileErrorType::NotDefined("enum Unknown".to_string()),
        ),
        (
            r#"
            struct Bar { self_ref struct Bar }
            "#,
            CompileErrorType::Unknown(
                "Found cyclic dependencies when compiling structs:\n- [Bar]".into(),
            ),
        ),
        (
            r#"
            struct Bar { f int }
            fact Foo[]=>{ s struct Unknown, b struct Bar, fi struct Fi }
            struct Fi { s string }
            "#,
            CompileErrorType::NotDefined("struct Unknown".to_string()),
        ),
    ];

    for (text, expected) in cases {
        let err = compile_fail(text);
        assert_eq!(err, expected);
    }
}

#[test]
fn test_substruct_errors() {
    struct Case {
        t: &'static str,
        e: &'static str,
    }

    let cases = [
        Case {
            t: r#"
                struct Baz {
                    x string,
                    y int,
                }
                action foo(x struct Baz) {
                    let new_struct = x substruct Bar
                    publish new_struct
                }
            "#,
            e: "not defined: Struct `Bar` not defined",
        },
        Case {
            t: r#"
                struct Baz {
                    x string,
                    y int,
                }
                action foo() {
                    let new_struct = Foo { x: "x", y: 0, z: false } substruct Baz
                    publish new_struct
                }
            "#,
            e: "not defined: Struct `Foo` not defined",
        },
        Case {
            t: r#"
                command Foo {
                    fields {
                        x int,
                        y bool,
                        z string,
                    }
                    seal { return todo() }
                    open { return todo() }
                    policy {
                        finish {}
                    }
                }
                struct Bar {
                    x int,
                    y bool,
                }
                action baz(source struct Bar) {
                    publish source substruct Foo
                }
            "#,
            e: "invalid substruct operation: `Struct Foo` must be a strict subset of `Struct Bar`",
        },
    ];

    for (i, c) in cases.iter().enumerate() {
        let err = compile_fail(c.t);
        match err {
            CompileErrorType::NotDefined(_) | CompileErrorType::InvalidSubstruct(_, _) => {}
            err => {
                panic!("Did not get NotDefined or InvalidSubstruct for case {i}: {err:?} ({err})");
            }
        }

        assert_eq!(err.to_string(), c.e);
    }
}

#[test]
fn test_struct_conversion_errors() {
    let cases = [
        (
            "RHS not defined",
            r#"
            struct Foo { a int, b string }
            function convert() struct Foo {
                return Foo { a: 1, b: "test" } as Bar
            }
            "#,
            CompileErrorType::NotDefined("struct Bar".to_string()),
        ),
        (
            "types don't match",
            r#"
            struct Foo { a int, b string }
            struct Bar { a bool, b string }
            function convert() struct Bar {
                return Foo { a: 1, b: "test" } as Bar
            }
            "#,
            CompileErrorType::InvalidCast(ident!("Foo"), ident!("Bar")),
        ),
        (
            "field names don't match",
            r#"
            struct Foo { a int, b string }
            struct Bar { a bool, s string }
            function convert() struct Bar {
                return Foo { a: 1, b: "test" } as Bar
            }
            "#,
            CompileErrorType::InvalidCast(ident!("Foo"), ident!("Bar")),
        ),
        (
            "different number of fields",
            r#"
            struct Foo { a int, b string }
            struct Bar { a int, b string, c bool }
            function convert() struct Bar {
                return Foo { a: 1, b: "test" } as Bar
            }
            "#,
            CompileErrorType::InvalidCast(ident!("Foo"), ident!("Bar")),
        ),
    ];

    for (i, (msg, text, expected)) in cases.into_iter().enumerate() {
        let err = compile_fail(text);
        println!("Test case: {msg}");
        assert_eq!(err, expected, "#{i}");
    }
}

#[test]
fn test_struct_conversion() {
    let cases = [
        (
            "struct to struct",
            r#"
            struct Foo {
                a int,
                b string,
            }

            struct Bar {
                b string,
                a int,
            }

            function convert() struct Bar {
                return Foo { a: 1, b: "test" } as Bar
            }
        "#,
        ),
        (
            "struct to command",
            r#"
            struct Foo {
                a int,
                b string,
            }
            command Bar {
                fields {
                    a int,
                    b string,
                }
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
            }
            action convert() {
                let bar = Foo { a: 1, b: "test" } as Bar
                publish bar
            }
        "#,
        ),
        (
            "cast to self - noop",
            r#"
            struct Foo { a int, b string }
            function convert() struct Foo {
                return Foo { a: 1, b: "test" } as Foo
            }
            "#,
        ),
    ];

    for (msg, text) in cases {
        println!("Test case: {msg}");
        compile_pass(text);
    }
}

#[test]
fn if_expression_block() {
    let text = r#"
        action f(n int) {
            let x = if n > 1 {
                let x = saturating_add(n, 1)
                :x
            } else { :0 }
        }
    "#;

    compile_pass(text);
}

#[test]
fn test_ffi_fail_without_use() {
    let text = r#"
        function f(x int) bool {
            return test::doit(x)
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(err, CompileErrorType::NotDefined(String::from("test")));
}

/// See issue #336.
#[test]
fn test_function_used_before_definition() {
    let text = r#"
        // Returns x^n
        function pow(x int, n int) int {
            if n == 0 {
                // x^0 == x
                return 1
            }
            if n == 1 {
                // x^1 = x
                return x
            }
            if is_odd(n) {
                return multiply(x, pow(double(x), divide(saturating_sub(n, 1), 2)))
            }
            return pow(double(x), divide(n, 2))
        }

        function is_odd(x int) bool {
            return multiply(divide(x, 2), 2) != x
        }

        function double(x int) int {
            return multiply(x, 2)
        }

        function multiply(x int, y int) int {
            if x == 0 { return 0 }
            if y == 0 { return 0 }
            if x == 1 { return y }
            if y == 1 { return x }
            return saturating_add(unwrap add(x, y), multiply(x, saturating_sub(y, 1)))
        }

        function divide(x int, y int) int {
            check y > 0
            if x < y { return 0 }
            let got = divide0(Division {
                d: y,
                q: 0,
                r: x,
            })
            return got.q
        }
        struct Division {
            // Divisor
            d int,
            // Quotient
            q int,
            // Remainder. Starts == dividend
            r int,
        }
        function divide0(args struct Division) struct Division {
            let d = args.d
            let q = args.q
            let r = args.r

            check d > 0

            if r < d {
                return Division {
                    d: d,
                    q: q,
                    r: r,
                }
            }
            return divide0(Division {
                d: d,
                q: saturating_add(q, 1),
                r: saturating_sub(r, d),
            })
        }
    "#;

    compile_pass(text);
}

#[test]
fn test_action_command_persistence() {
    let valid_cases = [
        // Ephemeral action publishing ephemeral command
        r#"
            ephemeral command Cmd {
                fields {}
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
            }
            ephemeral action test() {
                publish Cmd {}
            }
        "#,
        // Persistent action publishing persistent command
        r#"
            command Cmd {
                fields {}
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
            }
            action test() {
                publish Cmd {}
            }
        "#,
    ];
    for case in valid_cases {
        compile_pass(case);
    }

    let invalid_cases = [
        // Ephemeral action publishing persistent command
        (
            r#"
                command Cmd {
                    fields {}
                    seal { return todo() }
                    open { return todo() }
                    policy {
                        finish {}
                    }
                }
                ephemeral action test() {
                    publish Cmd {}
                }
            "#,
            CompileErrorType::InvalidType(
                "ephemeral action `test` cannot publish persistent command `Cmd`".to_string(),
            ),
        ),
        // Persistent action publishing ephemeral command
        (
            r#"
                ephemeral command Cmd {
                    fields {}
                    seal { return todo() }
                    open { return todo() }
                    policy {
                        finish {}
                    }
                }
                action test() {
                    publish Cmd {}
                }
            "#,
            CompileErrorType::InvalidType(
                "persistent action `test` cannot publish ephemeral command `Cmd`".to_string(),
            ),
        ),
    ];
    for (text, expected) in invalid_cases {
        let err = compile_fail(text);
        assert_eq!(err, expected);
    }
}

#[test]
fn test_structs_listed_out_of_order() {
    let valid_cases = [
        r#"
            effect Fi { fum struct Fum }
            struct Fum { b struct Bar, f struct Foo }
            struct Bar { f struct Foo }
            struct Foo {}
        "#,
        r#"
            struct Fum { +Fi, +Foo }
            effect Fi { s string }
            fact Foo[x int]=>{ b bool }
        "#,
        r#"
            function ret_bar() struct Bar {
                let fum = Fum { b: true }
                return Bar { s: "s", num: 1, f: fum }
            }

            struct Fum { b bool }
            struct Bar { +Foo, num int, f struct Fum }
            struct Foo { s string }

        "#,
        r#"
            effect Fi { s struct Foo }
            command Foo {
                fields {
                    i int
                }
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
            }
        "#,
    ];

    let invalid_cases = [
        (
            r#"
            struct Fum { b struct Bar, f struct Foo }
            struct Bar { f struct Foo }
            struct Foo { fum struct Fum } // cycle
        "#,
            CompileErrorType::Unknown(String::from(
                "Found cyclic dependencies when compiling structs:\n- [Foo, Bar, Fum]",
            )),
        ),
        (
            r#"
            struct Fum { +Fi, +Foo }
            effect Fi { s string }
            fact Foo[x int]=>{ fum struct Fum } // cycle
        "#,
            CompileErrorType::Unknown(String::from(
                "Found cyclic dependencies when compiling structs:\n- [Foo, Fum]",
            )),
        ),
        (
            r#"
            effect Bar { s struct Co }
            command Co {
                fields {
                    fi struct Bar, // cycle
                    i int
                }
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
            }
        "#,
            CompileErrorType::Unknown(String::from(
                "Found cyclic dependencies when compiling structs:\n- [Co, Bar]",
            )),
        ),
        (
            r#"use cyclic_types"#,
            CompileErrorType::Unknown(String::from(
                "Found cyclic dependencies when compiling structs:\n- [FFIBar, FFIFoo]",
            )),
        ),
    ];

    for case in valid_cases {
        compile_pass(case);
    }

    for (src, expected_err) in invalid_cases {
        let err = compile_fail(src);
        assert_eq!(err, expected_err);
    }
}
