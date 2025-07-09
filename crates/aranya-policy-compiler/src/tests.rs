#![cfg(test)]

use std::collections::BTreeMap;

use aranya_policy_ast::{FieldDefinition, VType, Version, ident, text};
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::{
    Label, LabelType, Module, ModuleData, Value,
    ffi::{self, ModuleSchema},
};

use crate::{CompileErrorType, Compiler, InvalidCallColor, validate::validate};

// Helper function which parses and compiles policy expecting success.
#[track_caller]
fn compile_pass(text: &str) -> Module {
    let policy = match parse_policy_str(text, Version::V2) {
        Ok(p) => p,
        Err(err) => panic!("{err}"),
    };
    match Compiler::new(&policy).compile() {
        Ok(m) => m,
        Err(err) => panic!("{err}"),
    }
}

// Helper function which parses and compiles policy expecting compile failure.
#[track_caller]
fn compile_fail(text: &str) -> CompileErrorType {
    let policy = match parse_policy_str(text, Version::V2) {
        Ok(p) => p,
        Err(err) => panic!("{err}"),
    };
    match Compiler::new(&policy).compile() {
        Ok(_) => panic!("policy compilation should have failed"),
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
            let x = if b == 0 { :4+i } else { :3 }
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
            let y = x + 1
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
            policy {}
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
fn test_command_without_seal_block() {
    let text = r#"
        command Foo {
            fields {}
            policy {}
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::Unknown(String::from("Empty/missing seal block in command"))
    );
}

#[test]
fn test_command_without_open_block() {
    let text = r#"
        command Foo {
            fields {}
            seal { return todo() }
            policy {}
        }
    "#;

    let err = compile_fail(text);
    assert_eq!(
        err,
        CompileErrorType::Unknown(String::from("Empty/missing open block in command"))
    );
}

#[test]
fn test_command_with_no_return_in_seal_block() {
    let text = r#"
        command Foo {
            fields {}
            seal { let x = 3 }
            open { return todo() }
            policy {}
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
            policy {}
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
        }
    "#;

    let m = compile_pass(text);
    match m.data {
        ModuleData::V0(m) => {
            let attrs = m
                .command_attributes
                .get("A")
                .expect("should find command attribute map");
            assert_eq!(attrs.len(), 3);
            assert_eq!(
                attrs.get("i").expect("should find 1st value"),
                &Value::Int(5)
            );
            assert_eq!(
                attrs.get("s").expect("should find 2nd value"),
                &Value::String(text!("abc"))
            );
            assert_eq!(
                attrs.get("priority").expect("should find 3nd value"),
                &Value::Enum(ident!("Priority"), 1)
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
        open { return todo() }
        seal { return todo() }
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
            attributes { i: 2 + 1 }
            seal { return todo() }
            open { return todo() }
        }"#,
        r#"
        function f() int { return 3 }
        command A {
            attributes { i: f() }
            seal { return todo() }
            open { return todo() }
        }
    "#,
    ];

    for text in texts {
        let err = compile_fail(text);
        assert!(matches!(err, CompileErrorType::InvalidExpression(_)))
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
            policy {}
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let ModuleData::V0(module) = module.data;

    let want = BTreeMap::from([
        (ident!("a"), VType::Int),
        (ident!("b"), VType::String),
        (ident!("c"), VType::Bool),
    ]);
    let got = module.command_defs.get("Foo").unwrap();
    assert_eq!(got, &want);

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
                policy {}
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
                policy {}
            }
            "#,
            CompileErrorType::AlreadyDefined(String::from("a")),
        ),
    ];

    for (text, expected_error) in cases {
        let policy = parse_policy_str(text, Version::V2)?;
        let err = Compiler::new(&policy).compile().unwrap_err().err_type();
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
            policy {}
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
            policy {}
        }
        "#,
            CompileErrorType::AlreadyDefined(String::from("a")),
        ),
    ];

    for (text, e) in cases {
        let policy = parse_policy_str(text, Version::V2)?;
        let err = Compiler::new(&policy).compile().unwrap_err().err_type();
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
            identifier: ident!("a"),
            field_type: VType::Int,
        },
        FieldDefinition {
            identifier: ident!("b"),
            field_type: VType::Int,
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
            CompileErrorType::NotDefined("Foo".to_string()),
        ),
    ];
    for (text, err_type) in cases {
        let err = compile_fail(text);
        assert_eq!(err, err_type);
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
                    identifier: ident!("a"),
                    field_type: VType::Int,
                },
                FieldDefinition {
                    identifier: ident!("b"),
                    field_type: VType::String,
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
                    identifier: ident!("a"),
                    field_type: VType::Int,
                },
                FieldDefinition {
                    identifier: ident!("b"),
                    field_type: VType::String,
                },
                FieldDefinition {
                    identifier: ident!("c"),
                    field_type: VType::Bool,
                },
            ],
        ),
    ];

    for (text, want) in cases {
        let policy = parse_policy_str(text, Version::V2).expect("should parse");
        let result = Compiler::new(&policy).compile().expect("should compile");
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

    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    let m = Compiler::new(&policy).compile().expect("should compile");
    let ModuleData::V0(module) = m.data;

    let foo_want = vec![
        FieldDefinition {
            identifier: ident!("b"),
            field_type: VType::Bool,
        },
        FieldDefinition {
            identifier: ident!("s"),
            field_type: VType::String,
        },
    ];
    let foo_got = module.struct_defs.get("Foo").unwrap();
    assert_eq!(foo_got, &foo_want);

    let baz_want = vec![
        FieldDefinition {
            identifier: ident!("i"),
            field_type: VType::Int,
        },
        FieldDefinition {
            identifier: ident!("b"),
            field_type: VType::Bool,
        },
        FieldDefinition {
            identifier: ident!("s"),
            field_type: VType::String,
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
        check exists Foo[k: 1 + 1]=>{y: 5}
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
fn test_fact_expression_value_type() {
    let text = r#"
        fact Foo[i int] => {a int}
        action test() {
            check exists Foo[i: 1] => {a: 1+1}
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
fn test_should_not_allow_bind_key_in_fact_update() {
    let text = r#"
        fact F[i int] => {s string}

        command CreateBindValue {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    create F[i:1] => {s: ""}
                    update F[i:?] => {s: ""} to {s: ?}
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
                    0 + 1 => {}
                }
            }
        "#,
        r#"
        function f() int { return 0 }
        action foo(x int) {
            match x {
                f() => {}
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
    ];
    for (src, expected) in invalid_cases {
        let actual = compile_fail(src);
        assert_eq!(actual, expected);
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
            let x = None
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
            let x = x + 15
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
                policy {
                    finish {
                        create Foo[]=>{x:1+2}
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

const FAKE_SCHEMA: &[ModuleSchema<'static>] = &[ModuleSchema {
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
}];

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
                    return x + "foo"
                }
            "#,
            e: "Cannot do math on non-int types",
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
                    return "3" + "4"
                }
            "#,
            e: "Cannot do math on non-int types",
        },
        Case {
            t: r#"
                function g() bool {
                    return 3 || 4
                }
            "#,
            e: "Cannot use boolean operator on non-bool types",
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
            e: "Cannot compare non-int expressions",
        },
        Case {
            t: r#"
                function g(x string) bool {
                    return -x
                }
            "#,
            e: "cannot negate non-int expression of type string",
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
                    seal {
                      return serialize(3)
                    }
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
            e: "Argument 1 (`x`) in call to `bar` found `optional int`, expected `int`",
        },
        Case {
            t: r#"
                use test
                function foo() bool {
                    return test::doit(Some(3))
                }
            "#,
            e: "Argument 1 (`x`) in FFI call to `test::doit` found `optional int`, not `int`",
        },
        Case {
            t: r#"
                function foo(x int) bool {
                    match x {
                        "foo" => {
                        }
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
    ];

    for (i, c) in cases.iter().enumerate() {
        let policy =
            parse_policy_str(c.t, Version::V2).unwrap_or_else(|err| panic!("parse error: {err}"));
        let err = Compiler::new(&policy)
            .ffi_modules(FAKE_SCHEMA)
            .debug(true) // forced on to enable debug_assert()
            .compile()
            .err()
            .unwrap_or_else(|| panic!("policy compilation should have failed"))
            .err_type();

        let CompileErrorType::InvalidType(s) = err else {
            panic!("Did not get InvalidType for case {i}: {err:?} ({err})");
        };
        assert_eq!(s, c.e);
    }
}

#[test]
fn test_optional_types() {
    let err = compile_fail("function f() bool { return unwrap None }");
    assert_eq!(
        err,
        CompileErrorType::InvalidType("Cannot unwrap None".into())
    );

    let cases = [
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
                function f(y int) bool {
                    match y {
                        1 => { let x = 3 }
                        2 => { let z = 4 }
                    }
                    return false
                }
            "#,
            e: None,
        },
        Case {
            t: r#"
                function f() bool {
                    // this will fail at runtime but is allowed by the
                    // compiler because they are the same type
                    let x = 3
                    let x = 4
                    return false
                }
            "#,
            e: None,
        },
        Case {
            t: r#"
                function f() bool {
                    // this is allowed because todo() is indeterminate
                    let x = 3
                    let x = todo()
                    return false
                }
            "#,
            e: None,
        },
        Case {
            t: r#"
                function f() bool {
                    // this, however, fails because they are definitely
                    // different types
                    let x = 3
                    let x = "foo"
                    return false
                }
        "#,
            e: Some(CompileErrorType::InvalidType(
                "type mismatch: int != string".to_string(),
            )),
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
            function f() optional struct Foo {
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
            function baz(x optional struct UndefinedStruct) bool {
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
fn if_expression_block() {
    let text = r#"
        action f(n int) {
            let x = if n > 1 {
                let x = n + 1
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

    let policy =
        parse_policy_str(text, Version::V2).unwrap_or_else(|err| panic!("parse error: {err}"));
    let err = Compiler::new(&policy)
        .ffi_modules(FAKE_SCHEMA)
        .compile()
        .err()
        .unwrap_or_else(|| panic!("policy compilation should have failed"))
        .err_type();
    assert_eq!(err, CompileErrorType::NotDefined(String::from("test")));
}
