#![cfg(test)]

use anyhow::anyhow;
use policy_ast::{FieldDefinition, VType, Version};
use policy_lang::lang::parse_policy_str;
use policy_module::{ffi::ModuleSchema, Label, LabelType, ModuleData, Value};

use crate::{CallColor, CompileError, CompileErrorType, Compiler};

#[test]
fn test_compile() -> anyhow::Result<()> {
    let policy = parse_policy_str(
        r#"
        command Foo {
            fields {}
            seal { return None }
            open { return None }
        }
        action foo(b int) {
            let i = 4
            let x = if b == 0 { 4+i } else { 3 }
            let y = Foo{
                a: x,
                b: 4
            }
        }
    "#
        .trim(),
        Version::V1,
    )?;

    Compiler::new(&policy).compile()?;

    Ok(())
}

#[test]
fn test_undefined_struct() -> anyhow::Result<()> {
    let text = r#"
        action foo() {
            let v = Bar {}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    assert_eq!(
        Compiler::new(&policy)
            .compile()
            .expect_err("compilation succeeded where it should fail")
            .err_type,
        CompileErrorType::InvalidType(String::from("Struct `Bar` not defined")),
    );

    Ok(())
}

#[test]
fn test_function_no_return() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            let y = x + 1
            // no return value
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(err, CompileErrorType::NoReturn);

    Ok(())
}

#[test]
fn test_function_not_defined() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            return g()
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(
        err,
        CompileErrorType::InvalidType(String::from("Function `g` not defined"))
    );

    Ok(())
}

#[test]
fn test_function_already_defined() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            return 1
        }

        function f() int {}
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(err, CompileErrorType::AlreadyDefined(String::from("f")));

    Ok(())
}

#[test]
fn test_function_wrong_number_arguments() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            return 1
        }

        function g() int {
            return f()
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(
        err,
        CompileErrorType::BadArgument(String::from(
            "call to `f` has 0 arguments and it should have 1"
        ))
    );

    Ok(())
}

#[test]
fn test_function_duplicate_arg_names() -> anyhow::Result<()> {
    let text = r#"
        function f(x int, x int) int {
            return 1
        }

        function g() int {
            return f(1, 2)
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile();

    assert!(matches!(
        result,
        Err(CompileError {
            err_type: CompileErrorType::AlreadyDefined(_),
            ..
        })
    ));

    Ok(())
}

#[test]
fn test_function_wrong_color_pure() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            return x
        }

        finish function g() {
            f()
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(err, CompileErrorType::InvalidCallColor(CallColor::Pure));

    Ok(())
}

#[test]
fn test_function_wrong_color_finish() -> anyhow::Result<()> {
    let text = r#"
        finish function f(x int) {
            emit Foo {}
        }

        function g() int {
            return f()
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(
        err,
        CompileErrorType::InvalidType(String::from(
            "Finish functions are not allowed outside of finish blocks or finish functions"
        ))
    );

    Ok(())
}

#[test]
fn test_seal_open_command() -> anyhow::Result<()> {
    let text = r#"
        command Foo {
            fields {}
            seal { return None }
            open { return None }
            policy {}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let module = Compiler::new(&policy).compile()?;
    let ModuleData::V0(module) = module.data;

    assert!(module
        .labels
        .iter()
        .any(|l| *l.0 == Label::new("Foo", LabelType::CommandSeal)));
    assert!(module
        .labels
        .iter()
        .any(|l| *l.0 == Label::new("Foo", LabelType::CommandOpen)));

    Ok(())
}

#[test]
fn test_command_without_seal_block() -> anyhow::Result<()> {
    let text = r#"
        command Foo {
            fields {}
            policy {}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(
        err,
        CompileErrorType::Unknown(String::from("Empty/missing seal block in command"))
    );

    Ok(())
}

#[test]
fn test_command_without_open_block() -> anyhow::Result<()> {
    let text = r#"
        command Foo {
            fields {}
            seal { return None }
            policy {}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(
        err,
        CompileErrorType::Unknown(String::from("Empty/missing open block in command"))
    );

    Ok(())
}

#[test]
fn test_command_with_no_return_in_seal_block() -> anyhow::Result<()> {
    let text = r#"
        command Foo {
            fields {}
            seal { let x = 3 }
            open { return None }
            policy {}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(err, CompileErrorType::NoReturn);

    Ok(())
}

#[test]
fn test_command_with_no_return_in_open_block() -> anyhow::Result<()> {
    let text = r#"
        command Foo {
            fields {}
            seal { return None }
            open { let x = 3 }
            policy {}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(err, CompileErrorType::NoReturn);

    Ok(())
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
            seal { return None }
            open { return None }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1).expect("should parse");
    let m = Compiler::new(&policy).compile().expect("should compile");
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
                &Value::String("abc".to_string())
            );
            assert_eq!(
                attrs.get("priority").expect("should find 3nd value"),
                &Value::Enum("Priority".to_string(), "High".to_string())
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
        open { return None }
        seal { return None }
    }
    "#;
    let policy = parse_policy_str(text, Version::V1).expect("should parse");
    let err_type = Compiler::new(&policy).compile().unwrap_err().err_type;
    assert_eq!(err_type, CompileErrorType::AlreadyDefined("a".to_string()));
}

#[test]
fn test_command_attributes_must_be_literals() {
    let texts = [
        r#"
        command A {
            attributes { i: 2 + 1 }
            seal { return None }
            open { return None }
        }"#,
        r#"
        function f() int { return 3 }
        command A {
            attributes { i: f() }
            seal { return None }
            open { return None }
        }
    "#,
    ];

    for text in texts {
        let policy = parse_policy_str(text, Version::V1).expect("should parse");
        let err = Compiler::new(&policy).compile().unwrap_err().err_type;
        assert!(matches!(err, CompileErrorType::InvalidExpression(_)))
    }
}

#[test]
fn test_autodefine_struct() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[a int]=>{b int}

        function get_foo(a int) struct Foo {
            let foo = unwrap query Foo[a: a]=>{b: ?}

            return foo
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile()?;
    let ModuleData::V0(module) = result.data;

    let want = vec![
        FieldDefinition {
            identifier: "a".to_string(),
            field_type: VType::Int,
        },
        FieldDefinition {
            identifier: "b".to_string(),
            field_type: VType::Int,
        },
    ];
    let got = module.struct_defs.get("Foo").unwrap();
    assert_eq!(got, &want);

    Ok(())
}

#[test]
fn test_duplicate_struct_fact_names() -> anyhow::Result<()> {
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
        let policy = parse_policy_str(text, Version::V1)?;
        let result = Compiler::new(&policy).compile();
        assert!(matches!(
            result,
            Err(CompileError {
                err_type: CompileErrorType::AlreadyDefined(_),
                ..
            })
        ));
    }

    Ok(())
}

#[test]
fn test_enum_identifiers_are_unique() -> anyhow::Result<()> {
    let text = r#"
        enum Drink {
            Water, Coffee
        }

        enum Drink {
            Coke
        }

    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile().expect_err("").err_type;

    assert_eq!(
        result,
        CompileErrorType::AlreadyDefined(String::from("Drink"))
    );

    Ok(())
}

#[test]
fn test_enum_values_are_unique() -> anyhow::Result<()> {
    let text = r#"
        enum Drink {
            Water, Tea, Water
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile().expect_err("").err_type;

    assert_eq!(
        result,
        CompileErrorType::AlreadyDefined(String::from("Drink::Water"))
    );

    Ok(())
}

#[test]
fn test_enum_reference_undefined_enum() -> anyhow::Result<()> {
    let text = r#"
        action test() {
            let n = Drink::Coffee
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile().expect_err("").err_type;

    assert_eq!(result, CompileErrorType::NotDefined(String::from("Drink")));

    Ok(())
}

#[test]
fn test_enum_reference_undefined_value() -> anyhow::Result<()> {
    let text = r#"
        enum Drink { Water, Coffee }
        action test() {
            let n = Drink::Tea
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile().unwrap_err().err_type;

    assert_eq!(
        result,
        CompileErrorType::NotDefined(String::from("Drink::Tea"))
    );

    Ok(())
}

#[test]
fn test_enum_reference() -> anyhow::Result<()> {
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

    let policy = parse_policy_str(text, Version::V1)?;
    Compiler::new(&policy).compile().expect("should compile");

    Ok(())
}

#[test]
fn test_undefined_fact() -> anyhow::Result<()> {
    let text = r#"
        action test() {
            check exists Foo[]
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(err, CompileErrorType::NotDefined(String::from("Foo")));

    Ok(())
}

#[test]
fn test_fact_invalid_key_name() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[k: 1]
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral(String::from("Invalid key: expected i, got k"))
    );

    Ok(())
}

#[test]
fn test_fact_incomplete_key() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[]
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral(String::from("Fact keys don't match definition"))
    );

    Ok(())
}

#[test]
fn test_fact_nonexistent_key() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[i:0, j:1]
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral(String::from("Fact keys don't match definition"))
    );

    Ok(())
}

#[test]
fn test_fact_invalid_key_type() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[i: "1"]
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation should have failed")
        .err_type;
    assert!(matches!(err, CompileErrorType::InvalidType(_)));

    Ok(())
}

#[test]
fn test_fact_duplicate_key() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int, j int] => {a string}
        action test() {
            check exists Foo[i: 1, i: 2]
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral(String::from("Invalid key: expected j, got i"))
    );

    Ok(())
}

#[test]
fn test_fact_invalid_value_name() -> anyhow::Result<()> {
    let text = r#"
    fact Foo[k int]=>{x int}
    action test() {
        check exists Foo[k: 1 + 1]=>{y: 5}
    }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(
        err,
        CompileErrorType::InvalidFactLiteral(String::from("Expected value x, got y"))
    );

    Ok(())
}

#[test]
fn test_fact_invalid_value_type() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[i: 1] => {a: true}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation should have failed")
        .err_type;
    assert!(matches!(err, CompileErrorType::InvalidType(_)));

    Ok(())
}

#[test]
fn test_fact_bind_value_type() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[i: 1] => {a: ?}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    Compiler::new(&policy)
        .compile()
        .expect("compilation should have succeeded");

    Ok(())
}

#[test]
fn test_fact_expression_value_type() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int] => {a string}
        action test() {
            check exists Foo[i: 1] => {a: 1+1}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    Compiler::new(&policy)
        .compile()
        .expect("compilation should have succeeded");

    Ok(())
}

#[test]
fn test_fact_update_invalid_to_type() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int] => {a string}
        command test {
            fields {}
            seal { return None }
            open { return None }
            policy {
                finish {
                    update Foo[i: 1]=>{a: 1} to {a: 0}
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation should have failed")
        .err_type;
    assert!(matches!(err, CompileErrorType::InvalidType(_)));

    Ok(())
}

#[test]
fn test_immutable_fact_can_be_created_and_deleted() -> anyhow::Result<()> {
    let text = r#"
        immutable fact Foo[i int] => {a string}
        command test {
            fields {}
            seal { return None }
            open { return None }
            policy {
                finish {
                    create Foo[i: 1]=>{a: ""}
                    delete Foo[i: 1]=>{a: ""}
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    Compiler::new(&policy).compile()?;

    Ok(())
}

#[test]
fn test_immutable_fact_cannot_be_updated() -> anyhow::Result<()> {
    let text = r#"
        immutable fact Foo[i int] => {a string}
        command test {
            fields {}
            seal { return None }
            open { return None }
            policy {
                finish {
                    update Foo[i: 1]=>{a: 1} to {a: 0}
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(
        err,
        CompileErrorType::Unknown(String::from("fact is immutable"))
    );

    Ok(())
}

#[test]
fn test_serialize_deserialize() -> anyhow::Result<()> {
    let text = r#"
        function foo() int {
            let b = serialize(3)
            return deserialize(b)
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    Compiler::new(&policy)
        .compile()
        .expect("compilation should have succeeded");

    Ok(())
}

#[test]
fn finish_block_should_exit() -> anyhow::Result<()> {
    let text = r#"
        fact Blah[] => {}
        command Foo {
            fields {}
            seal { return None }
            open { return None }
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

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile().expect_err("").err_type;

    assert_eq!(
        result,
        CompileErrorType::Unknown("`finish` must be the last statement in the block".to_owned())
    );

    Ok(())
}

#[test]
fn test_should_not_allow_bind_key_in_fact_creation() -> anyhow::Result<()> {
    let text = r#"
        fact F[i int] => {s string}

        command CreateBindKey {
            fields {}
            seal { return None }
            open { return None }
            policy {
                finish {
                    create F[i:?] => {s: "abc"}
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile().expect_err("").err_type;

    assert_eq!(
        result,
        CompileErrorType::BadArgument("Cannot create fact with bind values".to_owned())
    );

    Ok(())
}

#[test]
fn test_should_not_allow_bind_value_in_fact_creation() -> anyhow::Result<()> {
    let text = r#"
        fact F[i int] => {s string}

        command CreateBindValue {
            fields {}
            seal { return None }
            open { return None }
            policy {
                finish {
                    create F[i:1] => {s:?}
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile().expect_err("").err_type;

    assert_eq!(
        result,
        CompileErrorType::BadArgument("Cannot create fact with bind values".to_owned())
    );

    Ok(())
}

#[test]
fn test_should_not_allow_bind_key_in_fact_update() -> anyhow::Result<()> {
    let text = r#"
        fact F[i int] => {s string}

        command CreateBindValue {
            fields {}
            seal { return None }
            open { return None }
            policy {
                finish {
                    create F[i:1] => {s: ""}
                    update F[i:?] => {s: ""} to {s: ?}
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile().expect_err("").err_type;

    assert_eq!(
        result,
        CompileErrorType::BadArgument("Cannot update fact to a bind value".to_owned())
    );

    Ok(())
}

#[test]
fn test_fact_duplicate_field_names() -> anyhow::Result<()> {
    let cases = [
        ("i", "fact F[i int, i string] => {a string}"),
        ("a", "fact F[i int] => {a int, a bool}"),
        ("i", "fact F[i int] => {i int}"),
    ];
    for (identifier, case) in cases {
        let policy = parse_policy_str(case, Version::V1)?;
        let result = Compiler::new(&policy).compile().unwrap_err().err_type;
        assert_eq!(
            result,
            CompileErrorType::AlreadyDefined(String::from(identifier))
        );
    }
    Ok(())
}

#[test]
fn test_fact_create_too_few_values() -> anyhow::Result<()> {
    {
        let policy = parse_policy_str(
            r#"
        fact User[user_id int]=>{name string, email string}

        finish function too_few() {
            create User[user_id:1]=>{name: "bob"}
        }
        "#,
            Version::V1,
        )?;
        let result = Compiler::new(&policy).compile().unwrap_err().err_type;

        assert_eq!(
            result,
            CompileErrorType::InvalidFactLiteral("incorrect number of values".to_owned())
        );
    }

    {
        let policy = parse_policy_str(
            r#"
        fact User[user_id int]=>{name string, email string}

        finish function too_few() {
            create User[user_id:1]
        }
        "#,
            Version::V1,
        )?;
        let result = Compiler::new(&policy).compile().unwrap_err().err_type;

        assert_eq!(
            result,
            CompileErrorType::InvalidFactLiteral("fact literal requires value".to_owned())
        );
    }

    Ok(())
}

#[test]
fn test_fact_create_too_many_values() -> anyhow::Result<()> {
    let text = r#"
        fact User[user_id int]=>{name string}

        finish function too_many() {
            create User[user_id:1]=>{name: "bob", email: "bob@email.com"}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let result = Compiler::new(&policy).compile().expect_err("").err_type;

    assert_eq!(
        result,
        CompileErrorType::InvalidFactLiteral("incorrect number of values".to_owned())
    );

    Ok(())
}

#[test]
fn test_match_duplicate() -> anyhow::Result<()> {
    let policy_str = r#"
        command Result {
            fields {
                x int
            }
            seal { return None }
            open { return None }
        }

        action foo(x int) {
            match x {
                5 => {
                    publish Result { x: x }
                }
                6=> {
                    publish Result { x: x }
                }
                5 => {
                    publish Result { x: x }
                }
            }
        }
    "#;
    let policy = parse_policy_str(policy_str, Version::V1)?;
    let res = Compiler::new(&policy).compile();
    assert!(matches!(
        res,
        Err(CompileError {
            err_type: CompileErrorType::AlreadyDefined(_),
            ..
        })
    ));

    Ok(())
}

#[test]
fn test_match_alternation_duplicates() -> anyhow::Result<()> {
    let policy_str = r#"
        command Result {
            fields {
                x int
            }
            seal { return None }
            open { return None }
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
    let policy = parse_policy_str(policy_str, Version::V1)?;
    let result = Compiler::new(&policy).compile().unwrap_err().err_type;
    assert_eq!(
        result,
        CompileErrorType::AlreadyDefined(String::from("duplicate match arm value"))
    );

    Ok(())
}

#[test]
fn test_match_default_not_last() -> anyhow::Result<()> {
    let policy_str = r#"
        command Result {
            fields {
                x int
            }
            seal { return None }
            open { return None }
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
    let policy = parse_policy_str(policy_str, Version::V1)?;
    let res = Compiler::new(&policy).compile();
    assert!(matches!(
        res,
        Err(CompileError {
            err_type: CompileErrorType::Unknown(_),
            ..
        })
    ));

    Ok(())
}

// Note: this test is not exhaustive
#[test]
fn test_bad_statements() -> anyhow::Result<()> {
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
        let policy = parse_policy_str(text, Version::V1)?;
        let res = Compiler::new(&policy).compile();
        assert!(matches!(
            res,
            Err(CompileError {
                err_type: CompileErrorType::InvalidStatement(_),
                ..
            })
        ));
    }

    Ok(())
}

#[test]
fn test_global_let_invalid_expressions() -> anyhow::Result<()> {
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
        let policy = parse_policy_str(text, Version::V1)?;
        let res = Compiler::new(&policy).compile();
        assert!(matches!(
            res,
            Err(CompileError {
                err_type: CompileErrorType::InvalidExpression(_),
                ..
            })
        ));
    }

    Ok(())
}

#[test]
fn test_field_collision() -> anyhow::Result<()> {
    let text = r#"
    struct Bar {
        x int,
        x int
    }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let machine = Compiler::new(&policy).compile();

    assert!(machine.is_err_and(
        |result| result.err_type == CompileErrorType::AlreadyDefined(String::from("x"))
    ));

    Ok(())
}

#[test]
fn test_invalid_finish_expressions() -> anyhow::Result<()> {
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
    let policy = parse_policy_str(invalid_expression, Version::V1)?;
    let res = Compiler::new(&policy).compile();
    assert!(matches!(
        res,
        Err(CompileError {
            err_type: CompileErrorType::InvalidExpression(_),
            ..
        })
    ));

    Ok(())
}

#[test]
fn test_count_up_to() -> anyhow::Result<()> {
    let test = r#"
        fact Foo[i int]=>{}
        function f() int {
            let x = count_up_to 0 Foo[i:?]
            return 0
        }
    "#;

    let policy = parse_policy_str(test, Version::V1)?;
    let err = Compiler::new(&policy).compile().unwrap_err().err_type;
    assert_eq!(
        err,
        CompileErrorType::BadArgument("count limit must be greater than zero".to_string())
    );

    Ok(())
}

const FAKE_SCHEMA: &[ModuleSchema<'static>] = &[ModuleSchema {
    name: "test",
    functions: &[],
    structs: &[],
}];

#[test]
fn test_type_errors() -> anyhow::Result<()> {
    struct Case {
        t: &'static str,
        e: &'static str,
    }
    let cases = [
        Case {
            t: r#"
                function f() bool {
                    let x = Foo{}
                }
            "#,
            e: "Struct `Foo` not defined",
        },
        Case {
            t: r#"
                function f() bool {
                    let x = query Foo[]
                }
            "#,
            e: "Fact `Foo` not defined",
        },
        Case {
            t: r#"
                function f(x int) bool {
                    return x + "foo"
                }
            "#,
            e: "types do not match: int and string",
        },
        Case {
            t: r#"
                function f() int {
                    return if 0 { 3 } else { 4 }
                }
            "#,
            e: "if condition must be a boolean expression",
        },
        Case {
            t: r#"
                finish function f() {}
                function g() bool {
                    return f()
                }
            "#,
            e: "Finish functions are not allowed outside of finish blocks or finish functions",
        },
        Case {
            t: r#"
                function g() bool {
                    return f()
                }
            "#,
            e: "Function `f` not defined",
        },
        Case {
            t: r#"
                function g() bool {
                    return x::f()
                }
            "#,
            e: "Module `x` not found",
        },
        Case {
            t: r#"
                function g() bool {
                    return test::f()
                }
            "#,
            e: "Foreign function `test::f` not defined",
        },
        Case {
            t: r#"
                function g() bool {
                    return x
                }
            "#,
            e: "Unknown identifier `x`",
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
                function g(x struct Foo) bool {
                    return x.y
                }
            "#,
            e: "Struct `Foo` not defined",
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
            e: "Cannot negate non-int expression",
        },
        Case {
            t: r#"
                function g(x int) bool {
                    return !x
                }
            "#,
            e: "Cannot invert non-boolean expression",
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
            e: "`is` must operate on an optional expression`",
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
            e: "Emit must be given a struct",
        },
    ];

    for c in cases {
        let policy = parse_policy_str(c.t, Version::V1)?;
        let err = Compiler::new(&policy)
            .ffi_modules(FAKE_SCHEMA)
            .compile()
            .expect_err("Did not get error")
            .err_type;
        let CompileErrorType::InvalidType(s) = err else {
            return Err(anyhow!("Did not get InvalidType: {}", err));
        };
        assert_eq!(s, c.e);
    }

    Ok(())
}
