#![cfg(test)]

use anyhow::anyhow;
use aranya_policy_ast::{FieldDefinition, VType, Version};
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::{
    ffi::{self, ModuleSchema},
    Label, LabelType, ModuleData, Value,
};

use crate::{validate::validate, CompileError, CompileErrorType, Compiler, InvalidCallColor};

#[test]
fn test_compile() -> anyhow::Result<()> {
    let policy = parse_policy_str(
        r#"
        command Foo {
            fields {
                a int,
                b int
            }
            seal { return None }
            open { return None }
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
    "#
        .trim(),
        Version::V2,
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

    let policy = parse_policy_str(text, Version::V2)?;
    assert_eq!(
        Compiler::new(&policy)
            .compile()
            .expect_err("compilation succeeded where it should fail")
            .err_type,
        CompileErrorType::NotDefined(String::from("Struct `Bar` not defined")),
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(err, CompileErrorType::NotDefined(String::from("g")));

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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(
        err,
        CompileErrorType::InvalidCallColor(InvalidCallColor::Pure)
    );

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

    let policy = parse_policy_str(text, Version::V2)?;
    let err = Compiler::new(&policy)
        .compile()
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(
        err,
        CompileErrorType::InvalidCallColor(InvalidCallColor::Finish)
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2).expect("should parse");
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
                &Value::Enum("Priority".to_string(), 1)
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
    let policy = parse_policy_str(text, Version::V2).expect("should parse");
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
        let policy = parse_policy_str(text, Version::V2).expect("should parse");
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

    let policy = parse_policy_str(text, Version::V2)?;
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
        let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
    Compiler::new(&policy)
        .compile()
        .expect("compilation should have succeeded");

    Ok(())
}

#[test]
fn test_fact_expression_value_type() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int] => {a int}
        action test() {
            check exists Foo[i: 1] => {a: 1+1}
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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
        struct Foo {}
        function foo(input struct Foo) struct Foo {
            let b = serialize(input)
            return deserialize(b)
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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

    let policy = parse_policy_str(text, Version::V2)?;
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
        let policy = parse_policy_str(case, Version::V2)?;
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
        fact Device[device_id int]=>{name string, email string}

        finish function too_few() {
            create Device[device_id:1]=>{name: "bob"}
        }
        "#,
            Version::V2,
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
        fact Device[device_id int]=>{name string, email string}

        finish function too_few() {
            create Device[device_id:1]
        }
        "#,
            Version::V2,
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
        fact Device[device_id int]=>{name string}

        finish function too_many() {
            create Device[device_id:1]=>{name: "bob", email: "bob@email.com"}
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let result = Compiler::new(&policy).compile().expect_err("").err_type;

    assert_eq!(
        result,
        CompileErrorType::InvalidFactLiteral("incorrect number of values".to_owned())
    );

    Ok(())
}

#[test]
fn test_match_duplicate() -> anyhow::Result<()> {
    let policy_str = [
        (r#"
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
        let policy = parse_policy_str(str, Version::V2)?;
        let err_type = Compiler::new(&policy).compile().unwrap_err().err_type;
        assert!(matches!(err_type, CompileErrorType::AlreadyDefined(_)));
    }

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
    let policy = parse_policy_str(policy_str, Version::V2)?;
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
    let policy = parse_policy_str(policy_str, Version::V2)?;
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

#[test]
fn test_match_arm_should_be_limited_to_literals() -> anyhow::Result<()> {
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
        let policy = parse_policy_str(text, Version::V2)?;
        let res = Compiler::new(&policy).compile().unwrap_err();
        assert_eq!(
            res.err_type,
            CompileErrorType::InvalidType(String::from("match arm is not a literal expression"))
        );
    }

    Ok(())
}

#[test]
fn test_match_expression() {
    let invalid_cases = vec![(
        // arms expressions have different types
        r#"action foo(a int) {
                let x = match a {
                    1 => { :"one" }
                    _ => { :false }
                }
            }
            "#,
        CompileErrorType::InvalidType(
            "match arm expression type mismatch; expected string, got bool".to_string(),
        ),
    )];
    for (src, result) in invalid_cases {
        let policy = parse_policy_str(src, Version::V2).expect("should parse");
        assert_eq!(
            Compiler::new(&policy).compile().unwrap_err().err_type,
            result
        );
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
        // match expression type is indeterminate
        r#"action f(n int) {
            check match n {
                0 => None
                _ => 0
            }
        }"#,
        // TODO: this should fail
        r#"action f(n int) {
            check match n {
                0 => None
                1 => 1
                _ => false
            }
        }"#,
    ];
    for src in valid_cases {
        let policy = parse_policy_str(src, Version::V2).expect("should parse");
        Compiler::new(&policy).compile().expect("should compile");
    }
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
        let policy = parse_policy_str(text, Version::V2)?;
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
        let policy = parse_policy_str(text, Version::V2)?;
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
fn test_global_let_duplicates() -> anyhow::Result<()> {
    let text = r#"
        let x = 10
        action foo() {
            let x = x + 15
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let err = Compiler::new(&policy).compile().unwrap_err();

    assert_eq!(err.err_type, CompileErrorType::AlreadyDefined("x".into()));

    let text = r#"
        let x = 10
        let x = 5
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let err = Compiler::new(&policy).compile().unwrap_err();

    assert_eq!(err.err_type, CompileErrorType::AlreadyDefined("x".into()));

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

    let policy = parse_policy_str(text, Version::V2)?;
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
    let policy = parse_policy_str(invalid_expression, Version::V2)?;
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

    let policy = parse_policy_str(test, Version::V2)?;
    let err = Compiler::new(&policy).compile().unwrap_err().err_type;
    assert_eq!(
        err,
        CompileErrorType::BadArgument("count limit must be greater than zero".to_string())
    );

    Ok(())
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
    let policy = parse_policy_str(test, Version::V2).expect("should parse");
    assert!(matches!(
        Compiler::new(&policy).compile().unwrap_err().err_type,
        CompileErrorType::InvalidStatement(..)
    ));

    let test = r#"
        fact Pet[name string]=>{age int}
        action pets() {
            map Pet[name:?] as p {
                let age = p.age
            }
        }
    "#;

    let policy = parse_policy_str(test, Version::V2).expect("should parse");
    let _module = Compiler::new(&policy).compile().expect("should compile");
}

#[test]
fn test_map_identifier_scope() -> anyhow::Result<()> {
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
        let policy = parse_policy_str(test, Version::V2)?;
        let _module = Compiler::new(&policy).compile()?;
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
        let policy = parse_policy_str(test, Version::V2)?;
        let err = Compiler::new(&policy).compile().unwrap_err().err_type;
        assert_eq!(err, expected);
    }

    Ok(())
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
    for (text, res) in cases {
        let policy = parse_policy_str(text, Version::V2).expect("should parse");
        let r = Compiler::new(&policy).compile().unwrap_err().err_type;
        assert_eq!(r, res)
    }
}

const FAKE_SCHEMA: &[ModuleSchema<'static>] = &[ModuleSchema {
    name: "test",
    functions: &[ffi::Func {
        name: "doit",
        args: &[ffi::Arg {
            name: "x",
            vtype: ffi::Type::Int,
        }],
        return_type: ffi::Type::Bool,
    }],
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
                function f(x int) bool {
                    return x + "foo"
                }
            "#,
            e: "types do not match: int and string",
        },
        Case {
            t: r#"
                function f() int {
                    return if 0 { :3 } else { :4 }
                }
            "#,
            e: "if condition must be a boolean expression",
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
            e: "Emit must be given a struct",
        },
        Case {
            t: r#"
                command Foo {
                    seal {
                      return serialize(3)
                    }
                }
            "#,
            e: "Serializing non-struct",
        },
        Case {
            t: r#"
                command Foo {
                    seal {
                        return None
                    }
                    open {
                      return deserialize(3)
                    }
                }
            "#,
            e: "Deserializing non-bytes",
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
            e: "match expression is `int` but arm expression 1 is `string`",
        },
        Case {
            t: r#"
                function foo(x int) bool {
                    if 3 {
                    }
                }
            "#,
            e: "if condition must be boolean",
        },
        Case {
            t: r#"
                function foo(x int) bool {
                    if 3 {
                    }
                }
            "#,
            e: "if condition must be boolean",
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
            e: "debug assertion must be a boolean expression",
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
        let policy = parse_policy_str(c.t, Version::V2)?;
        let err = Compiler::new(&policy)
            .ffi_modules(FAKE_SCHEMA)
            .debug(true) // forced on to enable debug_assert()
            .compile()
            .expect_err("Did not get error")
            .err_type;
        let CompileErrorType::InvalidType(s) = err else {
            return Err(anyhow!(
                "Did not get InvalidType for case {i}: {err:?} ({err})"
            ));
        };
        assert_eq!(s, c.e);
    }

    Ok(())
}

#[test]
fn test_optional_types() -> anyhow::Result<()> {
    let cases = [
        "42 == unwrap None",
        "42 == unwrap Some(42)",
        "None is Some",
        "None is None",
        "(Some(42)) is Some",
        "(Some(42)) is None",
    ];

    for (i, c) in cases.iter().enumerate() {
        let policy_text = format!(
            r#"
            function f() bool {{
                return {c}
            }}"#
        );
        let policy = parse_policy_str(&policy_text, Version::V2)?;
        Compiler::new(&policy)
            .ffi_modules(FAKE_SCHEMA)
            .compile()
            .unwrap_or_else(|e| panic!("Got error in case {i}: {e}"));
    }

    Ok(())
}

#[test]
fn test_duplicate_definitions() -> anyhow::Result<()> {
    struct Case {
        t: &'static str,
        e: Option<CompileError>,
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
                    // this is allowed because None is indeterminate
                    let x = 3
                    let x = None
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
            e: Some(CompileError::new(CompileErrorType::InvalidType(
                "Definitions of `x` do not have the same type: int != string".to_string(),
            ))),
        },
    ];

    for c in cases {
        let policy = parse_policy_str(c.t, Version::V2)?;
        let r = Compiler::new(&policy).compile().err();
        assert_eq!(r, c.e);
    }

    Ok(())
}

#[test]
fn test_action_duplicate_name() {
    let text = r#"
        action foo() {}
        action bar() {}
        action foo() {}
    "#;

    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    let err = Compiler::new(&policy).compile().unwrap_err().err_type;
    assert_eq!(err, CompileErrorType::AlreadyDefined("foo".to_string()));
}

#[test]
fn test_action_call_invalid_name() {
    let text = r#"
        action foo() {
            action bad()
        }
    "#;

    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    let err = Compiler::new(&policy).compile().unwrap_err().err_type;
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

    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    let err = Compiler::new(&policy).compile().unwrap_err().err_type;
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

    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    let err = Compiler::new(&policy).compile().unwrap_err().err_type;
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
        let policy = parse_policy_str(text, Version::V2).expect("should parse");
        let err = Compiler::new(&policy).compile().unwrap_err().err_type;
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

    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    let _m = Compiler::new(&policy).compile().expect("should compile");
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
        let policy = parse_policy_str(p, Version::V2).expect("should parse");
        let m = Compiler::new(&policy).compile().expect("should compile");
        assert!(!validate(&m));
    }

    for p in invalid {
        let policy = parse_policy_str(p, Version::V2).expect("should parse");
        let m = Compiler::new(&policy).compile().expect("should compile");
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
        let policy = parse_policy_str(text, Version::V2).expect("should parse");
        let err = Compiler::new(&policy).compile().unwrap_err().err_type;
        assert_eq!(err, expected);
    }
}

#[test]
fn test_function_arguments_with_undefined_types() -> anyhow::Result<()> {
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
        let policy = parse_policy_str(text, Version::V2).expect("should parse");
        let err = Compiler::new(&policy).compile().unwrap_err().err_type;
        assert_eq!(err, expected);
    }

    Ok(())
}

#[test]
fn test_substruct_errors() -> anyhow::Result<()> {
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
                    seal { return None }
                    open { return None }
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
        let policy = parse_policy_str(c.t, Version::V2)?;
        let err = Compiler::new(&policy)
            .ffi_modules(FAKE_SCHEMA)
            .compile()
            .expect_err("Did not get error")
            .err_type;
        match err {
            CompileErrorType::NotDefined(_) | CompileErrorType::InvalidSubstruct(_, _) => {}
            err => {
                return Err(anyhow!(
                    "Did not get NotDefined or InvalidSubstruct for case {i}: {err:?} ({err})"
                ));
            }
        }

        assert_eq!(err.to_string(), c.e);
    }

    Ok(())
}
#[test]
fn if_expression_block() {
    let cases = [(
        r#"action f(n int) {
            let x = if n > 1 {
                let x = n + 1
                :x
            } else { :0 }
        }"#,
        None,
    )];

    for (text, expected) in cases {
        println!(">");
        let policy = parse_policy_str(text, Version::V2).expect("should parse");
        let res = Compiler::new(&policy).compile().err();
        assert_eq!(res, expected);
    }
}
