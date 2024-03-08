#![cfg(test)]
use std::collections::BTreeMap;

use policy_ast::{FieldDefinition, VType, Version};
use policy_lang::lang::parse_policy_str;

use crate::{
    compile::error::CallColor, compile_from_policy, CompileError, CompileErrorType, Label,
    LabelType,
};

#[test]
fn test_undefined_struct() -> anyhow::Result<()> {
    let text = r#"
        action foo() {
            let v = Bar {}
        }
    "#;

    let policy = parse_policy_str(text, Version::V3)?;
    assert_eq!(
        compile_from_policy(&policy, &[])
            .expect_err("compilation succeeded where it should fail")
            .err_type,
        CompileErrorType::BadArgument(String::from("Bar")),
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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
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

    let policy = parse_policy_str(text, Version::V3)?;
    let result = compile_from_policy(&policy, &[]);

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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(err, CompileErrorType::InvalidCallColor(CallColor::Pure));

    Ok(())
}

#[test]
fn test_function_wrong_color_finish() -> anyhow::Result<()> {
    let text = r#"
        finish function f(x int) {
            effect Foo {}
        }

        function g() int {
            return f()
        }
    "#;

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    // Quirk: this gives us NotDefined because the compiler compiles all of the regular
    // functions _before_ the finish functions. So the finish function isn't yet defined.
    // Fixing this will require a two-pass compilation.
    assert_eq!(err, CompileErrorType::NotDefined(String::from("f")));

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

    let policy = parse_policy_str(text, Version::V3)?;
    let machine = compile_from_policy(&policy, &[])?;

    assert!(machine
        .labels
        .iter()
        .any(|l| *l.0 == Label::new("Foo", LabelType::CommandSeal)));
    assert!(machine
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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    assert_eq!(err, CompileErrorType::NoReturn);

    Ok(())
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

    let policy = parse_policy_str(text, Version::V3)?;
    let result = compile_from_policy(&policy, &[])?;

    assert_eq!(result.struct_defs, {
        let mut test_struct_map = BTreeMap::new();
        test_struct_map.insert(
            "Foo".to_string(),
            vec![
                FieldDefinition {
                    identifier: "a".to_string(),
                    field_type: VType::Int,
                },
                FieldDefinition {
                    identifier: "b".to_string(),
                    field_type: VType::Int,
                },
            ],
        );
        test_struct_map
    });

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
        let policy = parse_policy_str(text, Version::V3)?;
        let result = compile_from_policy(&policy, &[]);
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
fn test_undefined_fact() -> anyhow::Result<()> {
    let text = r#"
        action test() {
            check exists Foo[]
        }
    "#;

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(err, CompileErrorType::Missing(String::from("i")));

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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(err, CompileErrorType::Missing(String::from("i")));

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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(err, CompileErrorType::InvalidType);

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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(
        err,
        CompileErrorType::Unknown(String::from("Duplicate key: i"))
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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(err, CompileErrorType::NotDefined(String::from("y")));

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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(err, CompileErrorType::InvalidType);

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

    let policy = parse_policy_str(text, Version::V3)?;
    compile_from_policy(&policy, &[]).expect("compilation should have succeeded");

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

    let policy = parse_policy_str(text, Version::V3)?;
    compile_from_policy(&policy, &[]).expect("compilation should have succeeded");

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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
        .expect_err("compilation should have failed")
        .err_type;
    assert_eq!(err, CompileErrorType::InvalidType);

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

    let policy = parse_policy_str(text, Version::V3)?;
    compile_from_policy(&policy, &[])?;

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

    let policy = parse_policy_str(text, Version::V3)?;
    let err = compile_from_policy(&policy, &[])
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

    let policy = parse_policy_str(text, Version::V3)?;
    compile_from_policy(&policy, &[]).expect("compilation should have succeeded");

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
                    delete Blah[] => {}
                } // finish must be the last statement in policy
                finish {
                    delete Blah[] => {}
                }
                let a = 5
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V3)?;
    let result = compile_from_policy(&policy, &[]).expect_err("").err_type;

    assert_eq!(
        result,
        CompileErrorType::Unknown("`finish` must be the last statement in the block".to_owned())
    );

    Ok(())
}
