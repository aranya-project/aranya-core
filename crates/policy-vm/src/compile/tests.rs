#![cfg(test)]

use policy_ast::Version;
use policy_lang::lang::parse_policy_str;

use crate::{compile::error::CallColor, compile_from_policy, CompileErrorType};

#[test]
fn test_undefined_struct() -> anyhow::Result<()> {
    let text = r#"
        action foo() {
            let v = Bar {}
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    assert_eq!(
        compile_from_policy(&policy)
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

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy)
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

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy)
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

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy)
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

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy)
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
fn test_function_wrong_color_pure() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            return x
        }

        finish function g() {
            f()
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy)
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

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy)
        .expect_err("compilation succeeded where it should fail")
        .err_type;

    // Quirk: this gives us NotDefined because the compiler compiles all of the regular
    // functions _before_ the finish functions. So the finish function isn't yet defined.
    // Fixing this will require a two-pass compilation.
    assert_eq!(err, CompileErrorType::NotDefined(String::from("f")));

    Ok(())
}
