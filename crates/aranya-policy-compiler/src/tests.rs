#![cfg(test)]

use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::Module;

use crate::{CompileErrorType, Compiler, validate::validate};

// Helper function which parses and compiles policy expecting success.
#[track_caller]
fn compile_pass(text: &str) -> Module {
    let policy = match parse_policy_str(text, Version::V2) {
        Ok(p) => p,
        Err(err) => panic!("{err}"),
    };
    match Compiler::new(&policy).debug(true).compile() {
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
    match Compiler::new(&policy).debug(true).compile() {
        Ok(_) => panic!("policy compilation should have failed - src: {text}"),
        Err(err) => err.err_type(),
    }
}

#[test]
fn test_match_expression() {
    let invalid_cases = vec![
        (
            r#"function f(r result[int, string]) int {
                return match r {
                    Ok(n) => n
                }
            }"#,
            CompileErrorType::MissingDefaultPattern,
        ),
        (
            r#"function f(r result[int, string]) int {
                return match r {
                    Err(e) => 0
                }
            }"#,
            CompileErrorType::MissingDefaultPattern,
        ),
    ];
    for (src, expected) in invalid_cases {
        let actual = compile_fail(src);
        assert_eq!(actual, expected, "{src}");
    }
}

#[test]
fn test_match_expression_with_return() {
    let valid_cases = [
        // Basic case: return in one arm, value in another
        r#"function f(n int) int {
            let x = match n {
                0 => 1
                _ => return 2
            }
            return x
        }"#,
        // Nested match with return
        r#"function f(n int, m int) int {
            let x = match n {
                0 => match m {
                    0 => 1
                    _ => return 2
                }
                _ => 3
            }
            return x
        }"#,
    ];

    for (i, src) in valid_cases.iter().enumerate() {
        let result = std::panic::catch_unwind(|| compile_pass(src));
        if result.is_err() {
            panic!("Valid case {} failed to compile:\n{}", i, src);
        }
    }

    // Test invalid cases
    let invalid_cases = [
        (
            // Return outside function context
            r#"action f() {
                let x = match 0 {
                    0 => 1
                    _ => return 2
                }
            }"#,
            "invalid expression: Return(Int(2) @ 106..107) @ 99..124",
        ),
        (
            // Wrong return type
            r#"function f(n int) int {
                let x = match n {
                    0 => 1
                    _ => return "wrong"
                }
                return x
            }"#,
            "Return value of `f()` must be int",
        ),
    ];

    for (i, (src, expected_msg)) in invalid_cases.iter().enumerate() {
        let err = compile_fail(src);
        let err_msg = err.to_string();
        assert!(
            err_msg.contains(expected_msg),
            "Invalid case {}: Expected '{}', got '{}'",
            i,
            expected_msg,
            err_msg
        );
    }
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
fn test_result_values() {
    let invalid = [
        // Not a result type
        "function f() result[int, string] { return 0 }",
        // Ok type mismatch
        "function f() result[int, string] { return Ok(\"1\") }",
        // Err type mismatch
        "function f() result[int, string] { return Err(1) }",
    ];

    for src in invalid {
        let result = compile_fail(src);
        assert_eq!(
            result,
            CompileErrorType::InvalidType(
                "Return value of `f()` must be result[int, string]".to_string(),
            ),
            "expected error for source: {}",
            src
        );
    }
}

#[test]
fn test_result_match() {
    let policy_str = r#"
        function may_fail(x int) result[int, string] {
            if x > 0 {
                return Ok(x)
            } else {
                return Err("negative input")
            }
        }

        function match_statement(r result[int, string]) int {
            match r {
                Ok(v) => {
                    return v
                }
                Err(e) => {
                    return 0
                }
            }
        }

        function match_expr_with_return(x int) result[int, string] {
            let n = match may_fail(x) {
                Ok(n) => n
                Err(e) => return Err(e)
            }
            return Ok(n)
        }
    "#;

    compile_pass(policy_str);

    let invalid = [
        (
            r#"
        function match_duplicate_arms(r result[int, string]) int {
            return match r {
                Ok(v) => v
                Ok(v) => v
                _ => 0
            }
        }"#,
            CompileErrorType::AlreadyDefined("duplicate match arm value".to_string()),
        ),
        (
            r#"
        function f(r result[bool, bool]) int {
            return match r {
                Ok(true) | Ok(false) => 0
                Ok(x) => 1
            }
        }
        "#,
            CompileErrorType::Unknown("Result patterns cannot be used in alternation.".to_string()),
        ),
    ];
    for (src, expected) in invalid {
        let err_type = compile_fail(src);
        assert_eq!(err_type, expected);
    }
}

#[test]
fn test_match_struct_with_result_field_needs_default() {
    let err = compile_fail(
        r#"
        struct Bar { r result[int, string] }

        function foo(b struct Bar) int {
            return match b {
                Bar { r: Ok(42) } => 1
                Bar { r: Ok(16) } => 2
            }
        }
    "#,
    );
    assert_eq!(err, CompileErrorType::MissingDefaultPattern);

    compile_pass(
        r#"
        struct Bar { r result[int, string] }

        function foo(b struct Bar) int {
            return match b {
                Bar { r: Ok(42) } => 1
                Bar { r: Ok(16) } => 2
                _ => 0
            }
        }
    "#,
    );
}

#[test]
fn test_nested_result() {
    let texts = vec![
        r#"
        enum Err { Fail }
        function foo(n int) result[result[int, enum Err], enum Err] {
            if n > 0 {
                return Ok(Ok(42))
            } else {
                return Err(Err::Fail)
            }
        }
        "#,
        r#"
        enum Err { Fail }
        function foo(n int) result[option[int], enum Err] {
            if n > 0 {
                return Ok(Some(42))
            } else if n == 0 {
                return Ok(None)
            } else {
                return Err(Err::Fail)
            }
        }
        "#,
        r#"
        enum Err { Fail }
        function bar(n int) option[result[int, enum Err]] {
            if n > 0 {
                return Some(Ok(42))
            } else if n == 0 {
                return Some(Err(Err::Fail))
            } else {
                return None
            }
        }
        "#,
    ];
    for text in texts {
        compile_pass(text);
    }
}
