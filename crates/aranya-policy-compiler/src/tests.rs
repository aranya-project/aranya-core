#![cfg(test)]

use std::panic::catch_unwind;

use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::Module;

use crate::{Compiler, validate::validate};

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

#[test]
fn test_todo_requires_debug_mode() {
    let text = r#"
        function f() int {
            check false else todo()
            return 1
        }
    "#;
    let policy = parse_policy_str(text, Version::V2).expect("parse ok");

    Compiler::new(&policy)
        .debug(true)
        .compile()
        .expect("compiles with debug mode enabled");

    let err = Compiler::new(&policy)
        .debug(false)
        .compile()
        .expect_err("`todo` requires debug mode");
    assert!(
        err.to_string().contains("todo()"),
        "unexpected error: {err}"
    );
}

// `test_fail`, like `todo()`, is only allowed when debug mode is enabled.
#[test]
fn test_fail_requires_debug_mode() {
    let text = r#"
        function f() int {
            check false else test_fail("boom")
            return 1
        }
    "#;
    let policy = parse_policy_str(text, Version::V2).expect("parse ok");

    Compiler::new(&policy)
        .debug(true)
        .compile()
        .expect("compiles with debug mode enabled");

    let err = Compiler::new(&policy)
        .debug(false)
        .compile()
        .expect_err("`test_fail` requires debug mode");
    assert!(
        err.to_string().contains("test_fail()"),
        "unexpected error: {err}"
    );
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
                recall default() {
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
fn validate_unused_values() {
    let cases = [
        (
            r#"
            function f() int {
                let x = 3 // unused variable
                return 0
            }
            "#,
            "unused variable(s): x",
        ),
        (
            r#"
            // Check that we're actually detecting ALL unused let variables
            function g() int {
                let a = 1
                let b = 2
                let c = saturating_add(a, b)
                return 0  // c is unused
            }
            "#,
            "unused variable(s): c",
        ),
        (
            r#"
            // Track variables in nested scopes
            function bar() int {
                let a = 0
                if a > 0 {
                    let x = 1 // x is unused
                }
                return a
            }
            "#,
            "unused variable(s): x",
        ),
        (
            r#"
            // Multiple unused variables in the same function
            function baz() int {
                let x = 1 // unused
                let y = 2
                let z = 3 // unused
                return y
            }
            "#,
            "unused variable(s): x, z",
        ),
        (
            r#"
            // Unused function argument
            function f(x int) int {
                return 42
            }
            "#,
            "unused variable(s): x",
        ),
        (
            r#"
            // Multiple unused function arguments
            function g(x int, y int, z int) int {
                return y
            }
            "#,
            "unused variable(s): z, x", // NOTE arg values are popped in reverse order
        ),
        (
            r#"
            // Used function argument should not error
            function h(x int) int {
                return x
            }
            "#,
            "", // Should not produce an error
        ),
        (
            r#"
            // Check inside nested blocks
            function qux() int {
                let x = 1
                if true {
                    let y = 2 // unused
                }
                return x
            }
            "#,
            "unused variable(s): y",
        ),
        (
            // Var used in one branch only is still used: no warning.
            r#"
            function f(n int) int {
                let a = n
                let b = saturating_add(n, 1)
                if n > 0 {
                    return a
                }
                else {
                    return b
                }
            }
            "#,
            "",
        ),
        (
            // Arg unused on every branch is still flagged.
            r#"
            function unused_both(x int, b bool) int {
                if b {
                    return 0
                }
                else {
                    return 1
                }
            }
            "#,
            "unused variable(s): x",
        ),
        (
            // `map ... as` uses `QueryNext`, not `Def`... ensure that ident is checked too
            r#"
            fact User[i int]=>{name string}
            command Foo {
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
            }
            action map_unused() {
                map User[i:?] as u {
                    // u is unused
                }
                publish Foo {}
            }
            "#,
            "unused variable(s): u",
        ),
        (
            r#"
            function f() int {
                let x = {
                    let y = 42 // unused
                    : 0
                }
                return x
            }"#,
            "unused variable(s): y",
        ),
        (
            r#"
            function f() int {
                let x = {
                    let x = 42 // unused
                    : 0
                }
                return x
            }"#,
            "unused variable(s): x",
        ),
    ];

    for (i, (text, expected_msg)) in cases.iter().enumerate() {
        let policy = parse_policy_str(text, Version::V2).expect("should parse");

        if expected_msg.is_empty() {
            Compiler::new(&policy).compile().expect("should compile");
        } else {
            let err = catch_unwind(|| Compiler::new(&policy).compile()).expect_err("should panic");
            let msg = err
                .downcast_ref::<String>()
                .expect("panic payload should be string");
            assert_eq!(expected_msg, msg, "case #{i}");
        }
    }
}
