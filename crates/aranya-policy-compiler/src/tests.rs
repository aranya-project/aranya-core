#![cfg(test)]

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
fn test_recall_blocks() {
    // Test valid cases
    let valid_cases = [
        // Command with no recall blocks
        r#"
        command Cmd {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }"#,
        // Command with one unnamed recall block
        r#"
        command Cmd {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
            recall {
            }
        }"#,
        // Command with one named recall block
        r#"
        command Cmd {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
            recall foo() {
            }
        }"#,
        // Command with one unnamed and one named recall block
        r#"
        command Cmd {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
            recall {
            }
            recall foo() {
            }
        }"#,
        // Command with multiple named recall blocks
        r#"
        command Cmd {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
            recall foo() {
            }
            recall bar() {
            }
            recall baz() {
            }
        }"#,
    ];

    for policy in valid_cases {
        compile_pass(policy);
    }

    // Test invalid cases
    let invalid_cases = [
        // Command with duplicate named recall blocks
        (
            r#"
            command Cmd {
                fields {}
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
                recall foo() {
                }
                recall foo() {
                }
            }"#,
            CompileErrorType::AlreadyDefined("recall block 'foo'".to_string()),
        ),
        // Command with two unnamed recall blocks
        (
            r#"
            command Cmd {
                fields {}
                seal { return todo() }
                open { return todo() }
                policy {
                    finish {}
                }
                recall {
                }
                recall {
                }
            }"#,
            CompileErrorType::AlreadyDefined("recall block 'default'".to_string()),
        ),
    ];

    for (policy, expected_error) in invalid_cases {
        let err = compile_fail(policy);
        assert_eq!(err, expected_error);
    }
}

#[test]
fn test_check_statement() {
    let text = r#"
        action test_action() {
            // Basic check statement
            check true
            
            // Check with else clause
            check true
        }
    "#;

    compile_pass(text);
}
