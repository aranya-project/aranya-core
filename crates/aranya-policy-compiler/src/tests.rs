#![cfg(test)]

use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::Module;

use crate::{Compiler, validate::validate};

// Helper function which parses and compiles policy expecting success.
#[track_caller]
fn compile_pass(text: &str) -> Module {
    let policy = parse_policy_str(text, Version::V2).unwrap();
    Compiler::new(&policy)
        .debug(true)
        .allow_baseless(true)
        .compile()
        .unwrap()
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
fn test_validate_get_key() {
    let valid = [
        r#"
            base command Base {
                fields { key bytes }
                get_key { return Some(this.key) }
            }
        "#,
        r#"
            fact Key[author_id id]=>{key bytes}
            base command Base {
                get_key {
                    return Some((query Key[author_id: author_id] or return None).key)
                }
            }
        "#,
        r#"
            fact Key[author_id id]=>{key bytes}
            base command Base {
                get_key {
                    return match query Key[author_id: author_id] {
                        Some(f) => Some(f.key)
                        None => None
                    }
                }
            }
        "#,
        r#"
            fact Key[author_id id]=>{key bytes}
            base command Base {
                get_key {
                    match query Key[author_id: author_id] {
                        Some(f) => { return Some(f.key) }
                        None => { return None }
                    }
                }
            }
        "#,
    ];

    let invalid = [
        r#"
            base command Base {
                get_key { if false { return None } }
            }
        "#,
        r#"
            fact Key[author_id id]=>{key bytes}
            base command Base {
                get_key {
                    match query Key[author_id: author_id] {
                        Some(f) => { return Some(f.key) }
                        None => {}
                    }
                }
            }
        "#,
    ];

    // Need to use base command so label is produced.
    let common = r#"
        command C : Base {
            policy {}
        }
    "#;

    for p in valid {
        let p = p.to_string() + common;
        let m = compile_pass(&p);
        assert!(!validate(&m), "{p}");
    }

    for p in invalid {
        let p = p.to_string() + common;
        let m = compile_pass(&p);
        assert!(validate(&m), "{p}");
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
