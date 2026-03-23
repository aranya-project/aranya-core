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
        (
            r#"
            function f() result[struct Nonexistent, int] {
                return Err(1)
            }
            "#,
            CompileErrorType::NotDefined("struct Nonexistent".to_string()),
        ),
        (
            r#"
            function f() result[int, struct Nonexistent] {
                return Ok(1)
            }
            "#,
            CompileErrorType::NotDefined("struct Nonexistent".to_string()),
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
fn test_match_result_duplicate_arms() {
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
            function match_result_alternation_duplicate(r result[int, string]) int {
                match r {
                    Ok(1) | Ok(1) => { return 1 }
                    _ => { return -1 }
                }
            }"#,
            CompileErrorType::AlreadyDefined("duplicate match arm value".to_string()),
        ),
        (
            r#"
            function match_result_alternation_duplicate(r result[int, string]) int {
                match r {
                    Ok(1) | Ok(2) => { return 1 }
                    Ok(2) => { return 2 } // duplicate
                    _ => { return -1 }
                }
            }"#,
            CompileErrorType::AlreadyDefined("duplicate match arm value".to_string()),
        ),
        (
            r#"
            function dup(r result[bool, bool]) int {
                match r {
                    Ok(true) => { return 1 }
                    Ok(true) => { return 2 } // duplicate
                    Ok(false) => { return 0 }
                    Err(e) => { return -1 }
                }
            }"#,
            CompileErrorType::AlreadyDefined("duplicate match arm value".to_string()),
        ),
    ];
    for (src, expected) in invalid {
        let err_type = compile_fail(src);
        assert_eq!(err_type, expected);
    }
}

#[test]
fn test_result_default() {
    let valid = vec![
        r#"
        function f(r result[bool, bool]) int {
            match r {
                Ok(true) | Ok(false) => { return 1 }
                Err(true) => { return -1 }
                Err(false) => { return -2 }
            }
        }
        "#,
        r#"
        function f(r result[bool, bool]) int {
            match r {
                Ok(a) => { return 1 } // this accounts for both Ok(true) and Ok(false)
                Err(true) => { return -1 }
                Err(false) => { return -2 }
            }
        }
        "#,
    ];

    for src in valid {
        compile_pass(src);
    }

    let invalid = [
        (
            r#"
            function missing_err_default(r result[bool, string]) int {
                return match r {
                    Ok(true) => 1
                    Ok(false) => 0
                    // missing Err(_) arm, so not exhaustive
                }
            }"#,
            CompileErrorType::MissingDefaultPattern,
        ),
        (
            r#"
            function missing_err_default(r result[bool, bool]) int {
                return match r {
                    Ok(n) => 1
                    Err(true) => 0
                    // missing Err(false) arm, so not exhaustive
                }
            }"#,
            CompileErrorType::MissingDefaultPattern,
        ),
        (
            r#"
            function g() bool {
                return true
            }

            function non_literal_ok_inner(r result[bool, bool]) int {
                return match r {
                    Ok(g()) => 1
                    Err(e) => 0
                }
            }"#,
            CompileErrorType::InvalidType(
                "Result pattern value must be a literal or an identifier".to_string(),
            ),
        ),
        (
            r#"
            struct S {
                x bool,
            }

            function non_literal_ok_property(r result[bool, bool], s struct S) int {
                return match r {
                    Ok(s.x) => 1
                    Err(e) => 0
                }
            }"#,
            CompileErrorType::InvalidType(
                "Result pattern value must be a literal or an identifier".to_string(),
            ),
        ),
        (
            r#"
            function f(r result[bool, bool]) int {
                match r {
                    Ok(true) => { return 0 }
                    Err(e) => { return 0 }
                    Err(true) => { return -1 }  // previous arm already catches all Err cases, so these are unreachable
                    Err(false) => { return -2 }
                }
            }
            "#,
            CompileErrorType::UnreachableMatchArm,
        ),
        (
            r#"
            function f(r result[bool, bool]) int {
                match r {
                    Ok(n) => { return 0 }
                    Ok(true) => { return 1 } // unreachable: Ok(n) already covers all Ok values
                    Err(e) => { return -1 }
                }
            }
            "#,
            CompileErrorType::UnreachableMatchArm,
        ),
    ];
    for (src, expected) in invalid {
        let err_type = compile_fail(src);
        assert_eq!(err_type, expected);
    }
}

#[test]
fn test_result_match_matrix() {
    let valid = [
        (
            r#"
            function v3(r result[int, bool]) int {
                return match r {
                    Ok(1) => 1
                    Ok(n) => n
                    Err(true) => -1
                    Err(false) => -2
                }
            }
            "#,
            "literal before binding for same variant is allowed",
        ),
        (
            r#"
            function v5(r result[bool, string]) int {
                return match r {
                    Ok(true) => 1
                    _ => 0
                }
            }
            "#,
            "default handles open Err domain",
        ),
        (
            r#"
            function v6(r result[bool, bool]) int {
                return match r {
                    Err(true) => -1
                    Err(false) => -2
                    Ok(b) => 1
                }
            }
            "#,
            "variant order should not matter for exhaustiveness",
        ),
    ];

    for (src, msg) in valid {
        let result = compile(src);
        assert!(result.is_ok(), "{msg}: {src}");
    }

    let invalid = [
        (
            r#"
            function i2(r result[bool, bool]) int {
                return match r {
                    Err(e) => 0
                    Err(x) => 1
                    Ok(v) => 2
                }
            }
            "#,
            CompileErrorType::AlreadyDefined("duplicate match arm value".to_string()),
            "duplicate Err bindings",
        ),
        (
            r#"
            function i9(r result[bool, bool]) int {
                return match r {
                    _ => 0
                    Ok(true) => 1
                }
            }
            "#,
            CompileErrorType::Unknown("Default match case must be last.".to_string()),
            "default not last",
        ),
        (
            r#"
            function i10(r result[bool, bool]) int {
                return match r {
                    _ => 0
                    _ => 1
                }
            }
            "#,
            CompileErrorType::AlreadyDefined("duplicate match arm default value".to_string()),
            "duplicate default arm",
        ),
    ];

    for (src, expected, msg) in invalid {
        let err = compile_fail(src);
        assert_eq!(err, expected, "{msg}: {src}");
    }
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
