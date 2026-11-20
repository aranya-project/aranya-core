#![allow(clippy::panic)]

use aranya_policy_lang::lang::{
    self, Version, parse_expression, parse_policy_document, parse_policy_str, parse_vtype,
};
use snapbox::{ToDebug as _, assert_data_eq, str};

#[test]
#[allow(clippy::result_large_err)]
#[allow(deprecated)]
fn accept_only_latest_lang_version() {
    // parse string literal
    assert_data_eq!(
        parse_policy_str("", Version::V1)
            .expect_err("should not accept V1")
            .to_string(),
        str![[r#"
error: Invalid policy version 1, supported version is 2
  |
  = note: please update `policy-version` to 2
"#]]
    );

    parse_policy_str("", Version::V2).expect("should accept V2");

    // parse markdown (v1)
    let policy_v1_md = "\
---
policy-version: 1
---

```policy
```
";
    assert_data_eq!(
        parse_policy_document(policy_v1_md)
            .expect_err("should not accept V1")
            .to_string(),
        str![[r#"
error: Invalid policy version 1, supported version is 2
  |
  = note: please update `policy-version` to 2
"#]]
    );

    // parse markdown (v2)
    let policy_v2_md = "\
---
policy-version: 2
---

```policy
```
";
    parse_policy_document(policy_v2_md).expect("should accept V2");
}

#[test]
fn parse_ffi_decl() {
    let text = "function foo(x: int, y: struct bar) bool";
    let decl = lang::parse_ffi_decl(text).expect("parse");
    assert_data_eq!(decl.to_debug(), snapbox::file![_]);
}

#[test]
fn parse_ffi_decl_error() {
    let text = "function foo(x: optional optional int, y: struct bar) bool";
    let err = lang::parse_ffi_decl(text).unwrap_err();
    assert_data_eq!(err.to_string(), snapbox::file![_]);
}

/// A statement or expression ends at its last token. pest skips the
/// whitespace and comments before an optional or repeated part even when
/// the part is absent, so spans used to run on to the next token: a
/// `delete` or `let` underlined the next line too.
#[test]
fn spans_end_at_the_last_token() {
    let src = r#"
fact F[v: int]=>{}
command C with Base {
    fields { v: int }
    policy(this) {
        let found = exists F[v: this.v]   // trailing comment
        let text = "a // not a comment"
        check found else recall failed()  /* block comment */
        if found {
            let unused = 1
        }
        finish {
            delete F[v: this.v]
            // a comment
            delete F[v: 2]
        }
    }
    recall failed() { finish {} }
}
"#;
    let policy = parse_policy_str(src, Version::V2).expect("parse");
    let text = |span: aranya_policy_ast::Span| &src[span.start()..span.end()];
    let statements: Vec<&str> = policy.commands[0]
        .policy
        .body
        .iter()
        .map(|s| text(s.span))
        .collect();
    assert_eq!(
        statements[..4],
        [
            "let found = exists F[v: this.v]",
            r#"let text = "a // not a comment""#,
            "check found else recall failed()",
            "if found {\n            let unused = 1\n        }",
        ]
    );
    let aranya_policy_ast::StmtKind::Let(found) = &policy.commands[0].policy.body[0].inner else {
        panic!("expected a `let`");
    };
    assert_eq!(text(found.value.span), "exists F[v: this.v]");
    let aranya_policy_ast::StmtKind::Finish(finish) = &policy.commands[0].policy.body[4].inner
    else {
        panic!("expected a `finish`");
    };
    let deletes: Vec<&str> = finish.iter().map(|s| text(s.span)).collect();
    assert_eq!(deletes, ["delete F[v: this.v]", "delete F[v: 2]"]);
}

#[test]
fn parse_atom_number() {
    assert_data_eq!(
        parse_expression("12345").unwrap().to_debug(),
        str![[r#"
Int(
    12345 @ 0..5,
) @ 0..5

"#]]
    );
}

#[test]
fn parse_negative_number() {
    // negative integer literal
    assert_data_eq!(
        parse_expression("-42").unwrap().to_debug(),
        str![[r#"
Int(
    -42 @ 0..3,
) @ 0..3

"#]]
    );

    // minimum i64 value
    assert_data_eq!(
        parse_expression("-9223372036854775808").unwrap().to_debug(),
        str![[r#"
Int(
    -9223372036854775808 @ 0..20,
) @ 0..20

"#]]
    );
}

#[test]
fn parse_atom_fn() {
    // bare call
    assert_data_eq!(
        parse_expression(r#"call()"#).unwrap().to_debug(),
        str![[r#"
FunctionCall(
    FunctionCall {
        name: "call" @ 0..4,
        arguments: [],
    },
) @ 0..6

"#]]
    );

    // arguments
    assert_data_eq!(
        parse_expression(r#"call(3, "foo")"#).unwrap().to_debug(),
        str![[r#"
FunctionCall(
    FunctionCall {
        name: "call" @ 0..4,
        arguments: [
            Int(
                3 @ 5..6,
            ) @ 5..6,
            String(
                "foo",
            ) @ 8..13,
        ],
    },
) @ 0..14

"#]]
    );

    // terminal comma
    assert_data_eq!(
        parse_expression(r#"call(3, 4,)"#,).unwrap().to_debug(),
        str![[r#"
FunctionCall(
    FunctionCall {
        name: "call" @ 0..4,
        arguments: [
            Int(
                3 @ 5..6,
            ) @ 5..6,
            Int(
                4 @ 8..9,
            ) @ 8..9,
        ],
    },
) @ 0..11

"#]],
    );

    // calls within calls
    assert_data_eq!(
        parse_expression(r#"call(foo(), bar())"#,)
            .unwrap()
            .to_debug(),
        str![[r#"
FunctionCall(
    FunctionCall {
        name: "call" @ 0..4,
        arguments: [
            FunctionCall(
                FunctionCall {
                    name: "foo" @ 5..8,
                    arguments: [],
                },
            ) @ 5..10,
            FunctionCall(
                FunctionCall {
                    name: "bar" @ 12..15,
                    arguments: [],
                },
            ) @ 12..17,
        ],
    },
) @ 0..18

"#]],
    );

    // bad calls
    assert_data_eq!(
        parse_expression("call(,)").unwrap_err().to_string(),
        str![[r#"
error: Syntax error
  |
1 | call(,)
  |      ^ expected expression
"#]]
    );
    assert_data_eq!(
        parse_expression("call(a a)").unwrap_err().to_string(),
        str![[r#"
error: Syntax error
  |
1 | call(a a)
  |        ^ expected dot, substruct, cast, is, ?, add, subtract, greater_than, less_than, greater_than_or_equal, less_than_or_equal, equal, not_equal, and, or, or coalesce
"#]]
    );
    assert_data_eq!(
        parse_expression("call(-)").unwrap_err().to_string(),
        str![[r#"
error: Syntax error
  |
1 | call(-)
  |      ^ expected expression
"#]]
    );
}

#[test]
fn expression() {
    assert_data_eq!(
        parse_expression(r#"call(add(3, 7), saturating_sub(0, b), "foo\x7b")"#,)
            .unwrap()
            .to_debug(),
        str![[r#"
FunctionCall(
    FunctionCall {
        name: "call" @ 0..4,
        arguments: [
            FunctionCall(
                FunctionCall {
                    name: "add" @ 5..8,
                    arguments: [
                        Int(
                            3 @ 9..10,
                        ) @ 9..10,
                        Int(
                            7 @ 12..13,
                        ) @ 12..13,
                    ],
                },
            ) @ 5..14,
            FunctionCall(
                FunctionCall {
                    name: "saturating_sub" @ 16..30,
                    arguments: [
                        Int(
                            0 @ 31..32,
                        ) @ 31..32,
                        Identifier(
                            "b" @ 34..35,
                        ) @ 34..35,
                    ],
                },
            ) @ 16..36,
            String(
                "foo{",
            ) @ 38..47,
        ],
    },
) @ 0..48

"#]],
    );
}

#[test]
fn parse_coalesce_operator() {
    // Word boundary: `order` should parse as a single identifier, not `or der`.
    // There should be no coalesce operator in the expression.
    assert_data_eq!(
        parse_expression("x order").unwrap_err().to_string(),
        str![[r#"
error: Syntax error
  |
1 | x order
  |   ^ expected EOI, dot, substruct, cast, is, ?, add, subtract, greater_than, less_than, greater_than_or_equal, less_than_or_equal, equal, not_equal, and, or, or coalesce
"#]]
    );

    // Word boundary: don't split at `_`.
    assert_data_eq!(
        parse_expression("or_thing").unwrap().to_debug(),
        str![[r#"
Identifier(
    "or_thing" @ 0..8,
) @ 0..8

"#]]
    );

    // `or` can be followed by a non-whitespace, non-identifier character.
    assert_data_eq!(
        parse_expression("x or(y)").unwrap().to_debug(),
        str![[r#"
Coalesce(
    Identifier(
        "x" @ 0..1,
    ) @ 0..1,
    Identifier(
        "y" @ 5..6,
    ) @ 5..6,
) @ 0..6

"#]]
    );

    // Right-associativity: `a or b or c` should produce `Coalesce(a, Coalesce(b, c))`, not `Coalesce(Coalesce(a, b), c)`.
    assert_data_eq!(
        parse_expression("a or b or c").unwrap().to_debug(),
        str![[r#"
Coalesce(
    Identifier(
        "a" @ 0..1,
    ) @ 0..1,
    Coalesce(
        Identifier(
            "b" @ 5..6,
        ) @ 5..6,
        Identifier(
            "c" @ 10..11,
        ) @ 10..11,
    ) @ 5..11,
) @ 0..11

"#]]
    );
}

#[test]
fn parse_try_operator_precedence() {
    // Postfix ops apply left to right: `f(x)?.field` is `(f(x)?).field`.
    assert_data_eq!(
        parse_expression("f(x)?.field").unwrap().to_debug(),
        str![[r#"
Dot(
    Try(
        FunctionCall(
            FunctionCall {
                name: "f" @ 0..1,
                arguments: [
                    Identifier(
                        "x" @ 2..3,
                    ) @ 2..3,
                ],
            },
        ) @ 0..4,
    ) @ 0..5,
    "field" @ 6..11,
) @ 0..11

"#]]
    );

    // `x.y?` should parse as `(x.y)?`, i.e. `Try(Dot(x, y))`.
    assert_data_eq!(
        parse_expression("x.y?").unwrap().to_debug(),
        str![[r#"
Try(
    Dot(
        Identifier(
            "x" @ 0..1,
        ) @ 0..1,
        "y" @ 2..3,
    ) @ 0..3,
) @ 0..4

"#]]
    );

    // `?` binds tighter than prefix `!`: `!x?` is `!(x?)`.
    assert_data_eq!(
        parse_expression("!x?").unwrap().to_debug(),
        str![[r#"
Not(
    Try(
        Identifier(
            "x" @ 1..2,
        ) @ 1..2,
    ) @ 1..3,
) @ 0..3

"#]]
    );
}

#[test]
fn parse_optional() {
    #[track_caller]
    fn case(input: &str, output: snapbox::data::Inline) {
        assert_data_eq!(
            parse_vtype(input).map_or_else(|err| err.to_string(), |ok| ok.to_string()),
            output
        );
    }

    case("optional string", str!["option[string]"]);
    case("option[string]", str!["option[string]"]);
    case("optional bytes", str!["option[bytes]"]);
    case("option[bytes]", str!["option[bytes]"]);
    case("optional int", str!["option[int]"]);
    case("option[int]", str!["option[int]"]);
    case("optional bool", str!["option[bool]"]);
    case("option[bool]", str!["option[bool]"]);
    case("optional struct Foo", str!["option[struct Foo]"]);
    case("option[struct Foo]", str!["option[struct Foo]"]);
    case("option[option[bytes]]", str!["option[option[bytes]]"]);

    case(
        "optional blargh",
        str![[r#"
error: Syntax error
  |
1 | optional blargh
  |          ^ expected unit_t, bool_t, int_t, string_t, bytes_t, id_t, struct_t, enum_t, optional_t, or result_t
"#]],
    );

    case(
        "option[blargh]",
        str![[r#"
error: Syntax error
  |
1 | option[blargh]
  |        ^ expected unit_t, bool_t, int_t, string_t, bytes_t, id_t, struct_t, enum_t, optional_t, or result_t
"#]],
    );

    case(
        "optional optional bytes",
        str![[r#"
error: Invalid nested option
  |
1 | optional optional bytes
  | ^^^^^^^^^^^^^^^^^^^^^^^ Unable to use `optional T` for nested optional types.
  |
help: you should use `option[T]`
  |
1 - optional optional bytes
1 + option[option[bytes]]
  |
"#]],
    );

    case(
        "optional option[bytes]",
        str![[r#"
error: Invalid nested option
  |
1 | optional option[bytes]
  | ^^^^^^^^^^^^^^^^^^^^^^ Unable to use `optional T` for nested optional types.
  |
help: you should use `option[T]`
  |
1 - optional option[bytes]
1 + option[option[bytes]]
  |
"#]],
    );

    case(
        "option[optional bytes]",
        str![[r#"
error: Invalid nested option
  |
1 | option[optional bytes]
  | ^^^^^^^^^^^^^^^^^^^^^^ Unable to use `optional T` for nested optional types.
  |
help: you should use `option[T]`
  |
1 - option[optional bytes]
1 + option[option[bytes]]
  |
"#]],
    );
}

#[test]
fn parse_result() {
    #[track_caller]
    fn case(input: &str, output: snapbox::data::Inline) {
        assert_data_eq!(
            parse_vtype(input).map_or_else(|err| err.to_string(), |ok| ok.to_string()),
            output
        );
    }

    case("result[int, string]", str!["result[int, string]"]);
    case("result[bytes, bool]", str!["result[bytes, bool]"]);
    case(
        "result[struct Foo, string]",
        str!["result[struct Foo, string]"],
    );
    case("result[int, enum Error]", str!["result[int, enum Error]"]);

    case(
        "result[result[int, string], bool]",
        str!["result[result[int, string], bool]"],
    );

    // missing error type
    case(
        "result[int]",
        str![[r#"
error: Syntax error
  |
1 | result[int]
  |        ^ expected unit_t or bool_t
"#]],
    );

    // missing ok type
    case(
        "result[, string]",
        str![[r#"
error: Syntax error
  |
1 | result[, string]
  |        ^ expected unit_t, bool_t, int_t, string_t, bytes_t, id_t, struct_t, enum_t, optional_t, or result_t
"#]],
    );

    // invalid ok type
    case(
        "result[blargh, string]",
        str![[r#"
error: Syntax error
  |
1 | result[blargh, string]
  |        ^ expected unit_t, bool_t, int_t, string_t, bytes_t, id_t, struct_t, enum_t, optional_t, or result_t
"#]],
    );

    // invalid error type
    case(
        "result[int, blargh]",
        str![[r#"
error: Syntax error
  |
1 | result[int, blargh]
  |             ^ expected unit_t, bool_t, int_t, string_t, bytes_t, id_t, struct_t, enum_t, optional_t, or result_t
"#]],
    );
}

/// Nested option/result should only accept bracket form.
#[test]
fn parse_option_result() {
    #[track_caller]
    fn case(input: &str, output: snapbox::data::Inline) {
        assert_data_eq!(
            parse_vtype(input).map_or_else(|err| err.to_string(), |ok| ok.to_string()),
            output
        );
    }

    case(
        "result[option[int], string]",
        str!["result[option[int], string]"],
    );
    case(
        "result[int, option[string]]",
        str!["result[int, option[string]]"],
    );
    case(
        "result[option[int], option[string]]",
        str!["result[option[int], option[string]]"],
    );
    case(
        "option[result[int, string]]",
        str!["option[result[int, string]]"],
    );

    case(
        "result[optional int, string]",
        str![[r#"
error: Invalid nested option
  |
1 | result[optional int, string]
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Unable to use `optional T` for nested optional types.
  |
help: you should use `option[T]`
  |
1 - result[optional int, string]
1 + result[option[int], string]
  |
"#]],
    );

    case(
        "result[int, optional string]",
        str![[r#"
error: Invalid nested option
  |
1 | result[int, optional string]
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Unable to use `optional T` for nested optional types.
  |
help: you should use `option[T]`
  |
1 - result[int, optional string]
1 + result[int, option[string]]
  |
"#]],
    );

    case(
        "optional result[int, string]",
        str![[r#"
error: Invalid type
  |
1 | optional result[int, string]
  |          ^^^^^^^^^^^^^^^^^^^ Replace `optional T` with the new `option[T]` to use complex types
"#]],
    );
}

#[test]
fn test_result_literal() {
    #[track_caller]
    fn case(input: &str, output: snapbox::data::Inline) {
        assert_data_eq!(parse_expression(input).unwrap().to_debug(), output);
    }

    case(
        "Ok(42)",
        str![[r#"
Ok(
    Int(
        42 @ 3..5,
    ) @ 3..5,
) @ 0..6

"#]],
    );

    case(
        "Ok(true)",
        str![[r#"
Ok(
    Bool(
        true,
    ) @ 3..7,
) @ 0..8

"#]],
    );

    case(
        "Ok(get_value())",
        str![[r#"
Ok(
    FunctionCall(
        FunctionCall {
            name: "get_value" @ 3..12,
            arguments: [],
        },
    ) @ 3..14,
) @ 0..15

"#]],
    );

    case(
        "Ok(Foo {})",
        str![[r#"
Ok(
    NamedStruct(
        NamedStruct {
            name: "Foo" @ 3..6,
            fields: [],
            sources: [],
            span: 3..9,
        },
    ) @ 3..9,
) @ 0..10

"#]],
    );

    case(
        "Err(\"error message\")",
        str![[r#"
Err(
    String(
        "error message",
    ) @ 4..19,
) @ 0..20

"#]],
    );

    case(
        "Err(Error::NotFound)",
        str![[r#"
Err(
    EnumReference(
        EnumReference {
            enumeration: "Error" @ 4..9,
            variant: "NotFound" @ 11..19,
        },
    ) @ 4..19,
) @ 0..20

"#]],
    );
}

#[test]
fn parse_foreign_function_call() {
    assert_data_eq!(
        parse_expression(r#"foo::bar(5, "baz")"#)
            .unwrap()
            .to_debug(),
        str![[r#"
ForeignFunctionCall(
    ForeignFunctionCall {
        module: "foo" @ 0..3,
        function: "bar" @ 5..8,
        arguments: [
            Int(
                5 @ 9..10,
            ) @ 9..10,
            String(
                "baz",
            ) @ 12..17,
        ],
    },
) @ 0..18

"#]]
    );
}

#[test]
fn parse_struct_composition() {
    assert_data_eq!(
        parse_expression("Foo { c: false, ...x }")
            .unwrap()
            .to_debug(),
        str![[r#"
NamedStruct(
    NamedStruct {
        name: "Foo" @ 0..3,
        fields: [
            (
                "c" @ 6..7,
                Bool(
                    false,
                ) @ 9..14,
            ),
        ],
        sources: [
            "x" @ 19..20,
        ],
        span: 0..22,
    },
) @ 0..22

"#]]
    );
}

#[test]
fn parse_enum_reference() {
    assert_data_eq!(
        parse_expression("Color::Red").unwrap().to_debug(),
        str![[r#"
EnumReference(
    EnumReference {
        enumeration: "Color" @ 0..5,
        variant: "Red" @ 7..10,
    },
) @ 0..10

"#]]
    );
}
