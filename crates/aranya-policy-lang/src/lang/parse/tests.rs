#![cfg(test)]
#![allow(clippy::panic)]

use aranya_policy_ast::VType;
use pest::Parser as _;
use snapbox::{ToDebug as _, assert_data_eq, str};

use super::{Pair, PolicyParser, Result, Rule, parse_expression};

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
        snapbox::str![[r#"
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
fn parse_atom_fn() -> Result<()> {
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

    Ok(())
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
fn parse_coalesce_operator() -> Result<()> {
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

    Ok(())
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
fn parse_errors() {
    // TODO: Move to file tests
    // description: String::from("Invalid function body"),
    // input: r#"function foo(x: int) bool { invalid }"#.to_string(),
    // error_message: String::from(
    //     " --> 1:29\n  |\n1 | function foo(x: int) bool { invalid }\n  \
    //         |                             ^---\n  |\n  = expected publish_statement, \
    //         let_statement, check_statement, match_statement, if_statement, finish_statement, \
    //         map_statement, create_statement, update_statement, delete_statement, \
    //         emit_statement, return_statement, recall_statement, debug_assert, function_call, \
    //         or action_call",
    // ),
}

/// Helper for testing complex type parsing.
fn parse_vtype(text: &str) -> Result<VType> {
    let pratt = super::get_pratt_parser();
    let p = super::ChunkParser::new(0, &pratt, text.len());
    let mut pairs = PolicyParser::parse(Rule::vtype, text)
        .map_err(|e| super::ParseError::from(e).with_source(text.into()))?;
    let pair = pairs.next().unwrap();
    p.parse_type(pair).map_err(|e| e.with_source(text.into()))
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
fn parse_field() -> Result<()> {
    let mut pairs = PolicyParser::parse(Rule::field_definition, "bar: int")?;

    let tokens: Vec<Pair> = pairs.next().unwrap().into_inner().collect();
    assert_eq!(tokens[0].as_rule(), Rule::identifier);
    assert_eq!(tokens[0].as_str(), "bar");
    assert_eq!(tokens[1].as_rule(), Rule::int_t);
    assert_eq!(tokens[1].as_str(), "int");
    Ok(())
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
