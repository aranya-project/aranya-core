#![allow(clippy::panic)]

use aranya_policy_ast::VType;
use pest::{Parser as _, error::Error as PestError, iterators::Pair};

use super::{ChunkParser, ParseError, PolicyParser, Rule, get_pratt_parser};

#[test]
#[allow(clippy::result_large_err)]
fn parse_atom_number() -> Result<(), PestError<Rule>> {
    let mut pair = PolicyParser::parse(Rule::atom, "12345")?;
    let token: Pair<'_, Rule> = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::int_literal);

    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_negative_number() -> Result<(), PestError<Rule>> {
    // negative integer literal
    let mut pair = PolicyParser::parse(Rule::atom, "-42")?;
    let token: Pair<'_, Rule> = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::int_literal);
    assert_eq!(token.as_str(), "-42");

    // minimum i64 value
    let mut pair = PolicyParser::parse(Rule::atom, "-9223372036854775808")?;
    let token: Pair<'_, Rule> = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::int_literal);
    assert_eq!(token.as_str(), "-9223372036854775808");

    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_atom_string() -> Result<(), PestError<Rule>> {
    // basic string
    let mut pair = PolicyParser::parse(Rule::atom, r#""foo bar""#)?;
    let token: Pair<'_, Rule> = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::string_literal);

    // empty string
    let mut pair = PolicyParser::parse(Rule::atom, r#""""#)?;
    let token: Pair<'_, Rule> = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::string_literal);

    // escapes
    let mut pair = PolicyParser::parse(Rule::atom, r#""\n\xf7\\""#)?;
    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::string_literal);

    // invalid escapes
    let cases = vec![r#""\b""#, r#""\xfg""#, r#""\x""#, r#""\""#];
    for c in cases {
        let result = PolicyParser::parse(Rule::atom, c);
        assert!(result.is_err());
    }
    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_atom_fn() -> Result<(), PestError<Rule>> {
    // bare call
    let mut pair = PolicyParser::parse(Rule::atom, r#"call()"#)?;
    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::function_call);

    // arguments
    let mut pair = PolicyParser::parse(Rule::atom, r#"call(3, "foo")"#)?;
    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::function_call);

    // terminal comma
    let mut pair = PolicyParser::parse(
        Rule::atom,
        r#"call(
            3,
            4,
        )"#,
    )?;
    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::function_call);

    // calls within calls
    let mut pair = PolicyParser::parse(Rule::atom, r#"call(foo(), bar())"#)?;
    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::function_call);
    let mut pair = token.into_inner();
    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::identifier);
    assert_eq!(token.as_str(), "call");
    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::expression);
    let mut pair = token.into_inner();
    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::function_call);
    assert_eq!(token.as_str(), "foo()");

    // bad calls
    let cases = vec!["call(,)", "call(a a)", "call(-)"];
    for c in cases {
        // We use Rule::function_call here directly as otherwise
        // these bad calls fall back to parsing as identifiers.
        let result = PolicyParser::parse(Rule::function_call, c);
        assert!(result.is_err());
    }

    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_expression() -> Result<(), PestError<Rule>> {
    let mut pairs = PolicyParser::parse(
        Rule::expression,
        r#"unwrap call(unwrap add(3, 7), saturating_sub(0, b), "foo\x7b")"#,
    )?;

    let token = pairs.next().unwrap();
    assert_eq!(token.as_rule(), Rule::expression);

    let mut pair = token.into_inner();
    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::unwrap);

    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::function_call);

    let mut pair = token.into_inner();
    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::identifier);
    assert_eq!(token.as_str(), "call");

    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::expression);
    assert_eq!(token.as_str(), "unwrap add(3, 7)");

    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::expression);
    assert_eq!(token.as_str(), "saturating_sub(0, b)");

    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::expression);
    assert_eq!(token.as_str(), "\"foo\\x7b\"");

    Ok(())
}

#[test]
fn parse_expression_pratt() -> Result<(), ParseError> {
    let source = r#"
        unwrap call(unwrap add(3, 7), saturating_sub(0, b), "foo\x7b")
    "#
    .trim();
    let mut pairs = PolicyParser::parse(Rule::expression, source)?;
    let pratt = get_pratt_parser();
    let p = ChunkParser::new(0, &pratt, source.len());
    let expr_pair = pairs.next().unwrap();
    let expr_parsed = p.parse_expression(expr_pair)?;
    insta::assert_debug_snapshot!(expr_parsed);
    Ok(())
}

struct ErrorInput {
    description: String,
    input: String,
    error_message: String,
    rule: Rule,
}

#[test]
fn parse_errors() -> Result<(), ParseError> {
    let cases = vec![ErrorInput {
        description: String::from("Invalid function body"),
        input: r#"function foo(x int) bool { invalid }"#.to_string(),
        error_message: String::from(
            " --> 1:28\n  |\n1 | function foo(x int) bool { invalid }\n  \
                |                            ^---\n  |\n  = expected function_call, \
                return_expression, action_call, publish_statement, let_statement, check_statement, match_statement, \
                if_statement, finish_statement, map_statement, create_statement, update_statement, \
                delete_statement, emit_statement, or debug_assert",
        ),
        rule: Rule::top_level_statement,
    }];
    for case in cases {
        match PolicyParser::parse(case.rule, &case.input) {
            Ok(_) => panic!("{}", case.description),
            Err(e) => assert_eq!(case.error_message, e.to_string(), "{}", case.description,),
        }
    }
    Ok(())
}

#[test]
fn parse_expression_errors() -> Result<(), ParseError> {
    let cases = vec![
        ErrorInput {
            description: String::from("Integer overflow"),
            input: r#"18446744073709551617"#.to_string(),
            error_message: String::from(
                "Invalid number: line 1 column 1: number too large to fit in target type",
            ),
            rule: Rule::expression,
        },
        ErrorInput {
            description: String::from("Integer overflow line 2"),
            input: r#"call(
                18446744073709551617
            )"#
            .to_string(),
            error_message: String::from(
                "Invalid number: line 2 column 17: number too large to fit in target type",
            ),
            rule: Rule::expression,
        },
        ErrorInput {
            description: String::from("Invalid string escape"),
            input: r#""\\""#.to_string(),
            error_message: String::from("Invalid string: line 1 column 1: invalid escape: \\"),
            rule: Rule::expression,
        },
    ];
    let pratt = get_pratt_parser();
    for case in cases {
        let p = ChunkParser::new(0, &pratt, case.input.len());
        let mut pairs = PolicyParser::parse(case.rule, &case.input)?;
        let expr_pair = pairs.next().unwrap();
        match p.parse_expression(expr_pair.clone()) {
            Ok(parsed) => panic!("{}: {:?} - {expr_pair:?}", case.description, parsed),
            Err(e) => assert_eq!(case.error_message, e.to_string(), "{}", case.description,),
        }
    }
    Ok(())
}

#[test]
fn parse_optional() {
    fn parse_vtype(text: &str) -> Result<VType, ParseError> {
        let pratt = get_pratt_parser();
        let p = ChunkParser::new(0, &pratt, text.len());
        let mut pairs = PolicyParser::parse(Rule::vtype, text)?;
        let pair = pairs.next().unwrap();
        p.parse_type(pair)
    }

    let optional_types = &[
        // (case, is valid)
        ("optional string", true),
        ("option[string]", true),
        ("optional bytes", true),
        ("option[bytes]", true),
        ("optional int", true),
        ("option[int]", true),
        ("optional bool", true),
        ("option[bool]", true),
        ("optional struct Foo", true),
        ("option[struct Foo]", true),
        ("optional blargh", false),
        ("option[blargh]", false),
        ("optional optional bytes", false),
        ("optional option[bytes]", false),
        ("option[optional bytes]", false),
        ("option[option[bytes]]", true),
    ];
    for (case, is_valid) in optional_types {
        let r = parse_vtype(case);
        assert!(*is_valid == r.is_ok(), "{}: {:?}", case, r);
    }
}

#[test]
fn parse_result() {
    let result_types = &[
        // (case, is valid)
        ("result[int, string]", true),
        ("result[bytes, bool]", true),
        ("result[struct Foo, string]", true),
        ("result[optional int, string]", true),
        ("result[int, optional string]", true),
        ("result[int, enum Error]", true),
        ("result[result[int, string], bool]", true), // nested result is allowed by grammar. not sure we want it
        ("result[int]", false),                      // missing error type
        ("result[, string]", false),                 // missing ok type
        ("result[blargh, string]", false),           // invalid ok type
        ("result[int, blargh]", false),              // invalid error type
    ];
    for (case, is_valid) in result_types {
        let r = PolicyParser::parse(Rule::result_t, case);
        assert!(*is_valid == r.is_ok(), "{}: {:?}", case, r);
    }
}

#[test]
fn test_result_literal() -> Result<(), ParseError> {
    let cases = [
        "Ok(42)",
        "Ok(true)",
        "Ok(get_value())",
        "Ok(Foo {})",
        "Err(\"error message\")",
        "Err(Error::NotFound)",
    ];
    for src in cases {
        let r = PolicyParser::parse(Rule::result_literal, src);
        assert!(r.is_ok(), "Failed to parse result literal: {}", src);
    }
    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_field() -> Result<(), PestError<Rule>> {
    let mut pairs = PolicyParser::parse(Rule::field_definition, "bar int")?;

    let tokens: Vec<Pair<'_, Rule>> = pairs.next().unwrap().into_inner().collect();
    assert_eq!(tokens[0].as_rule(), Rule::identifier);
    assert_eq!(tokens[0].as_str(), "bar");
    assert_eq!(tokens[1].as_rule(), Rule::int_t);
    assert_eq!(tokens[1].as_str(), "int");
    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_fact() -> Result<(), PestError<Rule>> {
    let src = r#"
        fact Foo[a int] => {b id, c string}
    "#
    .trim();

    let mut pairs = PolicyParser::parse(Rule::top_level_statement, src)?;
    let token = pairs.next().unwrap();
    assert_eq!(token.as_rule(), Rule::fact_definition);

    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_action() -> Result<(), PestError<Rule>> {
    let src = r#"
        action init(owner id) {
            publish Init{
                Owner: owner
            }
        }
    "#
    .trim();
    let mut pairs = PolicyParser::parse(Rule::top_level_statement, src)?;
    let token = pairs.next().unwrap();
    assert_eq!(token.as_rule(), Rule::action_definition);

    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_effect() -> Result<(), PestError<Rule>> {
    let src = r#"
        effect Foo {
            owner id dynamic,
        }
    "#
    .trim();
    let mut pairs = PolicyParser::parse(Rule::top_level_statement, src)?;
    let token = pairs.next().unwrap();
    assert_eq!(token.as_rule(), Rule::effect_definition);

    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_command() -> Result<(), PestError<Rule>> {
    let src = r#"
        command Foo {
            fields {
                owner id,
            }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    create Foo[]=>{}
                }
            }
        }
    "#
    .trim();
    let mut pairs = PolicyParser::parse(Rule::top_level_statement, src)?;
    let token = pairs.next().unwrap();
    assert_eq!(token.as_rule(), Rule::command_definition);

    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_function() -> Result<(), PestError<Rule>> {
    let src = r#"
    function foo(x int) bool {
        return true
    }
    "#
    .trim();
    let mut pairs = PolicyParser::parse(Rule::top_level_statement, src)?;
    let token = pairs.next().unwrap();
    assert_eq!(token.as_rule(), Rule::function_definition);

    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_foreign_function_call() -> Result<(), PestError<Rule>> {
    let src = r#"
        let x = foo::bar(5, "baz")
    "#
    .trim();

    let mut pairs = PolicyParser::parse(Rule::let_statement, src)?;
    let let_expr = pairs.next().unwrap();

    let mut let_parts = let_expr.into_inner();
    let_parts.next().unwrap(); // skip 'x' identifier
    let ffi_expr = let_parts.next().unwrap().into_inner().next().unwrap();
    println!("> {}", ffi_expr);
    assert_eq!(ffi_expr.as_rule(), Rule::foreign_function_call);

    let mut f = ffi_expr.into_inner();
    f.next().unwrap(); // skip function_call identifier

    // list of argument expressions
    let mut args = f.next().unwrap().into_inner();
    args.next().unwrap(); // skip identifier
    println!("arg_expr {}", args);

    // verify number and type of args
    assert_eq!(args.len(), 2);
    let arg1 = args.next().unwrap().into_inner().next().unwrap();
    assert_eq!(arg1.as_rule(), Rule::int_literal);
    let arg2 = args.next().unwrap().into_inner().next().unwrap();
    assert_eq!(arg2.as_rule(), Rule::string_literal);

    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_struct_composition() -> Result<(), PestError<Rule>> {
    let input = "{ c: false, ...x }";

    let struct_literal = PolicyParser::parse(Rule::struct_literal, input)?;

    for field in struct_literal {
        match field.as_rule() {
            Rule::struct_literal_field => {
                let mut parts = field.into_inner();
                let field_name = parts.next().unwrap().as_str();
                assert_eq!(field_name, "c");
                let field_value = parts.next().unwrap().as_str();
                assert_eq!(field_value, "false");
            }
            Rule::struct_composition => {
                let identifer = field.into_inner().next().unwrap().as_str();
                assert_eq!(identifer, "x");
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_enum_reference() -> Result<(), PestError<Rule>> {
    let mut pair = PolicyParser::parse(Rule::enum_reference, "Color::Red")?;
    let token: Pair<'_, Rule> = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::enum_reference);

    let mut parts = token.into_inner();
    let enum_name = parts.next().unwrap().as_str();
    assert_eq!(enum_name, "Color");
    let enum_value = parts.next().unwrap().as_str();
    assert_eq!(enum_value, "Red");

    Ok(())
}
