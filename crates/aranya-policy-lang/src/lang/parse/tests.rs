#![allow(clippy::panic)]

use std::{fs::OpenOptions, io::Read};

use aranya_policy_ast::{ident, text};
use ast::{Expression, FactField, ForeignFunctionCall, MatchPattern};
use pest::{Parser, error::Error as PestError, iterators::Pair};

use super::{
    ParseError, PolicyParser, Rule, Version, ast, ast::AstNode, get_pratt_parser,
    parse_policy_document, parse_policy_str,
};
use crate::lang::{ChunkParser, FfiTypes, ParseErrorKind};

#[test]
#[allow(clippy::result_large_err)]
#[allow(deprecated)]
fn accept_only_latest_lang_version() -> Result<(), PestError<Rule>> {
    // parse string literal
    let src = "function f() int { return 0 }";
    assert_eq!(
        parse_policy_str(src, Version::V1)
            .expect_err("should not accept V1")
            .kind,
        ParseErrorKind::InvalidVersion {
            found: "1".to_string(),
            required: Version::V2
        }
    );
    parse_policy_str(src, Version::V2).expect("should accept V2");

    // parse markdown (v1)
    let policy_v1_md = r#"---
policy-version: 1
---

```policy
```
"#;
    assert!(parse_policy_document(policy_v1_md).is_err_and(|r| r.kind
        == ParseErrorKind::InvalidVersion {
            found: "1".to_string(),
            required: Version::V2
        }));

    // parse markdown (v2)
    let policy_v2_md = r#"---
policy-version: 2
---

```policy
```
"#;
    assert!(parse_policy_document(policy_v2_md).is_ok());

    Ok(())
}

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
    let mut pairs = PolicyParser::parse(Rule::expression, r#"unwrap call(3 + 7, -b, "foo\x7b")"#)?;

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
    assert_eq!(token.as_str(), "3 + 7");

    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::expression);
    assert_eq!(token.as_str(), "-b");

    let token = pair.next().unwrap();
    assert_eq!(token.as_rule(), Rule::expression);
    assert_eq!(token.as_str(), "\"foo\\x7b\"");

    Ok(())
}

#[test]
fn parse_expression_pratt() -> Result<(), ParseError> {
    let mut pairs = PolicyParser::parse(
        Rule::expression,
        r#"
        unwrap call(3 + 7, -b, "foo\x7b")
    "#
        .trim(),
    )?;
    let pratt = get_pratt_parser();
    let mut p = ChunkParser::new(0, &pratt);
    let expr = pairs.next().unwrap();
    let expr_parsed = p.parse_expression(expr)?;
    assert_eq!(
        expr_parsed,
        Expression::Unwrap(Box::new(Expression::FunctionCall(ast::FunctionCall {
            identifier: ident!("call"),
            arguments: vec![
                Expression::Add(Box::new(Expression::Int(3)), Box::new(Expression::Int(7))),
                Expression::Negative(Box::new(Expression::Identifier(ident!("b")))),
                Expression::String(text!("foo\x7b")),
            ]
        })))
    );
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
                action_call, publish_statement, let_statement, check_statement, match_statement, \
                if_statement, finish_statement, map_statement, create_statement, update_statement, \
                delete_statement, emit_statement, return_statement, or debug_assert",
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
        ErrorInput {
            description: String::from("Expect Invalid substruct operation"),
            input: r#"x substruct 4"#.to_string(),
            error_message: String::from(
                "Invalid substruct operation: line 1 column 3: Expression `Int(4)` to the right of the substruct operator must be an identifier",
            ),
            rule: Rule::expression,
        },
    ];
    let pratt = get_pratt_parser();
    let mut p = ChunkParser::new(0, &pratt);
    for case in cases {
        let mut pairs = PolicyParser::parse(case.rule, &case.input)?;
        let expr = pairs.next().unwrap();
        match p.parse_expression(expr.clone()) {
            Ok(parsed) => panic!("{}: {:?} - {expr:?}", case.description, parsed),
            Err(e) => assert_eq!(case.error_message, e.to_string(), "{}", case.description,),
        }
    }
    Ok(())
}

#[test]
fn parse_optional() {
    let optional_types = &[
        // (case, is valid)
        ("optional string", true),
        ("optional bytes", true),
        ("optional int", true),
        ("optional bool", true),
        ("optional struct Foo", true),
        ("optional optional bytes", false),
        ("optional blargh", false),
    ];
    for (case, is_valid) in optional_types {
        let r = PolicyParser::parse(Rule::optional_t, case);
        assert!(*is_valid == r.is_ok(), "{}: {:?}", case, r)
    }
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
fn test_parse_effect_with_field_insertion() {
    let cases = [(
        r#"struct Foo { x int }
        effect Bar {
            +Foo,
            y int
        }
        "#,
        vec![
            ast::StructItem::StructRef(ident!("Foo")),
            ast::StructItem::Field(ast::EffectFieldDefinition {
                identifier: ident!("y"),
                field_type: ast::VType::Int,
                dynamic: false,
            }),
        ],
    )];
    for (case, expected) in cases {
        let policy = parse_policy_str(case, Version::V2).expect("should parse");
        assert_eq!(
            policy.effects[0].inner.items, expected,
            "case: {case:?} => {expected:?}"
        );
    }
}

#[test]
#[allow(clippy::result_large_err)]
fn parse_command() -> Result<(), PestError<Rule>> {
    let src = r#"
        command Foo {
            fields {
                owner id,
            }

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
fn parse_command_attributes() {
    let src = r#"
        command Foo {
            attributes {
                priority: "high",
            }
        }
    "#;
    let policy = parse_policy_str(src, Version::V2).expect("should parse");
    let command_def = &policy.commands[0];

    let (id, value) = &command_def.attributes[0];
    assert_eq!(id, "priority");
    assert_eq!(value, &Expression::String(text!("high")));
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
fn parse_policy_test() -> Result<(), ParseError> {
    let policy_str = r#"
        // This is not a valid policy. It is just meant to exercise
        // every feature of the parser.
        /* block comment */
        fact F[v string]=>{x int, y bool}

        action add(x int, y int) {
            let obj = Add {
                count: x,
            }
            publish obj
        }

        effect Added {
            x int dynamic,
            y int,
        }

        command Add {
            fields {
                count int
            }

            policy {
                let envelope_id = envelope::command_id(envelope)
                let author = envelope::author_id(envelope)
                let new_x = x + count
                check exists TestFact[v: "test"]=>{}
                match x {
                    0 => {
                        check positive(Some(new_x))
                    }
                    1 => {
                        check positive(None)
                    }
                    _ => {

                    }
                }

                if x == 3 {
                    check new_x < 10
                }

                let a = foo::ext_func(x)

                finish {
                    create F[v: "hello"]=>{x: x, y: -x}
                    update F[]=>{x: x} to {x: new_x}
                    delete F[v: "hello"]
                    emit Added {
                        x: new_x,
                        y: count,
                    }
                }
            }
            recall {
                let envelope_id = envelope::command_id(envelope)
                let author = envelope::author_id(envelope)
                let new_x = x + count
                finish {
                    create F[v: "hello"]=>{x: x, y: -x}
                    update F[]=>{x: x} to {x: new_x}
                    delete F[v: "hello"]
                    emit Added {
                        x: new_x,
                        y: count,
                    }
                }
            }
        }

        function positive(v optional int) bool {
            let x = unwrap v
            return x > 0
        }

        finish function next(x int) {
            create Next[]=>{}
        }

    "#;

    let policy = parse_policy_str(policy_str, Version::V2)?;

    assert_eq!(
        policy.facts,
        vec![AstNode::new(
            ast::FactDefinition {
                immutable: false,
                identifier: ident!("F"),
                key: vec![ast::FieldDefinition {
                    identifier: ident!("v"),
                    field_type: ast::VType::String,
                }],
                value: vec![
                    ast::FieldDefinition {
                        identifier: ident!("x"),
                        field_type: ast::VType::Int,
                    },
                    ast::FieldDefinition {
                        identifier: ident!("y"),
                        field_type: ast::VType::Bool,
                    },
                ],
            },
            145,
        )]
    );
    assert_eq!(
        policy.actions,
        vec![AstNode::new(
            ast::ActionDefinition {
                identifier: ident!("add"),
                arguments: vec![
                    ast::FieldDefinition {
                        identifier: ident!("x"),
                        field_type: ast::VType::Int,
                    },
                    ast::FieldDefinition {
                        identifier: ident!("y"),
                        field_type: ast::VType::Int,
                    },
                ],
                statements: vec![
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("obj"),
                            expression: Expression::NamedStruct(ast::NamedStruct {
                                identifier: ident!("Add"),
                                fields: vec![(
                                    ident!("count"),
                                    Expression::Identifier(ident!("x")),
                                )],
                            }),
                        }),
                        227,
                    ),
                    AstNode::new(
                        ast::Statement::Publish(Expression::Identifier(ident!("obj"))),
                        295,
                    ),
                ],
            },
            188,
        )]
    );
    assert_eq!(
        policy.effects,
        vec![AstNode::new(
            ast::EffectDefinition {
                identifier: ident!("Added"),
                items: vec![
                    ast::StructItem::Field(ast::EffectFieldDefinition {
                        identifier: ident!("x"),
                        field_type: ast::VType::Int,
                        dynamic: true,
                    }),
                    ast::StructItem::Field(ast::EffectFieldDefinition {
                        identifier: ident!("y"),
                        field_type: ast::VType::Int,
                        dynamic: false,
                    }),
                ],
            },
            326,
        )]
    );
    assert_eq!(
        policy.commands,
        vec![AstNode::new(
            ast::CommandDefinition {
                attributes: vec![],
                identifier: ident!("Add"),
                fields: vec![ast::StructItem::Field(ast::FieldDefinition {
                    identifier: ident!("count"),
                    field_type: ast::VType::Int,
                })],
                seal: vec![],
                open: vec![],
                policy: vec![
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("envelope_id"),
                            expression: Expression::ForeignFunctionCall(ForeignFunctionCall {
                                module: ident!("envelope"),
                                identifier: ident!("command_id"),
                                arguments: vec![Expression::Identifier(ident!("envelope"))]
                            },),
                        }),
                        519,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("author"),
                            expression: Expression::ForeignFunctionCall(ForeignFunctionCall {
                                module: ident!("envelope"),
                                identifier: ident!("author_id"),
                                arguments: vec![Expression::Identifier(ident!("envelope"))]
                            },),
                        }),
                        584,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("new_x"),
                            expression: Expression::Add(
                                Box::new(Expression::Identifier(ident!("x"))),
                                Box::new(Expression::Identifier(ident!("count"))),
                            ),
                        }),
                        643,
                    ),
                    AstNode::new(
                        ast::Statement::Check(ast::CheckStatement {
                            expression: Expression::InternalFunction(
                                ast::InternalFunction::Exists(ast::FactLiteral {
                                    identifier: ident!("TestFact"),
                                    key_fields: vec![(
                                        ident!("v"),
                                        FactField::Expression(Expression::String(text!("test"))),
                                    )],
                                    value_fields: Some(vec![]),
                                }),
                            ),
                        }),
                        681,
                    ),
                    AstNode::new(
                        ast::Statement::Match(ast::MatchStatement {
                            expression: Expression::Identifier(ident!("x")),
                            arms: vec![
                                ast::MatchArm {
                                    pattern: MatchPattern::Values(vec![Expression::Int(0)]),
                                    statements: vec![AstNode::new(
                                        ast::Statement::Check(ast::CheckStatement {
                                            expression: Expression::FunctionCall(
                                                ast::FunctionCall {
                                                    identifier: ident!("positive"),
                                                    arguments: vec![Expression::Optional(Some(
                                                        Box::new(Expression::Identifier(ident!(
                                                            "new_x"
                                                        ),),)
                                                    ),)],
                                                },
                                            ),
                                        }),
                                        795,
                                    )],
                                },
                                ast::MatchArm {
                                    pattern: MatchPattern::Values(vec!(Expression::Int(1))),
                                    statements: vec![AstNode::new(
                                        ast::Statement::Check(ast::CheckStatement {
                                            expression: Expression::FunctionCall(
                                                ast::FunctionCall {
                                                    identifier: ident!("positive"),
                                                    arguments: vec![Expression::Optional(None,)],
                                                },
                                            ),
                                        }),
                                        896,
                                    )],
                                },
                                ast::MatchArm {
                                    pattern: MatchPattern::Default,
                                    statements: vec![],
                                },
                            ],
                        }),
                        734,
                    ),
                    AstNode::new(
                        ast::Statement::If(ast::IfStatement {
                            branches: vec![(
                                Expression::Equal(
                                    Box::new(Expression::Identifier(ident!("x"))),
                                    Box::new(Expression::Int(3)),
                                ),
                                vec![AstNode::new(
                                    ast::Statement::Check(ast::CheckStatement {
                                        expression: Expression::LessThan(
                                            Box::new(Expression::Identifier(ident!("new_x"))),
                                            Box::new(Expression::Int(10)),
                                        ),
                                    }),
                                    1056,
                                )],
                            )],
                            fallback: None
                        }),
                        1024
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("a"),
                            expression: Expression::ForeignFunctionCall(ForeignFunctionCall {
                                module: ident!("foo"),
                                identifier: ident!("ext_func"),
                                arguments: vec![Expression::Identifier(ident!("x"))],
                            }),
                        }),
                        1108
                    ),
                    AstNode::new(
                        ast::Statement::Finish(vec![
                            AstNode::new(
                                ast::Statement::Create(ast::CreateStatement {
                                    fact: ast::FactLiteral {
                                        identifier: ident!("F"),
                                        key_fields: vec![(
                                            ident!("v"),
                                            FactField::Expression(Expression::String(text!(
                                                "hello"
                                            )),)
                                        )],
                                        value_fields: Some(vec![
                                            (
                                                ident!("x"),
                                                FactField::Expression(Expression::Identifier(
                                                    ident!("x")
                                                ),)
                                            ),
                                            (
                                                ident!("y"),
                                                FactField::Expression(Expression::Negative(
                                                    Box::new(Expression::Identifier(ident!("x")),)
                                                )),
                                            ),
                                        ]),
                                    },
                                }),
                                1179
                            ),
                            AstNode::new(
                                ast::Statement::Update(ast::UpdateStatement {
                                    fact: ast::FactLiteral {
                                        identifier: ident!("F"),
                                        key_fields: vec![],
                                        value_fields: Some(vec![(
                                            ident!("x"),
                                            FactField::Expression(Expression::Identifier(ident!(
                                                "x"
                                            )),)
                                        )]),
                                    },
                                    to: vec![(
                                        ident!("x"),
                                        FactField::Expression(Expression::Identifier(ident!(
                                            "new_x"
                                        )),)
                                    )],
                                }),
                                1235
                            ),
                            AstNode::new(
                                ast::Statement::Delete(ast::DeleteStatement {
                                    fact: ast::FactLiteral {
                                        identifier: ident!("F"),
                                        key_fields: vec![(
                                            ident!("v"),
                                            FactField::Expression(Expression::String(text!(
                                                "hello"
                                            )),)
                                        )],
                                        value_fields: None,
                                    },
                                }),
                                1288
                            ),
                            AstNode::new(
                                ast::Statement::Emit(Expression::NamedStruct(ast::NamedStruct {
                                    identifier: ident!("Added"),
                                    fields: vec![
                                        (ident!("x"), Expression::Identifier(ident!("new_x")),),
                                        (ident!("y"), Expression::Identifier(ident!("count")),),
                                    ],
                                },)),
                                1329
                            ),
                        ]),
                        1150,
                    ),
                ],
                recall: vec![
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("envelope_id"),
                            expression: Expression::ForeignFunctionCall(ForeignFunctionCall {
                                module: ident!("envelope"),
                                identifier: ident!("command_id"),
                                arguments: vec![Expression::Identifier(ident!("envelope"))]
                            },),
                        }),
                        1501,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("author"),
                            expression: Expression::ForeignFunctionCall(ForeignFunctionCall {
                                module: ident!("envelope"),
                                identifier: ident!("author_id"),
                                arguments: vec![Expression::Identifier(ident!("envelope"))]
                            },),
                        }),
                        1566,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("new_x"),
                            expression: Expression::Add(
                                Box::new(Expression::Identifier(ident!("x"))),
                                Box::new(Expression::Identifier(ident!("count"))),
                            ),
                        }),
                        1625,
                    ),
                    AstNode::new(
                        ast::Statement::Finish(vec![
                            AstNode::new(
                                ast::Statement::Create(ast::CreateStatement {
                                    fact: ast::FactLiteral {
                                        identifier: ident!("F"),
                                        key_fields: vec![(
                                            ident!("v"),
                                            FactField::Expression(Expression::String(text!(
                                                "hello"
                                            ))),
                                        )],
                                        value_fields: Some(vec![
                                            (
                                                ident!("x"),
                                                FactField::Expression(Expression::Identifier(
                                                    ident!("x")
                                                )),
                                            ),
                                            (
                                                ident!("y"),
                                                FactField::Expression(Expression::Negative(
                                                    Box::new(Expression::Identifier(ident!("x")),)
                                                )),
                                            ),
                                        ]),
                                    },
                                }),
                                1692
                            ),
                            AstNode::new(
                                ast::Statement::Update(ast::UpdateStatement {
                                    fact: ast::FactLiteral {
                                        identifier: ident!("F"),
                                        key_fields: vec![],
                                        value_fields: Some(vec![(
                                            ident!("x"),
                                            FactField::Expression(Expression::Identifier(ident!(
                                                "x"
                                            )),)
                                        )]),
                                    },
                                    to: vec![(
                                        ident!("x"),
                                        FactField::Expression(Expression::Identifier(ident!(
                                            "new_x"
                                        )),)
                                    )],
                                }),
                                1748
                            ),
                            AstNode::new(
                                ast::Statement::Delete(ast::DeleteStatement {
                                    fact: ast::FactLiteral {
                                        identifier: ident!("F"),
                                        key_fields: vec![(
                                            ident!("v"),
                                            FactField::Expression(Expression::String(text!(
                                                "hello"
                                            )),)
                                        )],
                                        value_fields: None,
                                    },
                                }),
                                1801
                            ),
                            AstNode::new(
                                ast::Statement::Emit(Expression::NamedStruct(ast::NamedStruct {
                                    identifier: ident!("Added"),
                                    fields: vec![
                                        (ident!("x"), Expression::Identifier(ident!("new_x")),),
                                        (ident!("y"), Expression::Identifier(ident!("count")),),
                                    ],
                                },)),
                                1842
                            ),
                        ]),
                        1663,
                    ),
                ],
            },
            406,
        )]
    );
    assert_eq!(
        policy.functions,
        vec![AstNode::new(
            ast::FunctionDefinition {
                identifier: ident!("positive"),
                arguments: vec![ast::FieldDefinition {
                    identifier: ident!("v"),
                    field_type: ast::VType::Optional(Box::new(ast::VType::Int)),
                }],
                return_type: ast::VType::Bool,
                statements: vec![
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("x"),
                            expression: Expression::Unwrap(Box::new(Expression::Identifier(
                                ident!("v")
                            ),)),
                        }),
                        2049,
                    ),
                    AstNode::new(
                        ast::Statement::Return(ast::ReturnStatement {
                            expression: Expression::GreaterThan(
                                Box::new(Expression::Identifier(ident!("x"))),
                                Box::new(Expression::Int(0)),
                            ),
                        }),
                        2078,
                    ),
                ],
            },
            1996,
        )]
    );
    assert_eq!(
        policy.finish_functions,
        vec![AstNode::new(
            ast::FinishFunctionDefinition {
                identifier: ident!("next"),
                arguments: vec![ast::FieldDefinition {
                    identifier: ident!("x"),
                    field_type: ast::VType::Int,
                }],
                statements: vec![AstNode::new(
                    ast::Statement::Create(ast::CreateStatement {
                        fact: ast::FactLiteral {
                            identifier: ident!("Next"),
                            key_fields: vec![],
                            value_fields: Some(vec![]),
                        },
                    }),
                    2152
                )],
            },
            2110,
        )]
    );

    let (start, end) = *policy
        .ranges
        .iter()
        .find(|(start, _)| *start == 643)
        .expect("range not found");
    let text = &policy.text[start..end];
    assert_eq!(text.trim_end(), "let new_x = x + count");

    Ok(())
}

// NB: this test depends on the external file tictactoe.policy,
// which must be kept up-to-date with this test.
#[test]
fn parse_tictactoe() {
    let text = {
        let mut buf = vec![];
        let mut f = OpenOptions::new()
            .read(true)
            .open("src/lang/tictactoe-policy.md")
            .expect("could not open policy");
        f.read_to_end(&mut buf).expect("could not read policy file");
        String::from_utf8(buf).expect("File is not valid UTF-8")
    };

    let policy = parse_policy_document(&text).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(policy.facts.len(), 4);
    assert_eq!(policy.actions.len(), 2);
    assert_eq!(policy.actions.len(), 2);
    assert_eq!(policy.commands.len(), 3);
    assert_eq!(policy.functions.len(), 2);
    assert_eq!(policy.finish_functions.len(), 1);
}

#[test]
fn parse_policy_immutable_facts() -> Result<(), ParseError> {
    let policy_str = r#"
        fact A[]=>{}
        immutable fact B[]=>{}
    "#;

    let policy = parse_policy_str(policy_str, Version::V2)?;
    assert_eq!(
        policy.facts,
        vec![
            AstNode::new(
                ast::FactDefinition {
                    immutable: false,
                    identifier: ident!("A"),
                    key: vec![],
                    value: vec![],
                },
                9,
            ),
            AstNode::new(
                ast::FactDefinition {
                    immutable: true,
                    identifier: ident!("B"),
                    key: vec![],
                    value: vec![],
                },
                30,
            )
        ]
    );

    Ok(())
}

#[test]
fn empty_policy() -> Result<(), ParseError> {
    let policy = parse_policy_str("", Version::V2)?;
    assert!(policy.facts.is_empty());
    assert!(policy.actions.is_empty());
    assert!(policy.effects.is_empty());
    assert!(policy.commands.is_empty());
    assert!(policy.functions.is_empty());
    assert!(policy.finish_functions.is_empty());
    Ok(())
}

#[test]
fn parse_markdown() {
    let md = r#"---
policy-version: 2
---

# A fact

```policy
fact Markdown[]=>{}
```

```
fact NotAPolicyBlock[]=>{}
```

```policy
action foo() {
    publish SomeCommand{}
}
```
"#;

    let policy = parse_policy_document(md).unwrap_or_else(|e| panic!("{e}"));

    assert!(policy.version == Version::V2);
    assert!(policy.facts.len() == 1);
    assert!(policy.actions.len() == 1);
}

#[test]
fn parse_bytes() {
    let text = r#"
        function foo(x bytes) bytes {
            return x
        }
    "#
    .trim();

    parse_policy_str(text, Version::V2).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn parse_struct() {
    let text = r#"
        struct Foo {
            x int
        }

        function convert(foo struct Foo) struct Bar {
            return Bar {y: foo.x}
        }
    "#
    .trim();

    let policy = parse_policy_str(text, Version::V2).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        policy.structs,
        vec![AstNode::new(
            ast::StructDefinition {
                identifier: ident!("Foo"),
                items: vec![ast::StructItem::Field(ast::FieldDefinition {
                    identifier: ident!("x"),
                    field_type: ast::VType::Int,
                })]
            },
            0
        )]
    );
    assert_eq!(
        policy.functions,
        vec![AstNode::new(
            ast::FunctionDefinition {
                identifier: ident!("convert"),
                arguments: vec![ast::FieldDefinition {
                    identifier: ident!("foo"),
                    field_type: ast::VType::Struct(ident!("Foo")),
                }],
                return_type: ast::VType::Struct(ident!("Bar")),
                statements: vec![AstNode::new(
                    ast::Statement::Return(ast::ReturnStatement {
                        expression: Expression::NamedStruct(ast::NamedStruct {
                            identifier: ident!("Bar"),
                            fields: vec![(
                                ident!("y"),
                                Expression::Dot(
                                    Box::new(Expression::Identifier(ident!("foo"))),
                                    ident!("x")
                                )
                            )],
                        })
                    }),
                    108
                )]
            },
            50
        )]
    );
}

#[test]
fn parse_struct_with_field_insertion() {
    let cases = [(
        r#"struct Foo { x int }
        struct Bar {
            +Foo,
            y int
        }
        "#,
        vec![
            ast::StructItem::StructRef(ident!("Foo")),
            ast::StructItem::Field(ast::FieldDefinition {
                identifier: ident!("y"),
                field_type: ast::VType::Int,
            }),
        ],
    )];
    for (case, expected) in cases {
        let policy = parse_policy_str(case, Version::V2).expect("should parse");
        assert_eq!(
            policy.structs[1].inner.items, expected,
            "case: {case:?} => {expected:?}"
        );
    }
}

#[test]
fn parse_enum_definition() {
    let text = r#"
        enum Color {
            Red,
            Green,
            Blue,
        }
    "#
    .trim();

    let policy = parse_policy_str(text, Version::V2).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        policy.enums,
        vec![AstNode::new(
            ast::EnumDefinition {
                identifier: ident!("Color"),
                variants: vec![ident!("Red"), ident!("Green"), ident!("Blue")]
            },
            0
        )]
    );
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

#[test]
fn parse_ffi_decl() {
    let text = "function foo(x int, y struct bar) bool";
    let decl = super::parse_ffi_decl(text).expect("parse");
    assert_eq!(
        decl,
        ast::FunctionDecl {
            identifier: ident!("foo"),
            arguments: vec![
                ast::FieldDefinition {
                    identifier: ident!("x"),
                    field_type: ast::VType::Int,
                },
                ast::FieldDefinition {
                    identifier: ident!("y"),
                    field_type: ast::VType::Struct(ident!("bar")),
                }
            ],
            return_type: Some(ast::VType::Bool)
        }
    )
}

#[test]
fn parse_ffi_structs_enums() {
    let text = r#"
        struct A {
            x int,
            y bool
        }

        struct B {}

        enum Color { Red, White, Blue }
    "#
    .trim();
    let FfiTypes { structs, enums } = super::parse_ffi_structs_enums(text).expect("parse");
    assert_eq!(
        structs,
        vec![
            AstNode {
                inner: ast::StructDefinition {
                    identifier: ident!("A"),
                    items: vec![
                        ast::StructItem::Field(ast::FieldDefinition {
                            identifier: ident!("x"),
                            field_type: ast::VType::Int
                        }),
                        ast::StructItem::Field(ast::FieldDefinition {
                            identifier: ident!("y"),
                            field_type: ast::VType::Bool
                        })
                    ]
                },
                locator: 0,
            },
            AstNode {
                inner: ast::StructDefinition {
                    identifier: ident!("B"),
                    items: vec![],
                },
                locator: 68,
            }
        ],
    );

    assert_eq!(
        enums,
        vec![AstNode {
            inner: ast::EnumDefinition {
                identifier: ident!("Color"),
                variants: vec![ident!("Red"), ident!("White"), ident!("Blue")]
            },
            locator: 89
        }]
    );
}

#[test]
fn parse_seal_open() {
    let text = r#"
        command Foo {
            seal {
                return bar(this)
            }

            open {
                return baz(envelope)
            }
        }
    "#
    .trim();
    let policy = parse_policy_str(text, Version::V2).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        policy.commands,
        vec![AstNode::new(
            ast::CommandDefinition {
                attributes: vec![],
                identifier: ident!("Foo"),
                fields: vec![],
                policy: vec![],
                recall: vec![],
                seal: vec![AstNode::new(
                    ast::Statement::Return(ast::ReturnStatement {
                        expression: Expression::FunctionCall(ast::FunctionCall {
                            identifier: ident!("bar"),
                            arguments: vec![Expression::Identifier(ident!("this"))]
                        })
                    }),
                    49
                )],
                open: vec![AstNode::new(
                    ast::Statement::Return(ast::ReturnStatement {
                        expression: Expression::FunctionCall(ast::FunctionCall {
                            identifier: ident!("baz"),
                            arguments: vec![Expression::Identifier(ident!("envelope"))]
                        })
                    }),
                    116
                )],
            },
            0
        )]
    );
}

#[test]
fn parse_serialize_deserialize() {
    let text = r#"
        command Foo {
            seal {
                return serialize(this)
            }

            open {
                return deserialize(envelope)
            }
        }
    "#
    .trim();
    let policy = parse_policy_str(text, Version::V2).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        policy.commands,
        vec![AstNode::new(
            ast::CommandDefinition {
                attributes: vec![],
                identifier: ident!("Foo"),
                fields: vec![],
                policy: vec![],
                recall: vec![],
                seal: vec![AstNode::new(
                    ast::Statement::Return(ast::ReturnStatement {
                        expression: Expression::InternalFunction(ast::InternalFunction::Serialize(
                            Box::new(Expression::Identifier(ident!("this")))
                        ))
                    }),
                    49
                )],
                open: vec![AstNode::new(
                    ast::Statement::Return(ast::ReturnStatement {
                        expression: Expression::InternalFunction(
                            ast::InternalFunction::Deserialize(Box::new(Expression::Identifier(
                                ident!("envelope")
                            )))
                        )
                    }),
                    122
                )],
            },
            0
        )]
    );
}

#[test]
fn parse_keyword_collision() -> anyhow::Result<()> {
    let texts = &[
        r#"
            struct int {
            }
        "#,
        r#"
            struct foo {
                int int
            }
        "#,
        r#"
            function int(x int) int {
                publish Bar{}
            }
        "#,
        r#"
            fact int[]=>{}
        "#,
        r#"
            fact x[int int]=>{}
        "#,
        r#"
            fact x[]=>{int int}
        "#,
        r#"
            action foo() {
                let int = 3
            }
        "#,
        r#"
            action int() {
            }
        "#,
        r#"
            effect int {
            }
        "#,
    ];

    for text in texts {
        let policy = parse_policy_str(text, Version::V2);
        assert!(policy.is_err_and(|result| result.kind == ParseErrorKind::ReservedIdentifier))
    }
    Ok(())
}

#[test]
fn parse_global_let_statements() -> Result<(), ParseError> {
    let policy_str = r#"
        let x = 42
        let y = "hello"
        let z = true

        action foo() {
            let a = x + 1
            let b = y + " world"
            let c = !z
            emit Bar {
                a: a,
                b: b,
                c: c,
            }
        }
    "#;

    let policy = parse_policy_str(policy_str, Version::V2)?;

    assert_eq!(
        policy.global_lets,
        vec![
            AstNode::new(
                ast::GlobalLetStatement {
                    identifier: ident!("x"),
                    expression: Expression::Int(42),
                },
                9,
            ),
            AstNode::new(
                ast::GlobalLetStatement {
                    identifier: ident!("y"),
                    expression: Expression::String(text!("hello")),
                },
                28,
            ),
            AstNode::new(
                ast::GlobalLetStatement {
                    identifier: ident!("z"),
                    expression: Expression::Bool(true),
                },
                52,
            ),
        ]
    );

    assert_eq!(
        policy.actions,
        vec![AstNode::new(
            ast::ActionDefinition {
                identifier: ident!("foo"),
                arguments: vec![],
                statements: vec![
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("a"),
                            expression: Expression::Add(
                                Box::new(Expression::Identifier(ident!("x"))),
                                Box::new(Expression::Int(1)),
                            ),
                        }),
                        101,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("b"),
                            expression: Expression::Add(
                                Box::new(Expression::Identifier(ident!("y"))),
                                Box::new(Expression::String(text!(" world"))),
                            ),
                        }),
                        127,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: ident!("c"),
                            expression: Expression::Not(Box::new(Expression::Identifier(ident!(
                                "z"
                            )),)),
                        }),
                        160,
                    ),
                    AstNode::new(
                        ast::Statement::Emit(Expression::NamedStruct(ast::NamedStruct {
                            identifier: ident!("Bar"),
                            fields: vec![
                                (ident!("a"), Expression::Identifier(ident!("a")),),
                                (ident!("b"), Expression::Identifier(ident!("b")),),
                                (ident!("c"), Expression::Identifier(ident!("c")),),
                            ],
                        })),
                        183,
                    ),
                ],
            },
            74,
        )]
    );
    Ok(())
}

#[test]
fn test_fact_key_can_have_bind_value() -> anyhow::Result<()> {
    let text = r#"
        action test() {
            let x = query A[i:1, j:?]
        }
    "#;
    parse_policy_str(text, Version::V2)?;
    Ok(())
}

#[test]
fn test_ffi_use() -> anyhow::Result<()> {
    let text = r#"
        use crypto
        use perspective
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    assert_eq!(policy.ffi_imports.len(), 2);
    assert_eq!(policy.ffi_imports[0], "crypto");
    assert_eq!(policy.ffi_imports[1], "perspective");
    Ok(())
}

#[test]
fn test_ffi_use_bad_identifier() -> anyhow::Result<()> {
    let texts = vec!["use one, two", "use _"];

    for text in texts {
        let err = parse_policy_str(text, Version::V2).unwrap_err().kind;
        assert_eq!(err, ParseErrorKind::Syntax);
    }

    Ok(())
}

#[test]
fn test_if_statement() -> anyhow::Result<()> {
    let text = r#"
        action test() {
            if 0 {
                check 1
            }

            if 0 {
                check 1
            } else {
                check 2
            }

            if 0 {
                check 1
                check 1 + 1
            } else if 2 {
                check 3
            } else if 4 {
                check 5
            } else {
                check 6
            }
        }
    "#;
    parse_policy_str(text, Version::V2)?;
    Ok(())
}

#[test]
fn if_expression() {
    let text = r#"
        action test() {
            let b = if true { :1 } else { :0 }
        }
    "#;
    parse_policy_str(text, Version::V2).expect("should parse");
}

#[test]
fn test_action_call() -> anyhow::Result<()> {
    let text = r#"
    action ping() {}
    action pong() {
        action ping()
    }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    assert_eq!(
        policy.actions[1],
        AstNode {
            inner: ast::ActionDefinition {
                identifier: ident!("pong"),
                arguments: vec![],
                statements: vec![AstNode {
                    inner: ast::Statement::ActionCall(ast::FunctionCall {
                        identifier: ident!("ping"),
                        arguments: vec![]
                    }),
                    locator: 50
                }]
            },
            locator: 26
        }
    );

    Ok(())
}

#[test]
fn test_map_statement() {
    let text = r#"
        fact Foo[i int]=>{n int}
        action foo() {
            map Foo[i:1] as f {
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    assert_eq!(
        policy.actions[0].statements,
        vec![AstNode {
            inner: ast::Statement::Map(ast::MapStatement {
                fact: ast::FactLiteral {
                    identifier: ident!("Foo"),
                    key_fields: vec![(ident!("i"), FactField::Expression(Expression::Int(1)))],
                    value_fields: None,
                },
                identifier: ident!("f"),
                statements: vec![]
            }),
            locator: 69
        }]
    );
}

#[test]
fn test_block_expression() {
    let text = r#"
    action foo() {
        let x = {
            let a = 3
            let b = 4
            : a + b
        }
    }
    "#;

    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    assert_eq!(
        policy.actions[0].statements,
        vec![AstNode {
            inner: ast::Statement::Let(ast::LetStatement {
                identifier: ident!("x"),
                expression: Expression::Block(
                    vec![
                        AstNode::new(
                            ast::Statement::Let(ast::LetStatement {
                                identifier: ident!("a"),
                                expression: Expression::Int(3),
                            }),
                            50
                        ),
                        AstNode::new(
                            ast::Statement::Let(ast::LetStatement {
                                identifier: ident!("b"),
                                expression: Expression::Int(4),
                            }),
                            72
                        ),
                    ],
                    Box::new(Expression::Add(
                        Box::new(Expression::Identifier(ident!("a"))),
                        Box::new(Expression::Identifier(ident!("b"))),
                    ))
                )
            }),
            locator: 28
        }]
    );
}

#[test]
fn parse_match_expression() {
    let src = r#"
        action foo(n int) {
            let x = match n {
                0 => {
                    let x = true
                    : x
                }
                _ => false
            }
        }
    "#;

    let policy = parse_policy_str(src, Version::V2).expect("should parse");
    assert_eq!(
        policy.actions[0].statements,
        vec![AstNode {
            inner: ast::Statement::Let(ast::LetStatement {
                identifier: ident!("x"),
                expression: Expression::Match(Box::new(ast::MatchExpression {
                    scrutinee: Expression::Identifier(ident!("n")),
                    arms: vec![
                        AstNode::new(
                            ast::MatchExpressionArm {
                                pattern: MatchPattern::Values(vec![Expression::Int(0)]),
                                expression: Expression::Block(
                                    vec![AstNode::new(
                                        ast::Statement::Let(ast::LetStatement {
                                            identifier: ident!("x"),
                                            expression: Expression::Bool(true)
                                        }),
                                        102
                                    )],
                                    Box::new(Expression::Identifier(ident!("x")))
                                )
                            },
                            75
                        ),
                        AstNode::new(
                            ast::MatchExpressionArm {
                                pattern: MatchPattern::Default,
                                expression: Expression::Bool(false)
                            },
                            173
                        )
                    ]
                }))
            }),
            locator: 41
        }]
    );
}

#[test]
fn test_match_expression() {
    let invalid = vec![
        (
            // block without subexpression (`:value`)
            r#"action foo(status string) {
                let x = match a {
                    "ready" => {
                        1
                    }
                    _ => {
                        0
                    }
                }
            }"#,
            ParseErrorKind::Syntax,
        ),
        (
            // expression not assigned
            r#"function f(n int) bool {
                match n {
                    0 => {
                        :true
                    }
                    1 => {
                        : false
                    }
                }
            }"#,
            ParseErrorKind::Syntax,
        ),
        (
            // empty match
            r#"function f(n int) bool {
                return match n {}
            }"#,
            ParseErrorKind::Syntax,
        ),
    ];

    for (src, expected) in invalid {
        let err_kind = parse_policy_str(src, Version::V2).unwrap_err().kind;
        assert_eq!(err_kind, expected);
    }
}

#[test]
fn test_invalid_this() {
    let cases = [
        "action this() { }",
        "function this() int {}",
        "struct this {}",
        "enum this { A }",
        "enum A { this }",
        "let this = 42",
        "use this",
        "fact this[]=>{}",
    ];

    for src in cases {
        let err_kind = parse_policy_str(src, Version::V2).unwrap_err().kind;
        assert_eq!(err_kind, ParseErrorKind::ReservedIdentifier, "{src}");
    }
}

#[test]
fn test_invalid_text() {
    let cases = [
        // real nul byte
        "let x = \"a\0b\"",
        // \x00 escaped nul byte
        r#"let x = "a\x00b""#,
    ];

    for src in cases {
        let err = parse_policy_str(src, Version::V2).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::InvalidString, "{src:?}");
    }
}

#[test]
fn test_error_line_number_in_chunks() {
    let cases = [
        (
            r#"---
policy-version: 2
---

```policy
    let int = 0
```
"#,
            "Reserved identifier: line 6 column 9: int",
        ),
        (
            r#"---
policy-version: 2
---

```policy
    let x = 0
```
Next chunk:
```policy
    let x = 0
    let y = "a\\0b"
```
        "#,
            "Invalid string: line 11 column 13: invalid escape: \\",
        ),
        (
            r#"---
policy-version: 2
---

```policy
    let x = 0
```
Next chunk:
```policy
    let x = 0
    let = 2
```
        "#,
            r#"Syntax error: line 11 column 9:   --> 11:9
   |
11 |     let = 2
   |         ^---
   |
   = expected identifier"#,
        ),
    ];

    for (policy, expected) in cases {
        let err = parse_policy_document(policy).unwrap_err();
        assert_eq!(err.to_string(), expected);
    }
}
