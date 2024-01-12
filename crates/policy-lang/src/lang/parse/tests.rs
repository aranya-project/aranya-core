#![allow(clippy::panic)]

use std::{fs::OpenOptions, io::Read};

use ast::ForeignFunctionCall;
use pest::{error::Error as PestError, iterators::Pair, Parser};

use super::{
    ast, ast::AstNode, get_pratt_parser, parse_policy_document, parse_policy_str, ParseError,
    PolicyParser, Rule, Version,
};

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
    let expr = pairs.next().unwrap();
    let expr_parsed = super::parse_expression(expr, &pratt)?;
    assert_eq!(
        expr_parsed,
        ast::Expression::Unwrap(Box::new(ast::Expression::FunctionCall(ast::FunctionCall {
            identifier: String::from("call"),
            arguments: vec![
                ast::Expression::Add(
                    Box::new(ast::Expression::Int(3)),
                    Box::new(ast::Expression::Int(7))
                ),
                ast::Expression::Negative(Box::new(ast::Expression::Identifier(String::from("b")))),
                ast::Expression::String(String::from("foo\x7b")),
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
                emit_statement, let_statement, origin_modifier, match_statement, \
                when_statement, finish_statement, create_statement, update_statement, \
                delete_statement, effect_statement, or return_statement",
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
                "Invalid number: line 1 column 1: 18446744073709551617: \
                number too large to fit in target type",
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
                "Invalid number: line 2 column 17: 18446744073709551617: \
                number too large to fit in target type",
            ),
            rule: Rule::expression,
        },
        ErrorInput {
            description: String::from("Invalid string escape"),
            input: r#""\\""#.to_string(),
            error_message: String::from(
                "Invalid string: line 1 column 1: \"\\\\\": invalid escape: \\",
            ),
            rule: Rule::expression,
        },
    ];
    for case in cases {
        let mut pairs = PolicyParser::parse(case.rule, &case.input)?;
        let pratt = get_pratt_parser();
        let expr = pairs.next().unwrap();
        match super::parse_expression(expr, &pratt) {
            Ok(_) => panic!("{}", case.description),
            Err(e) => assert_eq!(case.error_message, e.to_string(), "{}", case.description,),
        }
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
            emit Init{
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
            emit obj
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
                let id = envelope::id(envelope)
                let author = envelope::author_id(envelope)
                let new_x = x + count
                check exists TestFact[v: "test"]=>{}
                match x {
                    0 => {
                        check positive(Some new_x)
                    }
                    1 => {
                        origin check positive(None)
                    }
                }

                when x == 3 {
                    check new_x < 10
                }

                let a = foo::ext_func(x)

                finish {
                    create F[v: "hello"]=>{x: x, y: -x}
                    update F[]=>{x: x} to {x: new_x}
                    delete F[v: "hello"]
                    effect Added {
                        x: new_x,
                        y: count,
                    }
                }
            }
            recall {
                let id = envelope::id(envelope)
                let author = envelope::author_id(envelope)
                let new_x = x + count
                finish {
                    create F[v: "hello"]=>{x: x, y: -x}
                    update F[]=>{x: x} to {x: new_x}
                    delete F[v: "hello"]
                    effect Added {
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

    let policy = parse_policy_str(policy_str, Version::V3)?;

    assert_eq!(
        policy.facts,
        vec![AstNode::new(
            ast::FactDefinition {
                identifier: String::from("F"),
                key: vec![ast::FieldDefinition {
                    identifier: String::from("v"),
                    field_type: ast::VType::String,
                }],
                value: vec![
                    ast::FieldDefinition {
                        identifier: String::from("x"),
                        field_type: ast::VType::Int,
                    },
                    ast::FieldDefinition {
                        identifier: String::from("y"),
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
                identifier: String::from("add"),
                arguments: vec![
                    ast::FieldDefinition {
                        identifier: String::from("x"),
                        field_type: ast::VType::Int,
                    },
                    ast::FieldDefinition {
                        identifier: String::from("y"),
                        field_type: ast::VType::Int,
                    },
                ],
                statements: vec![
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: String::from("obj"),
                            expression: ast::Expression::NamedStruct(ast::NamedStruct {
                                identifier: String::from("Add"),
                                fields: vec![(
                                    String::from("count"),
                                    ast::Expression::Identifier(String::from("x")),
                                )],
                            }),
                        }),
                        227,
                    ),
                    AstNode::new(
                        ast::Statement::Emit(ast::Expression::Identifier(String::from("obj"))),
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
                identifier: String::from("Added"),
                fields: vec![
                    ast::EffectFieldDefinition {
                        identifier: String::from("x"),
                        field_type: ast::VType::Int,
                        dynamic: true,
                    },
                    ast::EffectFieldDefinition {
                        identifier: String::from("y"),
                        field_type: ast::VType::Int,
                        dynamic: false,
                    },
                ],
            },
            323,
        )]
    );
    assert_eq!(
        policy.commands,
        vec![AstNode::new(
            ast::CommandDefinition {
                identifier: String::from("Add"),
                fields: vec![ast::FieldDefinition {
                    identifier: String::from("count"),
                    field_type: ast::VType::Int,
                }],
                seal: vec![],
                open: vec![],
                policy: vec![
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: String::from("id"),
                            expression: ast::Expression::ForeignFunctionCall(ForeignFunctionCall {
                                module: String::from("envelope"),
                                identifier: String::from("id"),
                                arguments: vec![ast::Expression::Identifier(String::from(
                                    "envelope"
                                ))]
                            },),
                        }),
                        516,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: String::from("author"),
                            expression: ast::Expression::ForeignFunctionCall(ForeignFunctionCall {
                                module: String::from("envelope"),
                                identifier: String::from("author_id"),
                                arguments: vec![ast::Expression::Identifier(String::from(
                                    "envelope"
                                ))]
                            },),
                        }),
                        564,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: String::from("new_x"),
                            expression: ast::Expression::Add(
                                Box::new(ast::Expression::Identifier(String::from("x"))),
                                Box::new(ast::Expression::Identifier(String::from("count"))),
                            ),
                        }),
                        623,
                    ),
                    AstNode::new(
                        ast::Statement::Check(ast::CheckStatement {
                            origin: false,
                            expression: ast::Expression::InternalFunction(
                                ast::InternalFunction::Exists(ast::FactLiteral {
                                    identifier: String::from("TestFact"),
                                    key_fields: vec![(
                                        String::from("v"),
                                        ast::Expression::String(String::from("test")),
                                    )],
                                    value_fields: Some(vec![]),
                                }),
                            ),
                        }),
                        661,
                    ),
                    AstNode::new(
                        ast::Statement::Match(ast::MatchStatement {
                            expression: ast::Expression::Identifier(String::from("x")),
                            arms: vec![
                                ast::MatchArm {
                                    value: Some(ast::Expression::Int(0)),
                                    statements: vec![AstNode::new(
                                        ast::Statement::Check(ast::CheckStatement {
                                            origin: false,
                                            expression: ast::Expression::FunctionCall(
                                                ast::FunctionCall {
                                                    identifier: String::from("positive"),
                                                    arguments: vec![ast::Expression::Optional(
                                                        Some(Box::new(
                                                            ast::Expression::Identifier(
                                                                String::from("new_x"),
                                                            ),
                                                        )),
                                                    )],
                                                },
                                            ),
                                        }),
                                        775,
                                    )],
                                },
                                ast::MatchArm {
                                    value: Some(ast::Expression::Int(1)),
                                    statements: vec![AstNode::new(
                                        ast::Statement::Check(ast::CheckStatement {
                                            origin: true,
                                            expression: ast::Expression::FunctionCall(
                                                ast::FunctionCall {
                                                    identifier: String::from("positive"),
                                                    arguments: vec![ast::Expression::Optional(
                                                        None,
                                                    )],
                                                },
                                            ),
                                        }),
                                        875,
                                    )],
                                },
                            ],
                        }),
                        714,
                    ),
                    AstNode::new(
                        ast::Statement::When(ast::WhenStatement {
                            expression: ast::Expression::Equal(
                                Box::new(ast::Expression::Identifier(String::from("x"))),
                                Box::new(ast::Expression::Int(3)),
                            ),
                            statements: vec![AstNode::new(
                                ast::Statement::Check(ast::CheckStatement {
                                    origin: false,
                                    expression: ast::Expression::LessThan(
                                        Box::new(ast::Expression::Identifier(String::from(
                                            "new_x",
                                        ))),
                                        Box::new(ast::Expression::Int(10)),
                                    ),
                                }),
                                994,
                            )],
                        }),
                        960,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: String::from("a"),
                            expression: ast::Expression::ForeignFunctionCall(ForeignFunctionCall {
                                module: String::from("foo"),
                                identifier: String::from("ext_func"),
                                arguments: vec![ast::Expression::Identifier(String::from("x"))],
                            }),
                        }),
                        1046
                    ),
                    AstNode::new(
                        ast::Statement::Finish(vec![
                            AstNode::new(
                                ast::Statement::Create(ast::CreateStatement {
                                    fact: ast::FactLiteral {
                                        identifier: String::from("F"),
                                        key_fields: vec![(
                                            String::from("v"),
                                            ast::Expression::String(String::from("hello")),
                                        )],
                                        value_fields: Some(vec![
                                            (
                                                String::from("x"),
                                                ast::Expression::Identifier(String::from("x")),
                                            ),
                                            (
                                                String::from("y"),
                                                ast::Expression::Negative(Box::new(
                                                    ast::Expression::Identifier(String::from("x")),
                                                )),
                                            ),
                                        ]),
                                    },
                                }),
                                1117
                            ),
                            AstNode::new(
                                ast::Statement::Update(ast::UpdateStatement {
                                    fact: ast::FactLiteral {
                                        identifier: String::from("F"),
                                        key_fields: vec![],
                                        value_fields: Some(vec![(
                                            String::from("x"),
                                            ast::Expression::Identifier(String::from("x")),
                                        )]),
                                    },
                                    to: vec![(
                                        String::from("x"),
                                        ast::Expression::Identifier(String::from("new_x")),
                                    )],
                                }),
                                1173
                            ),
                            AstNode::new(
                                ast::Statement::Delete(ast::DeleteStatement {
                                    fact: ast::FactLiteral {
                                        identifier: String::from("F"),
                                        key_fields: vec![(
                                            String::from("v"),
                                            ast::Expression::String(String::from("hello")),
                                        )],
                                        value_fields: None,
                                    },
                                }),
                                1226
                            ),
                            AstNode::new(
                                ast::Statement::Effect(ast::Expression::NamedStruct(
                                    ast::NamedStruct {
                                        identifier: String::from("Added"),
                                        fields: vec![
                                            (
                                                String::from("x"),
                                                ast::Expression::Identifier(String::from("new_x")),
                                            ),
                                            (
                                                String::from("y"),
                                                ast::Expression::Identifier(String::from("count")),
                                            ),
                                        ],
                                    },
                                )),
                                1267
                            ),
                        ]),
                        1088,
                    ),
                ],
                recall: vec![
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: String::from("id"),
                            expression: ast::Expression::ForeignFunctionCall(ForeignFunctionCall {
                                module: String::from("envelope"),
                                identifier: String::from("id"),
                                arguments: vec![ast::Expression::Identifier(String::from(
                                    "envelope"
                                ))]
                            },),
                        }),
                        1441,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: String::from("author"),
                            expression: ast::Expression::ForeignFunctionCall(ForeignFunctionCall {
                                module: String::from("envelope"),
                                identifier: String::from("author_id"),
                                arguments: vec![ast::Expression::Identifier(String::from(
                                    "envelope"
                                ))]
                            },),
                        }),
                        1489,
                    ),
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: String::from("new_x"),
                            expression: ast::Expression::Add(
                                Box::new(ast::Expression::Identifier(String::from("x"))),
                                Box::new(ast::Expression::Identifier(String::from("count"))),
                            ),
                        }),
                        1548,
                    ),
                    AstNode::new(
                        ast::Statement::Finish(vec![
                            AstNode::new(
                                ast::Statement::Create(ast::CreateStatement {
                                    fact: ast::FactLiteral {
                                        identifier: String::from("F"),
                                        key_fields: vec![(
                                            String::from("v"),
                                            ast::Expression::String(String::from("hello")),
                                        )],
                                        value_fields: Some(vec![
                                            (
                                                String::from("x"),
                                                ast::Expression::Identifier(String::from("x")),
                                            ),
                                            (
                                                String::from("y"),
                                                ast::Expression::Negative(Box::new(
                                                    ast::Expression::Identifier(String::from("x")),
                                                )),
                                            ),
                                        ]),
                                    },
                                }),
                                1615
                            ),
                            AstNode::new(
                                ast::Statement::Update(ast::UpdateStatement {
                                    fact: ast::FactLiteral {
                                        identifier: String::from("F"),
                                        key_fields: vec![],
                                        value_fields: Some(vec![(
                                            String::from("x"),
                                            ast::Expression::Identifier(String::from("x")),
                                        )]),
                                    },
                                    to: vec![(
                                        String::from("x"),
                                        ast::Expression::Identifier(String::from("new_x")),
                                    )],
                                }),
                                1671
                            ),
                            AstNode::new(
                                ast::Statement::Delete(ast::DeleteStatement {
                                    fact: ast::FactLiteral {
                                        identifier: String::from("F"),
                                        key_fields: vec![(
                                            String::from("v"),
                                            ast::Expression::String(String::from("hello")),
                                        )],
                                        value_fields: None,
                                    },
                                }),
                                1724
                            ),
                            AstNode::new(
                                ast::Statement::Effect(ast::Expression::NamedStruct(
                                    ast::NamedStruct {
                                        identifier: String::from("Added"),
                                        fields: vec![
                                            (
                                                String::from("x"),
                                                ast::Expression::Identifier(String::from("new_x")),
                                            ),
                                            (
                                                String::from("y"),
                                                ast::Expression::Identifier(String::from("count")),
                                            ),
                                        ],
                                    },
                                )),
                                1765
                            ),
                        ]),
                        1586,
                    ),
                ],
            },
            403,
        )]
    );
    assert_eq!(
        policy.functions,
        vec![AstNode::new(
            ast::FunctionDefinition {
                identifier: String::from("positive"),
                arguments: vec![ast::FieldDefinition {
                    identifier: String::from("v"),
                    field_type: ast::VType::Optional(Box::new(ast::VType::Int)),
                }],
                return_type: ast::VType::Bool,
                statements: vec![
                    AstNode::new(
                        ast::Statement::Let(ast::LetStatement {
                            identifier: String::from("x"),
                            expression: ast::Expression::Unwrap(Box::new(
                                ast::Expression::Identifier(String::from("v")),
                            )),
                        }),
                        1974,
                    ),
                    AstNode::new(
                        ast::Statement::Return(ast::ReturnStatement {
                            expression: ast::Expression::GreaterThan(
                                Box::new(ast::Expression::Identifier(String::from("x"))),
                                Box::new(ast::Expression::Int(0)),
                            ),
                        }),
                        2003,
                    ),
                ],
            },
            1921,
        )]
    );
    assert_eq!(
        policy.finish_functions,
        vec![AstNode::new(
            ast::FinishFunctionDefinition {
                identifier: String::from("next"),
                arguments: vec![ast::FieldDefinition {
                    identifier: String::from("x"),
                    field_type: ast::VType::Int,
                }],
                statements: vec![AstNode::new(
                    ast::Statement::Create(ast::CreateStatement {
                        fact: ast::FactLiteral {
                            identifier: String::from("Next"),
                            key_fields: vec![],
                            value_fields: Some(vec![]),
                        },
                    }),
                    2077
                )],
            },
            2035,
        )]
    );

    let (start, end) = *policy
        .ranges
        .iter()
        .find(|(start, _)| *start == 623)
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
fn empty_policy() -> Result<(), ParseError> {
    let policy = parse_policy_str("", Version::V3)?;
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
policy-version: 3
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
    emit SomeCommand{}
}
```
"#;

    let policy = parse_policy_document(md).unwrap_or_else(|e| panic!("{e}"));

    assert!(policy.version == Version::V3);
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

    parse_policy_str(text, Version::V3).unwrap_or_else(|e| panic!("{e}"));
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

    let policy = parse_policy_str(text, Version::V3).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        policy.structs,
        vec![AstNode::new(
            ast::StructDefinition {
                identifier: String::from("Foo"),
                fields: vec![ast::FieldDefinition {
                    identifier: String::from("x"),
                    field_type: ast::VType::Int,
                }]
            },
            0
        )]
    );
    assert_eq!(
        policy.functions,
        vec![AstNode::new(
            ast::FunctionDefinition {
                identifier: String::from("convert"),
                arguments: vec![ast::FieldDefinition {
                    identifier: String::from("foo"),
                    field_type: ast::VType::Struct(String::from("Foo")),
                }],
                return_type: ast::VType::Struct(String::from("Bar")),
                statements: vec![AstNode::new(
                    ast::Statement::Return(ast::ReturnStatement {
                        expression: ast::Expression::NamedStruct(ast::NamedStruct {
                            identifier: String::from("Bar"),
                            fields: vec![(
                                String::from("y"),
                                ast::Expression::Dot(
                                    Box::new(ast::Expression::Identifier(String::from("foo"))),
                                    String::from("x")
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
fn parse_ffi_decl() {
    let text = "function foo(x int, y struct bar) bool";
    let decl = super::parse_ffi_decl(text).expect("parse");
    assert_eq!(
        decl,
        ast::FunctionDecl {
            identifier: String::from("foo"),
            arguments: vec![
                ast::FieldDefinition {
                    identifier: String::from("x"),
                    field_type: ast::VType::Int,
                },
                ast::FieldDefinition {
                    identifier: String::from("y"),
                    field_type: ast::VType::Struct(String::from("bar")),
                }
            ],
            return_type: Some(ast::VType::Bool)
        }
    )
}

#[test]
fn parse_ffi_structs() {
    let text = r#"
        struct A {
            x int,
            y bool
        }

        struct B {}
    "#
    .trim();
    let structs = super::parse_ffi_structs(text).expect("parse");
    assert_eq!(
        structs,
        vec![
            AstNode {
                inner: ast::StructDefinition {
                    identifier: String::from("A"),
                    fields: vec![
                        ast::FieldDefinition {
                            identifier: String::from("x"),
                            field_type: ast::VType::Int
                        },
                        ast::FieldDefinition {
                            identifier: String::from("y"),
                            field_type: ast::VType::Bool
                        }
                    ]
                },
                locator: 0,
            },
            AstNode {
                inner: ast::StructDefinition {
                    identifier: String::from("B"),
                    fields: vec![],
                },
                locator: 68,
            },
        ],
    )
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
    let policy = parse_policy_str(text, Version::V3).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        policy.commands,
        vec![AstNode::new(
            ast::CommandDefinition {
                identifier: String::from("Foo"),
                fields: vec![],
                policy: vec![],
                recall: vec![],
                seal: vec![AstNode::new(
                    ast::Statement::Return(ast::ReturnStatement {
                        expression: ast::Expression::FunctionCall(ast::FunctionCall {
                            identifier: String::from("bar"),
                            arguments: vec![ast::Expression::Identifier(String::from("this"))]
                        })
                    }),
                    49
                )],
                open: vec![AstNode::new(
                    ast::Statement::Return(ast::ReturnStatement {
                        expression: ast::Expression::FunctionCall(ast::FunctionCall {
                            identifier: String::from("baz"),
                            arguments: vec![ast::Expression::Identifier(String::from("envelope"))]
                        })
                    }),
                    116
                )],
            },
            0
        )]
    );
}
