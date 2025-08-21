#![allow(clippy::panic)]

use std::{fs::OpenOptions, io::Read};

use aranya_policy_ast::{ident, text, ExprKind, Ident, Identifier, Span, StmtKind, TypeKind};
use ast::{Expression, FactField, ForeignFunctionCall, MatchPattern};
use pest::{error::Error as PestError, iterators::Pair, Parser};

use super::{
    ast, get_pratt_parser, parse_policy_document, parse_policy_str, ParseError, PolicyParser, Rule,
    Version,
};
use crate::lang::{ChunkParser, FfiTypes, ParseErrorKind};

trait Spanned {
    type Type;
    fn at(self, span: impl Into<Span>) -> Self::Type;
}

impl Spanned for Identifier {
    type Type = Ident;
    fn at(self, span: impl Into<Span>) -> Self::Type {
        Ident {
            name: self,
            span: span.into(),
        }
    }
}

impl Spanned for TypeKind {
    type Type = ast::VType;
    fn at(self, span: impl Into<Span>) -> Self::Type {
        ast::VType {
            kind: self,
            span: span.into(),
        }
    }
}

impl Spanned for ExprKind {
    type Type = Expression;
    fn at(self, span: impl Into<Span>) -> Self::Type {
        Expression {
            kind: self,
            span: span.into(),
        }
    }
}

impl Spanned for StmtKind {
    type Type = ast::Statement;
    fn at(self, span: impl Into<Span>) -> Self::Type {
        ast::Statement {
            kind: self,
            span: span.into(),
        }
    }
}

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
    let source = r#"
        unwrap call(3 + 7, -b, "foo\x7b")
    "#
    .trim();
    let mut pairs = PolicyParser::parse(Rule::expression, source)?;
    let pratt = get_pratt_parser();
    let p = ChunkParser::new(0, &pratt, source.len());
    let expr_pair = pairs.next().unwrap();
    let expr_parsed = p.parse_expression(expr_pair)?;
    assert_eq!(
        expr_parsed,
        ExprKind::Unwrap(Box::new(
            ExprKind::FunctionCall(ast::FunctionCall {
                identifier: ident!("call").at(7..33),
                arguments: vec![
                    ExprKind::Add(
                        Box::new(ExprKind::Int(3).at(12..13)),
                        Box::new(ExprKind::Int(7).at(16..17))
                    )
                    .at(12..17),
                    ExprKind::Negative(Box::new(ExprKind::Identifier(ident!("b")).at(20..21)))
                        .at(19..21),
                    ExprKind::String(text!("foo\x7b")).at(23..32),
                ]
            })
            .at(7..33)
        ))
        .at(0..33)
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
                "Invalid substruct operation: line 1 column 3: Expression to the right of the substruct operator must be an identifier, got Int(4)",
            ),
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
                identifier: ident!("y").at(72..86),
                field_type: TypeKind::Int.at(74..77),
                dynamic: false,
            }),
        ],
    )];
    for (case, expected) in cases {
        let policy = parse_policy_str(case, Version::V2).expect("should parse");
        assert_eq!(
            policy.effects[0].items, expected,
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
    assert_eq!(value, &ExprKind::String(text!("high")).at(74..80));
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


        // ephemeral commands and actions

        ephemeral command C {
            fields {
                x int
            }
        }

        ephemeral action a() {}
    "#;

    let policy = parse_policy_str(policy_str, Version::V2)?;

    assert_eq!(
        policy.facts,
        vec![ast::FactDefinition {
            immutable: false,
            identifier: ident!("F").at(150..151),
            key: vec![ast::FieldDefinition {
                identifier: ident!("v").at(152..160),
                field_type: TypeKind::String.at(154..160),
            }],
            value: vec![
                ast::FieldDefinition {
                    identifier: ident!("x").at(164..169),
                    field_type: TypeKind::Int.at(166..169),
                },
                ast::FieldDefinition {
                    identifier: ident!("y").at(171..177),
                    field_type: TypeKind::Bool.at(173..177),
                },
            ],
            span: Span::new(145, 178),
        }]
    );
    assert_eq!(
        policy.actions,
        vec![
            ast::ActionDefinition {
                persistence: ast::Persistence::Persistent,
                identifier: ident!("add").at(195..198),
                arguments: vec![
                    ast::FieldDefinition {
                        identifier: ident!("x").at(199..204),
                        field_type: TypeKind::Int.at(201..204),
                    },
                    ast::FieldDefinition {
                        identifier: ident!("y").at(206..211),
                        field_type: TypeKind::Int.at(208..211),
                    },
                ],
                statements: vec![
                    StmtKind::Let(ast::LetStatement {
                        identifier: ident!("obj").at(231..234),
                        expression: ExprKind::NamedStruct(ast::NamedStruct {
                            identifier: ident!("Add").at(237..282),
                            fields: vec![(
                                ident!("count").at(259..267),
                                ExprKind::Identifier(ident!("x")).at(266..267)
                            )],
                        })
                        .at(237..282)
                    })
                    .at(227..295),
                    StmtKind::Publish(ExprKind::Identifier(ident!("obj")).at(303..306))
                        .at(295..315),
                ],
                span: Span::new(188, 316),
            },
            ast::ActionDefinition {
                persistence: ast::Persistence::Ephemeral,
                identifier: ident!("a").at(2348..2349),
                arguments: vec![],
                statements: vec![],
                span: Span::new(2331, 2354),
            }
        ]
    );
    assert_eq!(
        policy.effects,
        vec![ast::EffectDefinition {
            identifier: ident!("Added").at(333..338),
            items: vec![
                ast::StructItem::Field(ast::EffectFieldDefinition {
                    identifier: ident!("x").at(353..366),
                    field_type: TypeKind::Int.at(355..358),
                    dynamic: true,
                }),
                ast::StructItem::Field(ast::EffectFieldDefinition {
                    identifier: ident!("y").at(380..385),
                    field_type: TypeKind::Int.at(382..385),
                    dynamic: false,
                }),
            ],
            span: Span::new(326, 396),
        }]
    );
    assert_eq!(
        policy.commands,
        vec![
            ast::CommandDefinition {
                persistence: ast::Persistence::Persistent,
                attributes: vec![],
                identifier: ident!("Add").at(414..417),
                fields: vec![ast::StructItem::Field(ast::FieldDefinition {
                    identifier: ident!("count").at(457..466),
                    field_type: TypeKind::Int.at(463..466),
                })],
                seal: vec![],
                open: vec![],
                policy: vec![
                    StmtKind::Let(ast::LetStatement {
                        identifier: ident!("envelope_id").at(523..534),
                        expression: ExprKind::ForeignFunctionCall(ForeignFunctionCall {
                            module: ident!("envelope").at(537..567),
                            identifier: ident!("command_id").at(547..567),
                            arguments: vec![ExprKind::Identifier(ident!("envelope")).at(558..566)]
                        })
                        .at(537..567),
                    })
                    .at(519..584),
                    StmtKind::Let(ast::LetStatement {
                        identifier: ident!("author").at(588..594),
                        expression: ExprKind::ForeignFunctionCall(ForeignFunctionCall {
                            module: ident!("envelope").at(597..626),
                            identifier: ident!("author_id").at(607..626),
                            arguments: vec![ExprKind::Identifier(ident!("envelope")).at(617..625)]
                        })
                        .at(597..626),
                    })
                    .at(584..643),
                    StmtKind::Let(ast::LetStatement {
                        identifier: ident!("new_x").at(647..652),
                        expression: ExprKind::Add(
                            Box::new(ExprKind::Identifier(ident!("x")).at(655..656)),
                            Box::new(ExprKind::Identifier(ident!("count")).at(659..664))
                        )
                        .at(655..664)
                    })
                    .at(643..681),
                    StmtKind::Check(ast::CheckStatement {
                        expression: ExprKind::InternalFunction(ast::InternalFunction::Exists(
                            ast::FactLiteral {
                                identifier: ident!("TestFact").at(694..717),
                                key_fields: vec![(
                                    ident!("v").at(703..712),
                                    FactField::Expression(
                                        ExprKind::String(text!("test")).at(706..712)
                                    )
                                )],
                                value_fields: Some(vec![]),
                            }
                        ))
                        .at(687..717)
                    })
                    .at(681..734),
                    StmtKind::Match(ast::MatchStatement {
                        expression: ExprKind::Identifier(ident!("x")).at(740..741),
                        arms: vec![
                            ast::MatchArm {
                                pattern: MatchPattern::Values(vec![ExprKind::Int(0).at(764..765)]),
                                statements: vec![StmtKind::Check(ast::CheckStatement {
                                    expression: ExprKind::FunctionCall(ast::FunctionCall {
                                        identifier: ident!("positive").at(801..822),
                                        arguments: vec![ExprKind::Optional(Some(Box::new(
                                            ExprKind::Identifier(ident!("new_x")).at(815..820)
                                        )))
                                        .at(810..821)],
                                    })
                                    .at(801..822)
                                })
                                .at(795..843)],
                            },
                            ast::MatchArm {
                                pattern: MatchPattern::Values(vec![ExprKind::Int(1).at(865..866)]),
                                statements: vec![StmtKind::Check(ast::CheckStatement {
                                    expression: ExprKind::FunctionCall(ast::FunctionCall {
                                        identifier: ident!("positive").at(902..916),
                                        arguments: vec![ExprKind::Optional(None).at(911..915)],
                                    })
                                    .at(902..916)
                                })
                                .at(896..937)],
                            },
                            ast::MatchArm {
                                pattern: MatchPattern::Default,
                                statements: vec![],
                            },
                        ],
                    })
                    .at(734..1006),
                    StmtKind::If(ast::IfStatement {
                        branches: vec![(
                            ExprKind::Equal(
                                Box::new(ExprKind::Identifier(ident!("x")).at(1027..1028)),
                                Box::new(ExprKind::Int(3).at(1032..1033))
                            )
                            .at(1027..1033),
                            vec![StmtKind::Check(ast::CheckStatement {
                                expression: ExprKind::LessThan(
                                    Box::new(ExprKind::Identifier(ident!("new_x")).at(1062..1067)),
                                    Box::new(ExprKind::Int(10).at(1070..1072))
                                )
                                .at(1062..1072)
                            })
                            .at(1056..1089)],
                        )],
                        fallback: None
                    })
                    .at(1024..1108),
                    StmtKind::Let(ast::LetStatement {
                        identifier: ident!("a").at(1112..1113),
                        expression: ExprKind::ForeignFunctionCall(ForeignFunctionCall {
                            module: ident!("foo").at(1116..1132),
                            identifier: ident!("ext_func").at(1121..1132),
                            arguments: vec![ExprKind::Identifier(ident!("x")).at(1130..1131)]
                        })
                        .at(1116..1132)
                    })
                    .at(1108..1150),
                    StmtKind::Finish(vec![
                        StmtKind::Create(ast::CreateStatement {
                            fact: ast::FactLiteral {
                                identifier: ident!("F").at(1186..1214),
                                key_fields: vec![(
                                    ident!("v").at(1188..1198),
                                    FactField::Expression(
                                        ExprKind::String(text!("hello")).at(1191..1198)
                                    )
                                )],
                                value_fields: Some(vec![
                                    (
                                        ident!("x").at(1202..1206),
                                        FactField::Expression(
                                            ExprKind::Identifier(ident!("x")).at(1205..1206)
                                        )
                                    ),
                                    (
                                        ident!("y").at(1208..1213),
                                        FactField::Expression(
                                            ExprKind::Negative(Box::new(
                                                ExprKind::Identifier(ident!("x")).at(1212..1213)
                                            ))
                                            .at(1211..1213)
                                        )
                                    ),
                                ]),
                            },
                        })
                        .at(1179..1214),
                        StmtKind::Update(ast::UpdateStatement {
                            fact: ast::FactLiteral {
                                identifier: ident!("F").at(1242..1253),
                                key_fields: vec![],
                                value_fields: Some(vec![(
                                    ident!("x").at(1248..1252),
                                    FactField::Expression(
                                        ExprKind::Identifier(ident!("x")).at(1251..1252)
                                    )
                                )]),
                            },
                            to: vec![(
                                ident!("x").at(1242..1253),
                                FactField::Expression(
                                    ExprKind::Identifier(ident!("new_x")).at(1261..1266)
                                )
                            )],
                        })
                        .at(1235..1267),
                        StmtKind::Delete(ast::DeleteStatement {
                            fact: ast::FactLiteral {
                                identifier: ident!("F").at(1295..1329),
                                key_fields: vec![(
                                    ident!("v").at(1297..1307),
                                    FactField::Expression(
                                        ExprKind::String(text!("hello")).at(1300..1307)
                                    )
                                )],
                                value_fields: None,
                            },
                        })
                        .at(1288..1329),
                        StmtKind::Emit(
                            ExprKind::NamedStruct(ast::NamedStruct {
                                identifier: ident!("Added").at(1334..1431),
                                fields: vec![
                                    (
                                        ident!("x").at(1366..1374),
                                        ExprKind::Identifier(ident!("new_x")).at(1369..1374)
                                    ),
                                    (
                                        ident!("y").at(1400..1408),
                                        ExprKind::Identifier(ident!("count")).at(1403..1408)
                                    ),
                                ],
                            })
                            .at(1334..1431)
                        )
                        .at(1329..1448),
                    ])
                    .at(1150..1449),
                ],
                recall: vec![
                    StmtKind::Let(ast::LetStatement {
                        identifier: ident!("envelope_id").at(1505..1516),
                        expression: ExprKind::ForeignFunctionCall(ForeignFunctionCall {
                            module: ident!("envelope").at(1519..1549),
                            identifier: ident!("command_id").at(1529..1549),
                            arguments: vec![ExprKind::Identifier(ident!("envelope")).at(1540..1548)]
                        })
                        .at(1519..1549),
                    })
                    .at(1501..1566),
                    StmtKind::Let(ast::LetStatement {
                        identifier: ident!("author").at(1570..1576),
                        expression: ExprKind::ForeignFunctionCall(ForeignFunctionCall {
                            module: ident!("envelope").at(1579..1608),
                            identifier: ident!("author_id").at(1589..1608),
                            arguments: vec![ExprKind::Identifier(ident!("envelope")).at(1599..1607)]
                        })
                        .at(1579..1608),
                    })
                    .at(1566..1625),
                    StmtKind::Let(ast::LetStatement {
                        identifier: ident!("new_x").at(1629..1634),
                        expression: ExprKind::Add(
                            Box::new(ExprKind::Identifier(ident!("x")).at(1637..1638)),
                            Box::new(ExprKind::Identifier(ident!("count")).at(1641..1646))
                        )
                        .at(1637..1646),
                    })
                    .at(1625..1663),
                    StmtKind::Finish(vec![
                        StmtKind::Create(ast::CreateStatement {
                            fact: ast::FactLiteral {
                                identifier: ident!("F").at(1699..1727),
                                key_fields: vec![(
                                    ident!("v").at(1701..1711),
                                    FactField::Expression(
                                        ExprKind::String(text!("hello")).at(1704..1711)
                                    )
                                )],
                                value_fields: Some(vec![
                                    (
                                        ident!("x").at(1715..1719),
                                        FactField::Expression(
                                            ExprKind::Identifier(ident!("x")).at(1718..1719)
                                        ),
                                    ),
                                    (
                                        ident!("y").at(1721..1726),
                                        FactField::Expression(
                                            ExprKind::Negative(Box::new(
                                                ExprKind::Identifier(ident!("x")).at(1725..1726)
                                            ))
                                            .at(1724..1726)
                                        )
                                    ),
                                ]),
                            },
                        })
                        .at(1692..1727),
                        StmtKind::Update(ast::UpdateStatement {
                            fact: ast::FactLiteral {
                                identifier: ident!("F").at(1755..1766),
                                key_fields: vec![],
                                value_fields: Some(vec![(
                                    ident!("x").at(1761..1765),
                                    FactField::Expression(
                                        ExprKind::Identifier(ident!("x")).at(1764..1765)
                                    )
                                )]),
                            },
                            to: vec![(
                                ident!("x").at(1755..1766),
                                FactField::Expression(
                                    ExprKind::Identifier(ident!("new_x")).at(1774..1779)
                                )
                            )],
                        })
                        .at(1748..1780),
                        StmtKind::Delete(ast::DeleteStatement {
                            fact: ast::FactLiteral {
                                identifier: ident!("F").at(1808..1842),
                                key_fields: vec![(
                                    ident!("v").at(1810..1820),
                                    FactField::Expression(
                                        ExprKind::String(text!("hello")).at(1813..1820)
                                    )
                                )],
                                value_fields: None,
                            },
                        })
                        .at(1801..1842),
                        StmtKind::Emit(
                            ExprKind::NamedStruct(ast::NamedStruct {
                                identifier: ident!("Added").at(1847..1944),
                                fields: vec![
                                    (
                                        ident!("x").at(1879..1887),
                                        ExprKind::Identifier(ident!("new_x")).at(1882..1887)
                                    ),
                                    (
                                        ident!("y").at(1913..1921),
                                        ExprKind::Identifier(ident!("count")).at(1916..1921)
                                    ),
                                ],
                            })
                            .at(1847..1944)
                        )
                        .at(1842..1961),
                    ])
                    .at(1663..1962),
                ],
                span: Span::new(406, 1986),
            },
            ast::CommandDefinition {
                persistence: ast::Persistence::Ephemeral,
                attributes: vec![],
                identifier: ident!("C").at(2251..2252),
                fields: vec![ast::StructItem::Field(ast::FieldDefinition {
                    identifier: ident!("x").at(2292..2297),
                    field_type: TypeKind::Int.at(2294..2297),
                })],
                policy: vec![],
                seal: vec![],
                open: vec![],
                recall: vec![],
                span: Span::new(2233, 2321),
            }
        ]
    );
    assert_eq!(
        policy.functions,
        vec![ast::FunctionDefinition {
            identifier: ident!("positive").at(2005..2013),
            arguments: vec![ast::FieldDefinition {
                identifier: ident!("v").at(2014..2028),
                field_type: TypeKind::Optional(Box::new(TypeKind::Int.at(2025..2028)))
                    .at(2016..2028),
            }],
            return_type: TypeKind::Bool.at(2030..2034),
            statements: vec![
                StmtKind::Let(ast::LetStatement {
                    identifier: ident!("x").at(2053..2054),
                    expression: ExprKind::Unwrap(Box::new(
                        ExprKind::Identifier(ident!("v")).at(2064..2065)
                    ))
                    .at(2057..2065),
                })
                .at(2049..2078),
                StmtKind::Return(ast::ReturnStatement {
                    expression: ExprKind::GreaterThan(
                        Box::new(ExprKind::Identifier(ident!("x")).at(2085..2086)),
                        Box::new(ExprKind::Int(0).at(2089..2090))
                    )
                    .at(2085..2090),
                })
                .at(2078..2099),
            ],
            span: Span::new(1996, 2100),
        }]
    );
    assert_eq!(
        policy.finish_functions,
        vec![ast::FinishFunctionDefinition {
            identifier: ident!("next").at(2126..2130),
            arguments: vec![ast::FieldDefinition {
                identifier: ident!("x").at(2131..2136),
                field_type: TypeKind::Int.at(2133..2136),
            }],
            statements: vec![StmtKind::Create(ast::CreateStatement {
                fact: ast::FactLiteral {
                    identifier: ident!("Next").at(2159..2169),
                    key_fields: vec![],
                    value_fields: Some(vec![]),
                },
            })
            .at(2152..2169)],
            span: Span::new(2110, 2179),
        }]
    );

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
            ast::FactDefinition {
                immutable: false,
                identifier: ident!("A").at(14..15),
                key: vec![],
                value: vec![],
                span: Span::new(9, 21),
            },
            ast::FactDefinition {
                immutable: true,
                identifier: ident!("B").at(45..46),
                key: vec![],
                value: vec![],
                span: Span::new(30, 52),
            }
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
            return Bar { y: foo.x, ...baz, ...thud }
        }
    "#
    .trim();

    let policy = parse_policy_str(text, Version::V2).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        policy.structs,
        vec![ast::StructDefinition {
            identifier: ident!("Foo").at(7..10),
            items: vec![ast::StructItem::Field(ast::FieldDefinition {
                identifier: ident!("x").at(25..30),
                field_type: TypeKind::Int.at(27..30),
            })],
            span: Span::new(0, 40),
        }]
    );
    assert_eq!(
        policy.functions,
        vec![ast::FunctionDefinition {
            identifier: ident!("convert").at(59..66),
            arguments: vec![ast::FieldDefinition {
                identifier: ident!("foo").at(67..81),
                field_type: TypeKind::Struct(ident!("Foo")).at(71..81),
            }],
            return_type: TypeKind::Struct(ident!("Bar")).at(83..93),
            statements: vec![StmtKind::Return(ast::ReturnStatement {
                expression: ExprKind::NamedStruct(ast::NamedStruct {
                    identifier: ident!("Bar").at(115..129),
                    fields: vec![(
                        ident!("y").at(120..128),
                        ExprKind::Dot(
                            Box::new(ExprKind::Identifier(ident!("foo")).at(123..126)),
                            ident!("x").at(127..128)
                        )
                        .at(123..128)
                    )],
                })
                .at(115..129)
            })
            .at(108..138)],
            span: Span::new(50, 139),
        }]
    );
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
                identifier: ident!("y").at(72..77),
                field_type: TypeKind::Int.at(74..77),
            }),
        ],
    )];
    for (case, expected) in cases {
        let policy = parse_policy_str(case, Version::V2).expect("should parse");
        assert_eq!(
            policy.structs[1].items, expected,
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
        vec![ast::EnumDefinition {
            identifier: Ident {
                name: "Color".parse().unwrap(),
                span: Span::new(0, 76)
            },
            variants: vec![
                Ident {
                    name: "Red".parse().unwrap(),
                    span: Span::new(0, 76)
                },
                Ident {
                    name: "Green".parse().unwrap(),
                    span: Span::new(0, 76)
                },
                Ident {
                    name: "Blue".parse().unwrap(),
                    span: Span::new(0, 76)
                }
            ],
            span: Span::new(0, 76)
        }]
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
            identifier: ident!("foo").at(9..12),
            arguments: vec![
                ast::FieldDefinition {
                    identifier: ident!("x").at(13..18),
                    field_type: TypeKind::Int.at(15..18),
                },
                ast::FieldDefinition {
                    identifier: ident!("y").at(20..32),
                    field_type: TypeKind::Struct(ident!("bar")).at(22..32),
                }
            ],
            return_type: Some(TypeKind::Bool.at(34..38))
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
            ast::StructDefinition {
                identifier: ident!("A").at(7..8),
                items: vec![
                    ast::StructItem::Field(ast::FieldDefinition {
                        identifier: ident!("x").at(23..28),
                        field_type: TypeKind::Int.at(25..28)
                    }),
                    ast::StructItem::Field(ast::FieldDefinition {
                        identifier: ident!("y").at(42..48),
                        field_type: TypeKind::Bool.at(44..48)
                    })
                ],
                span: Span::new(0, 58),
            },
            ast::StructDefinition {
                identifier: ident!("B").at(75..76),
                items: vec![],
                span: Span::new(68, 79),
            }
        ],
    );

    assert_eq!(
        enums,
        vec![ast::EnumDefinition {
            identifier: ident!("Color").at(89..120),
            variants: vec![
                ident!("Red").at(89..120),
                ident!("White").at(89..120),
                ident!("Blue").at(89..120)
            ],
            span: Span::new(89, 120),
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
        vec![ast::CommandDefinition {
            persistence: ast::Persistence::Persistent,
            attributes: vec![],
            identifier: ident!("Foo").at(8..11),
            fields: vec![],
            policy: vec![],
            recall: vec![],
            seal: vec![StmtKind::Return(ast::ReturnStatement {
                expression: ExprKind::FunctionCall(ast::FunctionCall {
                    identifier: ident!("bar").at(56..65),
                    arguments: vec![ExprKind::Identifier(ident!("this")).at(60..64)]
                })
                .at(56..65)
            })
            .at(49..78)],
            open: vec![StmtKind::Return(ast::ReturnStatement {
                expression: ExprKind::FunctionCall(ast::FunctionCall {
                    identifier: ident!("baz").at(123..136),
                    arguments: vec![ExprKind::Identifier(ident!("envelope")).at(127..135)]
                })
                .at(123..136)
            })
            .at(116..149)],
            span: Span::new(0, 160),
        }]
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
        vec![ast::CommandDefinition {
            persistence: ast::Persistence::Persistent,
            attributes: vec![],
            identifier: ident!("Foo").at(8..11),
            fields: vec![],
            policy: vec![],
            recall: vec![],
            seal: vec![StmtKind::Return(ast::ReturnStatement {
                expression: ExprKind::InternalFunction(ast::InternalFunction::Serialize(Box::new(
                    ExprKind::Identifier(ident!("this")).at(66..70)
                )))
                .at(56..71)
            })
            .at(49..84)],
            open: vec![StmtKind::Return(ast::ReturnStatement {
                expression: ExprKind::InternalFunction(ast::InternalFunction::Deserialize(
                    Box::new(ExprKind::Identifier(ident!("envelope")).at(141..149))
                ))
                .at(129..150)
            })
            .at(122..163)],
            span: Span::new(0, 174),
        }]
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
            ast::GlobalLetStatement {
                identifier: ident!("x").at(13..14),
                expression: ExprKind::Int(42).at(17..19),
                span: Span::new(9, 28),
            },
            ast::GlobalLetStatement {
                identifier: ident!("y").at(32..33),
                expression: ExprKind::String(text!("hello")).at(36..43),
                span: Span::new(28, 52),
            },
            ast::GlobalLetStatement {
                identifier: ident!("z").at(56..57),
                expression: ExprKind::Bool(true).at(60..64),
                span: Span::new(52, 74),
            },
        ]
    );

    assert_eq!(
        policy.actions,
        vec![ast::ActionDefinition {
            persistence: ast::Persistence::Persistent,
            identifier: ident!("foo").at(81..84),
            arguments: vec![],
            statements: vec![
                StmtKind::Let(ast::LetStatement {
                    identifier: ident!("a").at(105..106),
                    expression: ExprKind::Add(
                        Box::new(ExprKind::Identifier(ident!("x")).at(109..110)),
                        Box::new(ExprKind::Int(1).at(113..114))
                    )
                    .at(109..114),
                })
                .at(101..127),
                StmtKind::Let(ast::LetStatement {
                    identifier: ident!("b").at(131..132),
                    expression: ExprKind::Add(
                        Box::new(ExprKind::Identifier(ident!("y")).at(135..136)),
                        Box::new(ExprKind::String(text!(" world")).at(139..147))
                    )
                    .at(135..147),
                })
                .at(127..160),
                StmtKind::Let(ast::LetStatement {
                    identifier: ident!("c").at(164..165),
                    expression: ExprKind::Not(Box::new(
                        ExprKind::Identifier(ident!("z")).at(169..170)
                    ))
                    .at(168..170),
                })
                .at(160..183),
                StmtKind::Emit(
                    ExprKind::NamedStruct(ast::NamedStruct {
                        identifier: ident!("Bar").at(188..273),
                        fields: vec![
                            (
                                ident!("a").at(210..214),
                                ExprKind::Identifier(ident!("a")).at(213..214)
                            ),
                            (
                                ident!("b").at(232..236),
                                ExprKind::Identifier(ident!("b")).at(235..236)
                            ),
                            (
                                ident!("c").at(254..258),
                                ExprKind::Identifier(ident!("c")).at(257..258)
                            ),
                        ],
                    })
                    .at(188..273)
                )
                .at(183..282),
            ],
            span: Span::new(74, 283),
        }]
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
        ast::ActionDefinition {
            persistence: ast::Persistence::Persistent,
            identifier: ident!("pong").at(33..37),
            arguments: vec![],
            statements: vec![StmtKind::ActionCall(ast::FunctionCall {
                identifier: ident!("ping").at(57..63),
                arguments: vec![]
            })
            .at(50..63)],
            span: Span::new(26, 69),
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
        vec![StmtKind::Map(ast::MapStatement {
            fact: ast::FactLiteral {
                identifier: ident!("Foo").at(73..82),
                key_fields: vec![(
                    ident!("i").at(77..80),
                    FactField::Expression(ExprKind::Int(1).at(79..80))
                )],
                value_fields: None,
            },
            identifier: ident!("f").at(85..86),
            statements: vec![]
        })
        .at(69..102)]
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
        vec![StmtKind::Let(ast::LetStatement {
            identifier: ident!("x").at(32..33),
            expression: ExprKind::Block(
                vec![
                    StmtKind::Let(ast::LetStatement {
                        identifier: ident!("a").at(54..55),
                        expression: ExprKind::Int(3).at(58..59)
                    })
                    .at(50..72),
                    StmtKind::Let(ast::LetStatement {
                        identifier: ident!("b").at(76..77),
                        expression: ExprKind::Int(4).at(80..81)
                    })
                    .at(72..94),
                ],
                Box::new(
                    ExprKind::Add(
                        Box::new(ExprKind::Identifier(ident!("a")).at(96..97)),
                        Box::new(ExprKind::Identifier(ident!("b")).at(100..101))
                    )
                    .at(96..101)
                )
            )
            .at(36..111)
        })
        .at(28..116)]
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
        vec![StmtKind::Let(ast::LetStatement {
            identifier: ident!("x").at(45..46),
            expression: ExprKind::Match(Box::new(ast::MatchExpression {
                scrutinee: ExprKind::Identifier(ident!("n")).at(55..56),
                arms: vec![
                    ast::MatchExpressionArm {
                        pattern: MatchPattern::Values(vec![ExprKind::Int(0).at(75..76)]),
                        expression: ExprKind::Block(
                            vec![StmtKind::Let(ast::LetStatement {
                                identifier: ident!("x").at(106..107),
                                expression: ExprKind::Bool(true).at(110..114)
                            })
                            .at(102..135)],
                            Box::new(ExprKind::Identifier(ident!("x")).at(137..138))
                        )
                        .at(80..156),
                        span: Span::new(75, 173)
                    },
                    ast::MatchExpressionArm {
                        pattern: MatchPattern::Default,
                        expression: ExprKind::Bool(false).at(178..183),
                        span: Span::new(173, 196)
                    }
                ]
            }))
            .at(49..197)
        })
        .at(41..206)]
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
