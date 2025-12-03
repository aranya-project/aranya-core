#![allow(clippy::panic)]

use std::{fs::OpenOptions, io::Read as _};

use aranya_policy_ast::{
    self as ast, ExprKind, Expression, Ident, Identifier, Span, StmtKind, TypeKind, ident, text,
};
use aranya_policy_lang::lang::{
    self, ParseError, ParseErrorKind, Version, parse_policy_document, parse_policy_str,
};

trait SpannedAt {
    type Type;
    fn at(self, span: impl Into<Span>) -> Self::Type;
}

impl SpannedAt for Identifier {
    type Type = Ident;
    fn at(self, span: impl Into<Span>) -> Self::Type {
        Ident {
            name: self,
            span: span.into(),
        }
    }
}

impl SpannedAt for TypeKind {
    type Type = ast::VType;
    fn at(self, span: impl Into<Span>) -> Self::Type {
        ast::VType {
            kind: self,
            span: span.into(),
        }
    }
}

impl SpannedAt for ExprKind {
    type Type = Expression;
    fn at(self, span: impl Into<Span>) -> Self::Type {
        Expression {
            kind: self,
            span: span.into(),
        }
    }
}

impl SpannedAt for StmtKind {
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
fn accept_only_latest_lang_version() {
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
}

#[test]
fn test_parse_effect_with_field_insertion() {
    let text = r#"struct Foo { x int }
        effect Bar {
            +Foo,
            y int
        }
        "#;
    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    insta::assert_debug_snapshot!(policy);
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
fn parse_policy_test() -> Result<(), ParseError> {
    let policy_str = r#"
        // This is not a valid policy. It is just meant to exercise
        // every feature of the parser.
        /* block comment */
        fact F[v string]=>{x int, y bool}

        action add2(x int, y int) {
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
                let new_x = add2(x, count)
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
                    create F[v: "hello"]=>{x: x, y: saturating_sub(0, x)}
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
                let new_x = add2(x, count)
                finish {
                    create F[v: "hello"]=>{x: x, y: saturating_sub(0, x)}
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

    insta::assert_debug_snapshot!(policy);

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
    insta::assert_debug_snapshot!(policy);
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
    insta::assert_debug_snapshot!(policy);

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
    insta::assert_debug_snapshot!(policy);
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
            ast::StructItem::StructRef(ident!("Foo").at(55..58)),
            ast::StructItem::Field(ast::FieldDefinition {
                identifier: ident!("y").at(72..73),
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
    insta::assert_debug_snapshot!(policy);
}

#[test]
fn parse_ffi_decl() {
    let text = "function foo(x int, y struct bar) bool";
    let decl = lang::parse_ffi_decl(text).expect("parse");
    insta::assert_debug_snapshot!(decl);
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
    let types = lang::parse_ffi_structs_enums(text).expect("parse");
    insta::assert_debug_snapshot!(types);
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
    insta::assert_debug_snapshot!(policy);
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
            seal: vec![
                StmtKind::Return(ast::ReturnStatement {
                    expression: ExprKind::InternalFunction(ast::InternalFunction::Serialize(
                        Box::new(ExprKind::Identifier(ident!("this").at(66..70)).at(66..70))
                    ))
                    .at(56..71)
                })
                .at(49..84)
            ],
            open: vec![
                StmtKind::Return(ast::ReturnStatement {
                    expression: ExprKind::InternalFunction(ast::InternalFunction::Deserialize(
                        Box::new(
                            ExprKind::Identifier(ident!("envelope").at(141..149)).at(141..149)
                        )
                    ))
                    .at(129..150)
                })
                .at(122..163)
            ],
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
        assert!(policy.is_err_and(|result| result.kind == ParseErrorKind::ReservedIdentifier));
    }
    Ok(())
}

#[test]
fn parse_global_let_statements() -> Result<(), ParseError> {
    let policy_str = r#"
        let x = 42
        let z = true

        action foo() {
            let a = unwrap add(x, 1)
            let c = !z
            emit Bar {
                a: a,
                c: c,
            }
        }
    "#;

    let policy = parse_policy_str(policy_str, Version::V2)?;
    insta::assert_debug_snapshot!(policy);

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
                let c = add(1, 1)
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
    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    insta::assert_debug_snapshot!(policy);
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
    insta::assert_debug_snapshot!(policy);

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
    insta::assert_debug_snapshot!(policy);
}

#[test]
fn test_block_expression() {
    let text = r#"
    action foo() {
        let x = {
            let a = 3
            let b = 4
            : unwrap saturating_add(a, b)
        }
    }
    "#;

    let policy = parse_policy_str(text, Version::V2).expect("should parse");
    insta::assert_debug_snapshot!(policy);
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
    insta::assert_debug_snapshot!(policy);
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
