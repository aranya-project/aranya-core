#![allow(clippy::panic)]

use std::path::{Path, PathBuf};

use aranya_policy_ast::Policy;
use aranya_policy_lang::lang::{
    self, ParseError, Version, error, parse_policy_document, parse_policy_str,
};

#[test]
#[allow(clippy::result_large_err)]
#[allow(deprecated)]
fn accept_only_latest_lang_version() {
    // parse string literal
    let src = "function f() int { return 0 }";
    assert_eq!(
        *parse_policy_str(src, Version::V1)
            .expect_err("should not accept V1")
            .kind,
        error::InvalidVersion {
            found: "1".to_string(),
            required: Version::V2
        }
        .into()
    );
    parse_policy_str(src, Version::V2).expect("should accept V2");

    // parse markdown (v1)
    let policy_v1_md = r#"---
policy-version: 1
---

```policy
```
"#;
    assert!(parse_policy_document(policy_v1_md).is_err_and(|r| {
        *r.kind
            == error::InvalidVersion {
                found: "1".to_string(),
                required: Version::V2,
            }
            .into()
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
fn parse_ffi_decl() {
    let text = "function foo(x int, y struct bar) bool";
    let decl = lang::parse_ffi_decl(text).expect("parse");
    insta::assert_debug_snapshot!(decl);
}

#[test]
fn parse_ffi_decl_error() {
    let text = "function foo(x optional optional int, y struct bar) bool";
    let err = lang::parse_ffi_decl(text).unwrap_err();
    insta::assert_snapshot!(err);
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
fn parse_ffi_structs_enums_error() {
    let text = r#"
        struct A {
            x int,
            y optional optional bool
        }

        struct B {}

        enum Color { Red, White, Blue }
    "#
    .trim();
    let err = lang::parse_ffi_structs_enums(text).unwrap_err();
    insta::assert_snapshot!(err);
}

#[test]
fn parse_expression_error() {
    let text = "3 + 7".trim();
    let err = lang::parse_expression(text).unwrap_err();
    insta::assert_snapshot!(err);
}

#[rstest::rstest]
fn test_policy(#[files("tests/data/**/*.policy")] src: PathBuf) {
    autotest(&src, |text| parse_policy_str(text, Version::V2));
}

#[rstest::rstest]
fn test_markdown(#[files("tests/data/**/*.md")] src: PathBuf) {
    autotest(&src, parse_policy_document);
}

fn autotest(src: &Path, parse: impl Fn(&str) -> Result<Policy, ParseError>) {
    let base = src.parent().expect("can't get parent");
    let name = src
        .file_stem()
        .expect("can't get filename stem")
        .to_str()
        .expect("filename not utf8");
    let text = std::fs::read_to_string(src).expect("could not read source file");
    let res = parse(&text);
    insta::with_settings!({ prepend_module_to_snapshot => false, snapshot_path => base }, {
        match res {
            Ok(ast) => insta::assert_debug_snapshot!(name, ast),
            Err(err) => insta::assert_snapshot!(name, err),
        }
    });
}

/// A statement or expression ends at its last token. pest skips the
/// whitespace and comments before an optional or repeated part even when
/// the part is absent, so spans used to run on to the next token: a
/// `delete` or `let` underlined the next line too.
#[test]
fn spans_end_at_the_last_token() {
    let src = r#"
fact F[v int]=>{}
command C {
    fields { v int }
    policy {
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
    let aranya_policy_ast::StmtKind::Let(found) = &policy.commands[0].policy[0].inner else {
        panic!("expected a `let`");
    };
    assert_eq!(text(found.expression.span), "exists F[v: this.v]");
    let aranya_policy_ast::StmtKind::Finish(finish) = &policy.commands[0].policy[4].inner else {
        panic!("expected a `finish`");
    };
    let deletes: Vec<&str> = finish.iter().map(|s| text(s.span)).collect();
    assert_eq!(deletes, ["delete F[v: this.v]", "delete F[v: 2]"]);
}
