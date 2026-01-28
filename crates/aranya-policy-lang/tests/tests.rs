#![allow(clippy::panic)]

use std::path::{Path, PathBuf};

use aranya_policy_ast::Policy;
use aranya_policy_lang::lang::{
    self, ParseError, ParseErrorKind, Token, Version, parse_policy_document, parse_policy_str,
};
use logos::Logos;

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
    assert!(parse_policy_document(policy_v1_md).is_err_and(|r| *r.kind
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

#[rstest::rstest]
fn test_policy(#[files("tests/data/**/*.policy")] src: PathBuf) {
    autotest(&src, |text| parse_policy_str(text, Version::V2));
}

#[rstest::rstest]
fn test_markdown(#[files("tests/data/**/*.md")] src: PathBuf) {
    autotest(&src, parse_policy_document);
}

// Produces snapshots for the lexer and parser.
fn autotest(src: &Path, parse: impl Fn(&str) -> Result<Policy, ParseError>) {
    let base = src.parent().expect("can't get parent");
    let is_markdown = src.extension().is_some_and(|ext| ext == "md");
    let name = src
        .file_stem()
        .expect("can't get filename stem")
        .to_str()
        .expect("filename not utf8");
    let text = std::fs::read_to_string(src).expect("could not read source file");

    // lexer snapshot
    let lexer_succeeded = if !is_markdown {
        let res: Result<Vec<_>, _> = Token::lexer(&text)
            .spanned()
            .map(|(res, span)| res.map(|token| (token, span)))
            .collect();

        let succeeded = res.is_ok();
        insta::with_settings!({ prepend_module_to_snapshot => false, snapshot_path => base, snapshot_suffix => "tokens" }, {
            match res {
                Ok(tokens) => insta::assert_debug_snapshot!(name, tokens),
                Err(err) => insta::assert_snapshot!(name, err),
            }
        });

        succeeded
    } else {
        true
    };

    // parser snapshot
    {
        let res = parse(&text);
        // check for regressions while migrating to custom lexer
        if res.is_ok() {
            assert!(lexer_succeeded)
        }
        insta::with_settings!({ prepend_module_to_snapshot => false, snapshot_path => base }, {
            match res {
                Ok(ast) => insta::assert_debug_snapshot!(name, ast),
                Err(err) => insta::assert_snapshot!(name, err),
            }
        });
    }
}
