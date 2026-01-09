#![allow(clippy::panic)]

use std::path::{Path, PathBuf};

use aranya_policy_ast::Policy;
use aranya_policy_lang::lang::{
    self, ParseError, Version, parse_policy_document, parse_policy_str,
};

#[test]
#[allow(clippy::result_large_err)]
#[allow(deprecated)]
fn accept_only_latest_lang_version() {
    let help_msg = Version::help_message();
    let err_msg = format!(
        "error: Invalid policy version 1, supported version is 2\n  |\n  = note: {help_msg}"
    );

    // parse string literal
    let src = "function f() int { return 0 }";
    assert_eq!(
        &parse_policy_str(src, Version::V1)
            .expect_err("should not accept V1")
            .to_string(),
        &err_msg,
    );
    parse_policy_str(src, Version::V2).expect("should accept V2");

    // parse markdown (v1)
    let policy_v1_md = r#"---
policy-version: 1
---

```policy
```
"#;
    assert_eq!(
        &parse_policy_document(policy_v1_md)
            .expect_err("should not accept V1")
            .to_string(),
        &err_msg
    );

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
