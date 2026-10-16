//! Rendering of warnings, and the analysis being off by default.

use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;

use super::command;
use crate::Compiler;

#[test]
fn rendered_warning_shows_label_note_and_help() {
    let text = command(
        r#"
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    );
    let policy = parse_policy_str(&text, Version::V2).expect("parse");
    let (_module, warnings) = Compiler::new(&policy)
        .debug(true)
        .allow_baseless(true)
        .compile_with_diagnostics()
        .expect("compile");
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    let rendered = warnings[0].render(&text);
    for expected in [
        "warning: cannot prove `Account[user: this.user]` does not exist before `create`",
        "this fact may already exist",
        "note: creating a fact that already exists is a runtime exception",
        "help: check that it does not exist first: `check !exists Account[user: this.user] else ...`",
    ] {
        assert!(
            rendered.contains(expected),
            "missing {expected:?} in:\n{rendered}"
        );
    }
}

#[test]
fn fact_read_in_a_block_statement_gets_a_note() {
    // The `exists` is in an `if` statement inside a block compared with 1,
    // which the analysis doesn't interpret, so the warning points at it.
    let text = command(
        r#"
        check { if exists Account[user: this.user] { let u = 1 } : 1 } == 1 else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    );
    let policy = parse_policy_str(&text, Version::V2).expect("parse");
    let (_module, warnings) = Compiler::new(&policy)
        .debug(true)
        .allow_baseless(true)
        .compile_with_diagnostics()
        .expect("compile");
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .notes
            .iter()
            .any(|(_, n)| n == "touches `Account` but is too complex to analyze"),
        "notes: {:?}",
        warnings[0].notes
    );
}
