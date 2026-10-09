//! Attacks on `if`, `match`, and block expressions: arms are joined by
//! intersection, and nothing from an arm's scope escapes.

use aranya_policy_ast::{Version, ident};
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::ffi::{self, ModuleSchema};
use rstest::rstest;

use super::{MEMBER, command, warnings_for, with_defs};
use crate::Compiler;

#[test]
fn attack_if_condition_facts_do_not_survive_arms() {
    let warnings = warnings_for(&command(
        r#"
        check if exists Account[user: this.user] { : true } else { : true }
            else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn attack_if_else_arm_or_proves_nothing() {
    let warnings = warnings_for(&command(
        r#"
        check if this.user == 1 {
            : !exists Account[user: this.user]
        } else {
            : !exists Account[user: this.user] || this.user == 2
        } else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn control_if_both_arms_prove() {
    let warnings = warnings_for(&command(
        r#"
        check if this.user == 1 {
            : !exists Account[user: this.user]
        } else {
            : !exists Account[user: this.user]
        } else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_match_default_true_proves_nothing() {
    let warnings = warnings_for(&command(
        r#"
        check match this.user {
            1 => !exists Account[user: this.user]
            2 => !exists Account[user: this.user]
            _ => true
        } else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn control_match_default_false_proves() {
    let warnings = warnings_for(&command(
        r#"
        check match this.user {
            1 => !exists Account[user: this.user]
            2 => !exists Account[user: this.user]
            _ => false
        } else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_if_query_arms_differ() {
    let warnings = warnings_for(&command(
        r#"
        let f = if this.user == 1 { : query Account[user: 1] } else { : query Account[user: 2] }
            or recall failed()
        finish { delete Account[user: 1] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_if_query_arms_agree() {
    let warnings = warnings_for(&command(
        r#"
        let f = if this.user == 1 { : query Account[user: 1] } else { : query Account[user: 1] }
            or recall failed()
        finish { delete Account[user: 1] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_match_let_binding_of_other_query() {
    let warnings = warnings_for(&command(
        r#"
        let a = match query Account[user: 1] { Some(x) => x  None => recall failed() }
        let a2 = match query Account[user: 2] { Some(x) => x  None => recall failed() }
        finish { update Account[user: 1]=>{balance: a2.balance} to {balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

#[test]
fn control_match_let_binding_of_same_query() {
    let warnings = warnings_for(&command(
        r#"
        let a = match query Account[user: 1] { Some(x) => x  None => recall failed() }
        let a2 = match query Account[user: 2] { Some(x) => x  None => recall failed() }
        finish { update Account[user: 1]=>{balance: a.balance} to {balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_block_binds_outer_let_name() {
    // Both arms bind an inner `m` to a team-1 fact but return a team-2
    // fact. The outer `m` is bound before its value is evaluated, so
    // only the arm-local filter keeps the inner facts out.
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        let m = if this.user == 1 {
            let m = query Member[team: 1, device: ?] or recall failed()
            let n = query Member[team: 2, device: ?] or recall failed()
            : n
        } else {
            let m = query Member[team: 1, device: ?] or recall failed()
            let n = query Member[team: 2, device: ?] or recall failed()
            : n
        }
        finish { delete Member[team: 1, device: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn attack_block_nested_if_binding_does_not_leak() {
    // `m` bound inside a nested `if` in the block, with or without an
    // `else`, is not the outer `m`.
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        let m = if this.user == 1 {
            if this.user == 2 {
                let m = query Member[team: 1, device: ?] or recall failed()
            } else {
                let m = query Member[team: 1, device: ?] or recall failed()
            }
            if this.user == 3 {
                let m = query Member[team: 1, device: ?] or recall failed()
            }
            let n = query Member[team: 2, device: ?] or recall failed()
            : n
        } else {
            let m = query Member[team: 1, device: ?] or recall failed()
            let n = query Member[team: 2, device: ?] or recall failed()
            : n
        }
        finish { delete Member[team: 1, device: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn attack_block_nested_match_binding_does_not_leak() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        let m = if this.user == 1 {
            match query Member[team: 1, device: ?] {
                Some(m) => { let unused = m.rank }
                None => { recall failed() }
            }
            let n = query Member[team: 2, device: ?] or recall failed()
            : n
        } else {
            let m = query Member[team: 1, device: ?] or recall failed()
            let n = query Member[team: 2, device: ?] or recall failed()
            : n
        }
        finish { delete Member[team: 1, device: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn attack_scoped_env_in_condition_block() {
    // The block's own `y` is 2, not the earlier branches' 1, so the
    // check says nothing about `Account[user: 1]`.
    let warnings = warnings_for(&command(
        r#"
        if this.user == 1 { let y = 1 } else { let y = 1 }
        check { let y = 2 : !exists Account[user: y] } else recall failed()
        finish { create Account[user: 1]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn attack_nested_return_in_if_arm_in_argument() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let x = saturating_add(1, if u == 1 { : 1 } else { : return true })
            return exists Account[user: u]
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
    assert!(
        warnings[0]
            .notes
            .iter()
            .any(|(_, n)| n.contains("too complex"))
    );
}

#[test]
fn attack_finish_inside_arm_without_value() {
    // The arm's block ends in `recall`, so it never produces a value, but
    // its `finish` still runs.
    let warnings = warnings_for(&command(
        r#"
        let x = if this.user == 1 {
            finish { create Account[user: this.user]=>{balance: 0} }
            : recall failed()
        } else {
            : 2
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn attack_finish_inside_check_else_block() {
    // The `else` runs when the check fails, finish and all.
    let warnings = warnings_for(&command(
        r#"
        check this.user == 1 else {
            finish { create Account[user: this.user]=>{balance: 0} }
            : recall failed()
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn attack_finish_inside_or_block() {
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        let a = query Account[user: this.user] or {
            finish { create Owner[]=>{user: this.user} }
            : recall failed()
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("`Owner[]` does not exist"));
}

#[test]
fn control_checked_finish_inside_check_else_block() {
    let warnings = warnings_for(&command(
        r#"
        check this.user == 1 else {
            check !exists Account[user: this.user] else recall failed()
            finish { create Account[user: this.user]=>{balance: 0} }
            : recall failed()
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

/// Definitions for the positions a block can sit in below.
const NESTED_DEFS: &str = r#"
    struct Pair { a int, b int }

    function same(x int) int {
        return x
    }

    function maybe(u int) option[int] {
        if u > 1 {
            return Some(u)
        }
        return None
    }

    function always(x int) bool {
        return true
    }

    function one_of(x int) option[int] {
        return Some(1)
    }
"#;

/// `statement` with `FINISH` replaced by a `finish` that creates
/// `Owner[]`, followed by a `finish` that ends the block.
fn nested(statement: &str) -> String {
    let finish = "finish { create Owner[]=>{user: this.user} }";
    format!("{}\nfinish {{}}", statement.replace("FINISH", finish))
}

/// A block that creates `Owner[]` before producing a value, nested in each
/// position an expression can hold one. Most of these positions are
/// evaluated without being interpreted, but the block's `finish` still
/// runs, so its `create` must be checked. Each case's control checks
/// first that `Owner[]` is absent, which must prove it: the block runs on
/// a path that knows what the path knew before the expression.
#[rstest]
#[case::call_argument("let n = same({ FINISH :0 })")]
#[case::struct_field("let p = Pair { a: { FINISH :0 }, b: 1 }")]
#[case::struct_field_before_a_block("let p = Pair { a: { FINISH :0 }, b: { let z = 1 :z } }")]
#[case::struct_field_after_a_block("let p = Pair { a: { let z = 1 :z }, b: { FINISH :0 } }")]
#[case::left_of_equal("check { FINISH :0 } == this.user else recall failed()")]
#[case::right_of_equal("check this.user == { FINISH :0 } else recall failed()")]
#[case::compared("check { FINISH :0 } > 0 else recall failed()")]
#[case::some("let n = Some({ FINISH :0 })")]
#[case::key_in_exists("check !exists Account[user: { FINISH :0 }] else recall failed()")]
#[case::key_in_query("let a = query Account[user: { FINISH :0 }]")]
#[case::key_in_count("check at_least 1 Account[user: { FINISH :0 }] else recall failed()")]
#[case::key_in_query_or_recall("let a = query Account[user: { FINISH :0 }] or recall failed()")]
#[case::call_condition("check always({ FINISH :0 }) else recall failed()")]
#[case::call_or_recall("let n = one_of({ FINISH :0 }) or recall failed()")]
#[case::branch_in_argument("let n = same(if this.user > 0 { :same({ FINISH :0 }) } else { :1 })")]
#[case::struct_field_read("check Pair { a: 1, b: { FINISH :0 } }.a == 1 else recall failed()")]
#[case::match_statement_scrutinee("match { FINISH :0 } { 0 => { let x = 1 } _ => { let y = 2 } }")]
#[case::match_expression_scrutinee("let n = match { FINISH :0 } { 0 => 1 _ => 2 }")]
#[case::arm_value("let n = if this.user > 0 { :Some({ FINISH :0 }) } else { :None }")]
#[case::left_of_or("let n = Some({ FINISH :0 }) or 1")]
#[case::right_of_or("let n = maybe(this.user) or { FINISH :0 }")]
#[case::left_of_terminal_or("let n = Some({ FINISH :0 }) or todo()")]
#[case::debug_assert("debug_assert({ FINISH :true })")]
fn attack_finish_inside_nested_block(#[case] statement: &str) {
    let warnings = warnings_for(&with_defs(NESTED_DEFS, &nested(statement)));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("`Owner[]` does not exist"));

    let checked = format!(
        "check !exists Owner[] else recall failed()\n{}",
        nested(statement)
    );
    let warnings = warnings_for(&with_defs(NESTED_DEFS, &checked));
    assert_eq!(warnings, vec![], "expected no warnings when checked");
}

/// A policy whose command has a recall block that takes an argument, with
/// `statement` as its policy block, as in [`nested`].
fn with_recall_argument(statement: &str) -> String {
    format!(
        r#"
        fact Owner[]=>{{user int}}

        command Foo {{
            fields {{ user int }}
            policy {{
                {}
            }}
            recall failed() {{ finish {{}} }}
            recall failed_with(n int) {{ finish {{}} }}
        }}
        "#,
        nested(statement)
    )
}

/// A block in a `recall`'s arguments runs before the recall, `finish` and
/// all, whether the `recall` is a `check`'s `else` or a statement.
#[rstest]
#[case::check_else("check this.user > 0 else recall failed_with({ FINISH :0 })")]
#[case::statement("if this.user > 0 { recall failed_with({ FINISH :0 }) }")]
fn attack_finish_inside_recall_argument(#[case] statement: &str) {
    let warnings = warnings_for(&with_recall_argument(statement));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("`Owner[]` does not exist"));

    let checked = format!("check !exists Owner[] else recall failed()\n{statement}");
    let warnings = warnings_for(&with_recall_argument(&checked));
    assert_eq!(warnings, vec![], "expected no warnings when checked");
}

#[test]
fn control_finish_inside_nested_arm_knows_its_condition() {
    // The `if` in the argument is walked as a branch, so the block in its
    // arm runs knowing `Owner[]` is absent there.
    let body = nested("let n = same(if !exists Owner[] { :same({ FINISH :0 }) } else { :1 })");
    assert_eq!(warnings_for(&with_defs(NESTED_DEFS, &body)), vec![]);
}

/// A module with a function returning an option, which the analysis
/// evaluates without interpreting it.
const FFI: &[ModuleSchema<'static>] = &[ModuleSchema {
    name: ident!("test"),
    functions: &[ffi::Func {
        name: ident!("maybe_int"),
        args: &[ffi::Arg {
            name: ident!("x"),
            vtype: ffi::Type::Int,
        }],
        return_type: ffi::Type::Optional(&ffi::Type::Int),
    }],
    structs: &[],
    enums: &[],
}];

#[test]
fn attack_finish_inside_ffi_argument() {
    // The call's arguments run before it, `finish` and all.
    let warnings = |statement: &str| {
        let text = format!("use test\n{}", with_defs("", &nested(statement)));
        let policy = parse_policy_str(&text, Version::V2).expect("parse");
        let (_module, warnings) = Compiler::new(&policy)
            .ffi_modules(FFI)
            .debug(true)
            .allow_baseless(true)
            .compile_with_diagnostics()
            .expect("compile");
        warnings
    };
    let statement = "let n = test::maybe_int({ FINISH :0 }) or recall failed()";
    let found = warnings(statement);
    assert_eq!(found.len(), 1, "warnings: {found:?}");
    assert!(found[0].message.contains("`Owner[]` does not exist"));

    let checked = format!("check !exists Owner[] else recall failed()\n{statement}");
    assert_eq!(
        warnings(&checked),
        vec![],
        "expected no warnings when checked"
    );
}

#[test]
fn attack_finish_inside_sibling_blocks() {
    // Walking one block doesn't stand in for walking the one beside it.
    let body = nested("let p = Pair { a: { FINISH :0 }, b: { FINISH :1 } }");
    let warnings = warnings_for(&with_defs(NESTED_DEFS, &body));
    assert_eq!(warnings.len(), 2, "warnings: {warnings:?}");
}
