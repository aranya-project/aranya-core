//! Attacks on helpers: a call's true side must keep only what holds on
//! every exit that can be true.

use super::{warnings_for, warnings_with_cap, with_defs};

#[test]
fn attack_early_exit_returning_true() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Account[user: u] else return true
            return exists Owner[]
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_early_exit_returning_false() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Account[user: u] else return false
            return exists Owner[]
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_exit_inside_block_in_match_arm() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let x = match u {
                1 => {
                    let y = query Account[user: u] or return true
                    : 1
                }
                _ => 2
            }
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
}

#[test]
fn control_exit_inside_block_returning_false() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let x = match u {
                1 => {
                    let y = query Account[user: u] or return false
                    : 1
                }
                _ => 2
            }
            return exists Account[user: u]
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_return_inside_fact_key_is_an_exit() {
    // `&&` short-circuits, so the key is evaluated before `Owner[]` is
    // checked. When `u` is not 1 the helper returns `true` having checked
    // nothing, so its true side cannot keep `Owner[]`.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Account[user: match u { 1 => 1  _ => return true }] && exists Owner[]
                else return false
            return true
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Owner[] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .message
            .contains("`Owner[]` exists before `delete`")
    );
}

#[test]
fn attack_return_inside_call_argument_is_an_exit() {
    // As above, with the `return` in a call argument evaluated first.
    let warnings = warnings_for(&with_defs(
        r#"
        function same(n int) int { return n }
        function f(u int) bool {
            check same(match u { 1 => 1  _ => return true }) == 1 && exists Owner[]
                else return false
            return true
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Owner[] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .message
            .contains("`Owner[]` exists before `delete`")
    );
}

#[test]
fn control_match_inside_fact_key_without_return() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Owner[] && exists Account[user: match u { 1 => 1  _ => 2 }]
                else return false
            return true
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Owner[] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_mutual_recursion_terminates() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool { return g(u) }
        function g(u int) bool { return f(u) }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn attack_non_substitutable_local_in_exit_facts() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f() bool {
            let n = if true { : 1 } else { : 2 }
            check exists Account[user: n] else return false
            return true
        }
        "#,
        r#"
        check f() else recall failed()
        finish { delete Account[user: 1] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_substitutable_local_in_exit_facts() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f() bool {
            let n = 1
            check exists Account[user: n] else return false
            return true
        }
        "#,
        r#"
        check f() else recall failed()
        finish { delete Account[user: 1] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_argument_rebound_after_call() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}
        fact Other[k int]=>{v int}

        function has(d int) bool { return exists Other[k: d] }
        "#,
        r#"
        if this.user == 1 {
            let m = query Member[team: 1, device: ?] or recall failed()
            check has(m.device) else recall failed()
        } else {
            let m = query Member[team: 1, device: ?] or recall failed()
            check has(m.device) else recall failed()
        }
        let m = query Member[team: 2, device: ?] or recall failed()
        finish { delete Other[k: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_argument_proves_current_binding() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}
        fact Other[k int]=>{v int}

        function has(d int) bool { return exists Other[k: d] }
        "#,
        r#"
        let m = query Member[team: 1, device: ?] or recall failed()
        check has(m.device) else recall failed()
        finish { delete Other[k: m.device] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_summary_reused_across_commands() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        function has(u int) bool { return exists Account[user: u] }

        command One {
            fields { user int }
            policy {
                check has(1) else recall failed()
                finish { delete Account[user: 1] }
            }
            recall failed() { finish {} }
        }

        command Two {
            fields { user int }
            policy {
                check has(2) else recall failed()
                finish { delete Account[user: 2] }
            }
            recall failed() { finish {} }
        }

        command Three {
            fields { user int }
            policy {
                check has(2) else recall failed()
                finish { delete Account[user: 1] }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .message
            .contains("`Account[user: 1]` exists before `delete`")
    );
}

/// A command that checks `f(this.user)` and then deletes the caller's
/// account, which `f` must prove exists.
const CHECK_F_THEN_DELETE: &str = r#"
    check f(this.user) else recall failed()
    finish { delete Account[user: this.user] }
"#;

#[test]
fn attack_return_inside_returned_value() {
    // When `u` is not 1, the inner `return true` returns without the fact.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            return match u { 1 => exists Account[user: u]  _ => return true }
        }
        "#,
        CHECK_F_THEN_DELETE,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_returned_match_without_return() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            return match u { 1 => exists Account[user: u]  _ => false }
        }
        "#,
        CHECK_F_THEN_DELETE,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_returns_inside_returned_value_hide_later_warnings() {
    // Every exit of `f` is a nested `return`. Losing them all would make
    // the call look like it never returns, hiding the unchecked create.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            return match u { 1 => return true  _ => return false }
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn attack_return_inside_returned_block() {
    // `f` returns false through the nested `return` when the account is
    // missing, so `!f(..)` says nothing about the account.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            return {
                check exists Account[user: u] else return false
                : exists Owner[]
            }
        }
        "#,
        r#"
        check !f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn attack_return_in_match_statement_scrutinee() {
    // `f(2)` returns true from inside the scrutinee, before any check.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            match (match u { 1 => 1  _ => return true }) {
                1 => { return exists Account[user: u] }
                _ => { return exists Account[user: u] }
            }
        }
        "#,
        CHECK_F_THEN_DELETE,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn attack_return_in_match_expression_scrutinee() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let x = match (match u { 1 => 1  _ => return true }) { 1 => 1  _ => 2 }
            return exists Account[user: u]
        }
        "#,
        CHECK_F_THEN_DELETE,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_match_scrutinee_without_return() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let x = match (match u { 1 => 1  _ => 2 }) { 1 => 1  _ => 2 }
            return exists Account[user: u]
        }
        "#,
        CHECK_F_THEN_DELETE,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_return_statement_in_block_argument() {
    // `f(1)` returns true from inside the block, before the final check.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let a = saturating_add(1, { if u == 1 { return true } : 1 })
            return exists Account[user: u]
        }
        "#,
        CHECK_F_THEN_DELETE,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_block_argument_without_return() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let a = saturating_add(1, { let b = 1 : b })
            return exists Account[user: u]
        }
        "#,
        CHECK_F_THEN_DELETE,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

/// A policy where a base command's `get_key` block and a user function
/// share the name `get_key`, and a command checks the user function.
fn with_get_key(base_body: &str, function_body: &str) -> String {
    format!(
        r#"
        fact Owner[]=>{{user int}}

        base command B {{
            get_key {{
                {base_body}
            }}
        }}

        function get_key(a int, b int) bool {{ {function_body} }}

        command Foo with B {{
            fields {{ user int }}
            policy {{
                check get_key(1, 2) else recall failed()
                finish {{ delete Owner[] }}
            }}
            recall failed() {{ finish {{}} }}
        }}
        "#
    )
}

#[test]
fn attack_base_get_key_does_not_replace_function() {
    // The call runs the user function, which proves nothing about `Owner`.
    let warnings = warnings_for(&with_get_key(
        "let o = query Owner[] or todo()\nreturn None",
        "return true",
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .message
            .contains("`Owner[]` exists before `delete`")
    );
}

#[test]
fn control_user_get_key_is_analyzed() {
    // Only the user function proves `Owner` exists.
    let warnings = warnings_for(&with_get_key("return None", "return exists Owner[]"));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_return_in_if_expression_arm() {
    // An `if` expression's arms are blocks, so this `return` sits inside
    // a block. When the account is missing, `f` returns true without it.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let x = if !exists Account[user: u] { : return true } else { : 1 }
            return exists Account[user: u]
        }
        "#,
        CHECK_F_THEN_DELETE,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

/// A helper whose `else` arm is a block with three ways through it and
/// a final `return {value}`, and a command that checks it and deletes
/// `Owner[]`. When `u` is 1 the arm can't run.
fn with_capped_arm(value: &str) -> String {
    with_defs(
        &format!(
            r#"
            function f(u int) bool {{
                if u == 1 {{
                    check exists Owner[] else test_fail("no owner")
                }}
                let x = if exists Owner[] {{
                    : 1
                }} else {{
                    if u == 2 {{ let a = 1 }} else if u == 3 {{ let b = 1 }} else {{ let c = 1 }}
                    : return {value}
                }}
                return exists Owner[]
            }}
            "#
        ),
        r#"
        check f(this.user) else recall failed()
        finish { delete Owner[] }
        "#,
    )
}

#[test]
fn attack_exit_in_block_over_cap() {
    // With room for only two ways through a block, the arm's block is
    // never evaluated where it can run, so its `return true` is missed
    // there. Where it can't run, the `return` still counts as recorded.
    // The helper must become unknown rather than drop that exit.
    let warnings = warnings_with_cap(&with_capped_arm("true"), 2);
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .message
            .contains("`Owner[]` exists before `delete`")
    );
}

#[test]
fn control_exit_in_block_within_cap() {
    // At the default cap the block is evaluated. The arm returns false
    // on each of its three ways through, and every way `f` returns true
    // knows `Owner[]` exists.
    let warnings = warnings_for(&with_capped_arm("false"));
    assert_eq!(warnings, vec![], "expected no warnings");
}
