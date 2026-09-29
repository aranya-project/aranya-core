//! Attacks on helpers: a call's true side must keep only what holds on
//! every exit that can be true.

use super::{warnings_for, with_defs};

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
    // When `u` is not 1 the helper returns `true` having checked
    // nothing, so its true side cannot keep `Owner[]`.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Owner[] && exists Account[user: match u { 1 => 1  _ => return true }]
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
    let warnings = warnings_for(&with_defs(
        r#"
        function same(n int) int { return n }
        function f(u int) bool {
            check exists Owner[] && same(match u { 1 => 1  _ => return true }) == 1
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
