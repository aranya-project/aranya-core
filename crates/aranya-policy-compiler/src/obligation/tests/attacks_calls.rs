//! Attacks on calls: a helper's facts hold only where its call runs, so a
//! call that may be skipped proves nothing.

use super::{warnings_for, with_defs};

/// Helpers that only return if `Account[user: u]` exists, or only on
/// some exits.
const HELPERS: &str = r#"
    function balance_of(u int) int {
        let a = query Account[user: u] or test_fail()
        return a.balance
    }

    function maybe(u int) option[int] {
        if u > 1 {
            return Some(u)
        }
        return None
    }

    function some_balance(u int) int {
        if u > 1 {
            let a = query Account[user: u] or test_fail()
            return a.balance
        }
        return 0
    }

    function both_balances(u int) int {
        if u > 1 {
            let a = query Account[user: u] or test_fail()
            return a.balance
        }
        let a = query Account[user: u] or test_fail()
        return 0
    }
"#;

/// A command that runs `uses`, then deletes the user's account.
fn deletes_after(uses: &str) -> String {
    with_defs(
        HELPERS,
        &format!(
            r#"
            {uses}
            finish {{ delete Account[user: this.user] }}
            "#
        ),
    )
}

#[track_caller]
fn assert_unproven(uses: &str) {
    let warnings = warnings_for(&deletes_after(uses));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[track_caller]
fn assert_proven(uses: &str) {
    let warnings = warnings_for(&deletes_after(uses));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_call_on_the_right_of_and() {
    // Where `this.user > 1` is false, the call never ran.
    assert_unproven("if this.user > 1 && balance_of(this.user) > 5 { recall failed() }");
}

#[test]
fn control_call_on_the_left_of_and() {
    assert_proven("if balance_of(this.user) > 5 && this.user > 1 { recall failed() }");
}

#[test]
fn attack_call_on_the_right_of_or() {
    let warnings = warnings_for(&with_defs(
        HELPERS,
        r#"
        if this.user > 1 || balance_of(this.user) > 5 {
            finish { delete Account[user: this.user] }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_call_on_the_left_of_or() {
    let warnings = warnings_for(&with_defs(
        HELPERS,
        r#"
        if balance_of(this.user) > 5 || this.user > 1 {
            finish { delete Account[user: this.user] }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_call_on_the_right_of_or_else() {
    // The right side runs only when `maybe` returns `None`.
    assert_unproven("let n = maybe(this.user) or balance_of(this.user)");
}

#[test]
fn control_call_on_the_left_of_or_else() {
    assert_proven("let n = Some(balance_of(this.user)) or 0");
}

#[test]
fn attack_call_in_one_arm_of_an_if() {
    assert_unproven("let n = if this.user > 1 { :balance_of(this.user) } else { :0 }");
}

#[test]
fn control_call_in_both_arms_of_an_if() {
    assert_proven(
        "let n = if this.user > 1 { :balance_of(this.user) } else { :balance_of(this.user) }",
    );
}

#[test]
fn attack_call_in_an_arm_of_a_compared_if() {
    assert_unproven(
        "check (if this.user > 1 { :balance_of(this.user) } else { :1 }) > 0 else recall failed()",
    );
}

#[test]
fn control_call_in_the_condition_of_a_compared_if() {
    assert_proven(
        "check (if balance_of(this.user) > 1 { :1 } else { :2 }) > 0 else recall failed()",
    );
}

#[test]
fn attack_call_in_an_arm_of_a_compared_match() {
    assert_unproven(
        "check (match this.user { 1 => balance_of(this.user) _ => 1 }) > 0 else recall failed()",
    );
}

#[test]
fn control_call_in_the_scrutinee_of_a_compared_match() {
    assert_proven("check (match balance_of(this.user) { 1 => 1 _ => 2 }) > 0 else recall failed()");
}

#[test]
fn attack_call_in_a_debug_assert() {
    // A release build skips the assertion, so the call may never run.
    assert_unproven("debug_assert(balance_of(this.user) > 0)");
}

#[test]
fn control_call_in_a_check() {
    assert_proven("check balance_of(this.user) > 0 else recall failed()");
}

#[test]
fn attack_call_whose_exits_disagree() {
    // The exit returning 0 never read the account.
    assert_unproven("let n = some_balance(this.user)");
}

#[test]
fn control_call_whose_exits_agree() {
    assert_proven("let n = both_balances(this.user)");
}

#[test]
fn attack_call_on_the_right_of_and_in_a_let() {
    assert_unproven("let ok = this.user > 1 && balance_of(this.user) > 5");
}

#[test]
fn control_call_on_the_left_of_and_in_a_let() {
    assert_proven("let ok = balance_of(this.user) > 5 && this.user > 1");
}

#[test]
fn attack_call_on_the_right_of_or_in_a_let() {
    assert_unproven("let ok = this.user > 1 || balance_of(this.user) > 5");
}

#[test]
fn control_call_on_the_left_of_or_in_a_let() {
    assert_proven("let ok = balance_of(this.user) > 5 || this.user > 1");
}
