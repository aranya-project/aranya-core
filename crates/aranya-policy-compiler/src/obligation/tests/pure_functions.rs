//! Calls to pure functions, evaluated through their summaries: which
//! exits can make a call true, exits that can't run, recursion, the exit
//! limit, terminals that are not exits, and `return`s the walk can't
//! record.

use super::{warnings_for, warnings_with_cap, with_defs};

#[test]
fn one_line_helper_proves() {
    let warnings = warnings_for(&with_defs(
        r#"
        function account_exists(u int) bool {
            return exists Account[user: u]
        }
        "#,
        r#"
        check !account_exists(this.user) else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_in_if_condition_proves() {
    let warnings = warnings_for(&with_defs(
        r#"
        function account_exists(u int) bool {
            return exists Account[user: u]
        }
        "#,
        r#"
        if !account_exists(this.user) {
            finish { create Account[user: this.user]=>{balance: 0} }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_returning_false_on_missing_fact_proves_exists() {
    let warnings = warnings_for(&with_defs(
        r#"
        function has_account(u int) bool {
            let account = query Account[user: u] or return false
            return account.balance >= 0
        }
        "#,
        r#"
        check has_account(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_returning_query_used_as_value() {
    let warnings = warnings_for(&with_defs(
        r#"
        function find_account(u int) option[struct Account] {
            return query Account[user: u]
        }
        "#,
        r#"
        let account = find_account(this.user)
        if account is None {
            recall failed()
        }
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_combining_checks_with_or() {
    let warnings = warnings_for(&with_defs(
        r#"
        function taken(u int) bool {
            let has_account = exists Account[user: u]
            let has_owner = exists Owner[]
            return has_account || has_owner
        }
        "#,
        r#"
        check !taken(this.user) else recall failed()
        finish {
            create Account[user: this.user]=>{balance: 0}
            create Owner[]=>{user: this.user}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn exit_path_cap_makes_calls_unknown() {
    let text = with_defs(
        r#"
        function has_account(u int) bool {
            let account = query Account[user: u] or return false
            return true
        }
        "#,
        r#"
        check has_account(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    );
    assert_eq!(warnings_with_cap(&text, 2), vec![], "two exits fit");
    let warnings = warnings_with_cap(&text, 1);
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .notes
            .iter()
            .any(|(_, n)| n.contains("touches `Account`")),
        "notes: {:?}",
        warnings[0].notes
    );
}

#[test]
fn recursive_pure_function_terminates() {
    let warnings = warnings_for(&with_defs(
        r#"
        function spin(u int) bool {
            return spin(u)
        }
        "#,
        r#"
        check !spin(this.user) else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn impossible_check_exit_in_helper_is_not_recorded() {
    // The second check's failure contradicts the first, so its
    // `return true` exit can't weaken the call.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Account[user: u] else return false
            check exists Account[user: u] else return true
            return true
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
fn impossible_or_return_exit_in_helper_is_not_recorded() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Account[user: u] else return false
            let a = query Account[user: u] or return true
            return true
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
fn mutual_recursion_through_checks_terminates() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check g(u) else return false
            return true
        }
        function g(u int) bool {
            check f(u) else return false
            return true
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
fn mutual_recursion_through_query_helpers_terminates() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) option[struct Account] { return g(u) }
        function g(u int) option[struct Account] { return f(u) }
        "#,
        r#"
        let a = f(this.user) or recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn unknown_call_notes_facts_in_if_without_else() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            if u == 1 {
                return f(u)
            }
            if u == 2 {
                return f(u)
            } else {
                let z = exists Owner[]
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
    assert!(
        warnings[0]
            .notes
            .iter()
            .any(|(_, n)| n.contains("too complex"))
    );
}

#[test]
fn helper_check_else_test_fail_is_not_an_exit() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Account[user: u] else test_fail("gone")
            let a = query Account[user: u] or test_fail("gone")
            return true
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
fn helper_arm_test_fail_is_not_an_exit() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let x = match u {
                1 => 1
                _ => test_fail("no")
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
fn nested_return_in_each_unmodeled_position() {
    // Each position is inside an opaque expression, so the walk can't
    // record the exit and the helper must become unknown.
    for (position, body) in [
        (
            "comparison operand",
            "(match u { 1 => 1  _ => return true }) == 1",
        ),
        (
            "match scrutinee",
            "saturating_add(1, match (match u { 1 => 1  _ => return true }) { 1 => 1  _ => 2 })",
        ),
        (
            "if condition",
            "saturating_add(1, if (match u { 1 => true  _ => return true }) { : 1 } else { : 2 })",
        ),
        (
            "if arm",
            "saturating_add(1, if u == 1 { : return true } else { : 2 })",
        ),
        (
            "block statement",
            "saturating_add(1, { let y = query Account[user: u] or return true  let z = 1  : 1 })",
        ),
    ] {
        let warnings = warnings_for(&with_defs(
            &format!(
                "function f(u int) bool {{\n\
                     let a = {body}\n\
                     return exists Account[user: u]\n\
                 }}"
            ),
            r#"
            check f(this.user) else recall failed()
            finish { delete Account[user: this.user] }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "{position}: {warnings:?}");
        assert!(
            warnings[0].message.contains("before `delete`"),
            "{position}"
        );
        assert!(
            warnings[0]
                .notes
                .iter()
                .any(|(_, n)| n.contains("too complex")),
            "{position}: {:?}",
            warnings[0].notes
        );
    }
}

#[test]
fn nested_return_makes_helper_unknown() {
    let warnings = warnings_for(&with_defs(
        r#"
        function has(u int) bool {
            let x = saturating_add(1, match u {
                1 => 1
                _ => return true
            })
            return exists Account[user: u]
        }
        "#,
        r#"
        check has(this.user) else recall failed()
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
