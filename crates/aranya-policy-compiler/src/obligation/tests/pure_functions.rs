//! Calls to pure functions, evaluated through their summaries.

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
fn helper_locals_are_not_confused_with_caller_names() {
    // Both the helper and the command have a variable named `account`,
    // holding different facts. The helper's `Link[user: account.balance]`
    // must not prove the command's.
    let warnings = warnings_for(&with_defs(
        r#"
        fact Link[user int]=>{}

        function linked() bool {
            let account = query Account[user: 1] or return false
            return exists Link[user: account.balance]
        }
        "#,
        r#"
        let account = query Account[user: this.user] or recall failed()
        check linked() else recall failed()
        finish { delete Link[user: account.balance] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("exists before `delete`"));
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
}
