//! Attacks on polarity: a negative observation must name every fact
//! with its key, and a positive one with a bind marker must not name a
//! particular key.
//!
//! Each attack is a policy whose mutation can fail at runtime, asserting
//! that the analysis warns. Its control twin removes the trick and
//! asserts no warnings, so the warning is attributable to the attack.

use super::{MEMBER, command, warnings_for, with_defs};

#[test]
fn attack_filtered_not_exists_does_not_prove_absent() {
    // Only accounts with balance 0 are known absent; one with another
    // balance may exist and would be clobbered.
    let warnings = warnings_for(&command(
        r#"
        check !exists Account[user: this.user]=>{balance: 0} else recall failed()
        finish { create Account[user: this.user]=>{balance: 1} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn control_unfiltered_not_exists_proves_absent() {
    let warnings = warnings_for(&command(
        r#"
        check !exists Account[user: this.user] else recall failed()
        finish { create Account[user: this.user]=>{balance: 1} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn control_bind_only_filter_proves_absent() {
    // A value bind marker is not a filter.
    let warnings = warnings_for(&command(
        r#"
        check !exists Account[user: this.user]=>{balance: ?} else recall failed()
        finish { create Account[user: this.user]=>{balance: 1} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_filtered_query_is_none_does_not_prove_absent() {
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: this.user]=>{balance: 0}
        if a is Some { recall failed() }
        finish { create Account[user: this.user]=>{balance: 1} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn control_unfiltered_query_is_none_proves_absent() {
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: this.user]
        if a is Some { recall failed() }
        finish { create Account[user: this.user]=>{balance: 1} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_filtered_match_none_arm_does_not_prove_absent() {
    let warnings = warnings_for(&command(
        r#"
        match query Account[user: this.user]=>{balance: 0} {
            None => { finish { create Account[user: this.user]=>{balance: 1} } }
            Some(a) => { finish {} }
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn attack_filtered_count_does_not_prove_absent() {
    let warnings = warnings_for(&command(
        r#"
        check !(at_least 1 Account[user: this.user]=>{balance: 0}) else recall failed()
        finish { create Account[user: this.user]=>{balance: 1} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn control_unfiltered_count_proves_absent() {
    let warnings = warnings_for(&command(
        r#"
        check !(at_least 1 Account[user: this.user]) else recall failed()
        finish { create Account[user: this.user]=>{balance: 1} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_filtered_helper_does_not_prove_absent() {
    let warnings = warnings_for(&with_defs(
        r#"
        function free(u int) bool {
            return !exists Account[user: u]=>{balance: 0}
        }
        "#,
        r#"
        check free(this.user) else recall failed()
        finish { create Account[user: this.user]=>{balance: 1} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn control_unfiltered_helper_proves_absent() {
    let warnings = warnings_for(&with_defs(
        r#"
        function free(u int) bool {
            return !exists Account[user: u]
        }
        "#,
        r#"
        check free(this.user) else recall failed()
        finish { create Account[user: this.user]=>{balance: 1} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_filtered_check_does_not_prune_branch() {
    // The branch can run, since an account with another balance may
    // exist, so the unchecked create inside it must be reported.
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check !exists Account[user: this.user]=>{balance: 0} else recall failed()
        if exists Account[user: this.user] {
            finish { create Owner[]=>{user: this.user} }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("`Owner[]` does not exist"));
}

#[test]
fn control_unfiltered_check_prunes_branch() {
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check !exists Account[user: this.user] else recall failed()
        if exists Account[user: this.user] {
            finish { create Owner[]=>{user: this.user} }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn control_filtered_query_still_proves_exists_and_values() {
    // A filtered match still means the fact exists, and the binding
    // still holds it.
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: this.user]=>{balance: 1} or recall failed()
        finish {
            update Account[user: this.user]=>{balance: a.balance} to {balance: 2}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_exists_prefix_via_count_does_not_prove_key() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check at_least 1 Member[team: this.user, device: ?] else recall failed()
        finish { delete Member[team: this.user, device: 5] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn attack_exists_prefix_via_match_does_not_prove_key() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        match query Member[team: this.user, device: ?] {
            Some(m) => { finish { delete Member[team: this.user, device: 5] } }
            None => { finish {} }
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn attack_exists_prefix_via_let_or_does_not_prove_key() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        let m = query Member[team: this.user, device: ?] or recall failed()
        finish { delete Member[team: this.user, device: 5] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_exists_exact_key_proves_delete() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check exists Member[team: this.user, device: 5] else recall failed()
        finish { delete Member[team: this.user, device: 5] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_not_exists_other_key_does_not_prove_absent() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check !exists Member[team: this.user, device: 1] else recall failed()
        finish { create Member[team: this.user, device: 2]=>{rank: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn control_not_exists_prefix_proves_any_key_absent() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check !exists Member[team: this.user, device: ?] else recall failed()
        finish { create Member[team: this.user, device: 2]=>{rank: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
