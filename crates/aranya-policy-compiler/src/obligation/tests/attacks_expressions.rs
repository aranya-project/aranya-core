//! Attacks on `if`, `match`, and block expressions: arms are joined by
//! intersection, and nothing from an arm's scope escapes.

use super::{MEMBER, command, warnings_for, with_defs};

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
