//! `if`, `match`, and block expressions.

use super::{MEMBER, command, warnings_for, warnings_with_cap, with_defs};

#[test]
fn if_expression_check_proves() {
    let warnings = warnings_for(&command(
        r#"
        check if this.user == 1 { : !exists Account[user: this.user] } else { : false }
            else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn match_expression_check_proves() {
    let warnings = warnings_for(&command(
        r#"
        check match this.user {
            1 => exists Account[user: 1]
            _ => false
        } else recall failed()
        finish { delete Account[user: 1] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn block_let_alias_in_arms_proves() {
    let warnings = warnings_for(&command(
        r#"
        check if this.user == 1 {
            let u = this.user
            : !exists Account[user: u]
        } else {
            : !exists Account[user: this.user]
        } else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn block_check_in_arms_proves() {
    let warnings = warnings_for(&command(
        r#"
        check if this.user == 1 {
            check !exists Account[user: this.user] else recall failed()
            : true
        } else {
            : !exists Account[user: this.user]
        } else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn block_if_statement_proves() {
    let warnings = warnings_for(&command(
        r#"
        let x = if this.user == 1 {
            if this.user == 2 {
                check !exists Account[user: this.user] else recall failed()
            } else {
                check !exists Account[user: this.user] else recall failed()
            }
            : 1
        } else {
            check !exists Account[user: this.user] else recall failed()
            : 2
        }
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn block_match_statement_proves() {
    let warnings = warnings_for(&command(
        r#"
        let x = if this.user == 1 {
            match query Account[user: this.user] {
                Some(a) => { let unused = a.balance }
                None => { recall failed() }
            }
            : 1
        } else {
            let a = query Account[user: this.user] or recall failed()
            : 2
        }
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn match_let_binds_query_result() {
    let warnings = warnings_for(&command(
        r#"
        let a = match query Account[user: this.user] {
            Some(x) => x
            None => recall failed()
        }
        finish {
            update Account[user: this.user]=>{balance: a.balance} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn match_let_learns_from_producing_arms() {
    let warnings = warnings_for(&command(
        r#"
        let d = match this.user {
            1 => {
                let a = query Account[user: this.user] or recall failed()
                : a.balance
            }
            _ => recall failed()
        }
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn if_expression_query_or_recall_proves() {
    let warnings = warnings_for(&command(
        r#"
        let f = if this.user == 1 { : query Account[user: this.user] } else { : None }
            or recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_returning_if_expression_proves() {
    let warnings = warnings_for(&with_defs(
        r#"
        function has(u int) bool {
            return if u == 1 { : exists Account[user: 1] } else { : false }
        }
        "#,
        r#"
        check has(1) else recall failed()
        finish { delete Account[user: 1] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn if_expression_else_true_proves_nothing() {
    let warnings = warnings_for(&command(
        r#"
        check if this.user == 1 { : !exists Account[user: this.user] } else { : true }
            else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn finish_inside_block_is_checked() {
    let warnings = warnings_for(&command(
        r#"
        let x = if this.user == 1 {
            finish { create Account[user: this.user]=>{balance: 0} }
            : 1
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
fn block_ends_over_cap_are_opaque() {
    let text = command(
        r#"
        check if this.user == 1 {
            if this.user == 2 {
                let a = 1
            } else {
                let b = 2
            }
            : !exists Account[user: this.user]
        } else {
            : !exists Account[user: this.user]
        } else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    );
    assert_eq!(warnings_with_cap(&text, 2), vec![], "expected no warnings");
    let warnings = warnings_with_cap(&text, 1);
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
    assert!(
        warnings[0]
            .notes
            .iter()
            .any(|(_, n)| n.contains("too complex"))
    );
}

#[test]
fn match_let_with_other_arm_does_not_bind() {
    let warnings = warnings_for(&command(
        r#"
        let other = query Account[user: 0] or recall failed()
        let a = match query Account[user: this.user] {
            Some(x) => x
            _ => other
        }
        finish {
            update Account[user: this.user]=>{balance: a.balance} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `update`"));
}

#[test]
fn helper_match_arm_return_is_an_exit() {
    // The `_` arm returns `true` without proving anything, so the call
    // proves nothing.
    let warnings = warnings_for(&with_defs(
        r#"
        function has(u int) bool {
            let x = match u {
                1 => 1
                _ => return true
            }
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

#[test]
fn arm_bound_name_does_not_leak() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}
        fact Other[k int]=>{v int}
        "#,
        r#"
        check match query Member[team: 1, device: ?] {
            Some(m) => exists Other[k: m.device]
            None => false
        } else recall failed()
        let m = query Member[team: 2, device: ?] or recall failed()
        finish { delete Other[k: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn block_local_name_does_not_leak() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        let x = if this.user == 1 {
            let a = query Member[team: 1, device: ?] or recall failed()
            : a.rank
        } else {
            let a = query Member[team: 1, device: ?] or recall failed()
            : a.rank
        }
        let a = query Member[team: 2, device: ?] or recall failed()
        finish { delete Member[team: 1, device: a.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}
