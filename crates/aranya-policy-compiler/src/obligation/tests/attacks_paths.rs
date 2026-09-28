//! Attacks on path pruning: a path may be dropped only when it cannot
//! run. A wrong contradiction hides every warning after it, so each
//! attack puts an unchecked mutation on the path in question.

use super::{MEMBER, command, warnings_for, with_defs};

#[test]
fn attack_exists_prefix_then_not_exists_exact_is_not_contradiction() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check exists Member[team: this.user, device: ?] else recall failed()
        if !exists Member[team: this.user, device: 1] {
            finish { create Owner[]=>{user: this.user} }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("`Owner[]` does not exist"));
}

#[test]
fn attack_not_exists_exact_then_exists_prefix_is_not_contradiction() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check !exists Member[team: this.user, device: 1] else recall failed()
        if exists Member[team: this.user, device: ?] {
            finish { create Owner[]=>{user: this.user} }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("`Owner[]` does not exist"));
}

#[test]
fn control_true_contradiction_prunes() {
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check exists Account[user: this.user] else recall failed()
        if !exists Account[user: this.user] {
            finish { create Owner[]=>{user: this.user} }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn control_prefix_absence_contradicts_exact_presence() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check !exists Member[team: this.user, device: ?] else recall failed()
        if exists Member[team: this.user, device: 1] {
            finish { create Owner[]=>{user: this.user} }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_at_least_two_then_not_exists_exact() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check at_least 2 Member[team: this.user, device: ?] else recall failed()
        if !exists Member[team: this.user, device: 1] {
            finish { create Owner[]=>{user: this.user} }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("`Owner[]` does not exist"));
}

#[test]
fn control_init_prunes_exists_branch() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}
        fact Owner[]=>{user int}

        command Init {
            attributes { init: true }
            fields { user int }
            policy {
                if exists Account[user: this.user] {
                    finish { create Owner[]=>{user: this.user} }
                }
                finish {}
            }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_non_init_does_not_prune_exists_branch() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}
        fact Owner[]=>{user int}

        command Foo {
            attributes { init: false }
            fields { user int }
            policy {
                if exists Account[user: this.user] {
                    finish { create Owner[]=>{user: this.user} }
                }
                finish {}
            }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("`Owner[]` does not exist"));
}

#[test]
fn attack_some_literal_arm_does_not_prune_binding_arm() {
    // `Some(1)` not matching does not mean `None`: the value may be
    // `Some(2)`, so the `Some(x)` arm can run.
    let warnings = warnings_for(&with_defs(
        "function maybe(u int) option[int] { return Some(u) }",
        r#"
        match maybe(this.user) {
            Some(1) => { finish {} }
            Some(x) => { finish { create Account[user: x]=>{balance: 0} } }
            None => { finish {} }
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn attack_some_literal_arm_does_not_prove_none_in_default_arm() {
    // A query result that isn't this particular account may still be
    // some account, so the default arm cannot assume the fact is absent.
    let warnings = warnings_for(&command(
        r#"
        match query Account[user: this.user] {
            Some(Account { user: 1, balance: 0 }) => { finish {} }
            _ => { finish { create Account[user: this.user]=>{balance: 0} } }
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn control_none_arm_after_literal_proves_absent() {
    let warnings = warnings_for(&command(
        r#"
        match query Account[user: this.user] {
            Some(Account { user: 1, balance: 0 }) => { finish {} }
            None => { finish { create Account[user: this.user]=>{balance: 0} } }
            _ => { finish {} }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn control_some_binding_arm_prunes_none_arm() {
    // `Some(x)` matches every `Some`, and the helper never returns
    // `None`, so the `None` arm cannot run.
    let warnings = warnings_for(&with_defs(
        "function maybe(u int) option[int] { return Some(u) }",
        r#"
        match maybe(this.user) {
            Some(x) => { finish {} }
            None => { finish { create Account[user: this.user]=>{balance: 0} } }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_not_and_proves_nothing() {
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check !(exists Account[user: this.user] && exists Owner[]) else recall failed()
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn control_not_or_proves_both() {
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check !(exists Account[user: this.user] || exists Owner[]) else recall failed()
        finish {
            create Account[user: this.user]=>{balance: 0}
            create Owner[]=>{user: this.user}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
