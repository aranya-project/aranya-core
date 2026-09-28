//! Attacks on path pruning: a path may be dropped only when it cannot
//! run. A wrong contradiction hides every warning after it, so each
//! attack puts an unchecked mutation on the path in question.

use super::{MEMBER, warnings_for, with_defs};

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
