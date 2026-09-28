//! Attacks on state: knowledge must be dropped whenever the database
//! may have changed.

use super::{MEMBER, command, warnings_for, with_defs};

#[test]
fn attack_aliasing_keys_in_one_finish() {
    // `this.user` may be 7, so the second delete may hit a deleted fact.
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check exists Member[team: 1, device: this.user] else recall failed()
        check exists Member[team: 1, device: 7] else recall failed()
        finish {
            delete Member[team: 1, device: this.user]
            delete Member[team: 1, device: 7]
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_single_delete_of_checked_key() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check exists Member[team: 1, device: this.user] else recall failed()
        check exists Member[team: 1, device: 7] else recall failed()
        finish { delete Member[team: 1, device: 7] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_aliasing_keys_through_finish_function() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}

        finish function rm(d int) {
            delete Member[team: 1, device: d]
        }
        "#,
        r#"
        check exists Member[team: 1, device: this.user] else recall failed()
        check exists Member[team: 1, device: 7] else recall failed()
        finish {
            rm(this.user)
            rm(7)
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
    assert!(
        warnings[0]
            .notes
            .iter()
            .any(|(_, n)| n.contains("in this call"))
    );
}

#[test]
fn attack_known_finish_function_drops_binding() {
    let warnings = warnings_for(&with_defs(
        r#"
        finish function bump(u int) {
            update Account[user: u] to {balance: 0}
        }
        "#,
        r#"
        let a = query Account[user: this.user] or recall failed()
        check exists Account[user: 1] else recall failed()
        finish {
            bump(1)
            update Account[user: this.user]=>{balance: a.balance} to {balance: 5}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `update`"));
}

#[test]
fn control_binding_survives_without_the_call() {
    let warnings = warnings_for(&with_defs(
        r#"
        finish function bump(u int) {
            update Account[user: u] to {balance: 0}
        }
        "#,
        r#"
        let a = query Account[user: this.user] or recall failed()
        check exists Account[user: 1] else recall failed()
        finish {
            update Account[user: this.user]=>{balance: a.balance} to {balance: 5}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_recursive_call_in_init_forgets_empty_db() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        finish function ping(u int) { pong(u) }
        finish function pong(u int) { ping(u) }

        command Init {
            attributes { init: true }
            fields { user int }
            policy {
                finish {
                    ping(this.user)
                    create Account[user: this.user]=>{balance: 0}
                }
            }
        }
        "#,
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.message.contains("before `create`")),
        "warnings: {warnings:?}"
    );
}

#[test]
fn control_init_create_after_known_call() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}
        fact Owner[]=>{user int}

        finish function own(u int) { create Owner[]=>{user: u} }

        command Init {
            attributes { init: true }
            fields { user int }
            policy {
                finish {
                    own(this.user)
                    create Account[user: this.user]=>{balance: 0}
                }
            }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_recall_block_does_not_inherit_policy_knowledge() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        command Foo {
            fields { user int }
            policy {
                check exists Account[user: this.user] else recall failed()
                finish {}
            }
            recall failed() {
                finish { delete Account[user: this.user] }
            }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_recall_block_with_its_own_check() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        command Foo {
            fields { user int }
            policy {
                check exists Account[user: this.user] else recall failed()
                finish {}
            }
            recall failed() {
                check exists Account[user: this.user] else test_fail("missing")
                finish { delete Account[user: this.user] }
            }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_finish_function_create_then_caller_update() {
    let warnings = warnings_for(&with_defs(
        r#"
        finish function mk(u int) { create Account[user: u]=>{balance: 0} }
        "#,
        r#"
        check !exists Account[user: this.user] else recall failed()
        finish {
            mk(this.user)
            update Account[user: this.user] to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("more than once"));
}

#[test]
fn attack_update_then_delete_same_finish() {
    let warnings = warnings_for(&command(
        r#"
        check exists Account[user: this.user] else recall failed()
        finish {
            update Account[user: this.user] to {balance: 1}
            delete Account[user: this.user]
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("more than once"));
}
