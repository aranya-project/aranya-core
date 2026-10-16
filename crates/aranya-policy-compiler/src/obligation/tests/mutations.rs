//! Each obligation passing with its observation and warning without it, key matching, and the finish-block touched set.

use super::{command, warnings_for, with_defs};

#[test]
fn check_then_create_passes() {
    let warnings = warnings_for(&command(
        r#"
        check !exists Account[user: this.user] else recall failed()
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn create_without_check_warns() {
    let warnings = warnings_for(&command(
        r#"
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(
        warnings[0].message,
        "cannot prove `Account[user: this.user]` does not exist before `create`"
    );
    assert!(warnings[0].notes.is_empty());
}

#[test]
fn update_without_check_warns() {
    let warnings = warnings_for(&command(
        r#"
        finish {
            update Account[user: this.user] to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(
        warnings[0].message,
        "cannot prove `Account[user: this.user]` exists before `update`"
    );
}

#[test]
fn delete_without_check_warns() {
    let warnings = warnings_for(&command(
        r#"
        finish {
            delete Account[user: this.user]
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(
        warnings[0].message,
        "cannot prove `Account[user: this.user]` exists before `delete`"
    );
}

#[test]
fn check_exists_then_delete_passes() {
    let warnings = warnings_for(&command(
        r#"
        check exists Account[user: this.user] else recall failed()
        finish {
            delete Account[user: this.user]
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn query_or_recall_then_update_passes() {
    let warnings = warnings_for(&command(
        r#"
        let account = query Account[user: this.user] or recall failed()
        finish {
            update Account[user: this.user] to {balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn check_not_exists_does_not_prove_exists() {
    let warnings = warnings_for(&command(
        r#"
        check !exists Account[user: this.user] else recall failed()
        finish {
            delete Account[user: this.user]
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("exists before `delete`"));
}

#[test]
fn bind_prefix_does_not_prove_exists() {
    let warnings = warnings_for(
        r#"
        fact Grant[user int, perm int]=>{}

        command Foo {
            fields { user int }
            policy {
                check exists Grant[user: this.user, perm: ?] else recall failed()
                finish {
                    delete Grant[user: this.user, perm: 3]
                }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("exists before `delete`"));
}

#[test]
fn bind_prefix_subsumes_concrete_key() {
    let warnings = warnings_for(
        r#"
        fact Grant[user int, perm int]=>{}

        command Foo {
            fields { user int }
            policy {
                check !exists Grant[user: this.user, perm: ?] else recall failed()
                finish {
                    create Grant[user: this.user, perm: 3]=>{}
                }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn let_alias_matches() {
    let warnings = warnings_for(&command(
        r#"
        let uid = this.user
        check !exists Account[user: uid] else recall failed()
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn double_create_warns() {
    let warnings = warnings_for(&command(
        r#"
        check !exists Account[user: this.user] else recall failed()
        finish {
            create Account[user: this.user]=>{balance: 0}
            create Account[user: this.user]=>{balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("more than once"));
}

#[test]
fn delete_then_create_warns() {
    let warnings = warnings_for(&command(
        r#"
        check exists Account[user: this.user] else recall failed()
        finish {
            delete Account[user: this.user]
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("more than once"));
}

// --- Key matching forms.
#[test]
fn enum_keys_match_by_value() {
    let warnings = warnings_for(
        r#"
        enum Role { Admin, Member }
        fact Grant[role enum Role]=>{v int}

        command Foo {
            fields { user int }
            policy {
                check !exists Grant[role: Role::Admin] else recall failed()
                finish { create Grant[role: Role::Admin]=>{v: 0} }
            }
            recall failed() { finish {} }
        }

        command Bar {
            fields { user int }
            policy {
                check !exists Grant[role: Role::Admin] else recall failed()
                finish { create Grant[role: Role::Member]=>{v: 0} }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("Role::Member"));
}

#[test]
fn dot_keys_differ_by_field() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        command Foo {
            fields { user int, other int }
            policy {
                check !exists Account[user: this.user] else recall failed()
                finish { create Account[user: this.other]=>{balance: 0} }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .message
            .contains("`Account[user: this.other]` does not exist")
    );
}

#[test]
fn call_keys_match_same_function() {
    let warnings = warnings_for(&with_defs(
        "function one(u int) int { return u }",
        r#"
        let k = one(this.user)
        check !exists Account[user: k] else recall failed()
        finish { create Account[user: k]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn call_keys_differ_by_function() {
    let warnings = warnings_for(&with_defs(
        r#"
        function one(u int) int { return u }
        function two(u int) int { return u }
        "#,
        r#"
        let k = one(this.user)
        let k2 = two(this.user)
        check !exists Account[user: k] else recall failed()
        finish { create Account[user: k2]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .message
            .contains("`Account[user: k2]` does not exist")
    );
}

#[test]
fn branching_let_values_still_match_by_name() {
    // A `let` whose value contains an `if` or `match` is not substituted,
    // so the name matches itself in keys. Substituting would compare
    // two `if` expressions, which never match.
    for value in [
        "(if this.user == 1 { : 1 } else { : 2 }) == 1",
        "this.user == (if this.user == 1 { : 1 } else { : 2 })",
        "exists Account[user: match this.user { 1 => 1  _ => 2 }]",
    ] {
        let warnings = warnings_for(&with_defs(
            "fact Flag[on bool]=>{v int}",
            &format!(
                "let x = {value}\n\
                 check !exists Flag[on: x] else recall failed()\n\
                 finish {{ create Flag[on: x]=>{{v: 0}} }}"
            ),
        ));
        assert_eq!(warnings, vec![], "{value}: expected no warnings");
    }
}
