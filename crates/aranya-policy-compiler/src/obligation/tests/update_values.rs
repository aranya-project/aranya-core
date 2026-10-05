//! An `update`'s stated values.

use super::{command, warnings_for, with_defs};

#[test]
fn update_values_from_query_pass() {
    let warnings = warnings_for(&command(
        r#"
        let account = query Account[user: this.user]=>{balance: ?} or recall failed()
        finish {
            update Account[user: this.user]=>{balance: account.balance} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn update_values_through_let_alias_pass() {
    let warnings = warnings_for(&command(
        r#"
        let account = query Account[user: this.user] or recall failed()
        let old = account.balance
        finish {
            update Account[user: this.user]=>{balance: old} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn update_literal_values_warn() {
    let warnings = warnings_for(&command(
        r#"
        check exists Account[user: this.user] else recall failed()
        finish {
            update Account[user: this.user]=>{balance: 5} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0].message.contains("stated values"),
        "warnings: {warnings:?}"
    );
}

#[test]
fn update_values_from_query_of_other_fact_warn() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}
        fact Limit[user int]=>{balance int}

        command Foo {
            fields { user int }
            policy {
                let limit = query Limit[user: this.user] or recall failed()
                check exists Account[user: this.user] else recall failed()
                finish {
                    update Account[user: this.user]=>{balance: limit.balance} to {balance: 1}
                }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

// --- Update values.
#[test]
fn update_value_from_other_field_warns() {
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: this.user] or recall failed()
        finish { update Account[user: this.user]=>{balance: a.user} to {balance: 1} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

#[test]
fn update_value_from_nested_field_warns() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}
        struct Inner { balance int }

        command Foo {
            fields { user int, inner struct Inner }
            policy {
                check exists Account[user: this.user] else recall failed()
                finish {
                    update Account[user: this.user]=>{balance: this.inner.balance} to {balance: 1}
                }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

/// A fact with two values, read by a query and then updated.
fn update_pair(stated: &str) -> String {
    with_defs(
        "fact Pair[k int]=>{a int, b int}",
        &format!(
            "let p = query Pair[k: this.user] or recall failed()\n\
             finish {{ update Pair[k: this.user]=>{{{stated}}} to {{a: 1, b: 2}} }}"
        ),
    )
}

#[test]
fn partially_stated_update_always_fails() {
    // The VM compares the stated values with the whole stored list.
    let warnings = warnings_for(&update_pair("a: p.a, b: ?"));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(
        warnings[0].message,
        "the stated values of `Pair[k: this.user]` can never match the stored fact"
    );
    assert_eq!(warnings[0].label, "this update always fails");
}

#[test]
fn fully_stated_update_passes() {
    let warnings = warnings_for(&update_pair("a: p.a, b: p.b"));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn update_binding_every_value_passes() {
    // With every value bound, the VM skips the comparison.
    let warnings = warnings_for(&update_pair("a: ?, b: ?"));
    assert_eq!(warnings, vec![], "expected no warnings");
}
