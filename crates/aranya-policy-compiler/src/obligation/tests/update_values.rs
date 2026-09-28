//! An `update`'s stated values.

use super::{command, warnings_for};

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
