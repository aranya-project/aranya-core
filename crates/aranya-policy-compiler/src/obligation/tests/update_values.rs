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

/// Helpers returning the stored balance of `u`, directly and through
/// another helper.
const BALANCE_OF: &str = r#"
    function balance_of(u int) int {
        let a = query Account[user: u] or test_fail()
        return a.balance
    }

    function balance_via(u int) int {
        return balance_of(u)
    }
"#;

#[rstest::rstest]
#[case::checked_equal(
    "let a = query Account[user: this.user] or recall failed()
     check a.balance == this.user else recall failed()"
)]
#[case::checked_equal_reversed(
    "let a = query Account[user: this.user] or recall failed()
     check this.user == a.balance else recall failed()"
)]
#[case::helper_return("check this.user == balance_of(this.user) else recall failed()")]
#[case::helper_return_through_helper(
    "check balance_via(this.user) == this.user else recall failed()"
)]
#[case::compared_twice(
    "let a = query Account[user: this.user] or recall failed()
     let b = a.balance
     check b == this.user else recall failed()"
)]
fn update_value_known_equal_to_the_stored_one_passes(#[case] proof: &str) {
    let warnings = warnings_for(&with_defs(
        BALANCE_OF,
        &format!(
            r#"
            {proof}
            finish {{
                update Account[user: this.user]=>{{balance: this.user}} to {{balance: 1}}
            }}
            "#
        ),
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[rstest::rstest]
#[case::exists("check exists Account[user: this.user]=>{balance: 5} else recall failed()")]
#[case::query("let a = query Account[user: this.user]=>{balance: 5} or recall failed()")]
#[case::at_least("check at_least 1 Account[user: this.user]=>{balance: 5} else recall failed()")]
fn update_value_filtered_on_passes(#[case] filter: &str) {
    let warnings = warnings_for(&command(&format!(
        r#"
        {filter}
        finish {{
            update Account[user: this.user]=>{{balance: 5}} to {{balance: 6}}
        }}
        "#
    )));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn update_value_filtered_on_in_a_match_arm_passes() {
    let warnings = warnings_for(&command(
        r#"
        match query Account[user: this.user]=>{balance: 5} {
            Some(a) => {
                finish {
                    update Account[user: this.user]=>{balance: 5} to {balance: 6}
                }
            }
            None => { finish {} }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn update_value_filtered_on_by_a_bound_key_query_passes() {
    let warnings = warnings_for(&with_defs(
        "fact Member[team int, device int]=>{rank int}",
        r#"
        let m = query Member[team: this.user, device: ?]=>{rank: 2} or recall failed()
        finish {
            update Member[team: this.user, device: m.device]=>{rank: 2} to {rank: 3}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn update_value_known_equal_through_a_finish_function_passes() {
    let warnings = warnings_for(&with_defs(
        r#"
        finish function set_balance(u int, old int, new int) {
            update Account[user: u]=>{balance: old} to {balance: new}
        }
        "#,
        r#"
        let a = query Account[user: this.user] or recall failed()
        check a.balance == this.user else recall failed()
        finish { set_balance(this.user, this.user, 1) }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn update_value_known_after_creating_another_fact_passes() {
    // Creating another fact leaves the stored value alone, and creating
    // this one would have failed.
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: this.user] or recall failed()
        check a.balance == this.user else recall failed()
        check !exists Account[user: 1] else recall failed()
        finish {
            create Account[user: 1]=>{balance: 0}
            update Account[user: this.user]=>{balance: this.user} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn update_value_known_alongside_a_key_passes() {
    // `a.user` equals `this.user` too, but it is a key, not a value.
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: this.user] or recall failed()
        check a.user == this.user else recall failed()
        check a.balance == this.user else recall failed()
        finish {
            update Account[user: this.user]=>{balance: this.user} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
