//! Attacks on stored values: a value counts as the stored one only for
//! that field of that fact, and only while nothing may have changed it.

use super::{command, warnings_for, with_defs};

#[track_caller]
fn assert_values_unproven(policy: &str) {
    let warnings = warnings_for(policy);
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0].message.contains("stated values"),
        "warnings: {warnings:?}"
    );
}

/// A command that reads the user's account into `a`, runs `proof`, and
/// updates the account stating `this.user` as its balance.
fn update_after(proof: &str) -> String {
    command(&format!(
        r#"
        let a = query Account[user: this.user] or recall failed()
        {proof}
        finish {{
            update Account[user: this.user]=>{{balance: this.user}} to {{balance: 1}}
        }}
        "#
    ))
}

#[test]
fn attack_value_checked_unequal() {
    assert_values_unproven(&update_after(
        "check a.balance != this.user else recall failed()",
    ));
}

#[test]
fn control_value_checked_equal() {
    let warnings = warnings_for(&update_after(
        "check a.balance == this.user else recall failed()",
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_value_equal_on_one_branch_only() {
    assert_values_unproven(&update_after(
        "if a.balance == this.user { let unused = 1 }",
    ));
}

#[test]
fn attack_value_equal_to_a_key() {
    // `a.user` is the key, not a stored value.
    assert_values_unproven(&update_after(
        "check a.user == this.user else recall failed()",
    ));
}

#[test]
fn attack_value_of_another_fact() {
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: 1] or recall failed()
        check a.balance == this.user else recall failed()
        check exists Account[user: 2] else recall failed()
        finish {
            update Account[user: 2]=>{balance: this.user} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

#[test]
fn control_value_of_the_same_fact() {
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: 1] or recall failed()
        check a.balance == this.user else recall failed()
        finish {
            update Account[user: 1]=>{balance: this.user} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

/// A fact with two values, `x` checked equal to `this.user`, updated
/// stating `stated`.
fn pair_update(stated: &str) -> String {
    with_defs(
        "fact Pair[k int]=>{x int, y int}",
        &format!(
            r#"
            let p = query Pair[k: 1] or recall failed()
            check p.x == this.user else recall failed()
            finish {{
                update Pair[k: 1]=>{{{stated}}} to {{x: 0, y: 0}}
            }}
            "#
        ),
    )
}

#[test]
fn attack_value_of_another_field() {
    assert_values_unproven(&pair_update("x: p.x, y: this.user"));
}

#[test]
fn control_value_of_the_checked_field() {
    let warnings = warnings_for(&pair_update("x: this.user, y: p.y"));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_value_filtered_on_a_key_prefix() {
    // Some member of the team has rank 2, not necessarily device 5.
    let warnings = warnings_for(&with_defs(
        "fact Member[team int, device int]=>{rank int}",
        r#"
        check exists Member[team: this.user, device: ?]=>{rank: 2} else recall failed()
        check exists Member[team: this.user, device: 5] else recall failed()
        finish {
            update Member[team: this.user, device: 5]=>{rank: 2} to {rank: 3}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

#[test]
fn attack_value_filtered_on_a_key_prefix_is_not_a_key() {
    // The rank filtered on must not stand in for the missing key.
    let warnings = warnings_for(&with_defs(
        "fact Member[team int, device int]=>{rank int}",
        r#"
        check exists Member[team: this.user, device: ?]=>{rank: 2} else recall failed()
        finish {
            delete Member[team: this.user, device: 2]
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_value_filtered_on_the_whole_key() {
    let warnings = warnings_for(&with_defs(
        "fact Member[team int, device int]=>{rank int}",
        r#"
        check exists Member[team: this.user, device: 5]=>{rank: 2} else recall failed()
        finish {
            update Member[team: this.user, device: 5]=>{rank: 2} to {rank: 3}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

/// Helpers whose exits return different stored values, or one read
/// through a key the helper bound.
const HELPERS: &str = r#"
    fact Limit[user int]=>{balance int}
    fact Member[team int, device int]=>{rank int}

    function limit_or_balance(u int) int {
        if u > 1 {
            let l = query Limit[user: u] or test_fail()
            return l.balance
        }
        let a = query Account[user: u] or test_fail()
        return a.balance
    }

    function rank_of(t int) int {
        let m = query Member[team: t, device: ?] or test_fail()
        return m.rank
    }
"#;

#[test]
fn attack_helper_whose_exits_return_different_values() {
    let warnings = warnings_for(&with_defs(
        HELPERS,
        r#"
        check exists Account[user: this.user] else recall failed()
        check this.user == limit_or_balance(this.user) else recall failed()
        finish {
            update Account[user: this.user]=>{balance: this.user} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

#[test]
fn attack_helper_value_read_through_a_key_it_bound() {
    // `rank_of` read some member of the team. The caller's `m` has the
    // same name but may be another member.
    let warnings = warnings_for(&with_defs(
        HELPERS,
        r#"
        let m = query Member[team: this.user, device: ?] or recall failed()
        check this.user == rank_of(this.user) else recall failed()
        finish {
            update Member[team: this.user, device: m.device]=>{rank: this.user} to {rank: 0}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}
