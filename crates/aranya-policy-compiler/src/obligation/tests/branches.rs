//! `if` and `match` branches, early exits, and impossible paths.

use super::{command, warnings_for, with_defs};

#[test]
fn if_exists_proves_each_branch() {
    let warnings = warnings_for(&command(
        r#"
        if exists Account[user: this.user] {
            finish { delete Account[user: this.user] }
        } else {
            finish { create Account[user: this.user]=>{balance: 0} }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn early_recall_proves_the_opposite() {
    let warnings = warnings_for(&command(
        r#"
        if exists Account[user: this.user] {
            recall failed()
        }
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn else_if_knows_earlier_conditions_were_false() {
    let warnings = warnings_for(&command(
        r#"
        if this.user == 1 {
            finish {}
        } else if exists Account[user: this.user] {
            finish { delete Account[user: this.user] }
        } else {
            finish { create Account[user: this.user]=>{balance: 0} }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn query_is_none_early_exit_proves_exists() {
    let warnings = warnings_for(&command(
        r#"
        let account = query Account[user: this.user]
        if account is None {
            recall failed()
        }
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn match_on_query_proves_each_arm() {
    let warnings = warnings_for(&command(
        r#"
        match query Account[user: this.user] {
            Some(account) => {
                finish {
                    update Account[user: this.user]=>{balance: account.balance} to {balance: 1}
                }
            }
            None => {
                finish { create Account[user: this.user]=>{balance: 0} }
            }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn impossible_branch_is_skipped() {
    // The branch can't run, so its unproven create is not reported.
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check !exists Account[user: this.user] else recall failed()
        if exists Account[user: this.user] {
            finish { create Owner[]=>{user: this.user} }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
