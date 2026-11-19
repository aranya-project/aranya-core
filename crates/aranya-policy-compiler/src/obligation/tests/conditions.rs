//! What `check` conditions prove: `&&`, `||`, `!`, and counting queries.

use super::{MEMBER, command, warnings_for, with_defs};

#[test]
fn check_and_proves_both_sides() {
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check exists Account[user: this.user] && !exists Owner[] else recall failed()
        finish {
            delete Account[user: this.user]
            create Owner[]=>{user: this.user}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn check_not_or_proves_both_absent() {
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

#[test]
fn check_or_proves_nothing_and_is_pointed_out() {
    let warnings = warnings_for(&command(
        r#"
        check !exists Account[user: this.user] || this.user == 1 else recall failed()
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .notes
            .iter()
            .any(|(_, n)| n.contains("too complex")),
        "notes: {:?}",
        warnings[0].notes
    );
}

#[test]
fn counting_queries() {
    // Counting is useful on a key prefix. That some fact matches can't
    // prove any one key, but rules out a later branch on none matching.
    // That none matches proves every key with the prefix absent. Count
    // limits must be at least 1.
    let prefix = "Member[team: this.user, device: ?]";
    let none_branch = "if !exists Member[team: this.user, device: ?] {
            finish { create Owner[]=>{user: this.user} }
        }
        finish {}";
    let create_key = "finish { create Member[team: this.user, device: 5]=>{rank: 0} }";
    let delete_key = "finish { delete Member[team: this.user, device: 5] }";
    for (check, then, expected) in [
        (format!("at_least 1 {prefix}"), none_branch, 0),
        (format!("at_least 2 {prefix}"), none_branch, 0),
        (format!("exactly 1 {prefix}"), none_branch, 0),
        (format!("!(at_most 1 {prefix})"), none_branch, 0),
        (format!("at_least 1 {prefix}"), delete_key, 1),
        (format!("at_most 1 {prefix}"), none_branch, 1),
        (format!("!(at_least 2 {prefix})"), none_branch, 1),
        (format!("!(exactly 1 {prefix})"), none_branch, 1),
        (format!("!(at_least 1 {prefix})"), create_key, 0),
        (format!("at_most 1 {prefix}"), create_key, 1),
        (format!("!(at_least 2 {prefix})"), create_key, 1),
        (format!("!(exactly 1 {prefix})"), create_key, 1),
    ] {
        let warnings = warnings_for(&with_defs(
            MEMBER,
            &format!("check {check} else recall failed()\n{then}"),
        ));
        assert_eq!(warnings.len(), expected, "{check}: {warnings:?}");
    }

    // A full key matches at most one fact, so there `at_least 1` and
    // `exactly 1` say what `exists` says.
    for check in [
        "at_least 1 Account[user: this.user]",
        "exactly 1 Account[user: this.user]",
    ] {
        let warnings = warnings_for(&command(&format!(
            "check {check} else recall failed()\n\
             finish {{ delete Account[user: this.user] }}"
        )));
        assert_eq!(warnings, vec![], "{check}");
    }
}

// `either` joins the sides of `||`: only what both imply is kept, and
// for `NotExists` the more specific pattern is implied by both.

#[test]
fn either_keeps_more_specific_absence_prefix_first() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check !exists Member[team: 1, device: ?] || !exists Member[team: 1, device: 5]
            else recall failed()
        finish { create Member[team: 1, device: 5]=>{rank: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn either_keeps_more_specific_absence_exact_first() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check !exists Member[team: 1, device: 5] || !exists Member[team: 1, device: ?]
            else recall failed()
        finish { create Member[team: 1, device: 5]=>{rank: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn either_dedups_patterns_implied_twice() {
    // Each side knows both the prefix and the exact key, so the exact
    // key is implied twice and kept once.
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check (!exists Member[team: 1, device: ?] && !exists Member[team: 1, device: 5])
            || (!exists Member[team: 1, device: ?] && !exists Member[team: 1, device: 5])
            else recall failed()
        finish { create Member[team: 1, device: 5]=>{rank: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn either_dedups_across_mixed_states() {
    // `out` holds an `Exists` entry when the `NotExists` pair is
    // compared against it.
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check (exists Account[user: 1] && !exists Owner[])
            || (exists Account[user: 1] && !exists Owner[])
            else recall failed()
        finish {
            delete Account[user: 1]
            create Owner[]=>{user: 1}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
