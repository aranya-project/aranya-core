//! What `check` conditions prove: `&&`, `||`, `!`, and counting queries.

use super::{command, warnings_for, with_defs};

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
    // Count limits must be at least 1.
    let create = "create Account[user: this.user]=>{balance: 0}";
    let delete = "delete Account[user: this.user]";
    for (check, mutation, expected) in [
        ("at_least 1 Account[user: this.user]", delete, 0),
        ("exactly 1 Account[user: this.user]", delete, 0),
        ("at_least 2 Account[user: this.user]", delete, 0),
        ("!(at_least 1 Account[user: this.user])", create, 0),
        ("!(at_most 1 Account[user: this.user])", delete, 0),
        ("at_most 1 Account[user: this.user]", create, 1),
        ("at_least 2 Account[user: this.user]", create, 1),
    ] {
        let warnings = warnings_for(&command(&format!(
            "check {check} else recall failed()\n\
             finish {{ {mutation} }}"
        )));
        assert_eq!(warnings.len(), expected, "{check}: {warnings:?}");
    }
}
