//! Path sensitivity, deduplication across paths, and opaque points in notes.

use super::{command, warnings_for, with_defs};

#[test]
fn check_in_one_branch_warns_on_other_path() {
    let warnings = warnings_for(&command(
        r#"
        if this.user == 1 {
            check !exists Account[user: this.user] else recall failed()
        }
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("cannot prove"));
}

#[test]
fn check_in_all_branches_passes() {
    let warnings = warnings_for(&command(
        r#"
        if this.user == 1 {
            check !exists Account[user: this.user] else recall failed()
        } else {
            check !exists Account[user: this.user] else recall failed()
        }
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn unchecked_on_several_paths_warns_once() {
    let warnings = warnings_for(&command(
        r#"
        if this.user == 1 {
            let a = 1
        } else {
            let b = 2
        }
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("cannot prove"));
}

#[test]
fn duplicate_warnings_merge_notes() {
    let warnings = warnings_for(&command(
        r#"
        if this.user == 1 {
            check !(exists Account[user: this.user] && this.user == 1) else recall failed()
        } else {
            check !(exists Account[user: this.user] && this.user == 2) else recall failed()
        }
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(warnings[0].notes.len(), 2, "notes: {:?}", warnings[0].notes);
}

#[test]
fn opaque_check_reported_in_notes() {
    let warnings = warnings_for(&command(
        r#"
        check !(exists Account[user: this.user] && this.user == 1) else recall failed()
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("cannot prove"));
    assert_eq!(warnings[0].notes.len(), 1, "notes: {:?}", warnings[0].notes);
    assert!(warnings[0].notes[0].1.contains("too complex"));
}

// --- Impossible paths.
#[test]
fn impossible_check_ends_path() {
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check !exists Account[user: this.user] else recall failed()
        check exists Account[user: this.user] else recall failed()
        finish { create Owner[]=>{user: this.user} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn policy_block_without_finish() {
    let warnings = warnings_for(&command(
        r#"
        check exists Account[user: this.user] else recall failed()
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

// --- Deduplication.
#[test]
fn duplicate_notes_are_merged() {
    let warnings = warnings_for(&command(
        r#"
        check !exists Account[user: this.user] || this.user == 1 else recall failed()
        if this.user == 2 { let a = 1 } else { let b = 2 }
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(warnings[0].notes.len(), 1, "notes: {:?}", warnings[0].notes);
}
