//! Path sensitivity, deduplication across paths, and opaque points in notes.

use std::{sync::mpsc, thread, time::Duration};

use super::{command, warnings_for, warnings_with_paths, with_defs};

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
fn merged_paths_keep_one_copy_of_each_note() {
    // The branches only bind locals, so their paths merge. Both carry the
    // note from the check before them, which must appear once.
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

#[test]
fn duplicate_notes_are_merged() {
    // The two paths know different things about `Owner`, so they stay
    // apart, and each reports the unproven create with the same note.
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check !exists Account[user: this.user] || this.user == 1 else recall failed()
        if exists Owner[] { let a = 1 } else { let b = 2 }
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(warnings[0].notes.len(), 1, "notes: {:?}", warnings[0].notes);
}

// --- Merging and joining paths.

/// A policy where the second `if` is only safe because it takes the same
/// branch as the first.
const CORRELATED: &str = r#"
    if exists Owner[] {
        check exists Account[user: 1] else recall failed()
    }
    if exists Owner[] {
        finish { delete Account[user: 1] }
    }
    finish {}
"#;

#[test]
fn distinct_paths_keep_their_correlation() {
    let warnings = warnings_for(&with_defs("", CORRELATED));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn paths_past_the_limit_are_joined() {
    // With room for one path, the two paths out of the first `if` are
    // joined, and the second `if` no longer knows which one it is on. The
    // join is reported, and the warning it causes points back at it.
    let text = with_defs("", CORRELATED);
    let warnings = warnings_with_paths(&text, 1);
    assert_eq!(warnings.len(), 2, "warnings: {warnings:?}");
    assert_eq!(
        warnings[0].message,
        "paths were joined here, dropping facts about `Owner`, `Account` that only some of them knew"
    );
    let rendered = warnings[0].render(&text);
    assert!(
        rendered.contains("help: raise the limit with `--max-paths`"),
        "{rendered}"
    );
    assert!(
        warnings[1]
            .message
            .contains("`Account[user: 1]` exists before `delete`")
    );
    assert!(
        warnings[1]
            .notes
            .iter()
            .any(|(span, n)| *span == warnings[0].span
                && n == "paths were joined here, dropping facts about `Account`"),
        "notes: {:?}",
        warnings[1].notes
    );
    assert!(
        warnings[1]
            .footnotes
            .iter()
            .any(|(_, text)| text.contains("may be a false positive")),
        "footnotes: {:?}",
        warnings[1].footnotes
    );
}

#[test]
fn joined_paths_keep_what_every_path_knows() {
    // The join drops only `Owner`, which one path didn't know about. Every
    // path knew the account exists, so the delete is still proven.
    let warnings = warnings_with_paths(
        &with_defs(
            "",
            r#"
            if this.user == 1 {
                check exists Account[user: 1] else recall failed()
                check exists Owner[] else recall failed()
            } else {
                check exists Account[user: 1] else recall failed()
            }
            finish { delete Account[user: 1] }
            "#,
        ),
        1,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(
        warnings[0].message,
        "paths were joined here, dropping facts about `Owner` that only some of them knew"
    );
}

#[test]
fn merged_paths_keep_their_correlation() {
    // Six branches that only bind locals sit between the correlated `if`s.
    // Walked separately they would make 2 * 2^6 = 128 paths, past the
    // limit, and the join would lose the correlation. Merged, they stay 2.
    let mut body =
        String::from("if exists Owner[] { check exists Account[user: 1] else recall failed() }\n");
    for i in 0..6 {
        body.push_str(&format!("if this.user == {i} {{ let x{i} = {i} }}\n"));
    }
    body.push_str("if exists Owner[] { finish { delete Account[user: 1] } }\nfinish {}\n");
    let warnings = warnings_for(&with_defs("", &body));
    assert_eq!(warnings, vec![], "expected no warnings");
}

/// Run `f` on another thread, failing if it takes longer than `secs`,
/// so a walk that blows up fails the test instead of hanging it.
#[track_caller]
fn within<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || tx.send(f()));
    rx.recv_timeout(Duration::from_secs(secs))
        .expect("the analysis took too long")
}

#[test]
fn branches_binding_only_locals_merge() {
    // Each `if` binds a local and learns nothing about facts, so its two
    // paths are the same once the local is forgotten. Walking each way
    // through them would take 2^60 paths.
    let mut body = String::new();
    for i in 0..60 {
        body.push_str(&format!("if this.user == {i} {{ let x{i} = {i} }}\n"));
    }
    body.push_str("finish { create Account[user: this.user]=>{balance: 0} }\n");
    let warnings = within(30, move || warnings_for(&command(&body)));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn branches_on_facts_stay_bounded() {
    // Each `if` splits the paths on a different fact, so they never
    // merge. Past the path limit they are joined, and each join is
    // reported.
    let mut body = String::new();
    for i in 0..40 {
        body.push_str(&format!(
            "if exists Account[user: {i}] {{ let x{i} = {i} }}\n"
        ));
    }
    body.push_str("finish { create Owner[]=>{user: this.user} }\n");
    let warnings = within(30, move || warnings_for(&with_defs("", &body)));
    let (joins, others): (Vec<_>, Vec<_>) = warnings
        .iter()
        .partition(|w| w.message.starts_with("paths were joined here"));
    assert!(!joins.is_empty(), "warnings: {warnings:?}");
    assert_eq!(others.len(), 1, "warnings: {warnings:?}");
    assert!(others[0].message.contains("`Owner[]` does not exist"));
}

/// A helper whose `if` splits its paths on `Owner`, and a command that
/// calls it.
const HELPER_WITH_BRANCH: &str = r#"
    function f(u int) bool {
        if exists Owner[] {
            check exists Account[user: u] else return false
        }
        return true
    }
"#;

#[test]
fn joins_inside_helpers_are_reported() {
    let warnings = warnings_with_paths(
        &with_defs(
            HELPER_WITH_BRANCH,
            "check f(this.user) else recall failed()\nfinish {}",
        ),
        1,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(
        warnings[0].message,
        "paths were joined here, dropping facts about `Owner`, `Account` that only some of them knew"
    );
}

#[test]
fn helpers_within_the_limit_report_no_join() {
    let warnings = warnings_for(&with_defs(
        HELPER_WITH_BRANCH,
        "check f(this.user) else recall failed()\nfinish {}",
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
