//! Expressing a helper's exit in the caller's terms. A fact or return
//! value that mentions one of the helper's locals is dropped, in every
//! position an `if`, `match`, or block can hold one, since a caller
//! variable of the same name holds something else. Names bound by the
//! block or arm itself are allowed.

use super::{warnings_for, with_defs};

#[test]
fn helper_locals_are_not_confused_with_caller_names() {
    // Both the helper and the command have a variable named `account`,
    // holding different facts. The helper's `Link[user: account.balance]`
    // must not prove the command's.
    let warnings = warnings_for(&with_defs(
        r#"
        fact Link[user int]=>{}

        function linked() bool {
            let account = query Account[user: 1] or return false
            return exists Link[user: account.balance]
        }
        "#,
        r#"
        let account = query Account[user: this.user] or recall failed()
        check linked() else recall failed()
        finish { delete Link[user: account.balance] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("exists before `delete`"));
}

// The tests below pin a conservative choice. The local appears only in
// a condition, scrutinee, or statement, where keeping the exit would be
// sound, but the rewriter rejects any mention it can't express. A more
// precise rewriter would make these pass without warnings.

#[test]
fn helper_if_condition_mentioning_local_is_dropped() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let n = if true { : 1 } else { : 2 }
            return if n == 1 { : exists Account[user: u] } else { : exists Account[user: u] }
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn local_in_both_arms_is_not_the_callers() {
    // The helper's `n` and the caller's `n` are different values. If the
    // exit leaked, `Exists Account[user: n]` would prove the delete.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let n = if u == 1 { : 1 } else { : 2 }
            return if u == 1 { : exists Account[user: n] } else { : exists Account[user: n] }
        }
        "#,
        r#"
        let n = if this.user == 1 { : 3 } else { : 4 }
        check f(this.user) else recall failed()
        finish { delete Account[user: n] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .message
            .contains("`Account[user: n]` exists before `delete`")
    );
}

#[test]
fn local_in_block_statement_is_not_the_callers() {
    // `z` is block-bound and allowed, but its value is the helper's `n`.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let n = if u == 1 { : 1 } else { : 2 }
            return if u == 1 {
                let z = n
                : exists Account[user: z]
            } else {
                let z = n
                : exists Account[user: z]
            }
        }
        "#,
        r#"
        let n = if this.user == 1 { : 3 } else { : 4 }
        check f(this.user) else recall failed()
        finish { delete Account[user: n] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .message
            .contains("`Account[user: n]` exists before `delete`")
    );
}

#[test]
fn helper_match_scrutinee_mentioning_local_is_dropped() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let n = if true { : 1 } else { : 2 }
            return match n {
                1 => exists Account[user: u]
                _ => exists Account[user: u]
            }
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn helper_block_check_mentioning_local_is_dropped() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let n = if true { : 1 } else { : 2 }
            return if u == 1 {
                check n == 1 else return false
                : exists Account[user: u]
            } else {
                : exists Account[user: u]
            }
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn helper_block_if_statement_mentioning_local_is_dropped() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let n = if true { : 1 } else { : 2 }
            return if u == 1 {
                if n == 1 { let z = 1 } else { let z = 2 }
                : exists Account[user: u]
            } else {
                : exists Account[user: u]
            }
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn helper_block_if_body_mentioning_local_is_dropped() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let n = if true { : 1 } else { : 2 }
            return if u == 1 {
                if u == 2 { let z = n } else { let z = 2 }
                : exists Account[user: u]
            } else {
                : exists Account[user: u]
            }
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn helper_block_match_statement_mentioning_local_is_dropped() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let n = if true { : 1 } else { : 2 }
            return if u == 1 {
                match n { 1 => { let z = 1 } _ => { let z = 2 } }
                : exists Account[user: u]
            } else {
                : exists Account[user: u]
            }
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn rewriter_accepts_every_form() {
    // Struct literals with and without composition, in the caller and
    // through a helper's exit, and a finish block inside a block
    // expression. None of these can change a proof: the walk resolves
    // finish statements itself, and a struct literal never matches a
    // key. The test shows the rewriter accepts them.
    let warnings = warnings_for(&with_defs(
        r#"
        function mk(u int) option[struct Account] {
            return Some(Account { user: u, balance: 0 })
        }
        function grow(a struct Account) option[struct Account] {
            return Some(Account { balance: 1, ...a })
        }
        "#,
        r#"
        let s = Account { user: this.user, balance: 0 }
        let a = mk(this.user) or recall failed()
        let b = grow(a) or recall failed()
        let q = query Account[user: this.user] or recall failed()
        let x = if this.user == 1 {
            finish { update Account[user: this.user]=>{balance: q.balance} to {balance: 1} }
            : 1
        } else {
            finish { delete Account[user: this.user] }
            : 2
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
