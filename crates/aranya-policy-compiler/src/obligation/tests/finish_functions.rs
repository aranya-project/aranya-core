//! Mutations inside finish functions, checked at each call.

use super::warnings_for;

/// A policy with a finish function that creates an `Account`.
fn with_open_function(policy_block: &str) -> String {
    format!(
        r#"
        fact Account[user int]=>{{balance int}}

        finish function open_account(u int) {{
            create Account[user: u]=>{{balance: 0}}
        }}

        command Foo {{
            fields {{ user int }}
            policy {{
                {policy_block}
            }}
            recall failed() {{ finish {{}} }}
        }}
        "#
    )
}

#[test]
fn finish_function_create_checked_by_caller_passes() {
    let warnings = warnings_for(&with_open_function(
        r#"
        check !exists Account[user: this.user] else recall failed()
        finish {
            open_account(this.user)
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn finish_function_create_unchecked_warns_with_call_note() {
    let warnings = warnings_for(&with_open_function(
        r#"
        finish {
            open_account(this.user)
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(
        warnings[0].message,
        "cannot prove `Account[user: u]` does not exist before `create`"
    );
    assert!(
        warnings[0]
            .notes
            .iter()
            .any(|(_, n)| n == "`Foo` calls `open_account` here"),
        "notes: {:?}",
        warnings[0].notes
    );
}

#[test]
fn finish_function_checked_for_other_key_warns() {
    let warnings = warnings_for(&with_open_function(
        r#"
        check !exists Account[user: this.user] else recall failed()
        finish {
            open_account(1)
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .message
            .contains("`Account[user: u]` does not exist")
    );
}

#[test]
fn finish_function_double_manipulation_across_call() {
    let warnings = warnings_for(&with_open_function(
        r#"
        check !exists Account[user: this.user] else recall failed()
        finish {
            create Account[user: this.user]=>{balance: 1}
            open_account(this.user)
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("more than once"));
}

#[test]
fn nested_finish_functions_are_followed() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        finish function open_inner(u int) {
            create Account[user: u]=>{balance: 0}
        }

        finish function open_outer(v int) {
            open_inner(v)
        }

        command Foo {
            fields { user int }
            policy {
                check !exists Account[user: this.user] else recall failed()
                finish {
                    open_outer(this.user)
                }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn shared_finish_function_warns_once_with_each_call() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        finish function open_account(u int) {
            create Account[user: u]=>{balance: 0}
        }

        command Foo {
            fields { user int }
            policy {
                finish { open_account(this.user) }
            }
        }

        command Bar {
            fields { user int }
            policy {
                finish { open_account(this.user) }
            }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    let calls: Vec<&str> = warnings[0].notes.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(
        calls,
        [
            "`Foo` calls `open_account` here",
            "`Bar` calls `open_account` here"
        ]
    );
}

#[test]
fn finish_function_update_uses_caller_query() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        finish function set_balance(u int, old int, new int) {
            update Account[user: u]=>{balance: old} to {balance: new}
        }

        command Foo {
            fields { user int }
            policy {
                let account = query Account[user: this.user] or recall failed()
                finish {
                    set_balance(this.user, account.balance, 5)
                }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn recursive_finish_function_warns() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        finish function ping(u int) {
            pong(u)
        }

        finish function pong(u int) {
            create Account[user: u]=>{balance: 0}
            ping(u)
        }

        command Foo {
            fields { user int }
            policy {
                check !exists Account[user: this.user] else recall failed()
                finish { ping(this.user) }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert_eq!(
        warnings[0].message,
        "cannot check fact mutations through recursive call to `ping`"
    );
}

#[test]
fn call_notes_name_each_caller() {
    // Innermost first, so the chain reads from the mutation back to the
    // command.
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        finish function open_account(u int) {
            create Account[user: u]=>{balance: 0}
        }

        finish function welcome(u int) {
            open_account(u)
        }

        command Foo {
            fields { user int }
            policy {
                finish { welcome(this.user) }
            }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    let notes: Vec<&str> = warnings[0].notes.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(
        notes,
        [
            "`welcome` calls `open_account` here",
            "`Foo` calls `welcome` here"
        ]
    );
}

#[test]
fn shared_finish_function_keeps_each_callers_footnotes() {
    // From `Foo`, a check would fix the delete. From `Init`, it always
    // fails. The merged warning says both, says which command the second
    // is about, and puts its notes before its help.
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        finish function close(u int) {
            delete Account[user: u]
        }

        command Foo {
            fields { user int }
            policy {
                finish { close(this.user) }
            }
        }

        command Init {
            attributes { init: true }
            fields { user int }
            policy {
                finish { close(this.user) }
            }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    let footnotes: Vec<&str> = warnings[0]
        .footnotes
        .iter()
        .map(|(_, text)| text.as_str())
        .collect();
    assert_eq!(
        footnotes,
        [
            "deleting a fact that does not exist is a runtime exception",
            "no facts exist when the `init` command `Init` runs, so this always fails in it",
            "check that it exists first: `check exists Account[user: u] else ...`",
        ]
    );
}
