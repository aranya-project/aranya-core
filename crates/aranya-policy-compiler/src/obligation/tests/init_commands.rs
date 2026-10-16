//! Init commands, which start with no facts.

use super::{init_command, warnings_for};

#[test]
fn init_command_create_passes() {
    let warnings = warnings_for(&init_command(
        r#"
        finish {
            create Account[user: this.user]=>{balance: 0}
            create Owner[]=>{user: this.user}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn init_command_double_create_warns() {
    let warnings = warnings_for(&init_command(
        r#"
        finish {
            create Account[user: this.user]=>{balance: 0}
            create Account[user: this.user]=>{balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("more than once"));
}

#[test]
fn init_false_is_not_init() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        command Foo {
            attributes { init: false }
            fields { user int }
            policy {
                finish {
                    create Account[user: this.user]=>{balance: 0}
                }
            }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn init_command_update_always_fails() {
    let warnings = warnings_for(&init_command(
        r#"
        finish {
            update Account[user: this.user] to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .footnotes
            .iter()
            .any(|(_, text)| text.contains("always fails")),
        "warnings: {warnings:?}"
    );
}
