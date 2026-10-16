//! What a mutation leaves known: facts that provably differ from the
//! mutated one, everything after a `create`, and absence after an
//! `update` or `delete`.

use rstest::rstest;

use super::{command, init_command, warnings_for};

/// Check that two keys of `Item` are absent, then create both.
fn create_two(key_type: &str, first: &str, second: &str) -> String {
    format!(
        r#"
        enum Color {{ Red, Blue }}
        fact Item[k {key_type}]=>{{}}

        command Foo {{
            fields {{ user int }}
            policy {{
                check !exists Item[k: {first}] else test_fail()
                check !exists Item[k: {second}] else test_fail()
                finish {{
                    create Item[k: {first}]=>{{}}
                    create Item[k: {second}]=>{{}}
                }}
            }}
        }}
        "#
    )
}

#[rstest]
#[case::int("int", "1", "2")]
#[case::string("string", r#""a""#, r#""b""#)]
#[case::bool("bool", "true", "false")]
#[case::enumeration("enum Color", "Color::Red", "Color::Blue")]
fn keys_differing_by_a_literal_stay_absent(
    #[case] key_type: &str,
    #[case] first: &str,
    #[case] second: &str,
) {
    let warnings = warnings_for(&create_two(key_type, first, second));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn init_command_creates_keys_differing_by_a_literal() {
    let warnings = warnings_for(&init_command(
        r#"
        finish {
            create Account[user: 1]=>{balance: 0}
            create Account[user: 2]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn absence_of_a_prefix_survives_creating_some_of_it() {
    let warnings = warnings_for(
        r#"
        enum Color { Red, Blue }
        fact Paint[user int, color enum Color]=>{}

        command Foo {
            fields { user int }
            policy {
                check !exists Paint[user: this.user, color: ?] else test_fail()
                finish {
                    create Paint[user: this.user, color: Color::Red]=>{}
                    create Paint[user: this.user, color: Color::Blue]=>{}
                }
            }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn create_keeps_what_exists() {
    let warnings = warnings_for(&command(
        r#"
        check exists Account[user: 1] else recall failed()
        check !exists Account[user: this.user] else recall failed()
        finish {
            create Account[user: this.user]=>{balance: 0}
            delete Account[user: 1]
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn update_keeps_facts_with_other_keys() {
    let warnings = warnings_for(&command(
        r#"
        check exists Account[user: 1] else recall failed()
        check exists Account[user: 2] else recall failed()
        finish {
            update Account[user: 2] to {balance: 0}
            delete Account[user: 1]
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn delete_keeps_what_is_absent() {
    let warnings = warnings_for(&command(
        r#"
        check exists Account[user: 1] else recall failed()
        check !exists Account[user: this.user] else recall failed()
        finish {
            delete Account[user: 1]
            create Account[user: this.user]=>{balance: 0}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn create_keeps_query_results() {
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: this.user] or recall failed()
        check !exists Account[user: 1] else recall failed()
        finish {
            create Account[user: 1]=>{balance: 0}
            update Account[user: this.user]=>{balance: a.balance} to {balance: 5}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
