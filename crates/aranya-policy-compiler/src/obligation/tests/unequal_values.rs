//! Values known to differ: a checked `!=`, or `==` failing, keeps two
//! keys apart, so a mutation of one leaves what is known about the other.

use rstest::rstest;

use super::warnings_for;

/// A command with fields `x` and `y` that runs `proof`, then `finish`.
fn two_keys(proof: &str, finish: &str) -> String {
    format!(
        r#"
        fact Item[k int]=>{{}}

        function differ(a int, b int) bool {{
            return a != b
        }}

        command Foo {{
            fields {{ x int, y int }}
            policy {{
                {proof}
                finish {{ {finish} }}
            }}
            recall failed() {{ finish {{}} }}
        }}
        "#
    )
}

/// Both items are absent, then both are created.
const CREATE_BOTH: &str = "create Item[k: this.x]=>{}
                           create Item[k: this.y]=>{}";

/// Both items exist, then both are deleted.
const DELETE_BOTH: &str = "delete Item[k: this.x]
                           delete Item[k: this.y]";

#[rstest]
#[case::checked_unequal("check this.x != this.y else recall failed()")]
#[case::equal_failing("if this.x == this.y { recall failed() }")]
#[case::negated_equal("check !(this.x == this.y) else recall failed()")]
#[case::reversed("check this.y != this.x else recall failed()")]
#[case::through_a_helper("check differ(this.x, this.y) else recall failed()")]
fn keys_known_to_differ_both_create(#[case] differ: &str) {
    let warnings = warnings_for(&two_keys(
        &format!(
            "check !exists Item[k: this.x] else recall failed()
             check !exists Item[k: this.y] else recall failed()
             {differ}"
        ),
        CREATE_BOTH,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn keys_known_to_differ_both_delete() {
    let warnings = warnings_for(&two_keys(
        "check exists Item[k: this.x] else recall failed()
         check exists Item[k: this.y] else recall failed()
         check this.x != this.y else recall failed()",
        DELETE_BOTH,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn init_command_creates_keys_known_to_differ() {
    let warnings = warnings_for(
        r#"
        fact Item[k int]=>{}

        command Init {
            attributes { init: true }
            fields { x int, y int }
            policy {
                check this.x != this.y else test_fail()
                finish {
                    create Item[k: this.x]=>{}
                    create Item[k: this.y]=>{}
                }
            }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn value_unequal_to_itself_is_impossible() {
    // Nothing after the check can run, so nothing is reported.
    let warnings = warnings_for(&two_keys(
        "check this.x != this.x else recall failed()",
        "delete Item[k: this.x]",
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
