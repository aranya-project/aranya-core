//! Values known equal: after `x == y` holds, a fact keyed by one is the
//! fact keyed by the other, as after `let x = y`.

use rstest::rstest;

use super::warnings_for;

/// A command with fields `x`, `y`, `z`, and `k` that runs `proof`, then
/// `finish`.
fn command_with(proof: &str, finish: &str) -> String {
    format!(
        r#"
        enum Color {{ Red, Blue }}
        fact Item[k int]=>{{v int}}
        fact Paint[c enum Color]=>{{}}

        function equal(a int, b int) bool {{
            return a == b
        }}

        function twice(a int) int {{
            return a
        }}

        command Foo {{
            fields {{ x int, y int, z int, k int, color enum Color }}
            policy {{
                {proof}
                finish {{ {finish} }}
            }}
            recall failed() {{ finish {{}} }}
        }}
        "#
    )
}

#[track_caller]
fn assert_proven(proof: &str, finish: &str) {
    let warnings = warnings_for(&command_with(proof, finish));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[rstest]
#[case::checked("check this.x == this.y else recall failed()")]
#[case::reversed("check this.y == this.x else recall failed()")]
#[case::not_unequal("check !(this.x != this.y) else recall failed()")]
#[case::unequal_failing("if this.x != this.y { recall failed() }")]
#[case::through_a_helper("check equal(this.x, this.y) else recall failed()")]
#[case::through_another_value(
    "check this.x == this.z else recall failed()
     check this.z == this.y else recall failed()"
)]
fn fact_keyed_by_an_equal_value_passes(#[case] equal: &str) {
    assert_proven(
        &format!(
            "check exists Item[k: this.x] else recall failed()
             {equal}"
        ),
        "delete Item[k: this.y]",
    );
}

#[test]
fn equality_before_the_fact_passes() {
    assert_proven(
        "check this.x == this.y else recall failed()
         check exists Item[k: this.x] else recall failed()",
        "delete Item[k: this.y]",
    );
}

#[test]
fn reference_read_from_a_fact_passes() {
    // `assignment.role_id` and `this.y` name the same role.
    let warnings = warnings_for(
        r#"
        fact AssignedRole[device_id int]=>{role_id int}
        fact RoleIndex[role_id int, device_id int]=>{}

        command Revoke {
            fields { x int, y int }
            policy {
                let assignment = query AssignedRole[device_id: this.x] or recall failed()
                check assignment.role_id == this.y else recall failed()
                check exists RoleIndex[role_id: this.y, device_id: this.x] else recall failed()
                finish {
                    delete AssignedRole[device_id: this.x]
                    delete RoleIndex[role_id: assignment.role_id, device_id: this.x]
                }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn self_branch_passes() {
    // What is known about the author is known about the target.
    let warnings = warnings_for(
        r#"
        fact Rank[object_id int]=>{rank int}

        function rank_of(obj int) int {
            let r = query Rank[object_id: obj] or test_fail()
            return r.rank
        }

        command Lower {
            fields { author int, target int, new_rank int }
            policy {
                let author_rank = rank_of(this.author)
                if this.author == this.target {
                    finish {
                        update Rank[object_id: this.target]=>{rank: author_rank} to {rank: this.new_rank}
                    }
                }
                finish {}
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[rstest]
#[case::literal_on_the_right("check this.k == 1 else recall failed()")]
#[case::literal_on_the_left("check 1 == this.k else recall failed()")]
fn literal_equality_tells_keys_apart(#[case] equal: &str) {
    assert_proven(
        &format!(
            "check !exists Item[k: this.k] else recall failed()
             check !exists Item[k: 2] else recall failed()
             {equal}"
        ),
        "create Item[k: this.k]=>{v: 0}
         create Item[k: 2]=>{v: 0}",
    );
}

#[test]
fn match_arm_on_a_literal_passes() {
    let warnings = warnings_for(&command_with(
        "check !exists Paint[c: this.color] else recall failed()
         check !exists Paint[c: Color::Blue] else recall failed()
         match this.color {
             Color::Red => {
                 finish {
                     create Paint[c: this.color]=>{}
                     create Paint[c: Color::Blue]=>{}
                 }
             }
             _ => { finish {} }
         }",
        "",
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn match_default_arm_knows_the_value_differs() {
    let warnings = warnings_for(&command_with(
        "check !exists Item[k: this.k] else recall failed()
         check !exists Item[k: 1] else recall failed()
         match this.k {
             1 => { recall failed() }
             _ => {
                 finish {
                     create Item[k: this.k]=>{v: 0}
                     create Item[k: 1]=>{v: 0}
                 }
             }
         }",
        "",
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn equal_keys_manipulated_twice_are_reported_as_such() {
    let warnings = warnings_for(&command_with(
        "check exists Item[k: this.x] else recall failed()
         check this.x == this.y else recall failed()",
        "update Item[k: this.x] to {v: 1}
         update Item[k: this.y] to {v: 2}",
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("more than once"));
}

#[test]
fn equality_with_a_term_containing_the_value_passes() {
    // `this.x` is kept. Writing it as `twice(this.x)` would write the fact
    // below as `twice(twice(this.x))`, and nothing would match it.
    assert_proven(
        "check exists Item[k: twice(this.x)] else recall failed()
         check this.x == twice(this.x) else recall failed()",
        "delete Item[k: this.x]",
    );
}

/// Each of these can't hold, so nothing after it runs and the delete,
/// unproven otherwise, is not reported.
#[rstest]
#[case::facts_disagree(
    "check exists Item[k: this.x] else recall failed()
     check !exists Item[k: this.y] else recall failed()
     check this.x == this.y else recall failed()"
)]
#[case::known_to_differ(
    "check this.x != this.y else recall failed()
     check this.x == this.y else recall failed()"
)]
#[case::then_unequal(
    "check this.x == this.y else recall failed()
     check this.x != this.y else recall failed()"
)]
#[case::two_literals(
    "check this.x == 1 else recall failed()
     check this.x == 2 else recall failed()"
)]
#[case::calls_known_to_differ(
    "check twice(this.x) != twice(this.y) else recall failed()
     check this.x == this.y else recall failed()"
)]
fn impossible_equality(#[case] proof: &str) {
    assert_proven(proof, "delete Item[k: 7]");
}

#[test]
fn value_equal_to_itself_changes_nothing() {
    let warnings = warnings_for(&command_with(
        "check this.x == this.x else recall failed()",
        "delete Item[k: 7]",
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
}
