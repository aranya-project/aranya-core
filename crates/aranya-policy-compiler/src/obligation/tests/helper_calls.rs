//! A helper's facts wherever its call always runs: compared, bound by
//! `let`, passed to another call, in a key, a struct, or a `match`
//! scrutinee, and through helpers that call helpers.

use rstest::rstest;

use super::{warnings_for, with_defs};

/// Helpers that only return if `Account[user: u]` exists.
const BALANCE_OF: &str = r#"
    struct Pair { a int, b int }
    fact Other[k int]=>{v int}

    function balance_of(u int) int {
        let a = query Account[user: u] or test_fail()
        return a.balance
    }

    function account_of(u int) struct Account {
        return query Account[user: u] or test_fail()
    }

    function is_positive(n int) bool {
        return n > 0
    }

    function has_balance(u int) bool {
        return balance_of(u) > 0
    }

    function can_spend(u int, n int) bool {
        let b = balance_of(u)
        if b < n {
            return false
        }
        return true
    }
"#;

#[rstest]
#[case::compared("check balance_of(this.user) > 0 else recall failed()")]
#[case::bound_by_let("let b = balance_of(this.user)")]
#[case::argument("check is_positive(balance_of(this.user)) else recall failed()")]
#[case::fact_key("check exists Other[k: balance_of(this.user)] else recall failed()")]
#[case::struct_field("let p = Pair { a: balance_of(this.user), b: 1 }")]
#[case::returned_from_or("let a = account_of(this.user)")]
#[case::through_helpers("check can_spend(this.user, 5) else recall failed()")]
#[case::in_a_returned_value("let ok = has_balance(this.user)")]
#[case::left_of_and("if balance_of(this.user) > 5 && this.user > 1 { recall failed() }")]
#[case::left_of_or_else("let n = Some(balance_of(this.user)) or 0")]
fn helper_call_proves_its_facts(#[case] uses: &str) {
    let warnings = warnings_for(&with_defs(
        BALANCE_OF,
        &format!(
            r#"
            {uses}
            finish {{ delete Account[user: this.user] }}
            "#
        ),
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_in_a_match_scrutinee_proves_its_facts() {
    let warnings = warnings_for(&with_defs(
        BALANCE_OF,
        r#"
        match balance_of(this.user) {
            0 => { recall failed() }
            _ => {
                finish { delete Account[user: this.user] }
            }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_on_the_left_of_or_proves_its_facts_where_true() {
    let warnings = warnings_for(&with_defs(
        BALANCE_OF,
        r#"
        if balance_of(this.user) > 5 || this.user > 1 {
            finish { delete Account[user: this.user] }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn exit_whose_value_cannot_be_computed_is_not_an_exit() {
    // The last `return` needs the account the `check` proved absent, so
    // `f` only returns through the `else`, where the account exists.
    let warnings = warnings_for(&with_defs(
        &format!(
            r#"
            {BALANCE_OF}

            function f(u int) int {{
                check !exists Account[user: u] else return 0
                return balance_of(u)
            }}
            "#
        ),
        r#"
        let n = f(this.user)
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
