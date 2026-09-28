//! Guards for what the analysis assumes the compiler enforces. Each
//! asserts that the compiler rejects, or accepts, a form the analysis
//! depends on, so a language change fails here instead of silently
//! unsounding the analysis.

use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;

use super::{MEMBER, command, with_defs};
use crate::Compiler;

/// Does the policy parse and compile?
fn compiles(text: &str) -> bool {
    let Ok(policy) = parse_policy_str(text, Version::V2) else {
        return false;
    };
    Compiler::new(&policy)
        .debug(true)
        .allow_baseless(true)
        .analyze_obligations(true)
        .compile_with_diagnostics()
        .is_ok()
}

#[test]
fn shadowing_an_enclosing_local_is_rejected() {
    // `forget_name` relies on a `let` never mentioning its own name.
    assert!(!compiles(&command(
        r#"
        let x = 1
        if this.user == 1 { let x = 2 }
        finish {}
        "#,
    )));
}

#[test]
fn shadowing_a_global_is_rejected() {
    assert!(!compiles(&with_defs(
        "let g = 1",
        r#"
        let g = 2
        finish {}
        "#,
    )));
}

#[test]
fn bind_marker_before_a_concrete_key_is_rejected() {
    // Fact keys are always a schema-order prefix of the definition.
    assert!(!compiles(&with_defs(
        MEMBER,
        r#"
        check exists Member[team: ?, device: 1] else recall failed()
        finish {}
        "#,
    )));
}

#[test]
fn function_call_in_finish_expression_is_rejected() {
    // Pure calls compare equal in keys because fact state can't change
    // between them; a call after a mutation would break that.
    assert!(!compiles(&with_defs(
        "function one() int { return 1 }",
        r#"
        finish { create Account[user: one()]=>{balance: 0} }
        "#,
    )));
}

#[test]
fn query_in_finish_expression_is_rejected() {
    assert!(!compiles(&command(
        r#"
        finish { create Account[user: 1]=>{balance: unwrap query Account[user: 2]} }
        "#,
    )));
}

#[test]
fn map_is_rejected_in_policy_blocks() {
    // So no attack on `map` can be written for a command, and the
    // walker's `map` arm is only reachable from actions.
    assert!(!compiles(&with_defs(
        MEMBER,
        r#"
        map Member[team: 1, device: ?] as m { let x = 1 }
        finish {}
        "#,
    )));
}

#[test]
fn mixed_some_and_none_arm_is_accepted() {
    // So the mixed-arm warning test stays meaningful.
    assert!(compiles(&command(
        r#"
        match query Account[user: this.user] {
            Some(a) | None => { finish {} }
        }
        "#,
    )));
}

#[test]
fn binding_and_literal_in_one_arm_is_rejected() {
    assert!(!compiles(&command(
        r#"
        match query Account[user: this.user] {
            Some(a) | Some(Account{user: 1, balance: 1}) => { finish {} }
            None => { finish {} }
        }
        "#,
    )));
}

#[test]
fn recursion_is_accepted() {
    // The recursion guards exist because the compiler does not reject
    // this yet (#607, #751).
    assert!(compiles(&with_defs(
        "function f(u int) bool { return f(u) }",
        r#"
        check f(this.user) else recall failed()
        finish {}
        "#,
    )));
}
