//! Guards for what the analysis assumes the compiler enforces. Each
//! asserts that the compiler rejects, or accepts, a form the analysis
//! depends on, so a language change fails here instead of silently
//! unsounding the analysis.

use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::{Instruction, Meta, ModuleData, ModuleV0};

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
fn finish_inside_a_block_expression_exits() {
    // `block_ends` relies on a `finish` ending its path, even when the
    // finish sits inside a block expression whose value is still
    // pending: every finish block is followed by an `Exit`. The three
    // are the one in the block, the one after the `let`, and the
    // recall block's.
    let policy = parse_policy_str(
        &command(
            r#"
            let x = if this.user == 1 {
                finish { create Account[user: this.user]=>{balance: 0} }
                : 1
            } else {
                : 2
            }
            finish {}
            "#,
        ),
        Version::V2,
    )
    .expect("parse");
    let module = Compiler::new(&policy)
        .debug(true)
        .allow_baseless(true)
        .compile()
        .expect("compile");
    let m: ModuleV0 = match module.data {
        ModuleData::V0(m) => m,
        ModuleData::V1(m) => m.into(),
    };
    let progmem = m.progmem;
    let finishes: Vec<usize> = progmem
        .iter()
        .enumerate()
        .filter(|(_, i)| matches!(i, Instruction::Meta(Meta::Finish(true))))
        .map(|(n, _)| n)
        .collect();
    assert_eq!(finishes.len(), 3, "finish blocks: {finishes:?}");
    for (n, start) in finishes.iter().enumerate() {
        let end = finishes
            .get(n.wrapping_add(1))
            .copied()
            .unwrap_or(progmem.len());
        let exits = progmem[*start..end]
            .iter()
            .any(|i| matches!(i, Instruction::Exit(_)));
        assert!(exits, "no exit after the finish at {start}");
    }
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
