//! Tests that reach rules the feature and attack tests don't: rarer
//! forms of the language, impossible paths, and visitor corners.

use super::{MEMBER, command, warnings_for, with_defs};

// --- `either`, which joins the sides of `||`: the more specific
// `NotExists` pattern is implied by both.

#[test]
fn either_keeps_more_specific_absence_prefix_first() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check !exists Member[team: 1, device: ?] || !exists Member[team: 1, device: 5]
            else recall failed()
        finish { create Member[team: 1, device: 5]=>{rank: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn either_keeps_more_specific_absence_exact_first() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check !exists Member[team: 1, device: 5] || !exists Member[team: 1, device: ?]
            else recall failed()
        finish { create Member[team: 1, device: 5]=>{rank: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn either_dedups_patterns_implied_twice() {
    // Each side knows both the prefix and the exact key, so the exact
    // key is implied twice and kept once.
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check (!exists Member[team: 1, device: ?] && !exists Member[team: 1, device: 5])
            || (!exists Member[team: 1, device: ?] && !exists Member[team: 1, device: 5])
            else recall failed()
        finish { create Member[team: 1, device: 5]=>{rank: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn either_dedups_across_mixed_states() {
    // `out` holds an `Exists` entry when the `NotExists` pair is
    // compared against it.
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check (exists Account[user: 1] && !exists Owner[])
            || (exists Account[user: 1] && !exists Owner[])
            else recall failed()
        finish {
            delete Account[user: 1]
            create Owner[]=>{user: 1}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
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
fn impossible_if_fallthrough_is_skipped() {
    let warnings = warnings_for(&command(
        r#"
        check exists Account[user: this.user] else recall failed()
        if exists Account[user: this.user] {
            finish {}
        }
        finish { create Account[user: this.user]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn impossible_match_arm_is_skipped() {
    let warnings = warnings_for(&with_defs(
        "",
        r#"
        check exists Account[user: this.user] else recall failed()
        match query Account[user: this.user] {
            None => { finish { create Owner[]=>{user: this.user} } }
            Some(a) => { finish {} }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn impossible_check_exit_in_helper_is_not_recorded() {
    // The second check's failure contradicts the first, so its
    // `return true` exit can't weaken the call.
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Account[user: u] else return false
            check exists Account[user: u] else return true
            return true
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn impossible_or_return_exit_in_helper_is_not_recorded() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Account[user: u] else return false
            let a = query Account[user: u] or return true
            return true
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
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
fn duplicate_notes_are_merged() {
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

// --- Helpers.

#[test]
fn mutual_recursion_through_checks_terminates() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check g(u) else return false
            return true
        }
        function g(u int) bool {
            check f(u) else return false
            return true
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
}

#[test]
fn mutual_recursion_through_query_helpers_terminates() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) option[struct Account] { return g(u) }
        function g(u int) option[struct Account] { return f(u) }
        "#,
        r#"
        let a = f(this.user) or recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
}

#[test]
fn helper_exits_returning_same_query_bind() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}

        function find(t int) option[struct Member] {
            if t == 1 {
                return query Member[team: t, device: ?]
            }
            return query Member[team: t, device: ?]
        }
        "#,
        r#"
        let m = find(this.user) or recall failed()
        finish { delete Member[team: this.user, device: m.device] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn unknown_call_notes_facts_in_if_without_else() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            if u == 1 {
                return f(u)
            }
            if u == 2 {
                return f(u)
            } else {
                let z = exists Owner[]
            }
            return exists Account[user: u]
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0]
            .notes
            .iter()
            .any(|(_, n)| n.contains("too complex"))
    );
}

#[test]
fn helper_check_else_test_fail_is_not_an_exit() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            check exists Account[user: u] else test_fail("gone")
            let a = query Account[user: u] or test_fail("gone")
            return true
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_arm_test_fail_is_not_an_exit() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let x = match u {
                1 => 1
                _ => test_fail("no")
            }
            return exists Account[user: u]
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

// --- Strict substitution failing inside `if`, `match`, and blocks.

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
}

#[test]
fn helper_if_arm_mentioning_local_is_dropped() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let n = if true { : 1 } else { : 2 }
            return if u == 1 { : exists Account[user: n] } else { : exists Account[user: u] }
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
}

#[test]
fn helper_block_statement_mentioning_local_is_dropped() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let n = if true { : 1 } else { : 2 }
            return if u == 1 {
                let z = n
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
}

#[test]
fn helper_returning_struct_literal_is_followed() {
    let warnings = warnings_for(&with_defs(
        r#"
        function mk(u int) struct Account {
            return Account { user: u, balance: 0 }
        }
        "#,
        r#"
        let a = mk(this.user)
        check exists Account[user: a.user] else recall failed()
        finish { delete Account[user: a.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn struct_literals_are_rewritten() {
    // Unsubstituted in the caller, and substituted through a helper's
    // exit, with and without composition.
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
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_returning_composed_struct_is_opaque() {
    let warnings = warnings_for(&with_defs(
        r#"
        function mk(a struct Account) struct Account {
            return Account { balance: 1, ...a }
        }
        "#,
        r#"
        let a = query Account[user: this.user] or recall failed()
        let b = mk(a)
        check exists Account[user: b.user] else recall failed()
        finish { delete Account[user: b.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

// --- Match arm shapes.

#[test]
fn some_literal_and_ok_literal_arms() {
    let warnings = warnings_for(&with_defs(
        r#"
        function maybe(u int) option[int] { return Some(u) }
        function lookup(u int) result[int, int] { return Ok(u) }
        "#,
        r#"
        match maybe(this.user) {
            Some(1) => { let a = 1 }
            Some(x) => { let a = x }
            None => { recall failed() }
        }
        match lookup(this.user) {
            Ok(1) => { let b = 1 }
            Ok(y) => { let b = y }
            Err(0) => { recall failed() }
            Err(e) => { recall failed() }
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn match_expression_is_none_condition() {
    let warnings = warnings_for(&command(
        r#"
        check match this.user {
            1 => query Account[user: 1]
            _ => query Account[user: 1]
        } is None else recall failed()
        finish { create Account[user: 1]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn match_let_with_mixed_arm_does_not_bind() {
    let warnings = warnings_for(&command(
        r#"
        let other = query Account[user: 0] or recall failed()
        let a = match query Account[user: this.user] {
            Some(x) | None => other
        }
        finish { update Account[user: 0]=>{balance: a.balance} to {balance: 1} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

#[test]
fn match_let_with_none_arm_value_does_not_bind() {
    let warnings = warnings_for(&command(
        r#"
        let other = query Account[user: 0] or recall failed()
        let a = match query Account[user: this.user] {
            Some(x) => x
            None => other
        }
        finish { update Account[user: 0]=>{balance: a.balance} to {balance: 1} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

// --- Update values.

#[test]
fn update_value_from_other_field_warns() {
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: this.user] or recall failed()
        finish { update Account[user: this.user]=>{balance: a.user} to {balance: 1} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

#[test]
fn update_value_from_nested_field_warns() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}
        struct Inner { balance int }

        command Foo {
            fields { user int, inner struct Inner }
            policy {
                check exists Account[user: this.user] else recall failed()
                finish {
                    update Account[user: this.user]=>{balance: this.inner.balance} to {balance: 1}
                }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("stated values"));
}

// --- Key matching forms.

#[test]
fn enum_keys_match_by_value() {
    let warnings = warnings_for(
        r#"
        enum Role { Admin, Member }
        fact Grant[role enum Role]=>{v int}

        command Foo {
            fields { user int }
            policy {
                check !exists Grant[role: Role::Admin] else recall failed()
                finish { create Grant[role: Role::Admin]=>{v: 0} }
            }
            recall failed() { finish {} }
        }

        command Bar {
            fields { user int }
            policy {
                check !exists Grant[role: Role::Admin] else recall failed()
                finish { create Grant[role: Role::Member]=>{v: 0} }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("Role::Member"));
}

#[test]
fn dot_keys_differ_by_field() {
    let warnings = warnings_for(
        r#"
        fact Account[user int]=>{balance int}

        command Foo {
            fields { user int, other int }
            policy {
                check !exists Account[user: this.user] else recall failed()
                finish { create Account[user: this.other]=>{balance: 0} }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
}

#[test]
fn call_keys_match_by_function() {
    let warnings = warnings_for(&with_defs(
        r#"
        function one(u int) int { return u }
        function two(u int) int { return u }
        "#,
        r#"
        let k = one(this.user)
        check !exists Account[user: k] else recall failed()
        finish { create Account[user: k]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
    let warnings = warnings_for(&with_defs(
        r#"
        function one(u int) int { return u }
        function two(u int) int { return u }
        "#,
        r#"
        let k = one(this.user)
        let k2 = two(this.user)
        check !exists Account[user: k] else recall failed()
        finish { create Account[user: k2]=>{balance: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
}

// --- Substitutability corners.

#[test]
fn comparison_with_branching_operand_is_not_substituted() {
    let warnings = warnings_for(&command(
        r#"
        let same = this.user == 1
        let odd = (if this.user == 1 { : 1 } else { : 2 }) == 1
        let anyway = exists Account[user: match this.user { 1 => 1  _ => 2 }]
        check same else recall failed()
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

// --- Visitor corners: names and returns nested in every form.

#[test]
fn rebinding_forgets_mentions_nested_in_every_form() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}
        fact Other[k int]=>{v int}
        "#,
        r#"
        if this.user == 1 {
            let m = query Member[team: 1, device: ?] or recall failed()
            let ok = exists Other[k: m.device]
            check !exists Other[k: match m.device { 1 => 1  _ => 2 }] else recall failed()
            check !exists Other[k: { let z = m.device  let w = m.rank : z }] else recall failed()
            check !exists Other[k: if m.rank == 1 { : 1 } else { : 2 }] else recall failed()
            check !exists Other[k: if m.rank == 1 { : m.device } else { : 2 }] else recall failed()
            check !exists Other[k: if this.user == 1 { : m.device } else { : 2 }] else recall failed()
            check !exists Other[k: match this.user { 1 => m.device  _ => 2 }] else recall failed()
        } else {
            let m = query Member[team: 1, device: ?] or recall failed()
        }
        let m = query Member[team: 2, device: ?] or recall failed()
        finish { delete Member[team: 2, device: m.device] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn nested_return_in_comparison_and_scrutinee() {
    let warnings = warnings_for(&with_defs(
        r#"
        function f(u int) bool {
            let a = (match u { 1 => 1  _ => return true }) == 1
            return exists Account[user: u]
        }
        function g(u int) bool {
            let b = saturating_add(1, match (match u { 1 => 1  _ => return true }) {
                1 => 1
                _ => 2
            })
            return exists Account[user: u]
        }
        function h(u int) bool {
            let c = saturating_add(1, if (match u { 1 => true  _ => return true }) { : 1 } else { : 2 })
            return exists Account[user: u]
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        check g(this.user) else recall failed()
        check h(this.user) else recall failed()
        finish { delete Account[user: this.user] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
}

#[test]
fn optional_values_in_arms_are_visited() {
    let warnings = warnings_for(&command(
        r#"
        let z = if this.user == 1 { : Some(exists Account[user: 1]) } else { : None }
        let w = Some(match this.user { 1 => true  _ => exists Account[user: 1] })
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn block_binding_names_in_nested_statements() {
    let warnings = warnings_for(&command(
        r#"
        let x = if this.user == 1 {
            if this.user == 2 { let a = 1 }
            if this.user == 3 { let b = 1 } else { let c = 2 }
            match this.user { 1 => { let d = 1 } _ => { let e = 2 } }
            : 1
        } else {
            : 2
        }
        finish {}
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn finish_inside_block_with_update_is_rewritten() {
    let warnings = warnings_for(&command(
        r#"
        let a = query Account[user: this.user] or recall failed()
        let x = if this.user == 1 {
            finish { update Account[user: this.user]=>{balance: a.balance} to {balance: 1} }
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
