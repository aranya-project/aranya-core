//! Attacks on names: two mentions of one name must refer to one
//! binding, and nothing local to a scope may escape it.

use super::{warnings_for, with_defs};

const MEMBER_AND_OTHER: &str = r#"
    fact Member[team int, device int]=>{rank int}
    fact Other[k int]=>{v int}
"#;

#[test]
fn attack_ok_arm_rebinding() {
    // The second `Ok(x)` binds a different value, so the first arm's
    // knowledge about `x` must not survive into it.
    let warnings = warnings_for(&with_defs(
        r#"
        fact Other[k int]=>{v int}

        function lookup(u int) result[int, int] {
            if u == 1 { return Ok(u) }
            return Err(0)
        }
        "#,
        r#"
        match lookup(this.user) {
            Ok(x) => { check exists Other[k: x] else recall failed() }
            Err(e) => { recall failed() }
        }
        match lookup(2) {
            Ok(x) => { finish { delete Other[k: x] } }
            Err(e) => { recall failed() }
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_ok_arm_binding_proves_in_arm() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Other[k int]=>{v int}

        function lookup(u int) result[int, int] {
            if u == 1 { return Ok(u) }
            return Err(0)
        }
        "#,
        r#"
        match lookup(this.user) {
            Ok(x) => {
                check exists Other[k: x] else recall failed()
                finish { delete Other[k: x] }
            }
            Err(e) => { recall failed() }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_finish_function_param_named_like_caller_var() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}

        finish function remove(m struct Member) {
            delete Member[team: 1, device: m.device]
        }
        "#,
        r#"
        let m = query Member[team: 1, device: ?] or recall failed()
        let other = query Member[team: 2, device: ?] or recall failed()
        finish { remove(other) }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_finish_function_param_bound_to_caller_var() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}

        finish function remove(m struct Member) {
            delete Member[team: 1, device: m.device]
        }
        "#,
        r#"
        let m = query Member[team: 1, device: ?] or recall failed()
        let other = query Member[team: 2, device: ?] or recall failed()
        finish { remove(m) }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_helper_param_named_like_caller_var() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}
        fact Other[k int]=>{v int}

        function has(m struct Member) bool {
            return exists Other[k: m.device]
        }
        "#,
        r#"
        let m = query Member[team: 1, device: ?] or recall failed()
        let other = query Member[team: 2, device: ?] or recall failed()
        check has(other) else recall failed()
        finish { delete Other[k: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_helper_param_bound_to_caller_var() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}
        fact Other[k int]=>{v int}

        function has(m struct Member) bool {
            return exists Other[k: m.device]
        }
        "#,
        r#"
        let m = query Member[team: 1, device: ?] or recall failed()
        let other = query Member[team: 2, device: ?] or recall failed()
        check has(m) else recall failed()
        finish { delete Other[k: m.device] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_rebinding_through_call_argument() {
    // Calls match structurally, so a stale fact keyed by `f(m.device)`
    // would prove the create for the new `m`.
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}
        fact Other[k int]=>{v int}

        function f(d int) int { return d }
        "#,
        r#"
        if this.user == 1 {
            let m = query Member[team: 1, device: ?] or recall failed()
            check !exists Other[k: f(m.device)] else recall failed()
        } else {
            let m = query Member[team: 1, device: ?] or recall failed()
            check !exists Other[k: f(m.device)] else recall failed()
        }
        let m = query Member[team: 2, device: ?] or recall failed()
        let k = f(m.device)
        finish { create Other[k: k]=>{v: 0} }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `create`"));
}

#[test]
fn control_call_argument_proves_current_binding() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}
        fact Other[k int]=>{v int}

        function f(d int) int { return d }
        "#,
        r#"
        let m = query Member[team: 1, device: ?] or recall failed()
        check !exists Other[k: f(m.device)] else recall failed()
        let k = f(m.device)
        finish { create Other[k: k]=>{v: 0} }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_arm_expression_binding_does_not_leak() {
    let warnings = warnings_for(&with_defs(
        MEMBER_AND_OTHER,
        r#"
        let ok = match query Member[team: 1, device: ?] {
            Some(m) => exists Other[k: m.device]
            None => false
        }
        let m = query Member[team: 2, device: ?] or recall failed()
        finish { delete Other[k: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn attack_helper_arm_name_does_not_leak() {
    // The helper's `m` is `Account[1]`, not the caller's `m`.
    let warnings = warnings_for(&with_defs(
        r#"
        fact G[b int]=>{}

        function f(p int) bool {
            return match query Account[user: p] { Some(m) => exists G[b: m.balance]  None => false }
        }
        "#,
        r#"
        let m = query Account[user: this.user] or recall failed()
        check f(1) else recall failed()
        finish { delete G[b: m.balance] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_helper_arm_fact_in_parameters() {
    // What the arm proves about the parameters still reaches the caller.
    let warnings = warnings_for(&with_defs(
        r#"
        fact G[b int]=>{}

        function f(p int) bool {
            return match query Account[user: p] { Some(m) => exists G[b: p]  None => false }
        }
        "#,
        r#"
        check f(this.user) else recall failed()
        finish { delete G[b: this.user] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn attack_argument_captured_by_helper_binder() {
    // The caller's `m` is 3 or 4. Inside the helper, the block's own `m`
    // is 1. Moving the argument into the block must not turn it into the
    // block's `m`.
    let warnings = warnings_for(&with_defs(
        r#"
        fact Pair2[k int, j int]=>{}

        function f(p int) bool { return { let m = 1 : exists Pair2[k: p, j: m] } }
        "#,
        r#"
        let m = if this.user == 1 { : 3 } else { : 4 }
        check f(m) else recall failed()
        finish { delete Pair2[k: 1, j: 1] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn control_helper_block_binder_without_capture() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Pair2[k int, j int]=>{}

        function f(p int) bool { return { let m = 1 : exists Pair2[k: p, j: m] } }
        "#,
        r#"
        check f(1) else recall failed()
        finish { delete Pair2[k: 1, j: 1] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
