//! Keys read from query results, and forgetting a name's earlier binding.

use super::{MEMBER, warnings_for, with_defs};

#[test]
fn bound_key_query_then_delete_passes() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        let m = query Member[team: this.user, device: ?] or recall failed()
        finish { delete Member[team: this.user, device: m.device] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn bound_key_query_then_update_passes() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        let m = query Member[team: this.user, device: ?] or recall failed()
        finish {
            update Member[team: this.user, device: m.device]=>{rank: m.rank} to {rank: 0}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn bound_key_match_then_delete_passes() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        match query Member[team: this.user, device: ?] {
            Some(m) => {
                finish { delete Member[team: this.user, device: m.device] }
            }
            None => {
                finish {}
            }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn bound_key_query_with_value_filter_passes() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        let m = query Member[team: this.user, device: ?]=>{rank: 1} or recall failed()
        finish { delete Member[team: this.user, device: m.device] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn bound_key_through_let_alias_passes() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        let m = query Member[team: this.user, device: ?] or recall failed()
        let d = m.device
        finish { delete Member[team: this.user, device: d] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn bound_key_through_finish_function_passes() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}

        finish function remove_member(t int, d int) {
            delete Member[team: t, device: d]
        }
        "#,
        r#"
        let m = query Member[team: this.user, device: ?] or recall failed()
        finish { remove_member(this.user, m.device) }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_returning_bound_key_query_with_let_passes() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}

        function find_member(t int) option[struct Member] {
            return query Member[team: t, device: ?]
        }
        "#,
        r#"
        let m = find_member(this.user) or recall failed()
        finish { delete Member[team: this.user, device: m.device] }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn helper_returning_bound_key_query_with_match_passes() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}

        function find_member(t int) option[struct Member] {
            return query Member[team: t, device: ?]
        }
        "#,
        r#"
        match find_member(this.user) {
            Some(m) => {
                finish { delete Member[team: this.user, device: m.device] }
            }
            None => {
                finish {}
            }
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn bound_key_query_in_init_command_reports_nothing() {
    // No fact can exist, so the path past the query is impossible.
    let warnings = warnings_for(
        r#"
        fact Member[team int, device int]=>{rank int}

        command Init {
            attributes { init: true }
            fields { user int }
            policy {
                let m = query Member[team: this.user, device: ?] or recall failed()
                finish { delete Member[team: this.user, device: m.device] }
            }
            recall failed() { finish {} }
        }
        "#,
    );
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn mixed_some_and_none_arm_warns() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        match query Member[team: this.user, device: ?] {
            Some(m) | None => {
                finish { delete Member[team: this.user, device: m.device] }
            }
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn rebound_let_forgets_earlier_binding() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        if this.user == 1 {
            let m = query Member[team: 1, device: ?] or recall failed()
        } else {
            let m = query Member[team: 1, device: ?] or recall failed()
        }
        let m = query Member[team: 2, device: ?] or recall failed()
        finish { delete Member[team: 1, device: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn rebound_match_arm_forgets_earlier_binding() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        match query Member[team: 1, device: ?] {
            Some(m) => { let unused = m.rank }
            None => { recall failed() }
        }
        match query Member[team: 2, device: ?] {
            Some(m) => {
                finish { delete Member[team: 1, device: m.device] }
            }
            None => { recall failed() }
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn rebinding_forgets_nested_mention() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}
        fact Other[k int]=>{v int}
        "#,
        r#"
        if this.user == 1 {
            let m = query Member[team: 1, device: ?] or recall failed()
            check exists Other[k: m.device] else recall failed()
        } else {
            let m = query Member[team: 1, device: ?] or recall failed()
            check exists Other[k: m.device] else recall failed()
        }
        let m = query Member[team: 2, device: ?] or recall failed()
        finish { delete Other[k: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn mutation_between_query_and_update_warns() {
    let warnings = warnings_for(&with_defs(
        MEMBER,
        r#"
        check exists Member[team: this.user, device: 5] else recall failed()
        let m = query Member[team: this.user, device: ?] or recall failed()
        finish {
            delete Member[team: this.user, device: 5]
            update Member[team: this.user, device: m.device]=>{rank: m.rank} to {rank: 0}
        }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `update`"));
}

#[test]
fn helper_with_differing_query_keys_warns() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}

        function find_member(t int) option[struct Member] {
            if t == 1 {
                return query Member[team: 1, device: ?]
            }
            return query Member[team: t, device: ?]
        }
        "#,
        r#"
        let m = find_member(this.user) or recall failed()
        finish { delete Member[team: this.user, device: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}

#[test]
fn helper_returning_some_local_warns() {
    let warnings = warnings_for(&with_defs(
        r#"
        fact Member[team int, device int]=>{rank int}

        function find_member(t int) option[struct Member] {
            let m = query Member[team: t, device: ?] or return None
            return Some(m)
        }
        "#,
        r#"
        let m = find_member(this.user) or recall failed()
        finish { delete Member[team: this.user, device: m.device] }
        "#,
    ));
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(warnings[0].message.contains("before `delete`"));
}
