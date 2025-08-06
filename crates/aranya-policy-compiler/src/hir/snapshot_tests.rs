#![cfg(test)]

use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;
use serde::Serialize;

use crate::hir::{self, arena::AstNodes, hir::Hir};

/// Wrapper struct for clean JSON snapshots
#[derive(Serialize)]
struct ParseSnapshot<'a> {
    hir: &'a Hir,
    ast_nodes: &'a AstNodes<'a>,
}

#[test]
fn test_parse_basic_policy() {
    let policy_text = r#"
action action1() {}
action action2(x int) {
    action action1()
    publish Cmd1 {}
}
action action3() {}

command Cmd1 {
    fields {}
    seal { return None }
    open { return None }
}

effect Effect1 {
    field1 int,
    field2 string,
}
effect Effect2 {}

// TODO: Add enum

fact Fact1[a int, b string]=>{c bool}
fact Fact2[]=>{}

// TODO: add function inputs
finish function func4() {}
finish function func5() {
    func4()
    delete Fact1[a: 42, b: "test"]
}

// TODO: add function inputs
function func1() int { return 42 }
function func2() bool { return true }
function func3() int { return func1() }

struct Struct1 {
    field1 bool,
    field2 int,
}
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, ast_nodes) = hir::lower(&policy, &[]);

    // Create snapshot of the parsed HIR and AST nodes
    let snapshot = ParseSnapshot {
        hir: &hir,
        ast_nodes: &ast_nodes,
    };

    insta::assert_json_snapshot!("basic_policy", &snapshot);
}

#[test]
fn test_parse_empty_policy() {
    let policy_text = "";
    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, ast_nodes) = hir::lower(&policy, &[]);

    let snapshot = ParseSnapshot {
        hir: &hir,
        ast_nodes: &ast_nodes,
    };

    insta::assert_json_snapshot!("empty_policy", &snapshot);
}

#[test]
fn test_parse_complex_expressions() {
    let policy_text = r#"
function complex_expr(x int, y int) bool {
    let sum = x + y
    let diff = x - y
    let is_positive = sum > 0
    let is_equal = x == y
    let result = is_positive && !is_equal
    return result || (diff < 0)
}

function optional_handling(x optional int) int {
    return unwrap x
}

function match_expr(x int) string {
    match x {
        1 => { return "one" }
        2 => { return "two" }
        _ => { return "other" }
    }
}
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, ast_nodes) = hir::lower(&policy, &[]);

    let snapshot = ParseSnapshot {
        hir: &hir,
        ast_nodes: &ast_nodes,
    };

    insta::assert_json_snapshot!("complex_expressions", &snapshot);
}

#[test]
fn test_parse_nested_structures() {
    let policy_text = r#"
struct Address {
    street string,
    city string,
}

struct Person {
    name string,
    age int,
    address struct Address,
}

command CreatePerson {
    fields {
        person struct Person,
    }
    seal { return None }
    open { return None }
}

action create_person(name string, age int, street string, city string) {
    let addr = Address {
        street: street,
        city: city,
    }
    let person = Person {
        name: name,
        age: age,
        address: addr,
    }
    publish CreatePerson { person: person }
}
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, ast_nodes) = hir::lower(&policy, &[]);

    let snapshot = ParseSnapshot {
        hir: &hir,
        ast_nodes: &ast_nodes,
    };

    insta::assert_json_snapshot!("nested_structures", &snapshot);
}

#[test]
fn test_parse_fact_operations() {
    let policy_text = r#"
fact User[user_id string]=>{name string, role string}
fact Permission[user_id string, resource string]=>{allowed bool}

action check_permissions(user_id string) {
    // map is valid in actions
    map Permission[user_id: user_id, resource: ?] as perm {
        check perm.allowed
    }
}

action check_admin(user_id string) {
    let user = query User[user_id: user_id]
    check user.role == "admin"
}

effect PermissionGranted {
    user_id string,
    resource string,
}

finish function grant_permission(user_id string, resource string) {
    create Permission[user_id: user_id, resource: resource]=>{allowed: true}
    // emit is valid in finish functions
    emit PermissionGranted {
        user_id: user_id,
        resource: resource,
    }
}

finish function revoke_permission(user_id string, resource string) {
    delete Permission[user_id: user_id, resource: resource]
}
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, ast_nodes) = hir::lower(&policy, &[]);

    let snapshot = ParseSnapshot {
        hir: &hir,
        ast_nodes: &ast_nodes,
    };

    insta::assert_json_snapshot!("fact_operations", &snapshot);
}
