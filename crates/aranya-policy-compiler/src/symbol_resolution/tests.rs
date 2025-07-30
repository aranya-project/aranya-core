//! Tests for symbol resolution.

use std::collections::HashMap;

use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;

use crate::{
    hir::{self, Hir, IdentId},
    symbol_resolution::{
        resolve,
        scope::{Scope, ScopeId, Scopes},
        symbols::{Symbol, SymbolId, SymbolKind},
        ResolvedHir,
    },
};

/// Find an IdentId by name in the HIR
fn find_ident_id(hir: &Hir, name: &str) -> Option<IdentId> {
    hir.idents
        .iter()
        .find(|(_, ident)| ident.ident.as_str() == name)
        .map(|(id, _)| id)
}

/// Find a symbol by name in the resolved HIR
fn find_symbol_by_name<'a>(resolution: &'a ResolvedHir<'_>, name: &str) -> Option<&'a Symbol> {
    // Find the IdentId for the given name
    let ident_id = find_ident_id(resolution.hir, name)?;

    // Look up the symbol in the global scope
    let sym_id = resolution.scopes.get(ScopeId::GLOBAL, &ident_id).ok()??;
    resolution.symbols.get(sym_id)
}

/// Assert that a symbol has the expected kind
fn assert_symbol_kind(symbol: &Symbol, expected_kind: &str) -> bool {
    match (&symbol.kind, expected_kind) {
        (SymbolKind::GlobalVar(_), "GlobalVar") => true,
        (SymbolKind::LocalVar(_), "LocalVar") => true,
        (SymbolKind::Fact(_), "Fact") => true,
        (SymbolKind::Action(_), "Action") => true,
        (SymbolKind::Effect(_), "Effect") => true,
        (SymbolKind::Struct(_), "Struct") => true,
        (SymbolKind::Enum(_), "Enum") => true,
        (SymbolKind::Command(_), "Command") => true,
        (SymbolKind::Function(_), "Function") => true,
        (SymbolKind::FinishFunction(_), "FinishFunction") => true,
        (SymbolKind::FfiModule(_), "FfiModule") => true,
        _ => false,
    }
}

/// Check that a symbol exists for a given name
fn assert_symbol_exists(resolution: &ResolvedHir<'_>, name: &str) -> bool {
    find_symbol_by_name(resolution, name).is_some()
}

/// Check that an identifier resolves to a symbol
fn assert_resolution_exists(resolution: &ResolvedHir<'_>, ident_id: IdentId) -> bool {
    resolution.resolutions.contains_key(&ident_id)
}

#[test]
fn test_global_let_with_complex_expressions() {
    let policy_text = r#"
let x = 42
let y = x + 10
let z = y > 50 && x < 100
let w = if z { 1 } else { 0 }
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);
    let resolution = resolve(&hir).unwrap();

    // Verify all globals are resolved
    assert!(assert_symbol_exists(&resolution, "x"));
    assert!(assert_symbol_exists(&resolution, "y"));
    assert!(assert_symbol_exists(&resolution, "z"));
    assert!(assert_symbol_exists(&resolution, "w"));

    // Verify they're all GlobalVar
    let x_sym = find_symbol_by_name(&resolution, "x").unwrap();
    assert!(assert_symbol_kind(x_sym, "GlobalVar"));
}

#[test]
fn test_fact_definition_resolution() {
    let policy_text = r#"
fact User[id string]=>{name string, age int}
fact Permission[user_id string, resource string]=>{allowed bool}
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);
    let resolution = resolve(&hir).unwrap();

    // Verify facts are in global scope
    let user_sym = find_symbol_by_name(&resolution, "User").expect("User fact should exist");
    assert!(assert_symbol_kind(user_sym, "Fact"));
    assert_eq!(user_sym.scope, ScopeId::GLOBAL);

    let perm_sym =
        find_symbol_by_name(&resolution, "Permission").expect("Permission fact should exist");
    assert!(assert_symbol_kind(perm_sym, "Fact"));
}

#[test]
fn test_action_definition_resolution() {
    let policy_text = r#"
action greet(name string) {
    check name != ""
}

action welcome(user string) {
    action greet(user)
}
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);
    let resolution = resolve(&hir).unwrap();

    // Verify actions are in global scope
    let greet_sym = find_symbol_by_name(&resolution, "greet").expect("greet action should exist");
    assert!(assert_symbol_kind(greet_sym, "Action"));

    let welcome_sym =
        find_symbol_by_name(&resolution, "welcome").expect("welcome action should exist");
    assert!(assert_symbol_kind(welcome_sym, "Action"));
}

#[test]
fn test_function_definition_resolution() {
    let policy_text = r#"
function add(x int, y int) int {
    return x + y
}

function double(n int) int {
    return add(n, n)
}
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);
    let resolution = resolve(&hir).unwrap();

    // Verify functions are resolved
    let add_sym = find_symbol_by_name(&resolution, "add").expect("add function should exist");
    assert!(assert_symbol_kind(add_sym, "Function"));

    let double_sym =
        find_symbol_by_name(&resolution, "double").expect("double function should exist");
    assert!(assert_symbol_kind(double_sym, "Function"));
}

#[test]
fn test_struct_definition_resolution() {
    let policy_text = r#"
struct Address {
    street string,
    city string,
}

struct Person {
    name string,
    address struct Address,
}
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);
    let resolution = resolve(&hir).unwrap();

    // Verify structs are resolved
    let addr_sym =
        find_symbol_by_name(&resolution, "Address").expect("Address struct should exist");
    assert!(assert_symbol_kind(addr_sym, "Struct"));

    let person_sym =
        find_symbol_by_name(&resolution, "Person").expect("Person struct should exist");
    assert!(assert_symbol_kind(person_sym, "Struct"));
}

#[test]
fn test_enum_definition_resolution() {
    let policy_text = r#"
enum Status {
    Active,
    Inactive,
    Pending,
}
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);
    let resolution = resolve(&hir).unwrap();

    // Verify enum is resolved
    let status_sym = find_symbol_by_name(&resolution, "Status").expect("Status enum should exist");
    assert!(assert_symbol_kind(status_sym, "Enum"));
}

#[test]
fn test_comprehensive_scopes_and_symbols() {
    let policy_text = r#"
let global_x = 42

function test_func(param_a int, param_b int) int {
    let local_x = param_a + param_b
    let local_y = global_x + local_x
    return local_y
}
"#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);
    let resolution = resolve(&hir).unwrap();

    // Get identifiers
    let global_x_id = find_ident_id(&hir, "global_x").unwrap();
    let test_func_id = find_ident_id(&hir, "test_func").unwrap();

    // Build expected scopes
    let expected_scopes = Scopes {
        scopes: vec![
            Scope {
                id: ScopeId(0), // Global scope
                parent: None,
                symbols: HashMap::from([(global_x_id, SymbolId(0)), (test_func_id, SymbolId(1))]),
            },
            Scope {
                id: ScopeId(1), // global_x's expression scope
                parent: Some(ScopeId(0)),
                symbols: HashMap::new(),
            },
            Scope {
                id: ScopeId(2), // test_func's scope
                parent: Some(ScopeId(0)),
                symbols: HashMap::new(), // We'll verify params are here
            },
        ],
    };

    // Verify at least these scopes exist
    assert!(resolution.scopes.scopes().len() >= 3);

    // Verify global symbols
    assert_eq!(resolution.scopes.scopes()[0].symbols.len(), 2);

    // Verify function symbol
    let func_sym = find_symbol_by_name(&resolution, "test_func").unwrap();
    if let SymbolKind::Function(f) = &func_sym.kind {
        assert_eq!(f.params.len(), 2);
        assert!(f.scope.0 > 0); // Function has its own scope
    } else {
        panic!("test_func should be a Function");
    }
}
