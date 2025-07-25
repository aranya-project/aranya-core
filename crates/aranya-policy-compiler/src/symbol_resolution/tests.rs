//! Tests for symbol resolution.

use aranya_policy_ast::{AstNode, Expression, GlobalLetStatement, Policy, Text, VType, Version};

use super::*;

fn create_test_policy(global_lets: Vec<AstNode<GlobalLetStatement>>) -> Policy {
    Policy {
        version: Version::V2,
        ffi_imports: vec![],
        facts: vec![],
        actions: vec![],
        effects: vec![],
        structs: vec![],
        enums: vec![],
        commands: vec![],
        functions: vec![],
        finish_functions: vec![],
        global_lets,
    }
}

fn create_global_let(name: &str, value: i64) -> AstNode<GlobalLetStatement> {
    AstNode {
        inner: GlobalLetStatement {
            identifier: Identifier::new(name),
            value_type: VType::Int,
            value: Expression::Int(value),
        },
        locator: 0,
    }
}

fn create_identifier_expr(name: &str) -> Expression {
    Expression::Identifier(Identifier::new(name))
}

#[test]
fn test_simple_global_resolution() {
    let policy = create_test_policy(vec![create_global_let("x", 42)]);

    let result = resolve(&policy, &[]);
    assert!(result.is_ok());

    let resolution = result.unwrap();
    assert!(resolution.symbol_table.contains(&Identifier::new("x")));

    if let Some(symbol) = resolution.symbol_table.get(&Identifier::new("x")) {
        assert!(matches!(symbol.kind, SymbolKind::Global { .. }));
    }
}

#[test]
fn test_duplicate_definition_error() {
    let policy = create_test_policy(vec![
        create_global_let("x", 42),
        create_global_let("x", 24), // Duplicate
    ]);

    let result = resolve(&policy, &[]);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(matches!(
        error.kind,
        SymbolResolutionErrorKind::DuplicateDefinition { .. }
    ));
}

#[test]
fn test_reserved_identifier_error() {
    let policy = create_test_policy(vec![AstNode {
        inner: GlobalLetStatement {
            identifier: Identifier::new("this"), // Reserved
            value_type: VType::Int,
            value: Expression::Int(42),
        },
        locator: 0,
    }]);

    let result = resolve(&policy, &[]);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(matches!(
        error.kind,
        SymbolResolutionErrorKind::ReservedIdentifier { .. }
    ));
}

#[test]
fn test_undefined_identifier_error() {
    let policy = create_test_policy(vec![AstNode {
        inner: GlobalLetStatement {
            identifier: Identifier::new("x"),
            value_type: VType::Int,
            value: create_identifier_expr("undefined"), // Undefined reference
        },
        locator: 0,
    }]);

    let result = resolve(&policy, &[]);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(matches!(
        error.kind,
        SymbolResolutionErrorKind::UndefinedIdentifier(_)
    ));
}

#[test]
fn test_dependency_graph_construction() {
    let policy = create_test_policy(vec![
        create_global_let("a", 1),
        AstNode {
            inner: GlobalLetStatement {
                identifier: Identifier::new("b"),
                value_type: VType::Int,
                value: create_identifier_expr("a"), // b depends on a
            },
            locator: 0,
        },
    ]);

    let result = resolve(&policy, &[]).unwrap();

    // Check that the dependency graph was built correctly
    let sorted = result.dependency_graph.topo_sort().unwrap();
    assert_eq!(sorted.len(), 2);

    // 'a' should come before 'b' in topological order
    let a_pos = sorted
        .iter()
        .position(|&idx| result.dependency_graph.get(idx) == Some(&Identifier::new("a")))
        .unwrap();
    let b_pos = sorted
        .iter()
        .position(|&idx| result.dependency_graph.get(idx) == Some(&Identifier::new("b")))
        .unwrap();

    assert!(a_pos < b_pos);
}

#[test]
fn test_symbol_table_lookup() {
    let policy = create_test_policy(vec![create_global_let("test_var", 123)]);

    let result = resolve(&policy, &[]).unwrap();

    let symbol = result
        .symbol_table
        .get(&Identifier::new("test_var"))
        .unwrap();
    assert!(matches!(symbol.kind, SymbolKind::Global { .. }));
    assert_eq!(symbol.location, Some(0));
}

#[test]
fn test_empty_policy() {
    let policy = create_test_policy(vec![]);

    let result = resolve(&policy, &[]);
    assert!(result.is_ok());

    let resolution = result.unwrap();
    assert_eq!(resolution.symbol_table.symbols().len(), 0);
}

#[test]
fn test_ffi_symbols_populated() {
    use aranya_policy_module::ffi::{self, VType as FfiVType};

    let ffi_module = ffi::Module {
        name: "test_module".to_string(),
        structs: vec![ffi::Struct {
            name: Identifier::new("TestStruct"),
            fields: vec![ffi::Field {
                name: Identifier::new("field1"),
                vtype: FfiVType::Int,
            }],
        }],
        enums: vec![],
        functions: vec![],
    };

    let policy = create_test_policy(vec![]);

    let result = resolve(&policy, &[ffi_module]).unwrap();

    // Check that FFI struct was added to symbol table
    let symbol = result
        .symbol_table
        .get(&Identifier::new("TestStruct"))
        .unwrap();
    assert!(matches!(symbol.kind, SymbolKind::Struct { .. }));
    assert_eq!(symbol.location, None); // FFI symbols don't have source locations
}
