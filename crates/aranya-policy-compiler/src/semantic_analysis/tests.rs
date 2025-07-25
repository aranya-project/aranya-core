//! Tests for semantic analysis.

use std::collections::HashMap;

use aranya_policy_ast::{
    ActionDefinition, AstNode, BinaryOperator, BooleanLiteral, Declaration, Expression,
    FunctionDefinition, GlobalLetDefinition, Identifier, IntegerLiteral, Policy, Statement, VType,
};

use super::*;
use crate::{
    dependency_graph::{DependencyGraph, DependencyKind},
    symbol_resolution::{ResolvedAst, Symbol, SymbolKind, SymbolTable},
};

fn create_test_policy(declarations: Vec<AstNode<Declaration>>) -> Policy {
    Policy {
        text: "test".to_string(),
        ranges: vec![],
        declarations,
    }
}

fn create_global_let(name: &str, value: i64) -> AstNode<Declaration> {
    AstNode {
        inner: Declaration::GlobalLet(GlobalLetDefinition {
            identifier: Identifier::new(name),
            value_type: VType::Int,
            value: AstNode {
                inner: Expression::IntegerLiteral(IntegerLiteral { value }),
                locator: 0,
            },
        }),
        locator: 0,
    }
}

fn create_function(name: &str, statements: Vec<AstNode<Statement>>) -> AstNode<Declaration> {
    AstNode {
        inner: Declaration::Function(FunctionDefinition {
            identifier: Identifier::new(name),
            arguments: vec![],
            return_type: VType::Int,
            statements,
        }),
        locator: 0,
    }
}

fn create_identifier_expr(name: &str) -> AstNode<Expression> {
    AstNode {
        inner: Expression::Identifier(Identifier::new(name)),
        locator: 0,
    }
}

fn create_binary_op(
    left: AstNode<Expression>,
    right: AstNode<Expression>,
    op: BinaryOperator,
) -> AstNode<Expression> {
    AstNode {
        inner: Expression::BinaryOp {
            left: Box::new(left),
            right: Box::new(right),
            operator: op,
        },
        locator: 0,
    }
}

fn create_resolved_ast_with_symbols(
    policy: Policy,
    symbols: Vec<(&str, SymbolKind)>,
) -> (ResolvedAst, SymbolTable) {
    let mut resolved_ast = ResolvedAst::new(policy);
    let mut symbol_table = SymbolTable::new();

    for (name, kind) in symbols {
        let symbol = Symbol {
            kind,
            location: Some(0),
        };
        symbol_table.insert(Identifier::new(name), symbol).unwrap();
    }

    (resolved_ast, symbol_table)
}

#[test]
fn test_simple_dependency_ordering() {
    let policy = create_test_policy(vec![create_global_let("b", 2), create_global_let("a", 1)]);

    let mut dependency_graph = DependencyGraph::new();
    dependency_graph.add_dependency(
        Identifier::new("b"),
        Identifier::new("a"),
        DependencyKind::Global,
    );

    let (resolved_ast, symbol_table) = create_resolved_ast_with_symbols(
        policy,
        vec![
            (
                "a",
                SymbolKind::Global {
                    value_type: VType::Int,
                },
            ),
            (
                "b",
                SymbolKind::Global {
                    value_type: VType::Int,
                },
            ),
        ],
    );

    let result = analyze(resolved_ast, symbol_table, dependency_graph);
    assert!(result.is_ok());

    let analysis = result.unwrap();

    // 'a' should come before 'b' in the sorted order
    let a_pos = analysis
        .sorted_declarations
        .iter()
        .position(|id| id == &Identifier::new("a"))
        .unwrap();
    let b_pos = analysis
        .sorted_declarations
        .iter()
        .position(|id| id == &Identifier::new("b"))
        .unwrap();

    assert!(a_pos < b_pos);
}

#[test]
fn test_circular_dependency_detection() {
    let policy = create_test_policy(vec![
        create_global_let("a", 1),
        create_global_let("b", 2),
        create_global_let("c", 3),
    ]);

    let mut dependency_graph = DependencyGraph::new();
    // Create a cycle: a -> b -> c -> a
    dependency_graph.add_dependency(
        Identifier::new("a"),
        Identifier::new("b"),
        DependencyKind::Global,
    );
    dependency_graph.add_dependency(
        Identifier::new("b"),
        Identifier::new("c"),
        DependencyKind::Global,
    );
    dependency_graph.add_dependency(
        Identifier::new("c"),
        Identifier::new("a"),
        DependencyKind::Global,
    );

    let (resolved_ast, symbol_table) = create_resolved_ast_with_symbols(
        policy,
        vec![
            (
                "a",
                SymbolKind::Global {
                    value_type: VType::Int,
                },
            ),
            (
                "b",
                SymbolKind::Global {
                    value_type: VType::Int,
                },
            ),
            (
                "c",
                SymbolKind::Global {
                    value_type: VType::Int,
                },
            ),
        ],
    );

    let result = analyze(resolved_ast, symbol_table, dependency_graph);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(matches!(
        error.kind,
        SemanticAnalysisErrorKind::CircularDependency { .. }
    ));
}

#[test]
fn test_type_checking_global_let() {
    let policy = create_test_policy(vec![create_global_let("x", 42)]);

    let dependency_graph = DependencyGraph::new();
    let (resolved_ast, symbol_table) = create_resolved_ast_with_symbols(
        policy,
        vec![(
            "x",
            SymbolKind::Global {
                value_type: VType::Int,
            },
        )],
    );

    let result = analyze(resolved_ast, symbol_table, dependency_graph);
    assert!(result.is_ok());

    let analysis = result.unwrap();

    // Check that the integer literal was type-checked
    assert!(analysis.type_checked_ast.expression_types.contains_key(&0));
    assert_eq!(analysis.type_checked_ast.expression_types[&0], VType::Int);
}

#[test]
fn test_type_checking_binary_operation() {
    let policy = create_test_policy(vec![AstNode {
        inner: Declaration::GlobalLet(GlobalLetDefinition {
            identifier: Identifier::new("result"),
            value_type: VType::Int,
            value: create_binary_op(
                AstNode {
                    inner: Expression::IntegerLiteral(IntegerLiteral { value: 10 }),
                    locator: 1,
                },
                AstNode {
                    inner: Expression::IntegerLiteral(IntegerLiteral { value: 20 }),
                    locator: 2,
                },
                BinaryOperator::Add,
            ),
        }),
        locator: 0,
    }]);

    let dependency_graph = DependencyGraph::new();
    let (resolved_ast, symbol_table) = create_resolved_ast_with_symbols(
        policy,
        vec![(
            "result",
            SymbolKind::Global {
                value_type: VType::Int,
            },
        )],
    );

    let result = analyze(resolved_ast, symbol_table, dependency_graph);
    assert!(result.is_ok());

    let analysis = result.unwrap();

    // Check that all expressions were type-checked
    assert_eq!(analysis.type_checked_ast.expression_types[&0], VType::Int); // Binary operation
    assert_eq!(analysis.type_checked_ast.expression_types[&1], VType::Int); // First operand
    assert_eq!(analysis.type_checked_ast.expression_types[&2], VType::Int); // Second operand
}

#[test]
fn test_type_mismatch_error() {
    let policy = create_test_policy(vec![AstNode {
        inner: Declaration::GlobalLet(GlobalLetDefinition {
            identifier: Identifier::new("x"),
            value_type: VType::Bool, // Declared as bool
            value: AstNode {
                inner: Expression::IntegerLiteral(IntegerLiteral { value: 42 }), // But assigned an int
                locator: 1,
            },
        }),
        locator: 0,
    }]);

    let dependency_graph = DependencyGraph::new();
    let (resolved_ast, symbol_table) = create_resolved_ast_with_symbols(
        policy,
        vec![(
            "x",
            SymbolKind::Global {
                value_type: VType::Bool,
            },
        )],
    );

    let result = analyze(resolved_ast, symbol_table, dependency_graph);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(matches!(
        error.kind,
        SemanticAnalysisErrorKind::TypeMismatch { .. }
    ));
}

#[test]
fn test_function_type_checking() {
    let policy = create_test_policy(vec![create_function(
        "test_func",
        vec![AstNode {
            inner: Statement::Return {
                value: Some(AstNode {
                    inner: Expression::IntegerLiteral(IntegerLiteral { value: 42 }),
                    locator: 1,
                }),
            },
            locator: 0,
        }],
    )]);

    let dependency_graph = DependencyGraph::new();
    let (resolved_ast, symbol_table) = create_resolved_ast_with_symbols(
        policy,
        vec![(
            "test_func",
            SymbolKind::Function {
                parameters: vec![],
                return_type: VType::Int,
                is_finish: false,
            },
        )],
    );

    let result = analyze(resolved_ast, symbol_table, dependency_graph);
    assert!(result.is_ok());

    let analysis = result.unwrap();

    // Check that the return expression was type-checked
    assert_eq!(analysis.type_checked_ast.expression_types[&1], VType::Int);
}

#[test]
fn test_function_return_type_mismatch() {
    let policy = create_test_policy(vec![create_function(
        "test_func",
        vec![AstNode {
            inner: Statement::Return {
                value: Some(AstNode {
                    inner: Expression::BooleanLiteral(BooleanLiteral { value: true }), // Returning bool
                    locator: 1,
                }),
            },
            locator: 0,
        }],
    )]);

    let dependency_graph = DependencyGraph::new();
    let (resolved_ast, symbol_table) = create_resolved_ast_with_symbols(
        policy,
        vec![(
            "test_func",
            SymbolKind::Function {
                parameters: vec![],
                return_type: VType::Int, // But function expects int
                is_finish: false,
            },
        )],
    );

    let result = analyze(resolved_ast, symbol_table, dependency_graph);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(matches!(
        error.kind,
        SemanticAnalysisErrorKind::TypeMismatch { .. }
    ));
}

#[test]
fn test_context_validation() {
    let policy = create_test_policy(vec![AstNode {
        inner: Declaration::Action(ActionDefinition {
            identifier: Identifier::new("test_action"),
            arguments: vec![],
            statements: vec![AstNode {
                inner: Statement::Publish {
                    expression: AstNode {
                        inner: Expression::IntegerLiteral(IntegerLiteral { value: 42 }),
                        locator: 1,
                    },
                },
                locator: 0,
            }],
        }),
        locator: 0,
    }]);

    let dependency_graph = DependencyGraph::new();
    let (resolved_ast, symbol_table) = create_resolved_ast_with_symbols(
        policy,
        vec![("test_action", SymbolKind::Action { parameters: vec![] })],
    );

    let result = analyze(resolved_ast, symbol_table, dependency_graph);
    assert!(result.is_ok());
}

#[test]
fn test_empty_policy() {
    let policy = create_test_policy(vec![]);
    let dependency_graph = DependencyGraph::new();
    let (resolved_ast, symbol_table) = create_resolved_ast_with_symbols(policy, vec![]);

    let result = analyze(resolved_ast, symbol_table, dependency_graph);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert!(analysis.sorted_declarations.is_empty());
}

#[test]
fn test_complex_dependency_graph() {
    let policy = create_test_policy(vec![
        create_global_let("config", 1),
        create_global_let("logger", 2),
        create_global_let("database", 3),
        create_global_let("app", 4),
    ]);

    let mut dependency_graph = DependencyGraph::new();
    // App depends on Database and Logger
    dependency_graph.add_dependency(
        Identifier::new("app"),
        Identifier::new("database"),
        DependencyKind::Global,
    );
    dependency_graph.add_dependency(
        Identifier::new("app"),
        Identifier::new("logger"),
        DependencyKind::Global,
    );
    // Database and Logger both depend on Config
    dependency_graph.add_dependency(
        Identifier::new("database"),
        Identifier::new("config"),
        DependencyKind::Global,
    );
    dependency_graph.add_dependency(
        Identifier::new("logger"),
        Identifier::new("config"),
        DependencyKind::Global,
    );

    let (resolved_ast, symbol_table) = create_resolved_ast_with_symbols(
        policy,
        vec![
            (
                "config",
                SymbolKind::Global {
                    value_type: VType::Int,
                },
            ),
            (
                "logger",
                SymbolKind::Global {
                    value_type: VType::Int,
                },
            ),
            (
                "database",
                SymbolKind::Global {
                    value_type: VType::Int,
                },
            ),
            (
                "app",
                SymbolKind::Global {
                    value_type: VType::Int,
                },
            ),
        ],
    );

    let result = analyze(resolved_ast, symbol_table, dependency_graph);
    assert!(result.is_ok());

    let analysis = result.unwrap();

    // Check proper ordering
    let config_pos = analysis
        .sorted_declarations
        .iter()
        .position(|id| id == &Identifier::new("config"))
        .unwrap();
    let logger_pos = analysis
        .sorted_declarations
        .iter()
        .position(|id| id == &Identifier::new("logger"))
        .unwrap();
    let database_pos = analysis
        .sorted_declarations
        .iter()
        .position(|id| id == &Identifier::new("database"))
        .unwrap();
    let app_pos = analysis
        .sorted_declarations
        .iter()
        .position(|id| id == &Identifier::new("app"))
        .unwrap();

    assert!(config_pos < logger_pos);
    assert!(config_pos < database_pos);
    assert!(logger_pos < app_pos);
    assert!(database_pos < app_pos);
}
