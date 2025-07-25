//! Tests for dependency analysis and cycle detection.

use super::*;
use crate::ir::test_utils::test_utils::*;
use aranya_policy_ast::ident;

// ===== Direct Recursion Tests =====

#[test]
fn test_direct_recursion_simple() {
    let source = r#"
function factorial(n int) int {
    if n <= 1 {
        return 1
    } else {
        return n + factorial(n - 1)
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let errors = ir.analyze_dependencies().unwrap_err();
    
    assert_eq!(errors.len(), 1);
    match &errors[0] {
        DependencyError::DirectRecursion { function, .. } => {
            assert_eq!(function.as_str(), "factorial");
        }
        _ => panic!("Expected DirectRecursion error, got {:?}", errors[0]),
    }
}

#[test]
fn test_direct_recursion_fibonacci() {
    let source = r#"
function fib(n int) int {
    if n <= 1 {
        return n
    } else {
        return fib(n - 1) + fib(n - 2)
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let errors = ir.analyze_dependencies().unwrap_err();
    
    assert_eq!(errors.len(), 1);
    match &errors[0] {
        DependencyError::DirectRecursion { function, .. } => {
            assert_eq!(function.as_str(), "fib");
        }
        _ => panic!("Expected DirectRecursion error"),
    }
}

// ===== Mutual Recursion Tests =====

#[test]
fn test_mutual_recursion_two_functions() {
    let source = r#"
function is_even(n int) bool {
    if n == 0 {
        return true
    } else {
        return is_odd(n - 1)
    }
}

function is_odd(n int) bool {
    if n == 0 {
        return false
    } else {
        return is_even(n - 1)
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let errors = ir.analyze_dependencies().unwrap_err();
    
    assert_eq!(errors.len(), 1);
    match &errors[0] {
        DependencyError::MutualRecursion { cycle, .. } => {
            assert_eq!(cycle.len(), 2);
            assert!(cycle.iter().any(|f| f.as_str() == "is_even"));
            assert!(cycle.iter().any(|f| f.as_str() == "is_odd"));
        }
        _ => panic!("Expected MutualRecursion error"),
    }
}

#[test]
fn test_mutual_recursion_three_functions() {
    let source = r#"
function foo() int {
    return bar()
}

function bar() int {
    return baz()
}

function baz() int {
    return foo()
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let errors = ir.analyze_dependencies().unwrap_err();
    
    assert_eq!(errors.len(), 1);
    match &errors[0] {
        DependencyError::MutualRecursion { cycle, .. } => {
            assert_eq!(cycle.len(), 3);
            let cycle_names: Vec<_> = cycle.iter().map(|f| f.as_str()).collect();
            assert!(cycle_names.contains(&"foo"));
            assert!(cycle_names.contains(&"bar"));
            assert!(cycle_names.contains(&"baz"));
        }
        _ => panic!("Expected MutualRecursion error"),
    }
}

// ===== Global Cycle Tests =====

#[test]
fn test_global_self_reference() {
    // This should fail during building, not dependency analysis
    let source = r#"
let x = x + 1
"#;
    
    let result = build_ir_from_source(source);
    assert!(result.is_err(), "Self-referencing global should fail to build");
}

#[test]
fn test_global_mutual_reference() {
    // This should fail during building since we don't support forward references in globals
    let source = r#"
struct Point { x int, y int }
let a = Point { x: b.y, y: 0 }
let b = Point { x: 0, y: a.x }
"#;
    
    let result = build_ir_from_source(source);
    assert!(result.is_err(), "Mutually referencing globals should fail to build");
}

// ===== Mixed Dependency Tests =====

#[test]
fn test_global_function_cycle() {
    let source = r#"
let config = get_config()

function get_config() struct Config {
    return Config { value: config.value + 1 }
}

struct Config {
    value int,
}
"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let errors = ir.analyze_dependencies().unwrap_err();
    
    assert!(!errors.is_empty());
    // Should detect a complex cycle involving global 'config' and function 'get_config'
    let has_cycle = errors.iter().any(|e| {
        matches!(e, DependencyError::ComplexCycle { .. }) ||
        matches!(e, DependencyError::DirectRecursion { .. }) ||
        matches!(e, DependencyError::MutualRecursion { .. })
    });
    assert!(has_cycle, "Should detect dependency cycle");
}

#[test]
fn test_global_initializer_calling_function() {
    let source = r#"
let helper = create_helper()

function create_helper() struct Helper {
    return Helper { value: 42 }
}

struct Helper {
    value int,
}
"#;
    
    // This tests that globals can call functions (forward reference)
    let ir = build_ir_from_source(source).expect("Should build IR");
    let result = ir.analyze_dependencies();
    
    // Should succeed - no recursion here
    assert!(result.is_ok(), "Non-recursive global initialization should be allowed");
    
    // Verify the dependency exists but isn't circular
    let global = ir.globals.get(&ident!("helper")).expect("Should have global");
    match &global.initializer {
        InitializerExpr::Call { func, .. } => {
            assert_eq!(func, &ident!("create_helper"));
        }
        _ => panic!("Expected global to be initialized with function call"),
    }
}

// ===== Tarjan's Algorithm Tests =====

#[test]
fn test_tarjan_simple_dag() {
    let source = r#"
function a() int {
    return b() + c()
}

function b() int {
    return c() + d()
}

function c() int {
    return d()
}

function d() int {
    return 42
}
"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let result = ir.analyze_dependencies();
    
    assert!(result.is_ok(), "DAG should have no cycles");
}

#[test]
fn test_tarjan_complex_scc() {
    let source = r#"
function a() int {
    return b() + e()
}

function b() int {
    return c()
}

function c() int {
    return d()
}

function d() int {
    return b()  // Creates cycle: b -> c -> d -> b
}

function e() int {
    return 42
}
"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let errors = ir.analyze_dependencies().unwrap_err();
    
    assert_eq!(errors.len(), 1);
    match &errors[0] {
        DependencyError::MutualRecursion { cycle, .. } => {
            assert_eq!(cycle.len(), 3);
            
            // The cycle should be detected in a specific order based on DFS traversal
            // We need to verify the actual cycle path, not just membership
            // The cycle could be reported as [b, c, d] or [c, d, b] or [d, b, c]
            // depending on which node is discovered first
            let cycle_str = cycle.iter()
                .map(|f| f.as_str())
                .collect::<Vec<_>>()
                .join(" -> ");
            
            // Verify it's one of the valid cycle representations
            assert!(
                cycle_str == "b -> c -> d" || 
                cycle_str == "c -> d -> b" || 
                cycle_str == "d -> b -> c",
                "Expected cycle b->c->d in some rotation, got: {}",
                cycle_str
            );
            
            // Also verify that 'a' and 'e' are NOT in the cycle
            assert!(!cycle.iter().any(|f| f.as_str() == "a"));
            assert!(!cycle.iter().any(|f| f.as_str() == "e"));
        }
        _ => panic!("Expected MutualRecursion error"),
    }
}

#[test]
fn test_multiple_independent_cycles() {
    let source = r#"
// First cycle: f1 <-> f2
function f1() int {
    return f2()
}

function f2() int {
    return f1()
}

// Second cycle: f3 -> f4 -> f5 -> f3
function f3() int {
    return f4()
}

function f4() int {
    return f5()
}

function f5() int {
    return f3()
}

// Non-recursive function
function f6() int {
    return 42
}
"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let errors = ir.analyze_dependencies().unwrap_err();
    
    // Should find both cycles
    assert_eq!(errors.len(), 2);
    
    // Check that we found both cycles
    let cycle_sizes: Vec<_> = errors.iter().map(|e| {
        match e {
            DependencyError::MutualRecursion { cycle, .. } => cycle.len(),
            _ => panic!("Expected MutualRecursion errors"),
        }
    }).collect();
    
    assert!(cycle_sizes.contains(&2)); // f1 <-> f2
    assert!(cycle_sizes.contains(&3)); // f3 -> f4 -> f5 -> f3
}

// ===== Valid Dependency Patterns =====

#[test]
fn test_forward_reference_allowed() {
    let source = r#"
let x = foo()

function foo() int {
    return 42
}
"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let result = ir.analyze_dependencies();
    
    assert!(result.is_ok(), "Forward references should be allowed");
}

#[test]
fn test_complex_valid_dependencies() {
    let source = r#"
let config = get_default()

function get_default() int {
    return 100
}

function process(x int) int {
    return x + config
}

function calculate() int {
    let base = get_default()
    return process(base)
}
"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let result = ir.analyze_dependencies();
    
    assert!(result.is_ok(), "Complex non-recursive dependencies should be valid");
}

#[test]
fn test_action_dependencies() {
    let source = r#"
fact Counter[name string]=>{value int}

action increment(name string) {
    let current = get_value(name)
    update Counter[name: name] to {value: current + 1}
}

function get_value(name string) int {
    let result = query Counter[name: name]=>{value: ?}
    if result is Some {
        return unwrap result
    } else {
        return 0
    }
}
"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let result = ir.analyze_dependencies();
    
    assert!(result.is_ok(), "Action calling function should be valid");
}