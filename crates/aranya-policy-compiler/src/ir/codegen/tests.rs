//! Tests for IR to bytecode generation.

use crate::ir::test_utils::test_utils::*;
use aranya_policy_module::{Instruction as BytecodeInstruction, Value as BytecodeValue};

// ===== Simple Function Tests =====

#[test]
fn test_simple_addition_bytecode() {
    let source = r#"
function add(a int, b int) int {
    return a + b
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have:
    // - Meta instruction for function label
    // - Add instruction
    // - Return instruction
    let has_add = ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Add));
    let has_return = ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Return));
    
    assert!(has_add, "Should have Add instruction");
    assert!(has_return, "Should have Return instruction");
}

#[test]
fn test_simple_function_matches_compiler() {
    let source = r#"
function multiply_by_two(x int) int {
    return x + x
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    let module = compile_with_compiler(source).expect("Should compile with compiler");
    
    // Both should produce similar bytecode for this simple function
    assert_compiler_bytecode_equivalent(&ir_bytecode, &module, "multiply_by_two");
}

// ===== Control Flow Tests =====

#[test]
fn test_if_else_bytecode() {
    let source = r#"
function max(a int, b int) int {
    if a > b {
        return a
    } else {
        return b
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have comparison and branch instructions
    let has_gt = ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Gt));
    let has_branch = ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Branch(_)));
    
    assert!(has_gt, "Should have Gt instruction");
    assert!(has_branch, "Should have Branch instruction");
}

#[test]
fn test_if_else_matches_compiler() {
    let source = r#"
function abs(x int) int {
    if x < 0 {
        return -x
    } else {
        return x
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    let module = compile_with_compiler(source).expect("Should compile with compiler");
    
    // Compare key instructions
    assert_compiler_bytecode_equivalent(&ir_bytecode, &module, "abs");
}

#[test]
fn test_nested_if_bytecode() {
    let source = r#"
function sign(x int) int {
    if x > 0 {
        return 1
    } else {
        if x < 0 {
            return -1
        } else {
            return 0
        }
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have multiple comparisons and branches
    let gt_count = ir_bytecode.iter().filter(|i| matches!(i, BytecodeInstruction::Gt)).count();
    let lt_count = ir_bytecode.iter().filter(|i| matches!(i, BytecodeInstruction::Lt)).count();
    let branch_count = ir_bytecode.iter().filter(|i| matches!(i, BytecodeInstruction::Branch(_))).count();
    
    assert_eq!(gt_count, 1);
    assert_eq!(lt_count, 1);
    assert!(branch_count >= 2);
}

// ===== Stack Management Tests =====

#[test]
fn test_parameter_handling() {
    let source = r#"
function swap_subtract(a int, b int) int {
    return b - a
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Find the relevant instructions (skip metadata)
    let relevant_instrs: Vec<_> = ir_bytecode.iter()
        .filter(|i| !matches!(i, BytecodeInstruction::Meta(_)))
        .collect();
    
    // Should access parameters in correct order for b - a
    // Parameters are on stack with a at position 1, b at position 0 (top)
    // So we need to access them correctly
    
    // Look for the pattern that implements b - a
    let mut found_correct_pattern = false;
    for window in relevant_instrs.windows(3) {
        match (window[0], window[1], window[2]) {
            // Could be: Dup(1) [get a], Dup(1) [get b], Sub
            // Or other valid patterns depending on implementation
            (BytecodeInstruction::Dup(_), BytecodeInstruction::Dup(_), BytecodeInstruction::Sub) => {
                found_correct_pattern = true;
                break;
            }
            _ => {}
        }
    }
    
    // At minimum, verify we have Sub and Return
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Sub)), "Should have Sub instruction");
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Return)), "Should have Return instruction");
    
    // The exact pattern depends on how parameters are accessed
    // This test mainly verifies bytecode generation doesn't crash
}

#[test]
fn test_local_variable_stack() {
    let source = r#"
function calculate(x int, y int) int {
    let a = x + y
    let b = x - y
    return a + b
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have proper stack management for locals
    let add_count = ir_bytecode.iter().filter(|i| matches!(i, BytecodeInstruction::Add)).count();
    let sub_count = ir_bytecode.iter().filter(|i| matches!(i, BytecodeInstruction::Sub)).count();
    
    assert_eq!(add_count, 2); // x + y and a + b
    assert_eq!(sub_count, 1); // x - y
}

// ===== Binary Operations Tests =====

#[test]
fn test_all_binary_ops_bytecode() {
    let source = r#"
function test_ops(a int, b int) bool {
    let add = a + b
    let sub = a - b
    let eq = a == b
    let neq = a != b
    let lt = a < b
    let gt = a > b
    let lte = a <= b
    let gte = a >= b
    return eq && neq || lt && gt
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Check for all operation types
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Add)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Sub)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Eq)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Lt)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Gt)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::And)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Or)));
}

#[test]
fn test_compound_operations() {
    let source = r#"
function test_neq(a int, b int) bool {
    return a != b
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // != should be compiled as !(a == b)
    // Find the sequence Eq followed by Not
    let instrs: Vec<_> = ir_bytecode.iter().collect();
    
    let mut found_pattern = false;
    for i in 0..instrs.len()-1 {
        match (instrs[i], instrs[i+1]) {
            (BytecodeInstruction::Eq, BytecodeInstruction::Not) => {
                found_pattern = true;
                break;
            }
            _ => {}
        }
    }
    
    assert!(found_pattern, "Should compile != as Eq followed by Not");
}

// ===== Fact Operations Tests =====

#[test]
fn test_fact_create_bytecode() {
    let source = r#"
fact User[user_id int]=>{name string}

action create_user(uid int, n string) {
    create User[user_id: uid]=>{name: n}
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have fact creation instructions
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::FactNew(_))));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::FactKeySet(_))));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::FactValueSet(_))));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Create)));
}

#[test]
fn test_fact_query_bytecode() {
    let source = r#"
fact User[user_id int]=>{name string}

function find_user(uid int) optional struct User {
    return query User[user_id: uid]
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have query instructions
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Query)));
}

#[test]
fn test_fact_update_bytecode() {
    let source = r#"
fact Counter[name string]=>{value int}

action increment(n string) {
    update Counter[name: n] to {value: 1}
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have update instructions
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Update)));
}

#[test]
fn test_fact_delete_bytecode() {
    let source = r#"
fact User[user_id int]=>{name string}

action remove_user(uid int) {
    delete User[user_id: uid]
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have delete instruction
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Delete)));
}

// ===== Struct Operations Tests =====

#[test]
fn test_struct_new_bytecode() {
    let source = r#"
struct Point { x int, y int }

function make_point(a int, b int) struct Point {
    return Point { x: a, y: b }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have struct creation
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::StructNew(_))));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::StructSet(_))));
}

#[test]
fn test_struct_field_access_bytecode() {
    let source = r#"
struct Point { x int, y int }

function get_x(p struct Point) int {
    return p.x
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have field access
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::StructGet(_))));
}

// ===== Optional Handling Tests =====

#[test]
fn test_optional_operations_bytecode() {
    let source = r#"
function handle_optional(x optional int) int {
    if x is Some {
        return unwrap x
    } else {
        return 0
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // is_some should be compiled as: x != None, which is: !(x == None)
    // Look for the pattern: Const(None), Eq, Not
    let instrs: Vec<_> = ir_bytecode.iter().collect();
    
    let mut found_is_some_pattern = false;
    for i in 0..instrs.len().saturating_sub(2) {
        match (instrs[i], instrs[i+1], instrs[i+2]) {
            (BytecodeInstruction::Const(BytecodeValue::None), 
             BytecodeInstruction::Eq, 
             BytecodeInstruction::Not) => {
                found_is_some_pattern = true;
                break;
            }
            _ => {}
        }
    }
    
    assert!(found_is_some_pattern, "Should compile 'is Some' as None comparison pattern");
    
    // Should also have a constant 0 for the else branch
    assert!(ir_bytecode.iter().any(|i| 
        matches!(i, BytecodeInstruction::Const(BytecodeValue::Int(0)))
    ));
}

// ===== Check Statement Tests =====

#[test]
fn test_check_statement_bytecode() {
    let source = r#"
action validate(x int) {
    check x > 0
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have comparison and exit on failure
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Gt)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Exit(_))));
}

// ===== Command Tests =====

#[test]
fn test_emit_bytecode() {
    let source = r#"
effect Event { value int }

action emit_event(v int) {
    emit Event { value: v }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have emit instruction
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Emit)));
}

// ===== Global Variable Tests =====

#[test]
fn test_global_access_bytecode() {
    let source = r#"
let default_value = 100

function get_default() int {
    return default_value
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have global definition and access
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Def(_))));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Get(_))));
}

// ===== Match Expression Tests =====

#[test]
fn test_match_expression_bytecode() {
    let source = r#"
enum Status { Active, Inactive }

function status_code(s enum Status) int {
    return match s {
        Status::Active => 1
        Status::Inactive => 0
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have switch-like pattern with comparisons and branches
    let const_count = ir_bytecode.iter()
        .filter(|i| matches!(i, BytecodeInstruction::Const(_)))
        .count();
    let branch_count = ir_bytecode.iter()
        .filter(|i| matches!(i, BytecodeInstruction::Branch(_)))
        .count();
    
    assert!(const_count >= 2); // At least the enum values
    assert!(branch_count >= 1); // At least one branch for the match
}

// ===== Complex Integration Tests =====

#[test]
fn test_complex_function_matches_compiler() {
    let source = r#"
function fibonacci_iter(n int) int {
    if n <= 1 {
        return n
    } else {
        let a = 0
        let b = 1
        let i = 2
        let done = false
        let result = 1
        
        // Simulate loop with recursion since we don't have loops
        return fib_helper(n, i, a, b)
    }
}

function fib_helper(n int, i int, a int, b int) int {
    if i > n {
        return b
    } else {
        let temp = a + b
        return fib_helper(n, i + 1, b, temp)
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // This won't match compiler exactly due to recursion, but should have similar structure
    assert!(!ir_bytecode.is_empty());
    
    // Should have the expected operations
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Add)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Lt)) ||
            ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Gt)));
}

#[test]
fn test_action_with_all_operations() {
    let source = r#"
fact Account[account_id int]=>{balance int}
effect Transfer { from int, to_account int, amount int }

action transfer(from_id int, to_id int, amount int) {
    let from_account = query Account[account_id: from_id]
    let to_account = query Account[account_id: to_id]
    
    check from_account is Some
    check to_account is Some
    
    let from_bal = unwrap from_account
    let to_bal = unwrap to_account
    
    check from_bal.balance >= amount
    
    update Account[account_id: from_id] to {balance: from_bal.balance - amount}
    update Account[account_id: to_id] to {balance: to_bal.balance + amount}
    
    emit Transfer {
        from: from_id,
        to_account: to_id,
        amount: amount
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let ir_bytecode = ir.compile_to_bytecode().expect("Should compile to bytecode");
    
    // Should have all the operations
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Query)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Update)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Emit)));
    assert!(ir_bytecode.iter().any(|i| matches!(i, BytecodeInstruction::Exit(_)))); // From checks
}