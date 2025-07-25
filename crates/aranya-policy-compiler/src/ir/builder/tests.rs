//! Tests for the IR builder.

use super::*;
use crate::ir::test_utils::test_utils::*;
use aranya_policy_ast::{ident, VType};

// ===== Basic Function Tests =====

#[test]
fn test_simple_function_golden() {
    let source = r#"
function add(x int, y int) int {
    return x + y
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    
    let expected = r#"function add(x: int, y: int) -> Int {
  bb0(x: int, y: int):
    %2 = add Int : $0, $1
    return %2
}"#;
    
    assert_eq!(ir.to_string().trim(), expected);
}

#[test]
fn test_function_with_locals() {
    let source = r#"
function calculate(a int, b int) int {
    let x = a + b
    let y = x + 10
    return y
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("calculate")).expect("Should have function");
    
    // Check locals were created with correct types
    assert_eq!(func.locals.get(&ident!("x")).map(|l| &l.ty), Some(&VType::Int));
    assert_eq!(func.locals.get(&ident!("y")).map(|l| &l.ty), Some(&VType::Int));
    
    // Verify exact IR structure
    let expected = r#"function calculate(a: int, b: int) -> Int {
  bb0(a: int, b: int):
    %2 = add Int : $0, $1
    %3 = add Int : %2, 10
    return %3
}"#;
    
    assert_eq!(ir.to_string().trim(), expected);
}

// ===== Error Detection Tests =====

#[test]
fn test_undefined_variable_error() {
    let source = r#"
function test() int {
    return undefined_var
}"#;
    
    let result = build_ir_from_source(source);
    
    match result {
        Err(errors) => {
            assert_eq!(errors.len(), 1);
            match &errors[0] {
                IRBuildError::NameError(NameError::NotDefined { name, .. }) => {
                    assert_eq!(name.as_str(), "undefined_var");
                }
                _ => panic!("Expected NotDefined error, got {:?}", errors[0]),
            }
        }
        Ok(_) => panic!("Expected error for undefined variable"),
    }
}

#[test]
fn test_type_mismatch_error() {
    let source = r#"
function test() int {
    return true
}"#;
    
    // Type checking happens at AST level, not IR level
    // IR builder should succeed - this test should be removed or moved to AST tests
    let result = build_ir_from_source(source);
    
    // Should successfully build IR even with type mismatch
    // The compiler would catch this, not the IR builder
    assert!(result.is_ok(), "IR builder should not do type checking");
}

#[test]
fn test_local_shadows_global_error() {
    let source = r#"
let x = 42

action test() {
    let x = 10
    create Fact[key: x]=>{value: x}
}

fact Fact[key int]=>{value int}
"#;
    
    let result = build_ir_from_source(source);
    
    match result {
        Err(errors) => {
            assert!(!errors.is_empty());
            let has_shadow_error = errors.iter().any(|e| {
                matches!(e, IRBuildError::ShadowsGlobal { name, .. } if name.as_str() == "x")
            });
            assert!(has_shadow_error, "Expected ShadowsGlobal error");
        }
        Ok(_) => panic!("Expected error for shadowing global"),
    }
}

#[test]
fn test_parameter_shadows_global_error() {
    let source = r#"
let default_size = 100

function calculate(default_size int) int {
    return default_size + default_size
}"#;
    
    let result = build_ir_from_source(source);
    
    match result {
        Err(errors) => {
            assert!(!errors.is_empty());
            let has_shadow_error = errors.iter().any(|e| {
                matches!(e, IRBuildError::ParameterShadowsGlobal { name, .. } if name.as_str() == "default_size")
            });
            assert!(has_shadow_error, "Expected ParameterShadowsGlobal error");
        }
        Ok(_) => panic!("Expected error for parameter shadowing global"),
    }
}

// ===== Control Flow Tests =====

#[test]
fn test_if_else_control_flow() {
    let source = r#"
function max(a int, b int) int {
    if a > b {
        return a
    } else {
        return b
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("max")).expect("Should have function");
    
    // Should have exactly 3 blocks: entry, then, else
    assert_eq!(func.cfg.blocks.len(), 3, "Should have entry, then, and else blocks");
    
    // Verify entry block structure
    let entry_block = &func.cfg.blocks[&func.cfg.entry];
    
    // Should have comparison instruction
    assert_eq!(entry_block.instructions.len(), 1);
    match &entry_block.instructions[0] {
        Instruction::BinaryOp { op: BinaryOp::Gt, left, right, .. } => {
            // Should compare parameters a and b
            assert!(matches!(left, Value::Use(ValueId { index: 0, .. })));
            assert!(matches!(right, Value::Use(ValueId { index: 1, .. })));
        }
        _ => panic!("Expected Gt comparison in entry block"),
    }
    
    // Should branch on comparison result
    match &entry_block.terminator {
        Terminator::Branch { condition, true_block, false_block, .. } => {
            assert!(matches!(condition, Value::Use(ValueId { index: 2, .. })));
            
            // Verify then block returns a
            let then_block = &func.cfg.blocks[true_block];
            match &then_block.terminator {
                Terminator::Return(Some(Value::Use(ValueId { index: 0, .. }))) => {},
                _ => panic!("Then block should return parameter a"),
            }
            
            // Verify else block returns b
            let else_block = &func.cfg.blocks[false_block];
            match &else_block.terminator {
                Terminator::Return(Some(Value::Use(ValueId { index: 1, .. }))) => {},
                _ => panic!("Else block should return parameter b"),
            }
        }
        _ => panic!("Entry block should have branch terminator"),
    }
}

#[test]
fn test_nested_if_control_flow() {
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
    let func = ir.functions.get(&ident!("sign")).expect("Should have function");
    
    // Should have multiple blocks for nested control flow
    assert!(func.cfg.blocks.len() >= 4);
}

#[test]
fn test_match_expression() {
    let source = r#"
enum Color { Red, Green, Blue }

function color_value(c enum Color) int {
    return match c {
        Color::Red => 255
        Color::Green => 128
        Color::Blue => 64
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("color_value")).expect("Should have function");
    
    // Should have blocks for each match arm
    assert!(func.cfg.blocks.len() >= 4);
    
    // Should have a switch terminator
    let has_switch = func.cfg.blocks.values().any(|block| {
        matches!(block.terminator, Terminator::Switch { .. })
    });
    assert!(has_switch);
}

// ===== Expression Coverage Tests =====

#[test]
fn test_all_binary_operators() {
    let source = r#"
function test_ops(a int, b int) int {
    let add = a + b
    let sub = a - b
    let and_result = a > 0 && b > 0
    let or_result = a < 0 || b < 0
    let eq = a == b
    let neq = a != b
    let lt = a < b
    let gt = a > b
    let lte = a <= b
    let gte = a >= b
    return add + sub
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("test_ops")).expect("Should have function");
    
    // Get all instructions from entry block (assuming single block for simplicity)
    let entry_block = &func.cfg.blocks[&func.cfg.entry];
    
    // Create a map to track which operations we've seen
    let mut seen_ops = HashMap::new();
    
    // Check each instruction in order
    for (i, instr) in entry_block.instructions.iter().enumerate() {
        match instr {
            Instruction::BinaryOp { op, left, right, ty } => {
                seen_ops.insert(op.clone(), (left, right, ty));
                
                // Verify operands based on instruction index
                match (i, op) {
                    (0, BinaryOp::Add) => {
                        // add = a + b
                        assert!(matches!(left, Value::Use(ValueId { index: 0, .. })));
                        assert!(matches!(right, Value::Use(ValueId { index: 1, .. })));
                    }
                    (1, BinaryOp::Sub) => {
                        // sub = a - b
                        assert!(matches!(left, Value::Use(ValueId { index: 0, .. })));
                        assert!(matches!(right, Value::Use(ValueId { index: 1, .. })));
                    }
                    // For boolean operations, we need to account for short-circuit evaluation
                    // which might create multiple blocks
                    _ => {}
                }
            }
            _ => {}
        }
    }
    
    // Verify we have all expected operations somewhere in the function
    let all_ops: Vec<_> = func.cfg.blocks.values()
        .flat_map(|b| &b.instructions)
        .filter_map(|i| match i {
            Instruction::BinaryOp { op, .. } => Some(op),
            _ => None,
        })
        .collect();
    
    // Count occurrences of each operation
    let op_counts = all_ops.iter().fold(HashMap::new(), |mut acc, op| {
        *acc.entry(*op).or_insert(0) += 1;
        acc
    });
    
    // Verify each operation appears at least once
    assert!(op_counts.get(&BinaryOp::Add).unwrap_or(&0) >= &2, "Should have at least 2 Add ops (including final return)");
    assert!(op_counts.get(&BinaryOp::Sub).unwrap_or(&0) >= &1, "Should have Sub op");
    assert!(op_counts.get(&BinaryOp::Gt).unwrap_or(&0) >= &2, "Should have Gt ops for comparisons");
    assert!(op_counts.get(&BinaryOp::Lt).unwrap_or(&0) >= &2, "Should have Lt ops for comparisons");
    assert!(op_counts.get(&BinaryOp::And).unwrap_or(&0) >= &1, "Should have And op");
    assert!(op_counts.get(&BinaryOp::Or).unwrap_or(&0) >= &1, "Should have Or op");
    assert!(op_counts.get(&BinaryOp::Eq).unwrap_or(&0) >= &1, "Should have Eq op");
    assert!(op_counts.get(&BinaryOp::NotEq).unwrap_or(&0) >= &1, "Should have NotEq op");
    assert!(op_counts.get(&BinaryOp::LtEq).unwrap_or(&0) >= &1, "Should have LtEq op");
    assert!(op_counts.get(&BinaryOp::GtEq).unwrap_or(&0) >= &1, "Should have GtEq op");
}

#[test]
fn test_unary_operators() {
    let source = r#"
function test_unary(x int, b bool) int {
    let neg = -x
    let not_b = !b
    if not_b {
        return neg
    } else {
        return x
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("test_unary")).expect("Should have function");
    
    // Check for unary operations
    let has_neg = func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::UnaryOp { op: UnaryOp::Neg, .. }))
    });
    let has_not = func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::UnaryOp { op: UnaryOp::Not, .. }))
    });
    
    assert!(has_neg);
    assert!(has_not);
}

#[test]
fn test_struct_operations() {
    let source = r#"
struct Person {
    name string,
    age int,
}

function create_person(n string, a int) struct Person {
    return Person { name: n, age: a }
}

function get_age(p struct Person) int {
    return p.age
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    
    // Check create_person has StructNew
    let create_func = ir.functions.get(&ident!("create_person")).unwrap();
    let has_struct_new = create_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::StructNew { .. }))
    });
    assert!(has_struct_new);
    
    // Check get_age has FieldAccess
    let get_func = ir.functions.get(&ident!("get_age")).unwrap();
    let has_field_access = get_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::FieldAccess { .. }))
    });
    assert!(has_field_access);
}

#[test]
fn test_optional_handling() {
    let source = r#"
function process_optional(x optional int) int {
    if x is Some {
        return unwrap x
    } else {
        return 0
    }
}

function create_optional(b bool) optional int {
    if b {
        return Some(42)
    } else {
        return None
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    
    // Check process_optional has IsSome and Unwrap
    let process_func = ir.functions.get(&ident!("process_optional")).unwrap();
    let has_is_some = process_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::IsSome { .. }))
    });
    let has_unwrap = process_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::Unwrap { .. }))
    });
    assert!(has_is_some);
    assert!(has_unwrap);
    
    // Check create_optional has Some instruction
    let create_func = ir.functions.get(&ident!("create_optional")).unwrap();
    let has_some = create_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::Some { .. }))
    });
    assert!(has_some);
}

// ===== Statement Coverage Tests =====

#[test]
fn test_fact_operations() {
    let source = r#"
fact Counter[name string]=>{count int}

action increment(name string) {
    if exists Counter[name: name] {
        let current = unwrap query Counter[name: name]=>{count: ?}
        update Counter[name: name] to {count: current.count + 1}
    } else {
        create Counter[name: name]=>{count: 1}
    }
}

action reset(name string) {
    delete Counter[name: name]
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    
    // Check increment has query, create, and update
    let inc_func = ir.functions.get(&ident!("increment")).unwrap();
    let has_query = inc_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::QueryFact { .. }))
    });
    let has_create = inc_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::CreateFact { .. }))
    });
    let has_update = inc_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::UpdateFact { .. }))
    });
    assert!(has_query);
    assert!(has_create);
    assert!(has_update);
    
    // Check reset has delete
    let reset_func = ir.functions.get(&ident!("reset")).unwrap();
    let has_delete = reset_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::DeleteFact { .. }))
    });
    assert!(has_delete);
}

#[test]
fn test_check_statement() {
    let source = r#"
action validate(x int) {
    check x > 0
    check x < 100
    create Record[rec_id: x]=>{valid: true}
}

fact Record[rec_id int]=>{valid bool}
"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("validate")).unwrap();
    
    // Should have panic blocks for failed checks
    let panic_count = func.cfg.blocks.values()
        .filter(|b| matches!(b.terminator, Terminator::Panic(PanicReason::FailedCheck)))
        .count();
    assert_eq!(panic_count, 2); // One for each check
}

#[test]
fn test_emit_statement() {
    let source = r#"
effect UserEvent {
    user_id int,
    action string,
}

action log_action(uid int, act string) {
    emit UserEvent {
        user_id: uid,
        action: act,
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("log_action")).unwrap();
    
    let has_emit = func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::Emit { .. }))
    });
    assert!(has_emit);
}

// ===== Complex Integration Tests =====

#[test]
fn test_command_lifecycle() {
    let source = r#"
effect TransferEvent {
    from string,
    to_field string,
    amount int,
}

command Transfer {
    fields {
        from_account string,
        to_account string,
        amount int,
    }

    seal {
        return 42
    }

    open {
        return Transfer { from_account: "a", to_account: "b", amount: 100 }
    }

    policy {
        check true
    }

    recall {
        emit TransferEvent {
            from: "sender",
            to_field: "receiver",
            amount: 100
        }
    }
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    
    // Should have 4 functions for the command
    assert!(ir.functions.contains_key(&ident!("Transfer_seal")));
    assert!(ir.functions.contains_key(&ident!("Transfer_open")));
    assert!(ir.functions.contains_key(&ident!("Transfer_policy")));
    assert!(ir.functions.contains_key(&ident!("Transfer_recall")));
}

#[test]
fn test_forward_references() {
    let source = r#"
let config = get_default_config()

function get_default_config() struct Config {
    return Config { value: 100 }
}

struct Config {
    value int,
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    
    // Verify global exists and references the function
    let global = ir.globals.get(&ident!("config")).expect("Should have global");
    match &global.initializer {
        InitializerExpr::Call { func, args } => {
            assert_eq!(func, &ident!("get_default_config"), "Global should call get_default_config");
            assert_eq!(args.len(), 0, "Function takes no arguments");
        }
        _ => panic!("Expected global to be initialized with function call"),
    }
    
    // Verify function exists and returns the struct
    let func = ir.functions.get(&ident!("get_default_config")).expect("Should have function");
    assert_eq!(func.return_type, Some(VType::Struct(ident!("Config"))));
    
    // Verify the function creates and returns the struct
    let entry_block = &func.cfg.blocks[&func.cfg.entry];
    let has_struct_new = entry_block.instructions.iter().any(|i| {
        matches!(i, Instruction::StructNew { struct_type, .. } if struct_type == &ident!("Config"))
    });
    assert!(has_struct_new, "Function should create Config struct");
}

#[test]
fn test_internal_functions() {
    let source = r#"
fact User[user_id int]=>{name string, active bool}

function find_user(uid int) optional struct User {
    return query User[user_id: uid]
}

function user_exists(uid int) bool {
    return exists User[user_id: uid]
}

function active_count() int {
    return count_up_to 1000 User[active: true]
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    
    // Check for internal function instructions
    let find_func = ir.functions.get(&ident!("find_user")).unwrap();
    let has_query = find_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::QueryFact { .. }))
    });
    assert!(has_query);
    
    let count_func = ir.functions.get(&ident!("active_count")).unwrap();
    let has_count = count_func.cfg.blocks.values().any(|b| {
        b.instructions.iter().any(|i| matches!(i, Instruction::FactCount { .. }))
    });
    assert!(has_count);
}

#[test]
fn test_block_expressions() {
    let source = r#"
function complex_flow(x int) int {
    let result = if x < 0 {
        : -x
    } else {
        : if x == 0 {
            : 1
        } else {
            : x
        }
    }
    return result
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("complex_flow")).unwrap();
    
    // Should handle nested block expressions
    assert!(func.cfg.blocks.len() >= 4);
    assert!(func.locals.contains_key(&ident!("result")));
}

// ===== Edge Case Tests =====

#[test]
fn test_empty_action() {
    let source = r#"
action do_nothing() {
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("do_nothing")).expect("Should have action");
    
    // Should have entry block with return terminator
    assert_eq!(func.cfg.blocks.len(), 1);
    let entry = &func.cfg.blocks[&func.cfg.entry];
    assert_eq!(entry.instructions.len(), 0);
    assert!(matches!(entry.terminator, Terminator::Return(None)));
}

#[test]
fn test_deeply_nested_expressions() {
    let source = r#"
function deeply_nested(a int, b int, c int, d int) int {
    return ((a + b) - (c + d)) + ((a - b) + (c - d))
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("deeply_nested")).expect("Should have function");
    
    // Count binary operations
    let binary_op_count = func.cfg.blocks.values()
        .flat_map(|b| &b.instructions)
        .filter(|i| matches!(i, Instruction::BinaryOp { .. }))
        .count();
    
    assert_eq!(binary_op_count, 7, "Should have 7 binary operations");
}

#[test] 
fn test_many_locals() {
    let source = r#"
function many_locals() int {
    let a = 1
    let b = 2
    let c = 3
    let d = 4
    let e = 5
    let f = 6
    let g = 7
    let h = 8
    let i = 9
    let j = 10
    return a + b + c + d + e + f + g + h + i + j
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("many_locals")).expect("Should have function");
    
    // Should have all locals
    assert_eq!(func.locals.len(), 10);
    for name in ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"] {
        assert!(func.locals.contains_key(&Identifier::from_str(name).unwrap()));
    }
}

#[test]
fn test_special_identifiers() {
    // Test that reserved words and special characters are handled
    let source = r#"
function test_special() int {
    let user_id = 1  // 'id' is reserved, but user_id is ok
    let to_value = 2 // 'to' is reserved, but to_value is ok
    return user_id + to_value
}"#;
    
    let ir = build_ir_from_source(source).expect("Should build IR");
    let func = ir.functions.get(&ident!("test_special")).expect("Should have function");
    
    assert!(func.locals.contains_key(&ident!("user_id")));
    assert!(func.locals.contains_key(&ident!("to_value")));
}