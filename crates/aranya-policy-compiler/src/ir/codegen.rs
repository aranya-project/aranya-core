//! Code generation from IR to bytecode instructions.

use std::collections::HashMap;
use std::str::FromStr;
use aranya_policy_ast::{Identifier, ident};
use aranya_policy_module::{Instruction as BytecodeInstruction, Value as BytecodeValue, Target, ExitReason, Label, LabelType};
use crate::ir::*;
use crate::ir::error::CodegenError;

#[cfg(test)]
mod tests;

/// State for code generation.
struct CodegenState {
    /// Current write pointer (instruction address).
    wp: usize,
    
    /// Instructions generated so far.
    instructions: Vec<BytecodeInstruction>,
    
    /// Mapping from blocks to instruction addresses.
    block_addresses: HashMap<BlockId, usize>,
    
    /// Mapping from values to stack positions.
    value_stack: ValueStack,
    
    /// Label counter for generating unique labels.
    label_counter: u32,
}

/// Tracks where values are on the stack.
struct ValueStack {
    /// Maps SSA values to their relative stack positions.
    positions: HashMap<ValueId, i32>,
    
    /// Current stack depth.
    depth: i32,
}

impl ValueStack {
    fn new() -> Self {
        Self {
            positions: HashMap::new(),
            depth: 0,
        }
    }
    
    fn push(&mut self, value_id: ValueId) {
        self.positions.insert(value_id, self.depth);
        self.depth += 1;
    }
    
    fn get_position(&self, value_id: ValueId) -> Option<i32> {
        self.positions.get(&value_id).map(|&pos| self.depth - pos - 1)
    }
    
    fn pop(&mut self) {
        self.depth -= 1;
    }
    
    fn mark_parameter(&mut self, value_id: ValueId, stack_position: usize) {
        // Parameters are already on the stack when function starts
        // Record their position
        self.positions.insert(value_id, stack_position as i32);
    }
}

/// Compile IR to bytecode instructions.
pub fn compile_ir_to_bytecode(ir: &IR) -> Result<Vec<BytecodeInstruction>, Vec<CodegenError>> {
    let mut errors = Vec::new();
    let mut all_instructions = Vec::new();
    
    // Compile globals first
    for (name, global) in &ir.globals {
        match compile_global(name, global) {
            Ok(mut instrs) => all_instructions.append(&mut instrs),
            Err(e) => errors.push(e),
        }
    }
    
    // Compile each function
    for (name, function) in &ir.functions {
        match compile_function(name, function) {
            Ok(mut instrs) => all_instructions.append(&mut instrs),
            Err(e) => errors.push(e),
        }
    }
    
    if errors.is_empty() {
        Ok(all_instructions)
    } else {
        Err(errors)
    }
}

/// Compile a global variable.
fn compile_global(name: &Identifier, global: &Global) -> Result<Vec<BytecodeInstruction>, CodegenError> {
    let mut state = CodegenState::new();
    
    // Compile initializer
    compile_initializer_expr(&mut state, &global.initializer)?;
    
    // Define the global
    state.emit(BytecodeInstruction::Def(name.clone()));
    
    Ok(state.instructions)
}

/// Compile an initializer expression.
fn compile_initializer_expr(state: &mut CodegenState, expr: &InitializerExpr) -> Result<(), CodegenError> {
    match expr {
        InitializerExpr::Const(value) => {
            let bytecode_value = const_to_bytecode(value)?;
            state.emit(BytecodeInstruction::Const(bytecode_value));
        }
        
        InitializerExpr::GlobalRef(name) => {
            state.emit(BytecodeInstruction::Get(name.clone()));
        }
        
        InitializerExpr::Struct { ty, fields } => {
            state.emit(BytecodeInstruction::StructNew(ty.clone()));
            for (field_name, field_value) in fields {
                compile_initializer_expr(state, field_value)?;
                state.emit(BytecodeInstruction::StructSet(field_name.clone()));
            }
        }
        
        InitializerExpr::Call { func, args } => {
            for arg in args {
                compile_initializer_expr(state, arg)?;
            }
            let label = Label {
                name: func.clone(),
                ltype: LabelType::Function,
            };
            state.emit(BytecodeInstruction::Call(Target::Unresolved(label)));
        }
    }
    
    Ok(())
}

/// Compile a function.
fn compile_function(name: &Identifier, function: &Function) -> Result<Vec<BytecodeInstruction>, CodegenError> {
    let mut state = CodegenState::new();
    
    // Initialize stack depth to account for parameters
    state.value_stack.depth = function.params.len() as i32;
    
    // Add function label
    state.emit(BytecodeInstruction::Meta(aranya_policy_module::Meta::Let(name.clone())));
    
    // First pass: assign addresses to blocks
    let mut block_order = vec![function.cfg.entry];
    let mut visited = std::collections::HashSet::new();
    visited.insert(function.cfg.entry);
    
    // DFS to get block order
    let mut stack = vec![function.cfg.entry];
    while let Some(block_id) = stack.pop() {
        let block = function.cfg.blocks.get(&block_id)
            .ok_or_else(|| CodegenError::BlockNotFound(block_id))?;
        
        // Get successor blocks
        let successors = match &block.terminator {
            Terminator::Jump { target, .. } => vec![*target],
            Terminator::Branch { true_block, false_block, .. } => vec![*true_block, *false_block],
            Terminator::Switch { cases, default, .. } => {
                let mut blocks = cases.iter().map(|c| c.block).collect::<Vec<_>>();
                if let Some((default_block, _)) = default {
                    blocks.push(*default_block);
                }
                blocks
            }
            _ => vec![],
        };
        
        for succ in successors {
            if !visited.contains(&succ) {
                visited.insert(succ);
                block_order.push(succ);
                stack.push(succ);
            }
        }
    }
    
    // Second pass: compile blocks
    for block_id in block_order {
        state.block_addresses.insert(block_id, state.wp);
        
        let block = function.cfg.blocks.get(&block_id)
            .ok_or_else(|| CodegenError::BlockNotFound(block_id))?;
        
        // Handle block parameters
        if block_id == function.cfg.entry {
            // For the entry block, parameters are function arguments
            // They're already on the stack when the function is called
            // We just need to record their positions for SSA references
            for (i, _param) in block.params.iter().enumerate() {
                let param_value_id = ValueId {
                    block: block_id,
                    index: i,
                };
                // Mark this value as being at a specific stack position
                // In a stack-based VM, parameter 0 is deepest, parameter n-1 is on top
                // We need to track this for when values reference these parameters
                state.value_stack.mark_parameter(param_value_id, block.params.len() - 1 - i);
            }
        } else {
            // For non-entry blocks, block parameters are phi nodes
            // They should be handled by the jumps to this block
            for _param in &block.params {
                // TODO: Handle phi nodes properly
            }
        }
        
        // Compile instructions
        for (i, instruction) in block.instructions.iter().enumerate() {
            let value_id = ValueId {
                block: block_id,
                index: block.params.len() + i,
            };
            compile_instruction(&mut state, instruction, Some(value_id))?;
        }
        
        // Compile terminator
        compile_terminator(&mut state, &block.terminator)?;
    }
    
    // Third pass: resolve jump targets
    resolve_targets(&mut state)?;
    
    Ok(state.instructions)
}

/// Compile a single instruction.
fn compile_instruction(state: &mut CodegenState, instruction: &Instruction, value_id: Option<ValueId>) -> Result<(), CodegenError> {
    match instruction {
        Instruction::BinaryOp { op, left, right, .. } => {
            compile_value(state, left)?;
            compile_value(state, right)?;
            
            let bytecode_op = match op {
                BinaryOp::Add => BytecodeInstruction::Add,
                BinaryOp::Sub => BytecodeInstruction::Sub,
                BinaryOp::And => BytecodeInstruction::And,
                BinaryOp::Or => BytecodeInstruction::Or,
                BinaryOp::Eq => BytecodeInstruction::Eq,
                BinaryOp::Lt => BytecodeInstruction::Lt,
                BinaryOp::Gt => BytecodeInstruction::Gt,
                BinaryOp::NotEq => {
                    // Implement as !(a == b)
                    state.emit(BytecodeInstruction::Eq);
                    BytecodeInstruction::Not
                }
                BinaryOp::LtEq => {
                    // Implement as !(a > b)
                    state.emit(BytecodeInstruction::Gt);
                    BytecodeInstruction::Not
                }
                BinaryOp::GtEq => {
                    // Implement as !(a < b)
                    state.emit(BytecodeInstruction::Lt);
                    BytecodeInstruction::Not
                }
                _ => return Err(CodegenError::UnsupportedFeature(format!("Binary op: {:?}", op))),
            };
            
            state.emit(bytecode_op);
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::UnaryOp { op, operand, .. } => {
            compile_value(state, operand)?;
            
            let bytecode_op = match op {
                UnaryOp::Not => BytecodeInstruction::Not,
                UnaryOp::Neg => {
                    // Implement negation as 0 - x
                    state.emit(BytecodeInstruction::Const(BytecodeValue::Int(0)));
                    state.emit(BytecodeInstruction::Swap(0));
                    BytecodeInstruction::Sub
                }
            };
            
            state.emit(bytecode_op);
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::Call { target, args, .. } => {
            // Push arguments
            for arg in args {
                compile_value(state, arg)?;
            }
            
            // Emit call
            match target {
                CallTarget::Function(name) => {
                    let label = Label {
                        name: name.clone(),
                        ltype: LabelType::Function,
                    };
                    state.emit(BytecodeInstruction::Call(Target::Unresolved(label)));
                }
                CallTarget::FFI(module, func) => {
                    state.emit(BytecodeInstruction::Meta(aranya_policy_module::Meta::FFI(
                        module.clone(),
                        func.clone(),
                    )));
                    // FFI calls would need module/procedure indices
                    return Err(CodegenError::UnsupportedFeature("FFI calls".to_string()));
                }
            }
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::StructNew { struct_type, fields, .. } => {
            state.emit(BytecodeInstruction::StructNew(struct_type.clone()));
            
            for (field_name, field_value) in fields {
                compile_value(state, field_value)?;
                state.emit(BytecodeInstruction::StructSet(field_name.clone()));
            }
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::FieldAccess { object, field, .. } => {
            compile_value(state, object)?;
            state.emit(BytecodeInstruction::StructGet(field.clone()));
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::QueryFact { fact_type, key_constraints, value_constraints, .. } => {
            // Create fact pattern
            state.emit(BytecodeInstruction::FactNew(fact_type.clone()));
            
            for (field, value) in key_constraints {
                compile_value(state, value)?;
                state.emit(BytecodeInstruction::FactKeySet(field.clone()));
            }
            
            for (field, value) in value_constraints {
                compile_value(state, value)?;
                state.emit(BytecodeInstruction::FactValueSet(field.clone()));
            }
            
            state.emit(BytecodeInstruction::Query);
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::CreateFact { fact_type, key_fields, value_fields } => {
            state.emit(BytecodeInstruction::FactNew(fact_type.clone()));
            
            for (field, value) in key_fields {
                compile_value(state, value)?;
                state.emit(BytecodeInstruction::FactKeySet(field.clone()));
            }
            
            for (field, value) in value_fields {
                compile_value(state, value)?;
                state.emit(BytecodeInstruction::FactValueSet(field.clone()));
            }
            
            state.emit(BytecodeInstruction::Create);
        }
        
        Instruction::Publish { command } => {
            compile_value(state, command)?;
            state.emit(BytecodeInstruction::Publish);
        }
        
        Instruction::UpdateFact { fact_type, key_fields, value_updates } => {
            state.emit(BytecodeInstruction::FactNew(fact_type.clone()));
            
            for (field, value) in key_fields {
                compile_value(state, value)?;
                state.emit(BytecodeInstruction::FactKeySet(field.clone()));
            }
            
            for (field, value) in value_updates {
                compile_value(state, value)?;
                state.emit(BytecodeInstruction::FactValueSet(field.clone()));
            }
            
            state.emit(BytecodeInstruction::Update);
        }
        
        Instruction::DeleteFact { fact_pattern } => {
            compile_value(state, fact_pattern)?;
            state.emit(BytecodeInstruction::Delete);
        }
        
        Instruction::Emit { effect_type, fields } => {
            // Create effect struct
            state.emit(BytecodeInstruction::StructNew(effect_type.clone()));
            
            for (field_name, field_value) in fields {
                compile_value(state, field_value)?;
                state.emit(BytecodeInstruction::StructSet(field_name.clone()));
            }
            
            state.emit(BytecodeInstruction::Emit);
        }
        
        Instruction::FactCount { fact_type, constraints, limit, .. } => {
            state.emit(BytecodeInstruction::FactNew(fact_type.clone()));
            
            for (field, value) in constraints {
                compile_value(state, value)?;
                state.emit(BytecodeInstruction::FactKeySet(field.clone()));
            }
            
            state.emit(BytecodeInstruction::FactCount(*limit));
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::Some { value, .. } => {
            compile_value(state, value)?;
            // Optional wrapping is implicit in the VM
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::IsSome { value } => {
            compile_value(state, value)?;
            // Check if not None
            state.emit(BytecodeInstruction::Const(BytecodeValue::None));
            state.emit(BytecodeInstruction::Eq);
            state.emit(BytecodeInstruction::Not);
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::Unwrap { value, .. } => {
            compile_value(state, value)?;
            // Unwrap is done by checking for None and potentially panicking
            // For now, we'll assume the VM handles this
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::Serialize { value } => {
            compile_value(state, value)?;
            state.emit(BytecodeInstruction::Serialize);
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
        
        Instruction::Deserialize { value, .. } => {
            compile_value(state, value)?;
            state.emit(BytecodeInstruction::Deserialize);
            
            if let Some(id) = value_id {
                state.value_stack.push(id);
            }
        }
    }
    
    Ok(())
}

/// Compile a value.
fn compile_value(state: &mut CodegenState, value: &Value) -> Result<(), CodegenError> {
    match value {
        Value::Const(c) => {
            let bytecode_value = const_to_bytecode(c)?;
            state.emit(BytecodeInstruction::Const(bytecode_value));
        }
        
        Value::Use(id) => {
            // Look up where this value is on the stack
            if let Some(position) = state.value_stack.get_position(*id) {
                if position > 0 {
                    state.emit(BytecodeInstruction::Dup(position as usize));
                }
                // If position is 0, value is already on top of stack
            } else {
                return Err(CodegenError::InvalidIR(format!("Value {:?} not found on stack", id)));
            }
        }
        
        Value::GlobalRef(name) => {
            state.emit(BytecodeInstruction::Get(name.clone()));
        }
        
        Value::Undef(_) => {
            return Err(CodegenError::InvalidIR("Undefined value in code generation".to_string()));
        }
    }
    
    Ok(())
}

/// Compile a terminator.
fn compile_terminator(state: &mut CodegenState, terminator: &Terminator) -> Result<(), CodegenError> {
    match terminator {
        Terminator::Return(value) => {
            if let Some(v) = value {
                compile_value(state, v)?;
            }
            state.emit(BytecodeInstruction::Return);
        }
        
        Terminator::Jump { target, args } => {
            // Push phi arguments
            for arg in args {
                compile_value(state, arg)?;
            }
            
            let label = state.block_label(*target);
            state.emit(BytecodeInstruction::Jump(Target::Unresolved(label)));
        }
        
        Terminator::Branch { condition, true_block, true_args, false_block, false_args } => {
            compile_value(state, condition)?;
            
            // For simplicity, we'll use a pattern where we branch to false if condition is false
            let false_label = state.block_label(*false_block);
            state.emit(BytecodeInstruction::Not);
            state.emit(BytecodeInstruction::Branch(Target::Unresolved(false_label.clone())));
            
            // True path: push args and jump
            for arg in true_args {
                compile_value(state, arg)?;
            }
            let true_label = state.block_label(*true_block);
            state.emit(BytecodeInstruction::Jump(Target::Unresolved(true_label)));
            
            // False path label will be resolved later
            state.emit(BytecodeInstruction::Meta(aranya_policy_module::Meta::Let(false_label.name)));
            
            // Push false args
            for arg in false_args {
                compile_value(state, arg)?;
            }
        }
        
        Terminator::Switch { scrutinee: _, cases, default } => {
            // For each case, duplicate scrutinee and compare
            for case in cases {
                state.emit(BytecodeInstruction::Dup(0));
                let case_value = const_to_bytecode(&case.value)?;
                state.emit(BytecodeInstruction::Const(case_value));
                state.emit(BytecodeInstruction::Eq);
                
                let case_label = state.block_label(case.block);
                state.emit(BytecodeInstruction::Branch(Target::Unresolved(case_label)));
            }
            
            // Default case or panic
            if let Some((default_block, default_args)) = default {
                state.emit(BytecodeInstruction::Pop); // Remove scrutinee
                for arg in default_args {
                    compile_value(state, arg)?;
                }
                let default_label = state.block_label(*default_block);
                state.emit(BytecodeInstruction::Jump(Target::Unresolved(default_label)));
            } else {
                state.emit(BytecodeInstruction::Exit(ExitReason::Panic));
            }
        }
        
        Terminator::Panic(reason) => {
            let exit_reason = match reason {
                PanicReason::FailedCheck => ExitReason::Check,
                PanicReason::NoMatchArm | PanicReason::UnwrapNone => ExitReason::Panic,
                PanicReason::AssertionFailed => ExitReason::Check,
                PanicReason::Exit => ExitReason::Normal,
            };
            state.emit(BytecodeInstruction::Exit(exit_reason));
        }
    }
    
    Ok(())
}

/// Convert IR constant to bytecode value.
fn const_to_bytecode(value: &ConstValue) -> Result<BytecodeValue, CodegenError> {
    Ok(match value {
        ConstValue::Int(n) => BytecodeValue::Int(*n),
        ConstValue::Bool(b) => BytecodeValue::Bool(*b),
        ConstValue::String(s) => BytecodeValue::String(s.clone()),
        ConstValue::Bytes(b) => BytecodeValue::Bytes(b.clone()),
        ConstValue::None => BytecodeValue::None,
        ConstValue::Enum(name, variant) => BytecodeValue::Enum(name.clone(), (*variant).into()),
    })
}

/// Resolve jump targets.
fn resolve_targets(state: &mut CodegenState) -> Result<(), CodegenError> {
    // Convert block addresses to instruction addresses
    let mut label_addresses = HashMap::new();
    let block_addresses = state.block_addresses.clone();
    for (block_id, address) in &block_addresses {
        let label = state.block_label(*block_id);
        label_addresses.insert(label.name.clone(), *address);
    }
    
    // Update all unresolved targets
    for (_i, instruction) in state.instructions.iter_mut().enumerate() {
        match instruction {
            BytecodeInstruction::Jump(Target::Unresolved(label)) |
            BytecodeInstruction::Branch(Target::Unresolved(label)) |
            BytecodeInstruction::Call(Target::Unresolved(label)) => {
                if let Some(&address) = label_addresses.get(&label.name) {
                    let target = Target::Resolved(address);
                    match instruction {
                        BytecodeInstruction::Jump(t) => *t = target,
                        BytecodeInstruction::Branch(t) => *t = target,
                        BytecodeInstruction::Call(t) => *t = target,
                        _ => unreachable!(),
                    }
                } else {
                    return Err(CodegenError::InvalidIR(format!("Unresolved label: {}", label.name)));
                }
            }
            _ => {}
        }
    }
    
    Ok(())
}

impl CodegenState {
    fn new() -> Self {
        Self {
            wp: 0,
            instructions: Vec::new(),
            block_addresses: HashMap::new(),
            value_stack: ValueStack::new(),
            label_counter: 0,
        }
    }
    
    fn emit(&mut self, instruction: BytecodeInstruction) {
        self.instructions.push(instruction);
        self.wp += 1;
    }
    
    fn block_label(&mut self, block_id: BlockId) -> Label {
        // Create a unique label for each block
        // Since identifiers must start with a letter, prefix with "block_"
        let name = Identifier::from_str(&format!("block_{}", block_id.0))
            .unwrap_or_else(|_| ident!("block"));
        Label {
            name,
            ltype: LabelType::Temporary,
        }
    }
}