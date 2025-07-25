//! Canonical display format for IR structures.
//!
//! This module provides a deterministic, human-readable text format for IR.
//! The format is designed to be:
//! - Canonical: semantically equivalent IR always produces identical text
//! - Readable: easy to understand and verify in tests
//! - Unambiguous: each construct has a clear syntax
//!
//! # IR Text Syntax
//!
//! ## Top-level Structure
//! ```text
//! global <name> : <type> = <initializer>
//! 
//! function <name>(<param>: <type>, ...) -> <type> {
//!   <basic-blocks>
//! }
//! ```
//!
//! ## Basic Blocks
//! ```text
//! bb<id>(<param>: <type>, ...):
//!   %<id> = <instruction>
//!   ...
//!   <terminator>
//! ```
//!
//! ## Values
//! - `$<n>` - Block parameter or function parameter (e.g., `$0`, `$1`)
//! - `%<n>` - SSA value produced by instruction (e.g., `%0`, `%1`)
//! - `@<name>` - Global variable reference (e.g., `@config`)
//! - `<literal>` - Constant value (e.g., `42`, `true`, `"hello"`)
//! - `undef : <type>` - Undefined value of given type
//!
//! ## Instructions
//! - Binary operations: `%<id> = <op> <type> : <left>, <right>`
//!   - Ops: `add`, `sub`, `and`, `or`, `eq`, `neq`, `lt`, `lte`, `gt`, `gte`
//! - Unary operations: `%<id> = <op> <type> : <operand>`
//!   - Ops: `not`, `neg`
//! - Function calls: `%<id> = call <target>(<args>) : <type>`
//! - Struct operations:
//!   - `%<id> = struct.new <type> {<field>: <value>, ...} : <type>`
//!   - `%<id> = field.get <type> : <object>, <field>`
//! - Fact operations:
//!   - `%<id> = query <fact>[<key>: <value>, ...]=>{{<field>: <value>, ...}} : <type>`
//!   - `create <fact>[<key>: <value>, ...]=>{{<field>: <value>, ...}}`
//!   - `update <fact>[<key>: <value>, ...] to {<field>: <value>, ...}`
//!   - `delete <pattern>`
//! - Command/Effect operations:
//!   - `publish <command>`
//!   - `emit <effect> {<field>: <value>, ...}`
//! - Optional operations:
//!   - `%<id> = some <value> : <type>`
//!   - `%<id> = is_some <value>`
//!   - `%<id> = unwrap <value> : <type>`
//! - Other operations:
//!   - `%<id> = count <fact> up to <limit> where {<field>: <value>, ...} : <type>`
//!   - `%<id> = serialize <value>`
//!   - `%<id> = deserialize <value> : <type>`
//!
//! ## Terminators
//! - `return` or `return <value>` - Return from function
//! - `jump bb<id>(<args>)` - Unconditional jump with arguments
//! - `br <cond>, bb<id>(<args>), bb<id>(<args>)` - Conditional branch
//! - `switch <value> { <const> => bb<id>(<args>), ... }` - Multi-way branch
//! - `panic <reason>` - Panic terminator
//!   - Reasons: `failed_check`, `no_match_arm`, `unwrap_none`, `assertion_failed`, `exit`
//!
//! ## Types
//! Types are displayed as their AST representation (e.g., `Int`, `Bool`, `String`)
//!
//! ## Ordering
//! For canonical output:
//! - Globals are sorted alphabetically by name
//! - Functions are sorted alphabetically by name
//! - Basic blocks are sorted by ID (bb0, bb1, ...)
//! - Struct fields in literals are sorted alphabetically
//! - Fact key/value constraints are sorted alphabetically

use std::fmt;
use aranya_policy_ast::{Identifier, VType};
use crate::ir::*;

impl fmt::Display for IR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Sort globals by name for deterministic output
        let mut globals: Vec<_> = self.globals.iter().collect();
        globals.sort_by_key(|(name, _)| name.as_str());
        
        // Display globals first
        for (name, global) in globals {
            writeln!(f, "global {} : {} = {}", name, display_type(&global.ty), global.initializer)?;
        }
        
        // Sort functions by name for deterministic output
        let mut functions: Vec<_> = self.functions.iter().collect();
        functions.sort_by_key(|(name, _)| name.as_str());
        
        // Display functions
        for (i, (name, function)) in functions.iter().enumerate() {
            if i > 0 || !self.globals.is_empty() {
                writeln!(f)?; // Blank line between items
            }
            write!(f, "{}", FunctionDisplay { name, function })?;
        }
        
        Ok(())
    }
}

/// Helper struct to display a function with its name.
struct FunctionDisplay<'a> {
    name: &'a Identifier,
    function: &'a Function,
}

impl<'a> fmt::Display for FunctionDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Function signature
        write!(f, "function {}(", self.name)?;
        for (i, param) in self.function.params.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}: {}", param.name, display_type(&param.ty))?;
        }
        write!(f, ")")?;
        
        // Return type
        if let Some(ret_ty) = &self.function.return_type {
            write!(f, " -> {}", display_type(ret_ty))?;
        }
        
        writeln!(f, " {{")?;
        
        // Sort blocks by ID for deterministic output
        let mut blocks: Vec<_> = self.function.cfg.blocks.iter().collect();
        blocks.sort_by_key(|(id, _)| id.0);
        
        // Display blocks
        for (i, (block_id, block)) in blocks.iter().enumerate() {
            if i > 0 {
                writeln!(f)?; // Blank line between blocks
            }
            write!(f, "{}", BlockDisplay { 
                block_id, 
                block,
                function: self.function,
                indent: 2 
            })?;
        }
        
        writeln!(f, "}}")?;
        Ok(())
    }
}

/// Helper struct to display a basic block.
struct BlockDisplay<'a> {
    block_id: &'a BlockId,
    block: &'a BasicBlock,
    function: &'a Function,
    indent: usize,
}

impl<'a> fmt::Display for BlockDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let indent = " ".repeat(self.indent);
        
        // Block header with parameters
        write!(f, "{}bb{}(", indent, self.block_id.0)?;
        for (i, param) in self.block.params.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}: {}", param.name, display_type(&param.ty))?;
        }
        writeln!(f, "):")?;
        
        // Instructions
        for (i, instr) in self.block.instructions.iter().enumerate() {
            let value_id = ValueId {
                block: *self.block_id,
                index: self.block.params.len() + i,
            };
            write!(f, "{}  ", indent)?;
            write!(f, "{}", InstructionDisplay { 
                instruction: instr, 
                value_id,
                function: self.function 
            })?;
            writeln!(f)?;
        }
        
        // Terminator
        write!(f, "{}  ", indent)?;
        write!(f, "{}", TerminatorDisplay { 
            terminator: &self.block.terminator,
            function: self.function
        })?;
        
        Ok(())
    }
}

/// Helper struct to display an instruction.
struct InstructionDisplay<'a> {
    instruction: &'a Instruction,
    value_id: ValueId,
    function: &'a Function,
}

impl<'a> fmt::Display for InstructionDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "%{} = ", self.value_id.index)?;
        
        match self.instruction {
            Instruction::BinaryOp { op, left, right, ty } => {
                write!(f, "{} {} : {}, {}", 
                    display_binary_op(op), 
                    display_type(ty),
                    display_value(left),
                    display_value(right)
                )
            }
            
            Instruction::UnaryOp { op, operand, ty } => {
                write!(f, "{} {} : {}", 
                    display_unary_op(op),
                    display_type(ty),
                    display_value(operand)
                )
            }
            
            Instruction::Call { target, args, ty } => {
                write!(f, "call {}", display_call_target(target))?;
                write!(f, "(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", display_value(arg))?;
                }
                write!(f, ") : {}", display_type(ty))
            }
            
            Instruction::StructNew { struct_type, fields, ty } => {
                write!(f, "struct.new {} {{", struct_type)?;
                let mut sorted_fields: Vec<_> = fields.iter().collect();
                sorted_fields.sort_by_key(|(name, _)| name.as_str());
                for (i, (field_name, field_value)) in sorted_fields.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field_name, display_value(field_value))?;
                }
                write!(f, "}} : {}", display_type(ty))
            }
            
            Instruction::FieldAccess { object, field, ty } => {
                write!(f, "field.get {} : {}, {}", 
                    display_type(ty),
                    display_value(object),
                    field
                )
            }
            
            Instruction::QueryFact { fact_type, key_constraints, value_constraints, ty } => {
                write!(f, "query {}", fact_type)?;
                write!(f, "[")?;
                let mut sorted_keys: Vec<_> = key_constraints.iter().collect();
                sorted_keys.sort_by_key(|(name, _)| name.as_str());
                for (i, (field, value)) in sorted_keys.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field, display_value(value))?;
                }
                write!(f, "]=>{{")?;
                let mut sorted_values: Vec<_> = value_constraints.iter().collect();
                sorted_values.sort_by_key(|(name, _)| name.as_str());
                for (i, (field, value)) in sorted_values.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field, display_value(value))?;
                }
                write!(f, "}} : {}", display_type(ty))
            }
            
            Instruction::CreateFact { fact_type, key_fields, value_fields } => {
                write!(f, "create {}", fact_type)?;
                write!(f, "[")?;
                let mut sorted_keys: Vec<_> = key_fields.iter().collect();
                sorted_keys.sort_by_key(|(name, _)| name.as_str());
                for (i, (field, value)) in sorted_keys.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field, display_value(value))?;
                }
                write!(f, "]=>{{")?;
                let mut sorted_values: Vec<_> = value_fields.iter().collect();
                sorted_values.sort_by_key(|(name, _)| name.as_str());
                for (i, (field, value)) in sorted_values.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field, display_value(value))?;
                }
                write!(f, "}}")
            }
            
            Instruction::UpdateFact { fact_type, key_fields, value_updates } => {
                write!(f, "update {}", fact_type)?;
                write!(f, "[")?;
                let mut sorted_keys: Vec<_> = key_fields.iter().collect();
                sorted_keys.sort_by_key(|(name, _)| name.as_str());
                for (i, (field, value)) in sorted_keys.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field, display_value(value))?;
                }
                write!(f, "] to {{")?;
                let mut sorted_updates: Vec<_> = value_updates.iter().collect();
                sorted_updates.sort_by_key(|(name, _)| name.as_str());
                for (i, (field, value)) in sorted_updates.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field, display_value(value))?;
                }
                write!(f, "}}")
            }
            
            Instruction::DeleteFact { fact_pattern } => {
                write!(f, "delete {}", display_value(fact_pattern))
            }
            
            Instruction::Publish { command } => {
                write!(f, "publish {}", display_value(command))
            }
            
            Instruction::Emit { effect_type, fields } => {
                write!(f, "emit {} {{", effect_type)?;
                let mut sorted_fields: Vec<_> = fields.iter().collect();
                sorted_fields.sort_by_key(|(name, _)| name.as_str());
                for (i, (field, value)) in sorted_fields.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field, display_value(value))?;
                }
                write!(f, "}}")
            }
            
            Instruction::FactCount { fact_type, constraints, limit, ty } => {
                write!(f, "count {} up to {}", fact_type, limit)?;
                if !constraints.is_empty() {
                    write!(f, " where {{")?;
                    let mut sorted: Vec<_> = constraints.iter().collect();
                    sorted.sort_by_key(|(name, _)| name.as_str());
                    for (i, (field, value)) in sorted.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}: {}", field, display_value(value))?;
                    }
                    write!(f, "}}")?;
                }
                write!(f, " : {}", display_type(ty))
            }
            
            Instruction::Some { value, ty } => {
                write!(f, "some {} : {}", display_value(value), display_type(ty))
            }
            
            Instruction::IsSome { value } => {
                write!(f, "is_some {}", display_value(value))
            }
            
            Instruction::Unwrap { value, ty } => {
                write!(f, "unwrap {} : {}", display_value(value), display_type(ty))
            }
            
            Instruction::Serialize { value } => {
                write!(f, "serialize {}", display_value(value))
            }
            
            Instruction::Deserialize { value, ty } => {
                write!(f, "deserialize {} : {}", display_value(value), display_type(ty))
            }
        }
    }
}

/// Helper struct to display a terminator.
struct TerminatorDisplay<'a> {
    terminator: &'a Terminator,
    function: &'a Function,
}

impl<'a> fmt::Display for TerminatorDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.terminator {
            Terminator::Return(value) => {
                write!(f, "return")?;
                if let Some(v) = value {
                    write!(f, " {}", display_value(v))?;
                }
                Ok(())
            }
            
            Terminator::Jump { target, args } => {
                write!(f, "jump bb{}(", target.0)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", display_value(arg))?;
                }
                write!(f, ")")
            }
            
            Terminator::Branch { condition, true_block, true_args, false_block, false_args } => {
                write!(f, "br {}, bb{}(", display_value(condition), true_block.0)?;
                for (i, arg) in true_args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", display_value(arg))?;
                }
                write!(f, "), bb{}(", false_block.0)?;
                for (i, arg) in false_args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", display_value(arg))?;
                }
                write!(f, ")")
            }
            
            Terminator::Switch { scrutinee, cases, default } => {
                write!(f, "switch {} {{", display_value(scrutinee))?;
                for case in cases {
                    write!(f, " {} => bb{}(", display_const(&case.value), case.block.0)?;
                    for (i, arg) in case.args.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", display_value(arg))?;
                    }
                    write!(f, "),")?;
                }
                if let Some((default_block, default_args)) = default {
                    write!(f, " _ => bb{}(", default_block.0)?;
                    for (i, arg) in default_args.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", display_value(arg))?;
                    }
                    write!(f, ")")?;
                }
                write!(f, " }}")
            }
            
            Terminator::Panic(reason) => {
                write!(f, "panic {}", display_panic_reason(reason))
            }
        }
    }
}

impl fmt::Display for InitializerExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitializerExpr::Const(value) => write!(f, "{}", display_const(value)),
            InitializerExpr::GlobalRef(name) => write!(f, "@{}", name),
            InitializerExpr::Struct { ty, fields } => {
                write!(f, "{} {{", ty)?;
                let mut sorted: Vec<_> = fields.iter().collect();
                sorted.sort_by_key(|(name, _)| name.as_str());
                for (i, (field, value)) in sorted.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field, value)?;
                }
                write!(f, "}}")
            }
            InitializerExpr::Call { func, args } => {
                write!(f, "{}(", func)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ")")
            }
        }
    }
}

// Helper functions for display

#[cfg(test)]
mod tests;

pub(crate) fn display_type(ty: &VType) -> String {
    format!("{:?}", ty) // TODO: Implement proper type display
}

pub(crate) fn display_value(value: &Value) -> String {
    match value {
        Value::Const(c) => display_const(c),
        Value::Use(id) => {
            if id.block == BlockId(0) && id.index < 10 {
                // Likely a parameter, use parameter syntax
                format!("${}", id.index)
            } else {
                format!("%{}", id.index)
            }
        }
        Value::GlobalRef(name) => format!("@{}", name),
        Value::Undef(ty) => format!("undef : {}", display_type(ty)),
    }
}

pub(crate) fn display_const(value: &ConstValue) -> String {
    match value {
        ConstValue::Int(n) => n.to_string(),
        ConstValue::Bool(b) => b.to_string(),
        ConstValue::String(s) => format!("{:?}", s), // Quoted string
        ConstValue::Bytes(b) => format!("bytes[{}]", b.len()),
        ConstValue::None => "none".to_string(),
        ConstValue::Enum(name, variant) => format!("{}::{}", name, variant),
    }
}

pub(crate) fn display_binary_op(op: &BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "add",
        BinaryOp::Sub => "sub",
        BinaryOp::And => "and",
        BinaryOp::Or => "or",
        BinaryOp::Eq => "eq",
        BinaryOp::NotEq => "neq",
        BinaryOp::Lt => "lt",
        BinaryOp::LtEq => "lte",
        BinaryOp::Gt => "gt",
        BinaryOp::GtEq => "gte",
        BinaryOp::Mul => "mul",
        BinaryOp::Div => "div",
        BinaryOp::Mod => "mod",
    }
}

pub(crate) fn display_unary_op(op: &UnaryOp) -> &'static str {
    match op {
        UnaryOp::Not => "not",
        UnaryOp::Neg => "neg",
    }
}

pub(crate) fn display_call_target(target: &CallTarget) -> String {
    match target {
        CallTarget::Function(name) => name.to_string(),
        CallTarget::FFI(module, func) => format!("{}::{}", module, func),
    }
}

pub(crate) fn display_panic_reason(reason: &PanicReason) -> &'static str {
    match reason {
        PanicReason::FailedCheck => "failed_check",
        PanicReason::NoMatchArm => "no_match_arm",
        PanicReason::UnwrapNone => "unwrap_none",
        PanicReason::AssertionFailed => "assertion_failed",
        PanicReason::Exit => "exit",
    }
}