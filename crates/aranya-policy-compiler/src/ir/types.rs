//! Core type definitions for the IR.

use std::collections::HashMap;
use aranya_policy_ast::{Identifier, VType, Text};

/// A function in the IR.
#[derive(Debug, Clone)]
pub struct Function {
    pub name: Identifier,
    pub params: Vec<Parameter>,
    pub return_type: Option<VType>,
    pub locals: HashMap<Identifier, Local>,
    pub cfg: ControlFlowGraph,
    pub kind: FunctionKind,
}

/// Function parameter.
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: Identifier,
    pub ty: VType,
}

/// Local variable information.
#[derive(Debug, Clone)]
pub struct Local {
    pub name: Identifier,
    pub ty: VType,
    pub defined_at: ValueId,
}

/// What kind of function this is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionKind {
    /// Pure function with return value.
    Pure,
    /// Action function with side effects.
    Action,
    /// Command seal function.
    CommandSeal,
    /// Command open function.
    CommandOpen,
    /// Command policy function.
    CommandPolicy,
    /// Command recall function.
    CommandRecall,
    /// Finish function.
    Finish,
}

/// A global variable.
#[derive(Debug, Clone)]
pub struct Global {
    pub name: Identifier,
    pub ty: VType,
    pub initializer: InitializerExpr,
    pub is_mutable: bool,
}

/// Expression used to initialize globals.
#[derive(Debug, Clone)]
pub enum InitializerExpr {
    Const(ConstValue),
    Struct {
        ty: Identifier,
        fields: HashMap<Identifier, InitializerExpr>,
    },
    Call {
        func: Identifier,
        args: Vec<InitializerExpr>,
    },
    GlobalRef(Identifier),
}

/// Control flow graph for a function.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub entry: BlockId,
    pub blocks: HashMap<BlockId, BasicBlock>,
}

/// Unique identifier for a basic block.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct BlockId(pub u32);

/// A basic block in the CFG.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    pub params: Vec<BlockParam>,
    pub instructions: Vec<Instruction>,
    pub terminator: Terminator,
}

/// Parameter for a basic block (phi node).
#[derive(Debug, Clone)]
pub struct BlockParam {
    pub name: Identifier,
    pub ty: VType,
}

/// SSA value that can be used in instructions.
#[derive(Debug, Clone)]
pub enum Value {
    /// Constant value.
    Const(ConstValue),
    /// Reference to an SSA value.
    Use(ValueId),
    /// Reference to a global variable.
    GlobalRef(Identifier),
    /// Undefined value (for analysis).
    Undef(VType),
}

/// Identifier for an SSA value.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ValueId {
    pub block: BlockId,
    /// Index in block: 0..params.len() for params, params.len().. for instructions.
    pub index: usize,
}

/// Constant values.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstValue {
    Int(i64),
    Bool(bool),
    String(Text),
    Bytes(Vec<u8>),
    None,
    Enum(Identifier, u8),
}

/// Non-terminating instructions.
#[derive(Debug, Clone)]
pub enum Instruction {
    /// Binary operation.
    BinaryOp {
        op: BinaryOp,
        left: Value,
        right: Value,
        ty: VType,
    },
    
    /// Unary operation.
    UnaryOp {
        op: UnaryOp,
        operand: Value,
        ty: VType,
    },
    
    /// Function call.
    Call {
        target: CallTarget,
        args: Vec<Value>,
        ty: VType,
    },
    
    /// Create a new struct.
    StructNew {
        struct_type: Identifier,
        fields: Vec<(Identifier, Value)>,
        ty: VType,
    },
    
    /// Access a field from a struct.
    FieldAccess {
        object: Value,
        field: Identifier,
        ty: VType,
    },
    
    /// Query for a fact.
    QueryFact {
        fact_type: Identifier,
        key_constraints: Vec<(Identifier, Value)>,
        value_constraints: Vec<(Identifier, Value)>,
        ty: VType,
    },
    
    /// Create a new fact.
    CreateFact {
        fact_type: Identifier,
        key_fields: Vec<(Identifier, Value)>,
        value_fields: Vec<(Identifier, Value)>,
    },
    
    /// Update an existing fact.
    UpdateFact {
        fact_type: Identifier,
        key_fields: Vec<(Identifier, Value)>,
        value_updates: Vec<(Identifier, Value)>,
    },
    
    /// Delete a fact.
    DeleteFact {
        fact_pattern: Value,
    },
    
    /// Emit an effect.
    Emit {
        effect_type: Identifier,
        fields: Vec<(Identifier, Value)>,
    },
    
    /// Publish a command.
    Publish {
        command: Value,
    },
    
    /// Count facts matching a pattern.
    FactCount {
        fact_type: Identifier,
        constraints: Vec<(Identifier, Value)>,
        limit: i64,
        ty: VType,
    },
    
    /// Cast to optional type.
    Some {
        value: Value,
        ty: VType,
    },
    
    /// Check if optional has value.
    IsSome {
        value: Value,
    },
    
    /// Unwrap optional value.
    Unwrap {
        value: Value,
        ty: VType,
    },
    
    /// Serialize a value.
    Serialize {
        value: Value,
    },
    
    /// Deserialize a value.
    Deserialize {
        value: Value,
        ty: VType,
    },
}

/// Binary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

/// Unary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
}

/// Call targets.
#[derive(Debug, Clone)]
pub enum CallTarget {
    Function(Identifier),
    FFI(Identifier, Identifier), // module, function
}

/// Block terminators.
#[derive(Debug, Clone)]
pub enum Terminator {
    /// Return from function.
    Return(Option<Value>),
    
    /// Unconditional jump.
    Jump {
        target: BlockId,
        args: Vec<Value>,
    },
    
    /// Conditional branch.
    Branch {
        condition: Value,
        true_block: BlockId,
        true_args: Vec<Value>,
        false_block: BlockId,
        false_args: Vec<Value>,
    },
    
    /// Multi-way branch (switch).
    Switch {
        scrutinee: Value,
        cases: Vec<SwitchCase>,
        default: Option<(BlockId, Vec<Value>)>,
    },
    
    /// Panic/exit.
    Panic(PanicReason),
}

/// Case in a switch statement.
#[derive(Debug, Clone)]
pub struct SwitchCase {
    pub value: ConstValue,
    pub block: BlockId,
    pub args: Vec<Value>,
}

/// Reasons for panicking.
#[derive(Debug, Clone)]
pub enum PanicReason {
    FailedCheck,
    NoMatchArm,
    UnwrapNone,
    AssertionFailed,
    Exit,
}

impl Value {
    /// Get the type of this value.
    pub fn ty<'a>(&self, ctx: &AnalysisContext<'a>) -> Option<VType> {
        match self {
            Value::Const(c) => Some(c.ty()),
            Value::Use(id) => ctx.get_value_type(*id),
            Value::GlobalRef(g) => ctx.get_global_type(g),
            Value::Undef(ty) => Some(ty.clone()),
        }
    }
}

impl ConstValue {
    /// Get the type of this constant.
    pub fn ty(&self) -> VType {
        match self {
            ConstValue::Int(_) => VType::Int,
            ConstValue::Bool(_) => VType::Bool,
            ConstValue::String(_) => VType::String,
            ConstValue::Bytes(_) => VType::Bytes,
            ConstValue::None => VType::Optional(Box::new(VType::Int)), // placeholder
            ConstValue::Enum(name, _) => VType::Enum(name.clone()),
        }
    }
}

/// Context for type analysis.
pub struct AnalysisContext<'a> {
    pub ir: &'a IR,
    pub current_function: Option<&'a Function>,
}

impl<'a> AnalysisContext<'a> {
    pub fn get_value_type(&self, id: ValueId) -> Option<VType> {
        // Look up the type from the instruction/param that defines this value
        let func = self.current_function?;
        let block = func.cfg.blocks.get(&id.block)?;
        
        // Check if it's a block parameter
        if id.index < block.params.len() {
            return Some(block.params[id.index].ty.clone());
        }
        
        // Otherwise it's an instruction result
        let instr_index = id.index - block.params.len();
        let instruction = block.instructions.get(instr_index)?;
        
        // Extract type from instruction
        match instruction {
            Instruction::BinaryOp { ty, .. } |
            Instruction::UnaryOp { ty, .. } |
            Instruction::Call { ty, .. } |
            Instruction::StructNew { ty, .. } |
            Instruction::FieldAccess { ty, .. } |
            Instruction::QueryFact { ty, .. } |
            Instruction::FactCount { ty, .. } |
            Instruction::Some { ty, .. } |
            Instruction::Unwrap { ty, .. } |
            Instruction::Deserialize { ty, .. } => Some(ty.clone()),
            
            Instruction::IsSome { .. } => Some(VType::Bool),
            Instruction::Serialize { .. } => Some(VType::Bytes),
            
            // These don't produce values
            Instruction::CreateFact { .. } |
            Instruction::UpdateFact { .. } |
            Instruction::DeleteFact { .. } |
            Instruction::Emit { .. } |
            Instruction::Publish { .. } => None,
        }
    }
    
    pub fn get_global_type(&self, name: &Identifier) -> Option<VType> {
        self.ir.globals.get(name).map(|g| g.ty.clone())
    }
    
    /// Create a new analysis context.
    pub fn new(ir: &'a IR) -> Self {
        Self {
            ir,
            current_function: None,
        }
    }
    
    /// Set the current function being analyzed.
    pub fn with_function(mut self, func: &'a Function) -> Self {
        self.current_function = Some(func);
        self
    }
}

use crate::ir::IR;