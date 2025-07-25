//! Builder for constructing IR from AST.

use std::collections::HashMap;
use std::str::FromStr;
use aranya_policy_ast::{self as ast, Identifier, VType, AstNode, ident};
use crate::ir::*;
use crate::ir::error::IRBuildError;
use crate::ir::name_resolution::{NameResolver, NameError, Binding, BindingKind};

#[cfg(test)]
mod tests;

/// Builder for constructing IR from AST.
pub struct IRBuilder {
    /// The IR being built.
    ir: IR,
    
    /// Name resolver for tracking scopes and detecting shadowing.
    resolver: NameResolver,
    
    /// Current function being built.
    current_function: Option<Identifier>,
    
    /// Current block being built.
    current_block: Option<BlockId>,
    
    /// Next block ID to allocate.
    next_block_id: u32,
    
    /// Next value index in current block.
    next_value_index: usize,
    
    /// Mapping from AST identifiers to IR values.
    value_map: HashMap<Identifier, Value>,
    
    /// Errors accumulated during building.
    errors: Vec<IRBuildError>,
}

impl IRBuilder {
    /// Create a new IR builder.
    pub fn new() -> Self {
        Self {
            ir: IR::new(),
            resolver: NameResolver::new(),
            current_function: None,
            current_block: None,
            next_block_id: 0,
            next_value_index: 0,
            value_map: HashMap::new(),
            errors: Vec::new(),
        }
    }
    
    /// Build IR from an AST policy.
    pub fn build_from_ast(ast_policy: &ast::Policy) -> Result<IR, Vec<IRBuildError>> {
        let mut builder = IRBuilder::new();
        let mut errors = Vec::new();
        
        // Set metadata
        builder.ir.metadata.ffi_imports = ast_policy.ffi_imports.clone();
        
        // Phase 1: Register all globals
        for global in &ast_policy.global_lets {
            if let Err(e) = builder.register_global(global) {
                errors.push(e);
            }
        }
        
        // Phase 2: Register all functions
        for func in &ast_policy.functions {
            if let Err(e) = builder.register_function(&func.inner) {
                errors.push(e);
            }
        }
        
        // Register actions
        for action in &ast_policy.actions {
            if let Err(e) = builder.register_action(&action.inner) {
                errors.push(e);
            }
        }
        
        // Register command functions
        for command_node in &ast_policy.commands {
            let command = &command_node.inner;
            if let Err(e) = builder.register_command(command) {
                errors.push(e);
            }
        }
        
        // Phase 3: Build globals (if we have no registration errors)
        if errors.is_empty() {
            for global in &ast_policy.global_lets {
                if let Err(e) = builder.build_global(global) {
                    errors.push(e);
                }
            }
        }
        
        // Phase 4: Build functions (if we have no errors so far)
        if errors.is_empty() {
            for func in &ast_policy.functions {
                if let Err(e) = builder.build_function(&func.inner) {
                    errors.push(e);
                }
            }
            
            for action in &ast_policy.actions {
                if let Err(e) = builder.build_action(&action.inner) {
                    errors.push(e);
                }
            }
            
            // Build command functions
            for command_node in &ast_policy.commands {
                let command = &command_node.inner;
                if let Err(e) = builder.build_command(command) {
                    errors.push(e);
                }
            }
        }
        
        if errors.is_empty() {
            Ok(builder.ir)
        } else {
            Err(errors)
        }
    }
    
    /// Register a global variable.
    fn register_global(&mut self, global_node: &AstNode<ast::GlobalLetStatement>) -> Result<(), IRBuildError> {
        let global = &global_node.inner;
        // Try to infer the type if possible, otherwise use a placeholder.
        // This is a best-effort approach to handle forward references.
        let ty = match self.try_infer_expression_type(&global.expression) {
            Some(t) => t,
            None => VType::String, // TODO: Use a proper "unknown" type
        };
        
        self.resolver.define_global(global.identifier.clone(), Binding {
            name: global.identifier.clone(),
            ty,
            kind: BindingKind::Global,
            defined_at: 0, // TODO: track source locations
        })?;
        Ok(())
    }
    
    /// Try to infer the type of an expression without failing if references are unresolved.
    fn try_infer_expression_type(&self, expr: &ast::Expression) -> Option<VType> {
        match expr {
            ast::Expression::Int(_) => Some(VType::Int),
            ast::Expression::Bool(_) => Some(VType::Bool),
            ast::Expression::String(_) => Some(VType::String),
            ast::Expression::Optional(opt) => {
                if let Some(inner_expr) = opt {
                    self.try_infer_expression_type(inner_expr)
                        .map(|t| VType::Optional(Box::new(t)))
                } else {
                    None
                }
            }
            ast::Expression::FunctionCall(call) => {
                // Try to look up the function if it's already registered
                if let Some(binding) = self.resolver.lookup(&call.identifier) {
                    if let BindingKind::Function = binding.kind {
                        // Try to get the function from IR
                        if let Some(func) = self.ir.functions.get(&call.identifier) {
                            func.return_type.clone()
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
    
    /// Register a function.
    fn register_function(&mut self, func: &ast::FunctionDefinition) -> Result<(), IRBuildError> {
        self.register_function_with_kind(func, FunctionKind::Pure)
    }
    
    /// Register a function with a specific kind.
    fn register_function_with_kind(&mut self, func: &ast::FunctionDefinition, kind: FunctionKind) -> Result<(), IRBuildError> {
        self.resolver.define_global(func.identifier.clone(), Binding {
            name: func.identifier.clone(),
            ty: VType::String, // TODO: function types
            kind: BindingKind::Function,
            defined_at: 0,
        })?;
        
        // Create empty function in IR
        let ir_func = Function {
            name: func.identifier.clone(),
            params: func.arguments.iter().map(|arg| Parameter {
                name: arg.identifier.clone(),
                ty: arg.field_type.clone(),
            }).collect(),
            return_type: Some(func.return_type.clone()),
            locals: HashMap::new(),
            cfg: ControlFlowGraph {
                entry: BlockId(0),
                blocks: HashMap::new(),
            },
            kind,
        };
        
        self.ir.functions.insert(func.identifier.clone(), ir_func);
        Ok(())
    }
    
    /// Register an action.
    fn register_action(&mut self, action: &ast::ActionDefinition) -> Result<(), IRBuildError> {
        self.register_action_with_kind(action, FunctionKind::Action)
    }
    
    /// Register an action with a specific kind.
    fn register_action_with_kind(&mut self, action: &ast::ActionDefinition, kind: FunctionKind) -> Result<(), IRBuildError> {
        self.resolver.define_global(action.identifier.clone(), Binding {
            name: action.identifier.clone(),
            ty: VType::String, // TODO: action types
            kind: BindingKind::Function,
            defined_at: 0,
        })?;
        
        // Create empty function in IR
        let ir_func = Function {
            name: action.identifier.clone(),
            params: action.arguments.iter().map(|arg| Parameter {
                name: arg.identifier.clone(),
                ty: arg.field_type.clone(),
            }).collect(),
            return_type: None,
            locals: HashMap::new(),
            cfg: ControlFlowGraph {
                entry: BlockId(0),
                blocks: HashMap::new(),
            },
            kind,
        };
        
        self.ir.functions.insert(action.identifier.clone(), ir_func);
        Ok(())
    }
    
    /// Register a command and its associated functions.
    fn register_command(&mut self, command: &ast::CommandDefinition) -> Result<(), IRBuildError> {
        // Commands have seal, open, policy, and recall blocks that act like functions
        
        // Register seal function if present
        if !command.seal.is_empty() {
            let seal_name = Identifier::from_str(&format!("{}_seal", command.identifier))
                .unwrap_or_else(|_| command.identifier.clone());
            self.resolver.define_global(seal_name.clone(), Binding {
                name: seal_name.clone(),
                ty: VType::Struct(ident!("Envelope")),
                kind: BindingKind::Function,
                defined_at: 0,
            })?;
            
            let ir_func = Function {
                name: seal_name.clone(),
                params: vec![Parameter {
                    name: ident!("this"),
                    ty: VType::Struct(command.identifier.clone()),
                }],
                return_type: Some(VType::Struct(ident!("Envelope"))),
                locals: HashMap::new(),
                cfg: ControlFlowGraph {
                    entry: BlockId(0),
                    blocks: HashMap::new(),
                },
                kind: FunctionKind::CommandSeal,
            };
            
            self.ir.functions.insert(seal_name, ir_func);
        }
        
        // Register open function if present
        if !command.open.is_empty() {
            let open_name = Identifier::from_str(&format!("{}_open", command.identifier))
                .unwrap_or_else(|_| command.identifier.clone());
            self.resolver.define_global(open_name.clone(), Binding {
                name: open_name.clone(),
                ty: VType::Struct(command.identifier.clone()),
                kind: BindingKind::Function,
                defined_at: 0,
            })?;
            
            let ir_func = Function {
                name: open_name.clone(),
                params: vec![Parameter {
                    name: ident!("envelope"),
                    ty: VType::Struct(ident!("Envelope")),
                }],
                return_type: Some(VType::Struct(command.identifier.clone())),
                locals: HashMap::new(),
                cfg: ControlFlowGraph {
                    entry: BlockId(0),
                    blocks: HashMap::new(),
                },
                kind: FunctionKind::CommandOpen,
            };
            
            self.ir.functions.insert(open_name, ir_func);
        }
        
        // Register policy function if present
        if !command.policy.is_empty() {
            let policy_name = Identifier::from_str(&format!("{}_policy", command.identifier))
                .unwrap_or_else(|_| command.identifier.clone());
            self.resolver.define_global(policy_name.clone(), Binding {
                name: policy_name.clone(),
                ty: VType::String,
                kind: BindingKind::Function,
                defined_at: 0,
            })?;
            
            let ir_func = Function {
                name: policy_name.clone(),
                params: vec![Parameter {
                    name: ident!("this"),
                    ty: VType::Struct(command.identifier.clone()),
                }],
                return_type: None,
                locals: HashMap::new(),
                cfg: ControlFlowGraph {
                    entry: BlockId(0),
                    blocks: HashMap::new(),
                },
                kind: FunctionKind::CommandPolicy,
            };
            
            self.ir.functions.insert(policy_name, ir_func);
        }
        
        // Register recall function if present
        if !command.recall.is_empty() {
            let recall_name = Identifier::from_str(&format!("{}_recall", command.identifier))
                .unwrap_or_else(|_| command.identifier.clone());
            self.resolver.define_global(recall_name.clone(), Binding {
                name: recall_name.clone(),
                ty: VType::String,
                kind: BindingKind::Function,
                defined_at: 0,
            })?;
            
            let ir_func = Function {
                name: recall_name.clone(),
                params: vec![Parameter {
                    name: ident!("this"),
                    ty: VType::Struct(command.identifier.clone()),
                }],
                return_type: None,
                locals: HashMap::new(),
                cfg: ControlFlowGraph {
                    entry: BlockId(0),
                    blocks: HashMap::new(),
                },
                kind: FunctionKind::CommandRecall,
            };
            
            self.ir.functions.insert(recall_name, ir_func);
        }
        
        Ok(())
    }
    
    /// Build a global variable.
    fn build_global(&mut self, global_node: &AstNode<ast::GlobalLetStatement>) -> Result<(), IRBuildError> {
        let global = &global_node.inner;
        let initializer = self.build_initializer_expr(&global.expression)?;
        let ty = self.infer_expression_type(&global.expression)?;
        
        let ir_global = Global {
            name: global.identifier.clone(),
            ty: ty.clone(),
            initializer,
            is_mutable: false,
        };
        
        self.ir.globals.insert(global.identifier.clone(), ir_global);
        Ok(())
    }
    
    /// Build an initializer expression for a global.
    fn build_initializer_expr(&self, expr: &ast::Expression) -> Result<InitializerExpr, IRBuildError> {
        match expr {
            ast::Expression::Int(n) => Ok(InitializerExpr::Const(ConstValue::Int(*n))),
            ast::Expression::Bool(b) => Ok(InitializerExpr::Const(ConstValue::Bool(*b))),
            ast::Expression::String(s) => Ok(InitializerExpr::Const(ConstValue::String(s.clone()))),
            ast::Expression::Identifier(id) => Ok(InitializerExpr::GlobalRef(id.clone())),
            ast::Expression::NamedStruct(s) => {
                let mut fields = HashMap::new();
                for (field_name, field_expr) in &s.fields {
                    fields.insert(field_name.clone(), self.build_initializer_expr(field_expr)?);
                }
                Ok(InitializerExpr::Struct {
                    ty: s.identifier.clone(),
                    fields,
                })
            }
            ast::Expression::FunctionCall(call) => {
                let mut args = Vec::new();
                for arg in &call.arguments {
                    args.push(self.build_initializer_expr(arg)?);
                }
                Ok(InitializerExpr::Call {
                    func: call.identifier.clone(),
                    args,
                })
            }
            _ => Err(IRBuildError::UnsupportedFeature(format!("Global initializer expression: {:?}", expr))),
        }
    }
    
    /// Build a function.
    fn build_function(&mut self, func: &ast::FunctionDefinition) -> Result<(), IRBuildError> {
        self.current_function = Some(func.identifier.clone());
        self.resolver.enter_scope();
        
        // Create entry block with parameters
        let entry_block = BlockId(self.next_block_id);
        self.next_block_id += 1;
        
        let block_params: Vec<BlockParam> = func.arguments.iter().map(|arg| BlockParam {
            name: arg.identifier.clone(),
            ty: arg.field_type.clone(),
        }).collect();
        
        let entry_basic_block = BasicBlock {
            id: entry_block,
            params: block_params,
            instructions: vec![],
            terminator: Terminator::Return(None), // placeholder
        };
        
        if let Some(func_name) = &self.current_function {
            self.ir.functions.get_mut(func_name).unwrap()
                .cfg.blocks.insert(entry_block, entry_basic_block);
        }
        
        self.current_block = Some(entry_block);
        
        // Add parameters to scope
        for (i, param) in func.arguments.iter().enumerate() {
            self.resolver.define(param.identifier.clone(), Binding {
                name: param.identifier.clone(),
                ty: param.field_type.clone(),
                kind: BindingKind::Parameter,
                defined_at: 0,
            })?;
            
            // Add parameter to value map as block parameter
            let param_value = Value::Use(ValueId {
                block: entry_block,
                index: i,
            });
            self.value_map.insert(param.identifier.clone(), param_value);
        }
        
        // Build function body
        self.build_statements(&func.statements)?;
        
        // Add implicit return if needed
        if let Some(block) = self.get_current_block_mut() {
            if !matches!(block.terminator, Terminator::Return(_)) {
                block.terminator = Terminator::Return(None);
            }
        }
        
        // Update function entry point
        if let Some(func_name) = &self.current_function {
            self.ir.functions.get_mut(func_name).unwrap().cfg.entry = entry_block;
        }
        
        self.resolver.exit_scope();
        self.current_function = None;
        Ok(())
    }
    
    /// Build an action.
    fn build_action(&mut self, action: &ast::ActionDefinition) -> Result<(), IRBuildError> {
        self.current_function = Some(action.identifier.clone());
        self.resolver.enter_scope();
        
        // Create entry block with parameters
        let entry_block = self.new_block();
        let block_params: Vec<BlockParam> = action.arguments.iter().map(|arg| BlockParam {
            name: arg.identifier.clone(),
            ty: arg.field_type.clone(),
        }).collect();
        
        // Create entry basic block with parameters
        let entry_basic_block = BasicBlock {
            id: entry_block,
            params: block_params,
            instructions: vec![],
            terminator: Terminator::Return(None),
        };
        
        // Add entry block to CFG
        if let Some(func_name) = &self.current_function {
            self.ir.functions.get_mut(func_name).unwrap()
                .cfg.blocks.insert(entry_block, entry_basic_block);
        }
        
        self.current_block = Some(entry_block);
        
        // Add parameters to scope and value map
        for (i, param) in action.arguments.iter().enumerate() {
            self.resolver.define(param.identifier.clone(), Binding {
                name: param.identifier.clone(),
                ty: param.field_type.clone(),
                kind: BindingKind::Parameter,
                defined_at: 0,
            })?;
            
            // Add parameter to value map as block parameter
            let param_value = Value::Use(ValueId {
                block: entry_block,
                index: i,
            });
            self.value_map.insert(param.identifier.clone(), param_value);
        }
        
        // Build action body
        self.build_statements(&action.statements)?;
        
        // Add implicit return if needed
        if let Some(block) = self.get_current_block_mut() {
            if !matches!(block.terminator, Terminator::Return(_)) {
                block.terminator = Terminator::Return(None);
            }
        }
        
        // Update function entry point
        if let Some(func_name) = &self.current_function {
            self.ir.functions.get_mut(func_name).unwrap().cfg.entry = entry_block;
        }
        
        self.resolver.exit_scope();
        self.current_function = None;
        Ok(())
    }
    
    /// Build a list of statements.
    fn build_statements(&mut self, statements: &[AstNode<ast::Statement>]) -> Result<(), IRBuildError> {
        for stmt in statements {
            self.build_statement(&stmt.inner)?;
        }
        Ok(())
    }
    
    /// Build a single statement.
    fn build_statement(&mut self, stmt: &ast::Statement) -> Result<(), IRBuildError> {
        match stmt {
            ast::Statement::Let(let_stmt) => {
                // Evaluate RHS first (before defining new variable)
                let value = self.build_expression(&let_stmt.expression)?;
                let ty = self.infer_expression_type(&let_stmt.expression)?;
                
                // Define the new variable
                self.resolver.define(let_stmt.identifier.clone(), Binding {
                    name: let_stmt.identifier.clone(),
                    ty: ty.clone(),
                    kind: BindingKind::Local,
                    defined_at: 0,
                })?;
                
                // Add to function's locals
                if let Some(func_name) = &self.current_function {
                    if let Some(func) = self.ir.functions.get_mut(func_name) {
                        let defined_at = match &value {
                            Value::Use(id) => *id,
                            _ => ValueId {
                                block: self.current_block.unwrap_or(BlockId(0)),
                                index: 0,
                            },
                        };
                        func.locals.insert(let_stmt.identifier.clone(), Local {
                            name: let_stmt.identifier.clone(),
                            ty,
                            defined_at,
                        });
                    }
                }
                
                // Map identifier to value (after using it above)
                self.value_map.insert(let_stmt.identifier.clone(), value);
            }
            
            ast::Statement::Check(check) => {
                let condition = self.build_expression(&check.expression)?;
                
                // Create success and panic blocks
                let success_block = self.new_block();
                let panic_block = self.new_block();
                
                // Branch on condition
                self.terminate_block(Terminator::Branch {
                    condition,
                    true_block: success_block,
                    true_args: vec![],
                    false_block: panic_block,
                    false_args: vec![],
                });
                
                // Panic block
                self.current_block = Some(panic_block);
                self.terminate_block(Terminator::Panic(PanicReason::FailedCheck));
                
                // Continue in success block
                self.current_block = Some(success_block);
            }
            
            ast::Statement::Return(ret) => {
                let value = self.build_expression(&ret.expression)?;
                self.terminate_block(Terminator::Return(Some(value)));
            }
            
            ast::Statement::If(if_stmt) => {
                self.build_if_statement(if_stmt)?;
            }
            
            ast::Statement::Match(match_stmt) => {
                self.build_match_statement(match_stmt)?;
            }
            
            ast::Statement::Finish(stmts) => {
                // Finish blocks are special - they run after the main body
                // For now, just compile them inline
                self.resolver.enter_scope();
                self.build_statements(stmts)?;
                self.resolver.exit_scope();
            }
            
            ast::Statement::Map(map_stmt) => {
                // Query for facts
                let mut key_constraints = Vec::new();
                let mut value_constraints = Vec::new();
                
                for (name, field) in &map_stmt.fact.key_fields {
                    if let ast::FactField::Expression(expr) = field {
                        let value = self.build_expression(expr)?;
                        key_constraints.push((name.clone(), value));
                    }
                }
                
                if let Some(value_fields) = &map_stmt.fact.value_fields {
                    for (name, field) in value_fields {
                        if let ast::FactField::Expression(expr) = field {
                            let value = self.build_expression(expr)?;
                            value_constraints.push((name.clone(), value));
                        }
                    }
                }
                
                // This is a complex operation that would need special IR support
                // For now, just return an error
                return Err(IRBuildError::UnsupportedFeature("Map statement".to_string()));
            }
            
            ast::Statement::ActionCall(call) => {
                let mut args = Vec::new();
                for arg in &call.arguments {
                    args.push(self.build_expression(arg)?);
                }
                
                let target = CallTarget::Function(call.identifier.clone());
                self.emit_call(target, args, VType::String)?; // Actions don't return values
            }
            
            ast::Statement::Publish(expr) => {
                let command = self.build_expression(expr)?;
                self.emit_instruction(Instruction::Publish { command })?;
            }
            
            ast::Statement::Create(create) => {
                let mut key_fields = Vec::new();
                let mut value_fields = Vec::new();
                
                for (name, field) in &create.fact.key_fields {
                    if let ast::FactField::Expression(expr) = field {
                        let value = self.build_expression(expr)?;
                        key_fields.push((name.clone(), value));
                    }
                }
                
                if let Some(values) = &create.fact.value_fields {
                    for (name, field) in values {
                        if let ast::FactField::Expression(expr) = field {
                            let value = self.build_expression(expr)?;
                            value_fields.push((name.clone(), value));
                        }
                    }
                }
                
                self.emit_instruction(Instruction::CreateFact {
                    fact_type: create.fact.identifier.clone(),
                    key_fields,
                    value_fields,
                })?;
            }
            
            ast::Statement::Update(update) => {
                let mut key_fields = Vec::new();
                let mut value_updates = Vec::new();
                
                for (name, field) in &update.fact.key_fields {
                    if let ast::FactField::Expression(expr) = field {
                        let value = self.build_expression(expr)?;
                        key_fields.push((name.clone(), value));
                    }
                }
                
                for (name, field) in &update.to {
                    let value = match field {
                        ast::FactField::Expression(expr) => self.build_expression(expr)?,
                        ast::FactField::Bind => {
                            return Err(IRBuildError::UnsupportedFeature("bind in update".to_string()));
                        }
                    };
                    value_updates.push((name.clone(), value));
                }
                
                self.emit_instruction(Instruction::UpdateFact {
                    fact_type: update.fact.identifier.clone(),
                    key_fields,
                    value_updates,
                })?;
            }
            
            ast::Statement::Delete(delete) => {
                // Build the fact pattern as a value
                let fact_pattern = self.build_fact_pattern(&delete.fact)?;
                self.emit_instruction(Instruction::DeleteFact { fact_pattern })?;
            }
            
            ast::Statement::Emit(expr) => {
                let _effect = self.build_expression(expr)?;
                
                // Extract effect type and fields from the expression
                // For now, use a placeholder
                self.emit_instruction(Instruction::Emit {
                    effect_type: ident!("Effect"),
                    fields: vec![],
                })?;
            }
            
            ast::Statement::FunctionCall(call) => {
                // Finish functions can call other finish functions
                let mut args = Vec::new();
                for arg in &call.arguments {
                    args.push(self.build_expression(arg)?);
                }
                
                let target = CallTarget::Function(call.identifier.clone());
                self.emit_call(target, args, VType::String)?; // Discard return value
            }
            
            ast::Statement::DebugAssert(expr) => {
                let condition = self.build_expression(expr)?;
                
                // Create success and panic blocks
                let success_block = self.new_block();
                let panic_block = self.new_block();
                
                // Branch on condition
                self.terminate_block(Terminator::Branch {
                    condition,
                    true_block: success_block,
                    true_args: vec![],
                    false_block: panic_block,
                    false_args: vec![],
                });
                
                // Panic block
                self.current_block = Some(panic_block);
                self.terminate_block(Terminator::Panic(PanicReason::AssertionFailed));
                
                // Continue in success block
                self.current_block = Some(success_block);
            }
        }
        Ok(())
    }
    
    /// Build an if statement.
    fn build_if_statement(&mut self, if_stmt: &ast::IfStatement) -> Result<(), IRBuildError> {
        let end_block = BlockId(self.next_block_id);
        self.next_block_id += 1;
        
        for (i, (condition, body)) in if_stmt.branches.iter().enumerate() {
            let condition_value = self.build_expression(condition)?;
            
            let then_block = self.new_block();
            let next_block = if i + 1 < if_stmt.branches.len() || if_stmt.fallback.is_some() {
                self.new_block()
            } else {
                end_block
            };
            
            self.terminate_block(Terminator::Branch {
                condition: condition_value,
                true_block: then_block,
                true_args: vec![],
                false_block: next_block,
                false_args: vec![],
            });
            
            // Build then branch
            self.current_block = Some(then_block);
            self.resolver.enter_scope();
            self.build_statements(body)?;
            self.resolver.exit_scope();
            if !self.is_terminated() {
                self.terminate_block(Terminator::Jump {
                    target: end_block,
                    args: vec![],
                });
            }
            
            // Continue with next condition
            self.current_block = Some(next_block);
        }
        
        // Build else branch if present
        if let Some(fallback) = &if_stmt.fallback {
            self.resolver.enter_scope();
            self.build_statements(fallback)?;
            self.resolver.exit_scope();
            if !self.is_terminated() {
                self.terminate_block(Terminator::Jump {
                    target: end_block,
                    args: vec![],
                });
            }
        }
        
        // Create and continue in end block
        if let Some(func_name) = &self.current_function {
            if !self.ir.functions.get(func_name).unwrap().cfg.blocks.contains_key(&end_block) {
                let block = BasicBlock {
                    id: end_block,
                    params: vec![],
                    instructions: vec![],
                    terminator: Terminator::Return(None), // placeholder
                };
                self.ir.functions.get_mut(func_name).unwrap()
                    .cfg.blocks.insert(end_block, block);
            }
            self.current_block = Some(end_block);
        }
        
        Ok(())
    }
    
    /// Build a match statement.
    fn build_match_statement(&mut self, match_stmt: &ast::MatchStatement) -> Result<(), IRBuildError> {
        let scrutinee = self.build_expression(&match_stmt.expression)?;
        let end_block = self.new_block_id();
        
        let mut cases = Vec::new();
        let mut default = None;
        
        for arm in &match_stmt.arms {
            match &arm.pattern {
                ast::MatchPattern::Values(values) => {
                    for value_expr in values {
                        let value = self.build_constant_expression(value_expr)?;
                        let arm_block = self.new_block();
                        cases.push(SwitchCase {
                            value,
                            block: arm_block,
                            args: vec![],
                        });
                    }
                }
                ast::MatchPattern::Default => {
                    let default_block = self.new_block();
                    default = Some((default_block, vec![]));
                }
            }
        }
        
        // Add switch terminator
        self.terminate_block(Terminator::Switch {
            scrutinee,
            cases: cases.clone(),
            default: default.clone(),
        });
        
        // Build arm bodies
        let mut arm_index = 0;
        for arm in &match_stmt.arms {
            match &arm.pattern {
                ast::MatchPattern::Values(values) => {
                    for _ in values {
                        let block_id = cases[arm_index].block;
                        arm_index += 1;
                        
                        self.current_block = Some(block_id);
                        self.resolver.enter_scope();
                        self.build_statements(&arm.statements)?;
                        self.resolver.exit_scope();
                        
                        if !self.is_terminated() {
                            self.terminate_block(Terminator::Jump {
                                target: end_block,
                                args: vec![],
                            });
                        }
                    }
                }
                ast::MatchPattern::Default => {
                    if let Some((default_block, _)) = default {
                        self.current_block = Some(default_block);
                        self.resolver.enter_scope();
                        self.build_statements(&arm.statements)?;
                        self.resolver.exit_scope();
                        
                        if !self.is_terminated() {
                            self.terminate_block(Terminator::Jump {
                                target: end_block,
                                args: vec![],
                            });
                        }
                    }
                }
            }
        }
        
        // Continue in end block
        self.current_block = Some(end_block);
        
        Ok(())
    }
    
    /// Build a command and its associated functions.
    fn build_command(&mut self, command: &ast::CommandDefinition) -> Result<(), IRBuildError> {
        // Build seal function if present
        if !command.seal.is_empty() {
            let seal_name = Identifier::from_str(&format!("{}_seal", command.identifier))
                .unwrap_or_else(|_| command.identifier.clone());
            self.current_function = Some(seal_name.clone());
            self.resolver.enter_function_scope();
            
            // Add 'this' parameter
            self.resolver.define(ident!("this"), Binding {
                name: ident!("this"),
                ty: VType::Struct(command.identifier.clone()),
                kind: BindingKind::Parameter,
                defined_at: 0,
            })?;
            
            // Create entry block
            let entry_block = self.new_block();
            self.current_block = Some(entry_block);
            
            // Build seal body
            self.build_statements(&command.seal)?;
            
            // Add implicit return if needed
            if let Some(block) = self.get_current_block_mut() {
                if !matches!(block.terminator, Terminator::Return(_)) {
                    return Err(IRBuildError::InvalidAst("seal block must return a value".to_string()));
                }
            }
            
            self.resolver.exit_scope();
            self.current_function = None;
        }
        
        // Build open function if present
        if !command.open.is_empty() {
            let open_name = Identifier::from_str(&format!("{}_open", command.identifier))
                .unwrap_or_else(|_| command.identifier.clone());
            self.current_function = Some(open_name.clone());
            self.resolver.enter_function_scope();
            
            // Add 'envelope' parameter
            self.resolver.define(ident!("envelope"), Binding {
                name: ident!("envelope"),
                ty: VType::Struct(ident!("Envelope")),
                kind: BindingKind::Parameter,
                defined_at: 0,
            })?;
            
            // Create entry block
            let entry_block = self.new_block();
            self.current_block = Some(entry_block);
            
            // Build open body
            self.build_statements(&command.open)?;
            
            // Add implicit return if needed
            if let Some(block) = self.get_current_block_mut() {
                if !matches!(block.terminator, Terminator::Return(_)) {
                    return Err(IRBuildError::InvalidAst("open block must return a value".to_string()));
                }
            }
            
            self.resolver.exit_scope();
            self.current_function = None;
        }
        
        // Build policy function if present
        if !command.policy.is_empty() {
            let policy_name = Identifier::from_str(&format!("{}_policy", command.identifier))
                .unwrap_or_else(|_| command.identifier.clone());
            self.current_function = Some(policy_name.clone());
            self.resolver.enter_function_scope();
            
            // Add 'this' parameter
            self.resolver.define(ident!("this"), Binding {
                name: ident!("this"),
                ty: VType::Struct(command.identifier.clone()),
                kind: BindingKind::Parameter,
                defined_at: 0,
            })?;
            
            // Create entry block
            let entry_block = self.new_block();
            self.current_block = Some(entry_block);
            
            // Build policy body
            self.build_statements(&command.policy)?;
            
            // Add implicit return if needed
            if let Some(block) = self.get_current_block_mut() {
                if !matches!(block.terminator, Terminator::Return(_)) {
                    block.terminator = Terminator::Return(None);
                }
            }
            
            self.resolver.exit_scope();
            self.current_function = None;
        }
        
        // Build recall function if present
        if !command.recall.is_empty() {
            let recall_name = Identifier::from_str(&format!("{}_recall", command.identifier))
                .unwrap_or_else(|_| command.identifier.clone());
            self.current_function = Some(recall_name.clone());
            self.resolver.enter_function_scope();
            
            // Add 'this' parameter
            self.resolver.define(ident!("this"), Binding {
                name: ident!("this"),
                ty: VType::Struct(command.identifier.clone()),
                kind: BindingKind::Parameter,
                defined_at: 0,
            })?;
            
            // Create entry block
            let entry_block = self.new_block();
            self.current_block = Some(entry_block);
            
            // Build recall body
            self.build_statements(&command.recall)?;
            
            // Add implicit return if needed
            if let Some(block) = self.get_current_block_mut() {
                if !matches!(block.terminator, Terminator::Return(_)) {
                    block.terminator = Terminator::Return(None);
                }
            }
            
            self.resolver.exit_scope();
            self.current_function = None;
        }
        
        Ok(())
    }
    
    /// Build an expression.
    fn build_expression(&mut self, expr: &ast::Expression) -> Result<Value, IRBuildError> {
        match expr {
            ast::Expression::Int(n) => Ok(Value::Const(ConstValue::Int(*n))),
            ast::Expression::Bool(b) => Ok(Value::Const(ConstValue::Bool(*b))),
            ast::Expression::String(s) => Ok(Value::Const(ConstValue::String(s.clone()))),
            
            ast::Expression::Identifier(id) => {
                // Look up the identifier
                if let Some(value) = self.value_map.get(id) {
                    Ok(value.clone())
                } else if self.resolver.lookup(id).map(|b| b.kind == BindingKind::Global).unwrap_or(false) {
                    Ok(Value::GlobalRef(id.clone()))
                } else {
                    Err(IRBuildError::NameError(NameError::NotDefined {
                        name: id.clone(),
                        location: 0,
                    }))
                }
            }
            
            ast::Expression::Add(left, right) => {
                let left_val = self.build_expression(left)?;
                let right_val = self.build_expression(right)?;
                self.emit_binary_op(BinaryOp::Add, left_val, right_val, VType::Int)
            }
            
            ast::Expression::Subtract(left, right) => {
                let left_val = self.build_expression(left)?;
                let right_val = self.build_expression(right)?;
                self.emit_binary_op(BinaryOp::Sub, left_val, right_val, VType::Int)
            }
            
            ast::Expression::Equal(left, right) => {
                let left_val = self.build_expression(left)?;
                let right_val = self.build_expression(right)?;
                self.emit_binary_op(BinaryOp::Eq, left_val, right_val, VType::Bool)
            }
            
            ast::Expression::NotEqual(left, right) => {
                let left_val = self.build_expression(left)?;
                let right_val = self.build_expression(right)?;
                self.emit_binary_op(BinaryOp::NotEq, left_val, right_val, VType::Bool)
            }
            
            ast::Expression::LessThan(left, right) => {
                let left_val = self.build_expression(left)?;
                let right_val = self.build_expression(right)?;
                self.emit_binary_op(BinaryOp::Lt, left_val, right_val, VType::Bool)
            }
            
            ast::Expression::LessThanOrEqual(left, right) => {
                let left_val = self.build_expression(left)?;
                let right_val = self.build_expression(right)?;
                self.emit_binary_op(BinaryOp::LtEq, left_val, right_val, VType::Bool)
            }
            
            ast::Expression::GreaterThan(left, right) => {
                let left_val = self.build_expression(left)?;
                let right_val = self.build_expression(right)?;
                self.emit_binary_op(BinaryOp::Gt, left_val, right_val, VType::Bool)
            }
            
            ast::Expression::GreaterThanOrEqual(left, right) => {
                let left_val = self.build_expression(left)?;
                let right_val = self.build_expression(right)?;
                self.emit_binary_op(BinaryOp::GtEq, left_val, right_val, VType::Bool)
            }
            
            ast::Expression::And(left, right) => {
                let left_val = self.build_expression(left)?;
                let right_val = self.build_expression(right)?;
                self.emit_binary_op(BinaryOp::And, left_val, right_val, VType::Bool)
            }
            
            ast::Expression::Or(left, right) => {
                let left_val = self.build_expression(left)?;
                let right_val = self.build_expression(right)?;
                self.emit_binary_op(BinaryOp::Or, left_val, right_val, VType::Bool)
            }
            
            ast::Expression::Not(operand) => {
                let val = self.build_expression(operand)?;
                self.emit_unary_op(UnaryOp::Not, val, VType::Bool)
            }
            
            ast::Expression::Negative(operand) => {
                let val = self.build_expression(operand)?;
                self.emit_unary_op(UnaryOp::Neg, val, VType::Int)
            }
            
            ast::Expression::FunctionCall(call) => {
                let mut args = Vec::new();
                for arg in &call.arguments {
                    args.push(self.build_expression(arg)?);
                }
                
                let target = CallTarget::Function(call.identifier.clone());
                let ty = self.get_function_return_type(&call.identifier)?;
                
                self.emit_call(target, args, ty)
            }
            
            ast::Expression::ForeignFunctionCall(call) => {
                let mut args = Vec::new();
                for arg in &call.arguments {
                    args.push(self.build_expression(arg)?);
                }
                
                let target = CallTarget::FFI(call.module.clone(), call.identifier.clone());
                // FFI return types would need to be looked up from module definitions
                let ty = VType::String; // placeholder
                
                self.emit_call(target, args, ty)
            }
            
            ast::Expression::Optional(opt) => {
                match opt {
                    None => Ok(Value::Const(ConstValue::None)),
                    Some(expr) => {
                        let value = self.build_expression(expr)?;
                        let inner_ty = self.infer_expression_type(expr)?;
                        self.emit_instruction(Instruction::Some {
                            value,
                            ty: VType::Optional(Box::new(inner_ty)),
                        })
                    }
                }
            }
            
            ast::Expression::NamedStruct(s) => {
                let mut fields = Vec::new();
                for (name, expr) in &s.fields {
                    let value = self.build_expression(expr)?;
                    fields.push((name.clone(), value));
                }
                
                self.emit_instruction(Instruction::StructNew {
                    struct_type: s.identifier.clone(),
                    fields,
                    ty: VType::Struct(s.identifier.clone()),
                })
            }
            
            ast::Expression::EnumReference(e) => {
                // Look up enum value from AST or IR
                // For now, use placeholder
                Ok(Value::Const(ConstValue::Enum(e.identifier.clone(), 0)))
            }
            
            ast::Expression::Dot(expr, field) => {
                let object = self.build_expression(expr)?;
                let object_ty = self.infer_expression_type(expr)?;
                
                // Infer field type based on object type
                let field_ty = match &object_ty {
                    VType::Struct(_) => VType::String, // placeholder - should look up struct def
                    _ => return Err(IRBuildError::TypeError("Cannot access field on non-struct".to_string())),
                };
                
                self.emit_instruction(Instruction::FieldAccess {
                    object,
                    field: field.clone(),
                    ty: field_ty,
                })
            }
            
            ast::Expression::Unwrap(expr) => {
                let value = self.build_expression(expr)?;
                let ty = self.infer_expression_type(expr)?;
                
                let inner_ty = match ty {
                    VType::Optional(inner) => *inner,
                    _ => return Err(IRBuildError::TypeError("Cannot unwrap non-optional".to_string())),
                };
                
                self.emit_instruction(Instruction::Unwrap {
                    value,
                    ty: inner_ty,
                })
            }
            
            ast::Expression::CheckUnwrap(expr) => {
                // Similar to unwrap but with check exit instead of panic
                let value = self.build_expression(expr)?;
                let ty = self.infer_expression_type(expr)?;
                
                let inner_ty = match ty {
                    VType::Optional(inner) => *inner,
                    _ => return Err(IRBuildError::TypeError("Cannot unwrap non-optional".to_string())),
                };
                
                // Generate check that value is Some
                let is_some = self.emit_instruction(Instruction::IsSome { value: value.clone() })?;
                
                // Create panic block
                let panic_block = self.new_block();
                let continue_block = self.new_block();
                
                // Branch on is_some
                self.terminate_block(Terminator::Branch {
                    condition: is_some,
                    true_block: continue_block,
                    true_args: vec![],
                    false_block: panic_block,
                    false_args: vec![],
                });
                
                // Panic block
                self.current_block = Some(panic_block);
                self.terminate_block(Terminator::Panic(PanicReason::FailedCheck));
                
                // Continue block with unwrap
                self.current_block = Some(continue_block);
                self.emit_instruction(Instruction::Unwrap {
                    value,
                    ty: inner_ty,
                })
            }
            
            ast::Expression::Is(expr, is_some) => {
                let value = self.build_expression(expr)?;
                
                if *is_some {
                    self.emit_instruction(Instruction::IsSome { value })
                } else {
                    // is None = !is_some
                    let is_some_val = self.emit_instruction(Instruction::IsSome { value })?;
                    self.emit_unary_op(UnaryOp::Not, is_some_val, VType::Bool)
                }
            }
            
            ast::Expression::Block(stmts, expr) => {
                self.resolver.enter_scope();
                self.build_statements(stmts)?;
                let result = self.build_expression(expr)?;
                self.resolver.exit_scope();
                Ok(result)
            }
            
            ast::Expression::Substruct(expr, _field) => {
                // Substruct is like a field access but returns a struct
                let object = self.build_expression(expr)?;
                let _object_ty = self.infer_expression_type(expr)?;
                
                // For now, return the object itself
                // TODO: implement proper substruct access
                Ok(object)
            }
            
            ast::Expression::Match(match_expr) => {
                self.build_match_expression(match_expr)
            }
            
            ast::Expression::InternalFunction(func) => {
                self.build_internal_function(func)
            }
        }
    }
    
    /// Build a constant expression.
    fn build_constant_expression(&mut self, expr: &ast::Expression) -> Result<ConstValue, IRBuildError> {
        match expr {
            ast::Expression::Int(n) => Ok(ConstValue::Int(*n)),
            ast::Expression::Bool(b) => Ok(ConstValue::Bool(*b)),
            ast::Expression::String(s) => Ok(ConstValue::String(s.clone())),
            ast::Expression::EnumReference(e) => {
                // TODO: look up enum value
                Ok(ConstValue::Enum(e.identifier.clone(), 0))
            }
            _ => Err(IRBuildError::InvalidAst("Expected constant expression".to_string())),
        }
    }
    
    /// Emit a binary operation instruction.
    fn emit_binary_op(&mut self, op: BinaryOp, left: Value, right: Value, ty: VType) -> Result<Value, IRBuildError> {
        let instr = Instruction::BinaryOp { op, left, right, ty: ty.clone() };
        self.emit_instruction(instr)
    }
    
    /// Emit a unary operation instruction.
    fn emit_unary_op(&mut self, op: UnaryOp, operand: Value, ty: VType) -> Result<Value, IRBuildError> {
        let instr = Instruction::UnaryOp { op, operand, ty: ty.clone() };
        self.emit_instruction(instr)
    }
    
    /// Emit a call instruction.
    fn emit_call(&mut self, target: CallTarget, args: Vec<Value>, ty: VType) -> Result<Value, IRBuildError> {
        let instr = Instruction::Call { target, args, ty: ty.clone() };
        self.emit_instruction(instr)
    }
    
    /// Emit an instruction and return the value it produces.
    fn emit_instruction(&mut self, instr: Instruction) -> Result<Value, IRBuildError> {
        let block = self.get_current_block_mut()
            .ok_or_else(|| IRBuildError::InvalidAst("No current block".to_string()))?;
        
        let value_id = ValueId {
            block: block.id,
            index: block.params.len() + block.instructions.len(),
        };
        
        block.instructions.push(instr);
        Ok(Value::Use(value_id))
    }
    
    /// Create a new basic block.
    fn new_block(&mut self) -> BlockId {
        let id = BlockId(self.next_block_id);
        self.next_block_id += 1;
        
        let block = BasicBlock {
            id,
            params: vec![],
            instructions: vec![],
            terminator: Terminator::Return(None), // placeholder
        };
        
        if let Some(func_name) = &self.current_function {
            self.ir.functions.get_mut(func_name).unwrap()
                .cfg.blocks.insert(id, block);
        }
        
        id
    }
    
    /// Get a new block ID without creating the block.
    fn new_block_id(&mut self) -> BlockId {
        let id = BlockId(self.next_block_id);
        self.next_block_id += 1;
        id
    }
    
    /// Get the current block being built.
    fn get_current_block_mut(&mut self) -> Option<&mut BasicBlock> {
        let block_id = self.current_block?;
        let func_name = self.current_function.as_ref()?;
        self.ir.functions.get_mut(func_name)?
            .cfg.blocks.get_mut(&block_id)
    }
    
    /// Check if the current block is already terminated.
    fn is_terminated(&self) -> bool {
        if let Some(block_id) = self.current_block {
            if let Some(func_name) = &self.current_function {
                if let Some(func) = self.ir.functions.get(func_name) {
                    if let Some(block) = func.cfg.blocks.get(&block_id) {
                        return !matches!(block.terminator, Terminator::Return(None));
                    }
                }
            }
        }
        false
    }
    
    /// Terminate the current block.
    fn terminate_block(&mut self, terminator: Terminator) {
        if let Some(block) = self.get_current_block_mut() {
            block.terminator = terminator;
        }
    }
    
    /// Infer the type of an expression.
    fn infer_expression_type(&self, expr: &ast::Expression) -> Result<VType, IRBuildError> {
        match expr {
            ast::Expression::Int(_) => Ok(VType::Int),
            ast::Expression::Bool(_) => Ok(VType::Bool),
            ast::Expression::String(_) => Ok(VType::String),
            ast::Expression::Identifier(id) => {
                // First check if it's a global in the IR (for forward references)
                if let Some(global) = self.ir.globals.get(id) {
                    return Ok(global.ty.clone());
                }
                
                // Otherwise look it up in the resolver
                self.resolver.lookup(id)
                    .map(|b| b.ty.clone())
                    .ok_or_else(|| IRBuildError::NameError(NameError::NotDefined {
                        name: id.clone(),
                        location: 0,
                    }))
            }
            ast::Expression::Add(_, _) |
            ast::Expression::Subtract(_, _) => Ok(VType::Int),
            ast::Expression::Equal(_, _) |
            ast::Expression::NotEqual(_, _) |
            ast::Expression::LessThan(_, _) |
            ast::Expression::LessThanOrEqual(_, _) |
            ast::Expression::GreaterThan(_, _) |
            ast::Expression::GreaterThanOrEqual(_, _) |
            ast::Expression::And(_, _) |
            ast::Expression::Or(_, _) |
            ast::Expression::Not(_) => Ok(VType::Bool),
            ast::Expression::Negative(_) => Ok(VType::Int),
            ast::Expression::NamedStruct(s) => Ok(VType::Struct(s.identifier.clone())),
            ast::Expression::FunctionCall(call) => self.get_function_return_type(&call.identifier),
            ast::Expression::ForeignFunctionCall(_) => Ok(VType::String), // placeholder
            ast::Expression::Optional(opt) => {
                match opt {
                    None => Ok(VType::Optional(Box::new(VType::Int))), // placeholder type
                    Some(expr) => {
                        let inner_ty = self.infer_expression_type(expr)?;
                        Ok(VType::Optional(Box::new(inner_ty)))
                    }
                }
            }
            ast::Expression::EnumReference(e) => Ok(VType::Enum(e.identifier.clone())),
            ast::Expression::Dot(expr, _field) => {
                let object_ty = self.infer_expression_type(expr)?;
                match object_ty {
                    VType::Struct(_) => Ok(VType::String), // placeholder - should look up field type
                    _ => Err(IRBuildError::TypeError("Cannot access field on non-struct".to_string())),
                }
            }
            ast::Expression::Unwrap(expr) | ast::Expression::CheckUnwrap(expr) => {
                let ty = self.infer_expression_type(expr)?;
                match ty {
                    VType::Optional(inner) => Ok(*inner),
                    _ => Err(IRBuildError::TypeError("Cannot unwrap non-optional".to_string())),
                }
            }
            ast::Expression::Is(_, _) => Ok(VType::Bool),
            ast::Expression::Block(_, expr) => self.infer_expression_type(expr),
            ast::Expression::Substruct(expr, _) => self.infer_expression_type(expr), // placeholder
            ast::Expression::Match(match_expr) => {
                // Assume all arms have same type as first arm
                self.infer_expression_type(&match_expr.arms[0].expression)
            }
            ast::Expression::InternalFunction(func) => {
                match func {
                    ast::InternalFunction::Query(fact) => {
                        Ok(VType::Optional(Box::new(VType::Struct(fact.identifier.clone()))))
                    }
                    ast::InternalFunction::Exists(_) => Ok(VType::Bool),
                    ast::InternalFunction::FactCount(cmp_type, _, _) => {
                        match cmp_type {
                            ast::FactCountType::UpTo => Ok(VType::Int),
                            ast::FactCountType::Exactly |
                            ast::FactCountType::AtLeast |
                            ast::FactCountType::AtMost => Ok(VType::Bool),
                        }
                    }
                    ast::InternalFunction::If(_, then_expr, _) => {
                        self.infer_expression_type(then_expr)
                    }
                    ast::InternalFunction::Serialize(_) => Ok(VType::Bytes),
                    ast::InternalFunction::Deserialize(_) => Ok(VType::String), // placeholder
                }
            }
        }
    }
    
    /// Get the return type of a function.
    fn get_function_return_type(&self, name: &Identifier) -> Result<VType, IRBuildError> {
        self.ir.functions.get(name)
            .and_then(|f| f.return_type.clone())
            .ok_or_else(|| IRBuildError::TypeError(format!("Unknown function: {}", name)))
    }
    
    /// Build a match expression.
    fn build_match_expression(&mut self, match_expr: &ast::MatchExpression) -> Result<Value, IRBuildError> {
        let scrutinee = self.build_expression(&match_expr.scrutinee)?;
        let end_block = self.new_block_id();
        
        // Result will be passed through phi node
        let result_ty = self.infer_expression_type(&match_expr.arms[0].expression)?;
        
        let mut cases = Vec::new();
        let mut default = None;
        let mut arm_blocks = Vec::new();
        
        for arm in &match_expr.arms {
            match &arm.pattern {
                ast::MatchPattern::Values(values) => {
                    for value_expr in values {
                        let value = self.build_constant_expression(value_expr)?;
                        let arm_block = self.new_block();
                        arm_blocks.push((arm_block, arm));
                        cases.push(SwitchCase {
                            value,
                            block: arm_block,
                            args: vec![],
                        });
                    }
                }
                ast::MatchPattern::Default => {
                    let default_block = self.new_block();
                    arm_blocks.push((default_block, arm));
                    default = Some((default_block, vec![]));
                }
            }
        }
        
        // Add switch terminator
        self.terminate_block(Terminator::Switch {
            scrutinee,
            cases,
            default,
        });
        
        // Build arm expressions
        let mut arm_results = Vec::new();
        for (block_id, arm) in arm_blocks {
            self.current_block = Some(block_id);
            let result = self.build_expression(&arm.expression)?;
            arm_results.push(result.clone());
            
            if !self.is_terminated() {
                self.terminate_block(Terminator::Jump {
                    target: end_block,
                    args: vec![result],
                });
            }
        }
        
        // Create end block with phi node
        let end_basic_block = BasicBlock {
            id: end_block,
            params: vec![BlockParam {
                name: ident!("match_result"),
                ty: result_ty,
            }],
            instructions: vec![],
            terminator: Terminator::Return(None), // placeholder
        };
        
        if let Some(func_name) = &self.current_function {
            self.ir.functions.get_mut(func_name).unwrap()
                .cfg.blocks.insert(end_block, end_basic_block);
        }
        
        self.current_block = Some(end_block);
        
        // Return the phi value
        Ok(Value::Use(ValueId {
            block: end_block,
            index: 0, // First parameter
        }))
    }
    
    /// Build an internal function expression.
    fn build_internal_function(&mut self, func: &ast::InternalFunction) -> Result<Value, IRBuildError> {
        match func {
            ast::InternalFunction::Query(fact) => {
                let mut key_constraints = Vec::new();
                let mut value_constraints = Vec::new();
                
                for (name, field) in &fact.key_fields {
                    if let ast::FactField::Expression(expr) = field {
                        let value = self.build_expression(expr)?;
                        key_constraints.push((name.clone(), value));
                    }
                }
                
                if let Some(value_fields) = &fact.value_fields {
                    for (name, field) in value_fields {
                        if let ast::FactField::Expression(expr) = field {
                            let value = self.build_expression(expr)?;
                            value_constraints.push((name.clone(), value));
                        }
                    }
                }
                
                self.emit_instruction(Instruction::QueryFact {
                    fact_type: fact.identifier.clone(),
                    key_constraints,
                    value_constraints,
                    ty: VType::Optional(Box::new(VType::Struct(fact.identifier.clone()))),
                })
            }
            
            ast::InternalFunction::Exists(fact) => {
                // Query and check if not None
                let query_result = self.build_internal_function(&ast::InternalFunction::Query(fact.clone()))?;
                self.emit_instruction(Instruction::IsSome { value: query_result })
            }
            
            ast::InternalFunction::FactCount(cmp_type, limit, fact) => {
                let mut constraints = Vec::new();
                
                for (name, field) in &fact.key_fields {
                    if let ast::FactField::Expression(expr) = field {
                        let value = self.build_expression(expr)?;
                        constraints.push((name.clone(), value));
                    }
                }
                
                if let Some(value_fields) = &fact.value_fields {
                    for (name, field) in value_fields {
                        if let ast::FactField::Expression(expr) = field {
                            let value = self.build_expression(expr)?;
                            constraints.push((name.clone(), value));
                        }
                    }
                }
                
                let count = self.emit_instruction(Instruction::FactCount {
                    fact_type: fact.identifier.clone(),
                    constraints,
                    limit: *limit,
                    ty: VType::Int,
                })?;
                
                // Generate comparison based on type
                let limit_val = Value::Const(ConstValue::Int(*limit));
                match cmp_type {
                    ast::FactCountType::Exactly => {
                        self.emit_binary_op(BinaryOp::Eq, count, limit_val, VType::Bool)
                    }
                    ast::FactCountType::AtLeast => {
                        self.emit_binary_op(BinaryOp::GtEq, count, limit_val, VType::Bool)
                    }
                    ast::FactCountType::UpTo => {
                        Ok(count) // Just return the count
                    }
                    ast::FactCountType::AtMost => {
                        self.emit_binary_op(BinaryOp::LtEq, count, limit_val, VType::Bool)
                    }
                }
            }
            
            ast::InternalFunction::If(cond, then_expr, else_expr) => {
                let condition = self.build_expression(cond)?;
                
                let then_block = self.new_block();
                let else_block = self.new_block();
                let end_block = self.new_block();
                
                // Branch on condition
                self.terminate_block(Terminator::Branch {
                    condition,
                    true_block: then_block,
                    true_args: vec![],
                    false_block: else_block,
                    false_args: vec![],
                });
                
                // Then block
                self.current_block = Some(then_block);
                let then_result = self.build_expression(then_expr)?;
                if !self.is_terminated() {
                    self.terminate_block(Terminator::Jump {
                        target: end_block,
                        args: vec![then_result],
                    });
                }
                
                // Else block
                self.current_block = Some(else_block);
                let else_result = self.build_expression(else_expr)?;
                if !self.is_terminated() {
                    self.terminate_block(Terminator::Jump {
                        target: end_block,
                        args: vec![else_result],
                    });
                }
                
                // End block with phi
                let result_ty = self.infer_expression_type(then_expr)?;
                let end_basic_block = BasicBlock {
                    id: end_block,
                    params: vec![BlockParam {
                        name: ident!("if_result"),
                        ty: result_ty,
                    }],
                    instructions: vec![],
                    terminator: Terminator::Return(None), // placeholder
                };
                
                if let Some(func_name) = &self.current_function {
                    self.ir.functions.get_mut(func_name).unwrap()
                        .cfg.blocks.insert(end_block, end_basic_block);
                }
                
                self.current_block = Some(end_block);
                
                Ok(Value::Use(ValueId {
                    block: end_block,
                    index: 0,
                }))
            }
            
            ast::InternalFunction::Serialize(expr) => {
                let value = self.build_expression(expr)?;
                self.emit_instruction(Instruction::Serialize { value })
            }
            
            ast::InternalFunction::Deserialize(expr) => {
                let value = self.build_expression(expr)?;
                // Type would need to be inferred from context
                let ty = VType::String; // placeholder
                self.emit_instruction(Instruction::Deserialize { value, ty })
            }
        }
    }
    
    /// Build a fact pattern as a value.
    fn build_fact_pattern(&mut self, fact: &ast::FactLiteral) -> Result<Value, IRBuildError> {
        // Build a struct representing the fact pattern
        let mut fields = Vec::new();
        
        for (name, field) in &fact.key_fields {
            if let ast::FactField::Expression(expr) = field {
                let value = self.build_expression(expr)?;
                fields.push((name.clone(), value));
            }
        }
        
        if let Some(value_fields) = &fact.value_fields {
            for (name, field) in value_fields {
                if let ast::FactField::Expression(expr) = field {
                    let value = self.build_expression(expr)?;
                    fields.push((name.clone(), value));
                }
            }
        }
        
        self.emit_instruction(Instruction::StructNew {
            struct_type: fact.identifier.clone(),
            fields,
            ty: VType::Struct(fact.identifier.clone()),
        })
    }
}