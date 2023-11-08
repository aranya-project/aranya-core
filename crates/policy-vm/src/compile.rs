extern crate alloc;

use alloc::{
    borrow::ToOwned,
    collections::{btree_map, BTreeMap},
    format,
    string::String,
    vec::Vec,
};
use core::fmt;

use cfg_if::cfg_if;
use policy_ast::{self as ast, AstNode};

use crate::{CodeMap, Instruction, Label, LabelType, Machine, Target, Value};

cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        use core::error;
    } else if #[cfg(feature = "std")] {
        use std::error;
    }
}

/// Errors that can occur during compilation.
#[derive(Debug, PartialEq)]
pub enum CompileError {
    /// Invalid - the AST element does not make sense in this context
    InvalidElement,
    /// Resolution of branch targets failed to find a valid target
    BadTarget,
    /// An argument to a function or an item in an expression did not
    /// make sense
    BadArgument,
    /// A thing referenced is not defined
    NotDefined,
    /// A thing by that name has already been defined
    AlreadyDefined,
    /// A pure function has no return statement
    NoReturn,
    /// All other errors
    Unknown(String),
}

impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidElement => write!(f, "Invalid element"),
            Self::BadTarget => write!(f, "Bad branch target"),
            Self::BadArgument => write!(f, "Bad argument"),
            Self::NotDefined => write!(f, "Not defined"),
            Self::AlreadyDefined => write!(f, "Already defined"),
            Self::NoReturn => write!(f, "Function has no return statement"),
            Self::Unknown(s) => write!(f, "Unknown error: {}", s),
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for CompileError {}

enum FunctionColor {
    /// Function has no side-effects and returns a value
    Pure(ast::VType),
    /// Function has side-effects and returns no value
    Finish,
}

/// This is like [FunctionDefinition](ast::FunctionDefinition), but
/// stripped down to only include positional argument types and return
/// type. Covers both regular (pure) functions and finish functions.
struct FunctionSignature {
    args: Vec<ast::VType>,
    color: FunctionColor,
}

/// The "compile state" of the machine.
pub struct CompileState {
    /// The underlying machine
    m: Machine,
    /// The write pointer used while compiling instructions into memory
    wp: usize,
    /// A counter used to generate temporary labels
    c: usize,
    /// A map between function names and signatures, so that they can
    /// be easily looked up for verification when called.
    function_signatures: BTreeMap<String, FunctionSignature>,
}

impl CompileState {
    /// Create a new CompileState which compiles into the owned
    /// machine.
    pub fn new(m: Machine) -> CompileState {
        CompileState {
            m,
            wp: 0,
            c: 0,
            function_signatures: BTreeMap::new(),
        }
    }

    /// Append an instruction to the program memory, and increment the
    /// program counter. If no other PC manipulation has been done,
    /// this means that the program counter points to the new
    /// instruction.
    pub fn append_instruction(&mut self, i: Instruction) {
        self.m.progmem.push(i);
        self.wp += 1;
    }

    /// Insert a struct definition.
    pub fn define_struct(&mut self, name: &str, fields: &[ast::FieldDefinition]) {
        self.m
            .struct_defs
            .insert(name.to_owned(), fields.to_owned());
    }

    /// Turn a [FunctionDefinition](ast::FunctionDefinition) into a
    /// [FunctionSignature].
    fn define_function_signature(
        &mut self,
        def: &ast::FunctionDefinition,
    ) -> Result<&FunctionSignature, CompileError> {
        match self.function_signatures.entry(def.identifier.clone()) {
            btree_map::Entry::Vacant(e) => {
                let signature = FunctionSignature {
                    args: def.arguments.iter().map(|a| a.field_type.clone()).collect(),
                    color: FunctionColor::Pure(def.return_type.clone()),
                };
                Ok(e.insert(signature))
            }
            btree_map::Entry::Occupied(_) => Err(CompileError::AlreadyDefined),
        }
    }

    /// Turn a [FinishFunctionDefinition](ast::FinishFunctionDefinition)
    /// into a [FunctionSignature].
    fn define_finish_function_signature(
        &mut self,
        def: &ast::FinishFunctionDefinition,
    ) -> Result<&FunctionSignature, CompileError> {
        match self.function_signatures.entry(def.identifier.clone()) {
            btree_map::Entry::Vacant(e) => {
                let signature = FunctionSignature {
                    args: def.arguments.iter().map(|a| a.field_type.clone()).collect(),
                    color: FunctionColor::Finish,
                };
                Ok(e.insert(signature))
            }
            btree_map::Entry::Occupied(_) => Err(CompileError::AlreadyDefined),
        }
    }

    /// Define a named Label.
    pub fn define_label(&mut self, identifier: &str, addr: usize, ntype: LabelType) {
        self.m
            .labels
            .insert(identifier.to_owned(), Label { addr, ltype: ntype });
    }

    /// Create an anonymous Label and return its identifier.
    pub fn anonymous_name(&mut self) -> String {
        let name = format!("anonymous{}", self.c);
        self.c += 1;
        name
    }

    /// Maps the current write pointer to a text range supplied by an AST node
    fn map_range<N: fmt::Debug>(&mut self, node: &AstNode<N>) -> Result<(), CompileError> {
        if let Some(codemap) = &mut self.m.codemap {
            codemap
                .map_instruction_range(self.wp, node.locator)
                .map_err(|_| {
                    CompileError::Unknown(format!(
                        "could not map address {} to text range {}",
                        self.wp, node.locator
                    ))
                })
        } else {
            // If there is no codemap, do nothing.
            Ok(())
        }
    }

    /// Resolve a target to an address from the Label mapping
    // This is a static method because it's used after self has already
    // been borrowed &mut in resolve_targets() below.
    fn resolve_target(
        target: &mut Target,
        labels: &mut BTreeMap<String, Label>,
    ) -> Result<(), CompileError> {
        match target.clone() {
            Target::Unresolved(s) => {
                let name = labels.get(&s).ok_or(CompileError::BadTarget)?;

                *target = Target::Resolved(name.addr);
                if name.ltype == LabelType::Temporary {
                    labels.remove(&s);
                }
                Ok(())
            }
            Target::Resolved(_) => Ok(()), // already resolved; do nothing
        }
    }

    /// Attempt to resolve any unresolved targets.
    pub fn resolve_targets(&mut self) -> Result<(), CompileError> {
        for ref mut instr in &mut self.m.progmem {
            match instr {
                Instruction::Branch(t) | Instruction::Jump(t) | Instruction::Call(t) => {
                    Self::resolve_target(t, &mut self.m.labels)?
                }
                _ => (),
            }
        }

        Ok(())
    }

    /// Compile instructions to construct a struct literal
    fn compile_struct_literal(&mut self, s: &ast::NamedStruct) -> Result<(), CompileError> {
        if !self.m.struct_defs.contains_key(&s.identifier) {
            // Because structs are dynamically created, this is all we
            // can check at this point. Field validation has to happen
            // at runtime.
            return Err(CompileError::BadArgument);
        }
        self.append_instruction(Instruction::Const(Value::String(s.identifier.clone())));
        self.append_instruction(Instruction::StructNew);
        for field in &s.fields {
            self.compile_expression(&field.1)?;
            self.append_instruction(Instruction::Const(Value::String(field.0.clone())));
            self.append_instruction(Instruction::StructSet);
        }
        Ok(())
    }

    /// Compile instructions to construct a fact literal
    fn compile_fact_literal(&mut self, f: &ast::FactLiteral) -> Result<(), CompileError> {
        self.append_instruction(Instruction::Const(Value::String(f.identifier.clone())));
        self.append_instruction(Instruction::FactNew);
        for field in &f.key_fields {
            self.compile_expression(&field.1)?;
            self.append_instruction(Instruction::Const(Value::String(field.0.clone())));
            self.append_instruction(Instruction::FactKeySet);
        }
        if let Some(value_fields) = &f.value_fields {
            for field in value_fields {
                if field.1 == ast::Expression::Bind {
                    // Bind expressions' values are unset
                    continue;
                }
                self.compile_expression(&field.1)?;
                self.append_instruction(Instruction::Const(Value::String(field.0.clone())));
                self.append_instruction(Instruction::FactValueSet);
            }
        }
        Ok(())
    }

    /// Compile an expression
    fn compile_expression(&mut self, expression: &ast::Expression) -> Result<(), CompileError> {
        match expression {
            ast::Expression::Int(n) => self.append_instruction(Instruction::Const(Value::Int(*n))),
            ast::Expression::String(s) => {
                self.append_instruction(Instruction::Const(Value::String(s.clone())))
            }
            ast::Expression::Bool(b) => {
                self.append_instruction(Instruction::Const(Value::Bool(*b)))
            }
            ast::Expression::Optional(o) => match o {
                None => self.append_instruction(Instruction::Const(Value::None)),
                Some(v) => {
                    self.compile_expression(v)?;
                }
            },
            ast::Expression::NamedStruct(s) => {
                self.compile_struct_literal(s)?;
            }
            ast::Expression::Bind => {
                return Err(CompileError::InvalidElement);
            }
            ast::Expression::InternalFunction(f) => match f {
                ast::InternalFunction::Query(f) => {
                    self.compile_fact_literal(f)?;
                    self.append_instruction(Instruction::Query);
                }
                ast::InternalFunction::Exists(f) => {
                    self.compile_fact_literal(f)?;
                    self.append_instruction(Instruction::Exists);
                }
                ast::InternalFunction::If(e, t, f) => {
                    let else_name = self.anonymous_name();
                    let end_name = self.anonymous_name();
                    self.compile_expression(e)?;
                    self.append_instruction(Instruction::Branch(Target::Unresolved(
                        else_name.clone(),
                    )));
                    self.compile_expression(f)?;
                    self.append_instruction(Instruction::Jump(Target::Unresolved(
                        end_name.clone(),
                    )));
                    self.define_label(&else_name, self.wp, LabelType::Temporary);
                    self.compile_expression(t)?;
                    self.define_label(&end_name, self.wp, LabelType::Temporary);
                }
                ast::InternalFunction::Id(_) => todo!(),
                ast::InternalFunction::AuthorId(_) => todo!(),
            },
            ast::Expression::FunctionCall(f) => {
                let signature = self
                    .function_signatures
                    .get(&f.identifier)
                    .ok_or(CompileError::NotDefined)?;
                // Check that this function is the right color - only
                // pure functions are allowed in expressions.
                if let FunctionColor::Finish = signature.color {
                    return Err(CompileError::InvalidElement);
                }
                // For now all we can do is check that the argument
                // list has the same length.
                // TODO(chip): Do more deep type analysis to check
                // arguments and return types.
                if signature.args.len() != f.arguments.len() {
                    return Err(CompileError::BadArgument);
                }
                for a in &f.arguments {
                    self.compile_expression(a)?;
                }
                self.append_instruction(Instruction::Call(Target::Unresolved(
                    f.identifier.clone(),
                )));
            }
            ast::Expression::Identifier(i) => {
                self.append_instruction(Instruction::Const(Value::String(i.clone())));
                self.append_instruction(Instruction::Get);
            }
            ast::Expression::Parentheses(e) => {
                self.compile_expression(e)?;
            }
            ast::Expression::Dot(t, s) => {
                self.compile_expression(t)?;
                let sr: &str = s.as_ref();
                self.append_instruction(Instruction::Const(sr.into()));
                self.append_instruction(Instruction::StructGet);
            }
            ast::Expression::Add(a, b)
            | ast::Expression::Subtract(a, b)
            | ast::Expression::And(a, b)
            | ast::Expression::Or(a, b)
            | ast::Expression::Equal(a, b)
            | ast::Expression::GreaterThan(a, b)
            | ast::Expression::LessThan(a, b) => {
                self.compile_expression(a)?;
                self.compile_expression(b)?;
                self.append_instruction(match expression {
                    ast::Expression::Add(_, _) => Instruction::Add,
                    ast::Expression::Subtract(_, _) => Instruction::Sub,
                    ast::Expression::And(_, _) => Instruction::And,
                    ast::Expression::Or(_, _) => Instruction::Or,
                    ast::Expression::Equal(_, _) => Instruction::Eq,
                    ast::Expression::GreaterThan(_, _) => Instruction::Gt,
                    ast::Expression::LessThan(_, _) => Instruction::Lt,
                    _ => unreachable!(),
                });
            }
            ast::Expression::GreaterThanOrEqual(a, b) | ast::Expression::LessThanOrEqual(a, b) => {
                self.compile_expression(a)?;
                self.compile_expression(b)?;
                // At this point we will have the values for a and b on the stack.
                // a b
                // Duplicate one below top to copy a to the top
                // a b a
                self.append_instruction(Instruction::Dup(1));
                // Ditto for b
                // a b a b
                self.append_instruction(Instruction::Dup(1));
                // Test for equivalence of a and b - we'll call this c
                // a b c
                self.append_instruction(Instruction::Eq);
                // Swap a and c
                // c b a
                self.append_instruction(Instruction::Swap(2));
                // Swap a and b
                // c a b
                self.append_instruction(Instruction::Swap(1));
                // Then execute the other comparison on a and b - we'll call this d
                // c d
                self.append_instruction(match expression {
                    ast::Expression::GreaterThanOrEqual(_, _) => Instruction::Gt,
                    ast::Expression::LessThanOrEqual(_, _) => Instruction::Lt,
                    _ => unreachable!(),
                });
                // Now OR those two binary results together - call this e
                // e
                self.append_instruction(Instruction::Or);
            }
            ast::Expression::NotEqual(a, b) => {
                self.compile_expression(a)?;
                self.compile_expression(b)?;
                self.append_instruction(Instruction::Eq);
                self.append_instruction(Instruction::Not);
            }
            ast::Expression::Negative(_) => todo!(),
            ast::Expression::Not(_) => todo!(),
            ast::Expression::Unwrap(e) => {
                // create an anonymous name for the successful case
                let not_none = self.anonymous_name();
                // evaluate the expression
                self.compile_expression(e)?;
                // Duplicate value for testing
                self.append_instruction(Instruction::Dup(0));
                // Push a None to compare against
                self.append_instruction(Instruction::Const(Value::None));
                // Is the value not equal to None?
                self.append_instruction(Instruction::Eq);
                self.append_instruction(Instruction::Not);
                // Then branch over the Panic
                self.append_instruction(Instruction::Branch(Target::Unresolved(not_none.clone())));
                // If the value is equal to None, panic
                self.append_instruction(Instruction::Panic);
                // Define the target of the branch as the instruction after the Panic
                self.define_label(&not_none, self.wp, LabelType::Temporary);
            }
            ast::Expression::Is(_, _) => todo!(),
        }

        Ok(())
    }

    /// Compile policy statements
    fn compile_statements(
        &mut self,
        statements: &[AstNode<ast::Statement>],
    ) -> Result<(), CompileError> {
        for statement in statements {
            self.map_range(statement)?;
            match &statement.inner {
                ast::Statement::Let(s) => {
                    self.compile_expression(&s.expression)?;
                    self.append_instruction(Instruction::Const(Value::String(
                        s.identifier.clone(),
                    )));
                    self.append_instruction(Instruction::Def);
                }
                ast::Statement::Check(s) => {
                    self.compile_expression(&s.expression)?;
                    // The current instruction is the branch. The next
                    // instruction is the following panic you arrive at
                    // if the expression is false. The instruction you
                    // branch to if the check succeeds is the
                    // instruction after that - current instruction + 2.
                    self.append_instruction(Instruction::Branch(Target::Resolved(self.wp + 2)));
                    self.append_instruction(Instruction::Panic);
                }
                ast::Statement::Match(_) => todo!(),
                ast::Statement::When(s) => {
                    let end_name = self.anonymous_name();
                    self.compile_expression(&s.expression)?;
                    self.append_instruction(Instruction::Not);
                    self.append_instruction(Instruction::Branch(Target::Unresolved(
                        end_name.clone(),
                    )));
                    self.compile_statements(&s.statements)?;
                    self.define_label(&end_name, self.wp, LabelType::Temporary);
                }
                ast::Statement::Emit(s) => {
                    self.compile_expression(s)?;
                    self.append_instruction(Instruction::Emit);
                }
                ast::Statement::Return(s) => {
                    self.compile_expression(&s.expression)?;
                    self.append_instruction(Instruction::Return);
                }
                ast::Statement::Finish(s) => {
                    self.compile_finish_statements(s)?;
                }
            }
        }
        Ok(())
    }

    /// Compile finish statements
    fn compile_finish_statements(
        &mut self,
        statements: &[AstNode<ast::FinishStatement>],
    ) -> Result<(), CompileError> {
        for statement in statements {
            self.map_range(statement)?;
            match &statement.inner {
                ast::FinishStatement::Create(s) => {
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Create);
                }
                ast::FinishStatement::Update(s) => {
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Dup(0));
                    for (k, v) in &s.to {
                        if *v == ast::Expression::Bind {
                            // Cannot bind in the set statement
                            return Err(CompileError::BadArgument);
                        }
                        self.compile_expression(v)?;
                        self.append_instruction(Instruction::Const(Value::String(k.clone())));
                        self.append_instruction(Instruction::FactValueSet);
                    }
                    self.append_instruction(Instruction::Update);
                }
                ast::FinishStatement::Delete(s) => {
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Delete);
                }
                ast::FinishStatement::Effect(s) => {
                    self.compile_expression(s)?;
                    self.append_instruction(Instruction::Effect);
                }
                ast::FinishStatement::FunctionCall(f) => {
                    let signature = self
                        .function_signatures
                        .get(&f.identifier)
                        .ok_or(CompileError::NotDefined)?;
                    // Check that this function is the right color -
                    // only finish functions are allowed in finish
                    // blocks.
                    if let FunctionColor::Pure(_) = signature.color {
                        return Err(CompileError::InvalidElement);
                    }
                    // For now all we can do is check that the argument
                    // list has the same length.
                    // TODO(chip): Do more deep type analysis to check
                    // arguments and return types.
                    if signature.args.len() != f.arguments.len() {
                        return Err(CompileError::BadArgument);
                    }
                    for a in &f.arguments {
                        self.compile_expression(a)?;
                    }
                    self.append_instruction(Instruction::Call(Target::Unresolved(
                        f.identifier.clone(),
                    )));
                }
            }
        }
        Ok(())
    }

    /// Compile a function
    fn compile_function(
        &mut self,
        function_node: &AstNode<ast::FunctionDefinition>,
    ) -> Result<(), CompileError> {
        let function = &function_node.inner;
        self.define_label(&function.identifier, self.wp, LabelType::Temporary);
        self.map_range(function_node)?;
        self.define_function_signature(function)?;
        for arg in function.arguments.iter().rev() {
            self.append_instruction(Instruction::Const(Value::String(arg.identifier.clone())));
            self.append_instruction(Instruction::Def);
        }
        let from = self.wp;
        self.compile_statements(&function.statements)?;
        // Check that there is a return statement somewhere in the compiled instructions.
        if !self.m.progmem[from..self.wp]
            .iter()
            .any(|i| matches!(i, Instruction::Return))
        {
            return Err(CompileError::NoReturn);
        }
        // If execution does not hit a return statement, it will panic here.
        self.append_instruction(Instruction::Panic);
        Ok(())
    }

    /// Compile a finish function
    fn compile_finish_function(
        &mut self,
        function_node: &AstNode<ast::FinishFunctionDefinition>,
    ) -> Result<(), CompileError> {
        let function = &function_node.inner;
        self.define_label(&function.identifier, self.wp, LabelType::Temporary);
        self.map_range(function_node)?;
        self.define_finish_function_signature(function)?;
        for arg in function.arguments.iter().rev() {
            self.append_instruction(Instruction::Const(Value::String(arg.identifier.clone())));
            self.append_instruction(Instruction::Def);
        }
        self.compile_finish_statements(&function.statements)?;
        // Finish functions cannot have return statements, so we add a return instruction
        // manually.
        self.append_instruction(Instruction::Return);
        Ok(())
    }

    /// Compile an action function
    fn compile_action(
        &mut self,
        action_node: &AstNode<ast::ActionDefinition>,
    ) -> Result<(), CompileError> {
        let action = &action_node.inner;
        self.define_label(&action.identifier, self.wp, LabelType::Action);
        self.map_range(action_node)?;

        for arg in action.arguments.iter().rev() {
            self.append_instruction(Instruction::Const(Value::String(arg.identifier.clone())));
            self.append_instruction(Instruction::Def);
        }

        self.compile_statements(&action.statements)?;

        self.append_instruction(Instruction::Exit);

        Ok(())
    }

    /// Compile a command policy block
    fn compile_command(
        &mut self,
        command_node: &AstNode<ast::CommandDefinition>,
    ) -> Result<(), CompileError> {
        let command = &command_node.inner;
        self.define_struct(&command.identifier, &command.fields);
        self.map_range(command_node)?;

        self.define_label(&command.identifier, self.wp, LabelType::Command);

        self.compile_statements(&command.policy)?;

        self.append_instruction(Instruction::Exit);

        Ok(())
    }

    /// Compile a policy into instructions inside the given Machine.
    pub fn compile(&mut self, policy: &ast::Policy) -> Result<(), CompileError> {
        for effect in &policy.effects {
            let fields: Vec<ast::FieldDefinition> =
                effect.inner.fields.iter().map(|f| f.into()).collect();
            self.define_struct(&effect.inner.identifier, &fields);
        }

        for struct_def in &policy.structs {
            self.define_struct(&struct_def.inner.identifier, &struct_def.inner.fields);
        }

        for function_def in &policy.functions {
            self.compile_function(function_def)?;
        }

        for function_def in &policy.finish_functions {
            self.compile_finish_function(function_def)?;
        }

        for command in &policy.commands {
            self.compile_command(command)?;
        }

        for action in &policy.actions {
            self.compile_action(action)?;
        }

        for effect in &policy.effects {
            let fields: Vec<ast::FieldDefinition> =
                effect.inner.fields.iter().map(|f| f.into()).collect();
            self.define_struct(&effect.inner.identifier, &fields);
        }

        self.resolve_targets()?;

        Ok(())
    }

    /// Finish compilation; return the internal machine
    pub fn into_machine(self) -> Machine {
        self.m
    }
}

/// Create a new Machine by compiling a policy AST.
pub fn compile_from_policy(policy: &ast::Policy) -> Result<Machine, CompileError> {
    let codemap = CodeMap::new(&policy.text, policy.ranges.clone());
    let machine = Machine::from_codemap(codemap);
    let mut cs = CompileState::new(machine);
    cs.compile(policy)?;
    Ok(cs.into_machine())
}
