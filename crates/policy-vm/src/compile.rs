extern crate alloc;

mod error;
mod tests;
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::{btree_map, BTreeMap},
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{fmt, ops::Range};

pub use ast::Policy as AstPolicy;
use ast::{Expression, FactDefinition, FactLiteral, FieldDefinition};
use buggy::BugExt;
use policy_ast::{self as ast, AstNode, VType};

pub use self::error::{CallColor, CompileError, CompileErrorType};
use crate::{ffi::ModuleSchema, CodeMap, Instruction, Label, LabelType, Machine, Target, Value};

enum FunctionColor {
    /// Function has no side-effects and returns a value
    Pure(#[allow(unused)] VType),
    /// Function has side-effects and returns no value
    Finish,
}

/// This is like [FunctionDefinition](ast::FunctionDefinition), but
/// stripped down to only include positional argument types and return
/// type. Covers both regular (pure) functions and finish functions.
struct FunctionSignature {
    args: Vec<VType>,
    color: FunctionColor,
}

/// Enumerates all the possible contexts a statement can be in, to validate whether a
/// statement is currently valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatementContext {
    /// An action
    Action,
    /// A command policy block
    CommandPolicy,
    /// A command recall block
    CommandRecall,
    /// A pure function
    PureFunction,
    /// A finish function or finish block
    Finish,
}

impl fmt::Display for StatementContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StatementContext::Action => write!(f, "action"),
            StatementContext::CommandPolicy => write!(f, "command policy block"),
            StatementContext::CommandRecall => write!(f, "command recall block"),
            StatementContext::PureFunction => write!(f, "pure function"),
            StatementContext::Finish => write!(f, "finish block/function"),
        }
    }
}

/// The "compile state" of the machine.
pub struct CompileState<'a> {
    /// The underlying machine
    m: Machine,
    /// The write pointer used while compiling instructions into memory
    wp: usize,
    /// A counter used to generate temporary labels
    c: usize,
    /// A map between function names and signatures, so that they can
    /// be easily looked up for verification when called.
    function_signatures: BTreeMap<String, FunctionSignature>,
    /// The last locator seen, for imprecise source locating.
    // TODO(chip): Push more precise source tracking further down into the AST.
    last_locator: usize,
    /// The current statement context, implemented as a stack so that it can be
    /// hierarchical.
    statement_context: Vec<StatementContext>,
    /// FFI module schemas. Used to validate FFI calls.
    ffi_modules: &'a [ModuleSchema<'a>],
}

impl<'a> CompileState<'a> {
    /// Create a new CompileState which compiles into the owned
    /// machine.
    pub fn new(m: Machine, ffi_modules: &'a [ModuleSchema<'a>]) -> Self {
        CompileState {
            m,
            wp: 0,
            c: 0,
            function_signatures: BTreeMap::new(),
            last_locator: 0,
            statement_context: vec![],
            ffi_modules,
        }
    }

    /// Begin parsing statements in this context
    fn enter_statement_context(&mut self, c: StatementContext) {
        self.statement_context.push(c);
    }

    /// End parsing statements in this context and return to the previous context
    fn exit_statement_context(&mut self) {
        self.statement_context.pop();
    }

    /// Get the statement context
    fn get_statement_context(&self) -> Result<StatementContext, CompileError> {
        let cs = self
            .statement_context
            .last()
            .ok_or(CompileError::from_locator(
                CompileErrorType::Unknown(String::from(
                    "compiling statement without statement context",
                )),
                self.last_locator,
                self.m.codemap.as_ref(),
            ))?
            .clone();
        Ok(cs)
    }

    /// Append an instruction to the program memory, and increment the
    /// program counter. If no other PC manipulation has been done,
    /// this means that the program counter points to the new
    /// instruction.
    fn append_instruction(&mut self, i: Instruction) {
        self.m.progmem.push(i);
        self.wp = self.wp.checked_add(1).expect("self.wp + 1 must not wrap");
    }

    /// Inserts a fact definition
    fn define_fact(&mut self, fact: &FactDefinition) -> Result<(), CompileError> {
        if self.m.fact_defs.contains_key(&fact.identifier) {
            return Err(CompileError::new(CompileErrorType::AlreadyDefined(
                fact.identifier.clone(),
            )));
        }

        self.m
            .fact_defs
            .insert(fact.identifier.clone(), fact.to_owned());
        Ok(())
    }

    /// Insert a struct definition while preventing duplicates.
    pub fn define_struct(
        &mut self,
        identifier: &str,
        fields: &[FieldDefinition],
    ) -> Result<(), CompileError> {
        match self.m.struct_defs.entry(identifier.to_string()) {
            btree_map::Entry::Vacant(e) => {
                e.insert(fields.to_vec());
                Ok(())
            }
            btree_map::Entry::Occupied(_) => Err(CompileError::from_locator(
                CompileErrorType::AlreadyDefined(identifier.to_string()),
                self.last_locator,
                self.m.codemap.as_ref(),
            )),
        }
    }

    /// Turn a [FunctionDefinition](ast::FunctionDefinition) into a
    /// [FunctionSignature].
    fn define_function_signature(
        &mut self,
        function_node: &AstNode<ast::FunctionDefinition>,
    ) -> Result<&FunctionSignature, CompileError> {
        let def = &function_node.inner;
        match self.function_signatures.entry(def.identifier.clone()) {
            btree_map::Entry::Vacant(e) => {
                let signature = FunctionSignature {
                    args: def.arguments.iter().map(|a| a.field_type.clone()).collect(),
                    color: FunctionColor::Pure(def.return_type.clone()),
                };
                Ok(e.insert(signature))
            }
            btree_map::Entry::Occupied(_) => Err(CompileError::from_locator(
                CompileErrorType::AlreadyDefined(def.identifier.clone()),
                function_node.locator,
                self.m.codemap.as_ref(),
            )),
        }
    }

    /// Turn a [FinishFunctionDefinition](ast::FinishFunctionDefinition)
    /// into a [FunctionSignature].
    fn define_finish_function_signature(
        &mut self,
        function_node: &AstNode<ast::FinishFunctionDefinition>,
    ) -> Result<&FunctionSignature, CompileError> {
        let def = &function_node.inner;
        match self.function_signatures.entry(def.identifier.clone()) {
            btree_map::Entry::Vacant(e) => {
                let signature = FunctionSignature {
                    args: def.arguments.iter().map(|a| a.field_type.clone()).collect(),
                    color: FunctionColor::Finish,
                };
                Ok(e.insert(signature))
            }
            btree_map::Entry::Occupied(_) => Err(CompileError::from_locator(
                CompileErrorType::AlreadyDefined(def.identifier.clone()),
                function_node.locator,
                self.m.codemap.as_ref(),
            )),
        }
    }

    /// Define a named Label.
    pub fn define_label(&mut self, label: Label, addr: usize) -> Result<(), CompileError> {
        match self.m.labels.entry(label.clone()) {
            btree_map::Entry::Vacant(e) => {
                e.insert(addr);
                Ok(())
            }
            btree_map::Entry::Occupied(_) => Err(CompileError::from_locator(
                CompileErrorType::AlreadyDefined(label.name),
                self.last_locator,
                self.m.codemap.as_ref(),
            )),
        }
    }

    /// Create an anonymous Label and return its identifier.
    pub fn anonymous_label(&mut self) -> Label {
        let name = format!("anonymous{}", self.c);
        self.c = self.c.checked_add(1).expect("self.c + 1 must not wrap");
        Label::new_temp(&name)
    }

    /// Maps the current write pointer to a text range supplied by an AST node
    fn map_range<N: fmt::Debug>(&mut self, node: &AstNode<N>) -> Result<(), CompileError> {
        self.last_locator = node.locator;
        if let Some(codemap) = &mut self.m.codemap {
            codemap
                .map_instruction_range(self.wp, node.locator)
                .map_err(|_| {
                    CompileError::from_locator(
                        CompileErrorType::Unknown(format!(
                            "could not map address {} to text range {}",
                            self.wp, node.locator
                        )),
                        node.locator,
                        self.m.codemap.as_ref(),
                    )
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
        labels: &mut BTreeMap<Label, usize>,
    ) -> Result<(), CompileError> {
        match target.clone() {
            Target::Unresolved(s) => {
                let addr = labels
                    .get(&s)
                    .ok_or(CompileErrorType::BadTarget(s.name.clone()))?;

                *target = Target::Resolved(*addr);
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

        // remove temporary labels
        self.m.labels.retain(|k, _| k.ltype != LabelType::Temporary);

        Ok(())
    }

    /// Compile instructions to construct a struct literal
    fn compile_struct_literal(&mut self, s: &ast::NamedStruct) -> Result<(), CompileError> {
        if !self.m.struct_defs.contains_key(&s.identifier) {
            // Because structs are dynamically created, this is all we
            // can check at this point. Field validation has to happen
            // at runtime.
            return Err(CompileError::from_locator(
                CompileErrorType::BadArgument(s.identifier.clone()),
                self.last_locator,
                self.m.codemap.as_ref(),
            ));
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

    fn err(&self, err_type: CompileErrorType) -> CompileError {
        CompileError::from_locator(err_type, self.last_locator, self.m.codemap.as_ref())
    }

    fn get_fact_def(&self, name: &String) -> Result<&FactDefinition, CompileError> {
        self.m
            .fact_defs
            .get(name)
            .ok_or(self.err(CompileErrorType::NotDefined(name.clone())))
    }

    /// Make sure fact literal matches its schema. Checks that:
    /// - a fact with this name was defined
    /// - the keys and values all exist, and have the correct types
    /// - there are no duplicate key or value names
    fn verify_fact_against_schema(&self, fact: &FactLiteral) -> Result<(), CompileError> {
        // Fetch schema
        let fact_def = self.get_fact_def(&fact.identifier)?;

        // Ensure there are no duplicate keys in the literal
        if let Some(dup_key) = find_duplicate(&fact.key_fields, |k| &k.0) {
            return Err(self.err(CompileErrorType::Unknown(format!(
                "Duplicate key: {}",
                dup_key
            ))));
        }

        // Ensure the fact has all keys defined in the schema, and they have matching types.
        // Key order doesn't matter.
        for schema_key in fact_def.key.iter() {
            let fact_key = fact
                .key_fields
                .iter()
                .find(|k| k.0 == schema_key.identifier)
                .ok_or(CompileError::from_locator(
                    CompileErrorType::Missing(schema_key.identifier.clone()),
                    self.last_locator,
                    self.m.codemap.as_ref(),
                ))?;

            let Some(vtype) = expression_vtype(&fact_key.1) else {
                // If the type cannot be determined, e.g. it's an expression or query, return Ok. The machine will verify the type at runtime.
                // TODO should we allow expressions/queries for key values?
                return Ok(());
            };

            // key type must be one of `HashableValue`
            if !((vtype == VType::Int
                || vtype == VType::Bool
                || vtype == VType::String
                || vtype == VType::Id)
                && schema_key.field_type == vtype)
            {
                return Err(self.err(CompileErrorType::InvalidType));
            };
        }

        if let Some(values) = &fact.value_fields {
            self.verify_fact_values(values, fact_def)
        } else {
            Ok(())
        }
    }

    fn verify_fact_values(
        &self,
        values: &[(String, Expression)],
        fact_def: &FactDefinition,
    ) -> Result<(), CompileError> {
        // Ensure there are no duplicate values in the literal
        if let Some(dup_value) = find_duplicate(values, |v| &v.0) {
            return Err(self.err(CompileErrorType::Unknown(format!(
                "Duplicate value: {}",
                dup_value
            ))));
        }

        // Ensure values exist in schema, and have matching types
        for lit_v in values.iter() {
            let def_v = fact_def
                .value
                .iter()
                .find(|v| v.identifier == lit_v.0)
                .ok_or(CompileError::from_locator(
                    CompileErrorType::NotDefined(lit_v.0.clone()),
                    self.last_locator,
                    self.m.codemap.as_ref(),
                ))?;

            let Some(lit_type) = expression_vtype(&lit_v.1) else {
                // Let complex expressions through, the machine will resolve and verify them.
                continue;
            };
            if lit_type != def_v.field_type {
                return Err(self.err(CompileErrorType::InvalidType));
            }
        }

        Ok(())
    }

    /// Compile instructions to construct a fact literal
    fn compile_fact_literal(&mut self, f: &FactLiteral) -> Result<(), CompileError> {
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
    fn compile_expression(&mut self, expression: &Expression) -> Result<(), CompileError> {
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
                return Err(CompileError::from_locator(
                    CompileErrorType::InvalidExpression(expression.clone()),
                    self.last_locator,
                    self.m.codemap.as_ref(),
                ));
            }
            ast::Expression::InternalFunction(f) => match f {
                ast::InternalFunction::Query(f) => {
                    self.verify_fact_against_schema(f)?;
                    self.compile_fact_literal(f)?;
                    self.append_instruction(Instruction::Query);
                }
                ast::InternalFunction::Exists(f) => {
                    self.verify_fact_against_schema(f)?;
                    self.compile_fact_literal(f)?;
                    self.append_instruction(Instruction::Query);
                    self.append_instruction(Instruction::Const(Value::None));
                    self.append_instruction(Instruction::Eq);
                    self.append_instruction(Instruction::Not);
                }
                ast::InternalFunction::If(e, t, f) => {
                    let else_name = self.anonymous_label();
                    let end_name = self.anonymous_label();
                    self.compile_expression(e)?;
                    self.append_instruction(Instruction::Branch(Target::Unresolved(
                        else_name.clone(),
                    )));
                    self.compile_expression(f)?;
                    self.append_instruction(Instruction::Jump(Target::Unresolved(
                        end_name.clone(),
                    )));
                    self.define_label(else_name, self.wp)?;
                    self.compile_expression(t)?;
                    self.define_label(end_name, self.wp)?;
                }
                ast::InternalFunction::Serialize(e) => {
                    if self.get_statement_context()? != StatementContext::PureFunction {
                        return Err(CompileError::from_locator(
                            CompileErrorType::InvalidExpression((**e).clone()),
                            self.last_locator,
                            self.m.codemap.as_ref(),
                        ));
                    }
                    self.compile_expression(e)?;
                    self.append_instruction(Instruction::Serialize);
                }
                ast::InternalFunction::Deserialize(e) => {
                    if self.get_statement_context()? != StatementContext::PureFunction {
                        return Err(CompileError::from_locator(
                            CompileErrorType::InvalidExpression((**e).clone()),
                            self.last_locator,
                            self.m.codemap.as_ref(),
                        ));
                    }
                    self.compile_expression(e)?;
                    self.append_instruction(Instruction::Deserialize);
                }
            },
            ast::Expression::FunctionCall(f) => {
                let signature = self.function_signatures.get(&f.identifier).ok_or(
                    CompileError::from_locator(
                        CompileErrorType::NotDefined(f.identifier.clone()),
                        self.last_locator,
                        self.m.codemap.as_ref(),
                    ),
                )?;
                // Check that this function is the right color - only
                // pure functions are allowed in expressions.
                if let FunctionColor::Finish = signature.color {
                    return Err(CompileError::from_locator(
                        CompileErrorType::InvalidCallColor(CallColor::Finish),
                        self.last_locator,
                        self.m.codemap.as_ref(),
                    ));
                }
                // For now all we can do is check that the argument
                // list has the same length.
                // TODO(chip): Do more deep type analysis to check
                // arguments and return types.
                if signature.args.len() != f.arguments.len() {
                    return Err(CompileError::from_locator(
                        CompileErrorType::BadArgument(format!(
                            "call to `{}` has {} arguments and it should have {}",
                            f.identifier,
                            f.arguments.len(),
                            signature.args.len()
                        )),
                        self.last_locator,
                        self.m.codemap.as_ref(),
                    ));
                }
                for a in &f.arguments {
                    self.compile_expression(a)?;
                }
                self.append_instruction(Instruction::Call(Target::Unresolved(Label::new_temp(
                    &f.identifier,
                ))));
            }
            ast::Expression::ForeignFunctionCall(f) => {
                // find module by name
                let (module_id, module) = self
                    .ffi_modules
                    .iter()
                    .enumerate()
                    .find(|(_, m)| m.name == f.module)
                    .ok_or(CompileError::from_locator(
                        CompileErrorType::NotDefined(f.module.clone()),
                        self.last_locator,
                        self.m.codemap.as_ref(),
                    ))?;

                // find module function by name
                let (procedure_id, procedure) = module
                    .functions
                    .iter()
                    .enumerate()
                    .find(|(_, proc)| proc.name == f.identifier)
                    .ok_or(CompileError::from_locator(
                        CompileErrorType::NotDefined(format!("{}::{}", f.module, f.identifier)),
                        self.last_locator,
                        self.m.codemap.as_ref(),
                    ))?;

                // verify number of arguments matches the function signature
                if f.arguments.len() != procedure.args.len() {
                    return Err(CompileError::from_locator(
                        CompileErrorType::BadArgument(f.identifier.clone()),
                        self.last_locator,
                        self.m.codemap.as_ref(),
                    ));
                }

                // push args
                for a in &f.arguments {
                    self.compile_expression(a)?;
                }

                self.append_instruction(Instruction::ExtCall(module_id, procedure_id));
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
            ast::Expression::Negative(e) => {
                if let ast::Expression::Int(value) = **e {
                    // Return negative of the int
                    self.append_instruction(Instruction::Const(Value::Int(
                        value
                            .checked_neg()
                            .assume("value is not `i64::MIN` because it is non-negative")?,
                    )));
                    return Ok(());
                }

                // Evaluate the expression
                self.compile_expression(e)?;

                // Push a 0 to subtract from
                self.append_instruction(Instruction::Const(Value::Int(0)));

                // Swap e and 0
                // 0 e
                self.append_instruction(Instruction::Swap(1));

                // Subtract
                self.append_instruction(Instruction::Sub);
            }
            ast::Expression::Not(e) => {
                // Evaluate the expression
                self.compile_expression(e)?;

                // Apply the logical NOT operation
                self.append_instruction(Instruction::Not);
            }
            ast::Expression::Unwrap(e) => {
                // create an anonymous name for the successful case
                let not_none = self.anonymous_label();
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
                self.define_label(not_none, self.wp)?;
            }
            ast::Expression::Is(e, expr_is_some) => {
                // Evaluate the expression
                self.compile_expression(e)?;
                // Push a None to compare against
                self.append_instruction(Instruction::Const(Value::None));
                // Check if the value is equal to None
                self.append_instruction(Instruction::Eq);
                if *expr_is_some {
                    // If we're checking for not Some, invert the result of the Eq to None
                    self.append_instruction(Instruction::Not);
                }
                // The result true or false is on the stack
            }
        }

        Ok(())
    }

    /// Compile policy statements
    fn compile_statements(
        &mut self,
        statements: &[AstNode<ast::Statement>],
    ) -> Result<(), CompileError> {
        let context = self.get_statement_context()?;
        for statement in statements {
            self.map_range(statement)?;
            // This match statement matches on a pair of the statement and its allowable
            // contexts, so that disallowed contexts will fall through to the default at the
            // bottom. This only checks the context at the statement level. It cannot, for
            // example, check whether an expression disallowed in finish context has been
            // evaluated from deep within a call chain. Further static analysis will have to
            // be done to ensure that.
            match (&statement.inner, &context) {
                (
                    ast::Statement::Let(s),
                    StatementContext::Action
                    | StatementContext::PureFunction
                    | StatementContext::CommandPolicy
                    | StatementContext::CommandRecall,
                ) => {
                    self.compile_expression(&s.expression)?;
                    self.append_instruction(Instruction::Const(Value::String(
                        s.identifier.clone(),
                    )));
                    self.append_instruction(Instruction::Def);
                }
                (
                    ast::Statement::Check(s),
                    StatementContext::Action
                    | StatementContext::CommandPolicy
                    | StatementContext::CommandRecall,
                ) => {
                    self.compile_expression(&s.expression)?;
                    // The current instruction is the branch. The next
                    // instruction is the following panic you arrive at
                    // if the expression is false. The instruction you
                    // branch to if the check succeeds is the
                    // instruction after that - current instruction + 2.
                    let next = self.wp.checked_add(2).assume("self.wp + 2 must not wrap")?;
                    self.append_instruction(Instruction::Branch(Target::Resolved(next)));
                    self.append_instruction(Instruction::Panic);
                }
                (
                    ast::Statement::Match(s),
                    StatementContext::Action
                    | StatementContext::PureFunction
                    | StatementContext::CommandPolicy
                    | StatementContext::CommandRecall,
                ) => {
                    // Ensure there are no duplicate arm values. Note that this is not completely reliable, because arm values are expressions, evaluated at runtime.
                    // Note: we don't check for zero arms, because that's syntactically invalid.
                    if find_duplicate(&s.arms, |a| &a.value).is_some() {
                        return Err(CompileError::from_locator(
                            CompileErrorType::AlreadyDefined(String::from(
                                "duplicate match arm value",
                            )),
                            statement.locator,
                            self.m.codemap.as_ref(),
                        ));
                    }

                    self.compile_expression(&s.expression)?;

                    let end_label = self.anonymous_label();

                    // 1. Generate branching instructions, and arm-start labels
                    let mut arm_labels: Vec<Label> = vec![];

                    for arm in s.arms.iter() {
                        self.append_instruction(Instruction::Dup(0));

                        let arm_label = self.anonymous_label();
                        arm_labels.push(arm_label.clone());

                        // Normal arm value
                        if let Some(value) = &arm.value {
                            self.compile_expression(value)?;

                            // if value == target, jump to start-of-arm
                            self.append_instruction(Instruction::Eq);
                            self.append_instruction(Instruction::Branch(Target::Unresolved(
                                arm_label.clone(),
                            )));
                        }
                        // Default case
                        else {
                            self.append_instruction(Instruction::Jump(Target::Unresolved(
                                arm_label.clone(),
                            )));

                            // Ensure this is the last case, and also that it's not the only case.
                            if arm != s.arms.last().expect("last arm") {
                                return Err(CompileError::new(CompileErrorType::Unknown(
                                    String::from("Default match case must be last."),
                                )));
                            }
                        }
                    }

                    // if no match, and no default case, panic
                    if !s.arms.iter().any(|a| a.value.is_none()) {
                        self.append_instruction(Instruction::Panic);
                    }

                    // 2. Define arm labels, and compile instructions
                    for (i, arm) in s.arms.iter().enumerate() {
                        let arm_start = arm_labels[i].to_owned();
                        self.define_label(arm_start, self.wp)?;

                        self.compile_statements(&arm.statements)?;

                        // break out of match
                        self.append_instruction(Instruction::Jump(Target::Unresolved(
                            end_label.clone(),
                        )));
                    }

                    self.define_label(end_label, self.wp)?;

                    // Drop expression value (It's still around because of the Dup)
                    self.append_instruction(Instruction::Pop);
                }
                (
                    ast::Statement::When(s),
                    StatementContext::Action
                    | StatementContext::PureFunction
                    | StatementContext::CommandPolicy
                    | StatementContext::CommandRecall,
                ) => {
                    let end_label = self.anonymous_label();
                    self.compile_expression(&s.expression)?;
                    self.append_instruction(Instruction::Not);
                    self.append_instruction(Instruction::Branch(Target::Unresolved(
                        end_label.clone(),
                    )));
                    self.compile_statements(&s.statements)?;
                    self.define_label(end_label, self.wp)?;
                }
                (ast::Statement::Emit(s), StatementContext::Action) => {
                    self.compile_expression(s)?;
                    self.append_instruction(Instruction::Emit);
                }
                (ast::Statement::Return(s), StatementContext::PureFunction) => {
                    self.compile_expression(&s.expression)?;
                    self.append_instruction(Instruction::Return);
                }
                (
                    ast::Statement::Finish(s),
                    StatementContext::CommandPolicy | StatementContext::CommandRecall,
                ) => {
                    self.enter_statement_context(StatementContext::Finish);
                    self.compile_statements(s)?;
                    self.exit_statement_context();
                }
                (ast::Statement::Create(s), StatementContext::Finish) => {
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Create);
                }
                (ast::Statement::Update(s), StatementContext::Finish) => {
                    self.verify_fact_against_schema(&s.fact)?;
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Dup(0));

                    // Verify the 'to' fact literal
                    let fact_def = self.get_fact_def(&s.fact.identifier)?;
                    self.verify_fact_values(&s.to, fact_def)?;

                    for (k, v) in &s.to {
                        if *v == ast::Expression::Bind {
                            // Cannot bind in the set statement
                            return Err(CompileError::from_locator(
                                CompileErrorType::BadArgument(String::from(
                                    "cannot bind in the set clause of an `update`",
                                )),
                                statement.locator,
                                self.m.codemap.as_ref(),
                            ));
                        }
                        self.compile_expression(v)?;
                        self.append_instruction(Instruction::Const(Value::String(k.clone())));
                        self.append_instruction(Instruction::FactValueSet);
                    }
                    self.append_instruction(Instruction::Update);
                }
                (ast::Statement::Delete(s), StatementContext::Finish) => {
                    self.verify_fact_against_schema(&s.fact)?;
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Delete);
                }
                (ast::Statement::Effect(s), StatementContext::Finish) => {
                    self.compile_expression(s)?;
                    self.append_instruction(Instruction::Effect);
                }
                (ast::Statement::FunctionCall(f), StatementContext::Finish) => {
                    let signature = self.function_signatures.get(&f.identifier).ok_or(
                        CompileError::from_locator(
                            CompileErrorType::NotDefined(f.identifier.clone()),
                            statement.locator,
                            self.m.codemap.as_ref(),
                        ),
                    )?;
                    // Check that this function is the right color -
                    // only finish functions are allowed in finish
                    // blocks.
                    if let FunctionColor::Pure(_) = signature.color {
                        return Err(CompileError::from_locator(
                            CompileErrorType::InvalidCallColor(CallColor::Pure),
                            statement.locator,
                            self.m.codemap.as_ref(),
                        ));
                    }
                    // For now all we can do is check that the argument
                    // list has the same length.
                    // TODO(chip): Do more deep type analysis to check
                    // arguments and return types.
                    if signature.args.len() != f.arguments.len() {
                        return Err(CompileError::from_locator(
                            CompileErrorType::BadArgument(format!(
                                "call to `{}` has {} arguments but it should have {}",
                                f.identifier,
                                f.arguments.len(),
                                signature.args.len()
                            )),
                            statement.locator,
                            self.m.codemap.as_ref(),
                        ));
                    }
                    for a in &f.arguments {
                        self.compile_expression(a)?;
                    }
                    self.append_instruction(Instruction::Call(Target::Unresolved(
                        Label::new_temp(&f.identifier),
                    )));
                }
                (_, _) => {
                    return Err(CompileError::from_locator(
                        CompileErrorType::InvalidStatement(context),
                        statement.locator,
                        self.m.codemap.as_ref(),
                    ))
                }
            }
        }
        Ok(())
    }

    fn instruction_range_contains<F>(&self, r: Range<usize>, pred: F) -> bool
    where
        F: FnMut(&Instruction) -> bool,
    {
        self.m.progmem[r].iter().any(pred)
    }

    /// Compile a function
    fn compile_function(
        &mut self,
        function_node: &AstNode<ast::FunctionDefinition>,
    ) -> Result<(), CompileError> {
        let function = &function_node.inner;
        self.define_label(Label::new_temp(&function.identifier), self.wp)?;
        self.map_range(function_node)?;
        self.define_function_signature(function_node)?;

        if let Some(identifier) = find_duplicate(&function.arguments, |a| &a.identifier) {
            return Err(CompileError::from_locator(
                CompileErrorType::AlreadyDefined(identifier.clone()),
                function_node.locator,
                self.m.codemap.as_ref(),
            ));
        }

        for arg in function.arguments.iter().rev() {
            self.append_instruction(Instruction::Const(Value::String(arg.identifier.clone())));
            self.append_instruction(Instruction::Def);
        }
        let from = self.wp;
        self.compile_statements(&function.statements)?;
        // Check that there is a return statement somewhere in the compiled instructions.
        if !self.instruction_range_contains(from..self.wp, |i| matches!(i, Instruction::Return)) {
            return Err(CompileError::from_locator(
                CompileErrorType::NoReturn,
                function_node.locator,
                self.m.codemap.as_ref(),
            ));
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
        self.define_label(Label::new_temp(&function.identifier), self.wp)?;
        self.map_range(function_node)?;
        self.define_finish_function_signature(function_node)?;
        for arg in function.arguments.iter().rev() {
            self.append_instruction(Instruction::Const(Value::String(arg.identifier.clone())));
            self.append_instruction(Instruction::Def);
        }
        self.compile_statements(&function.statements)?;
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
        self.define_label(Label::new(&action.identifier, LabelType::Action), self.wp)?;
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
        self.define_struct(&command.identifier, &command.fields)?;
        self.map_range(command_node)?;

        self.define_label(
            Label::new(&command.identifier, LabelType::CommandPolicy),
            self.wp,
        )?;
        self.enter_statement_context(StatementContext::CommandPolicy);
        self.compile_statements(&command.policy)?;
        self.exit_statement_context();
        self.append_instruction(Instruction::Exit);

        self.define_label(
            Label::new(&command.identifier, LabelType::CommandRecall),
            self.wp,
        )?;
        self.enter_statement_context(StatementContext::CommandRecall);
        self.compile_statements(&command.recall)?;
        self.exit_statement_context();
        self.append_instruction(Instruction::Exit);

        if command.seal.is_empty() {
            return Err(CompileError::from_locator(
                CompileErrorType::Unknown(String::from("Empty/missing seal block in command")),
                command_node.locator,
                self.m.codemap.as_ref(),
            ));
        }
        if command.open.is_empty() {
            return Err(CompileError::from_locator(
                CompileErrorType::Unknown(String::from("Empty/missing open block in command")),
                command_node.locator,
                self.m.codemap.as_ref(),
            ));
        }

        // Create a call stub for seal. Because it is function-like and
        // uses "return", we need something on the call stack to return
        // to.
        self.define_label(
            Label::new(&command.identifier, LabelType::CommandSeal),
            self.wp,
        )?;
        let actual_seal = self.anonymous_label();
        self.append_instruction(Instruction::Call(Target::Unresolved(actual_seal.clone())));
        self.append_instruction(Instruction::Exit);
        self.define_label(actual_seal, self.wp)?;
        self.enter_statement_context(StatementContext::PureFunction);
        self.append_instruction(Instruction::Const(Value::String("this".to_string())));
        self.append_instruction(Instruction::Def);
        let from = self.wp;
        self.compile_statements(&command.seal)?;
        if !self.instruction_range_contains(from..self.wp, |i| matches!(i, Instruction::Return)) {
            return Err(CompileError::from_locator(
                CompileErrorType::NoReturn,
                command_node.locator,
                self.m.codemap.as_ref(),
            ));
        }
        self.exit_statement_context();
        // If there is no return, this is an error. Panic if we get here.
        self.append_instruction(Instruction::Panic);

        // Same thing for open.
        self.define_label(
            Label::new(&command.identifier, LabelType::CommandOpen),
            self.wp,
        )?;
        let actual_open = self.anonymous_label();
        self.append_instruction(Instruction::Call(Target::Unresolved(actual_open.clone())));
        self.append_instruction(Instruction::Exit);
        self.define_label(actual_open, self.wp)?;
        self.enter_statement_context(StatementContext::PureFunction);
        self.append_instruction(Instruction::Const(Value::String("envelope".to_string())));
        self.append_instruction(Instruction::Def);
        let from = self.wp;
        self.compile_statements(&command.open)?;
        if !self.instruction_range_contains(from..self.wp, |i| matches!(i, Instruction::Return)) {
            return Err(CompileError::from_locator(
                CompileErrorType::NoReturn,
                command_node.locator,
                self.m.codemap.as_ref(),
            ));
        }
        self.exit_statement_context();
        self.append_instruction(Instruction::Panic);

        Ok(())
    }

    /// Compile a policy into instructions inside the given Machine.
    pub fn compile(&mut self, policy: &AstPolicy) -> Result<(), CompileError> {
        for effect in &policy.effects {
            let fields: Vec<FieldDefinition> =
                effect.inner.fields.iter().map(|f| f.into()).collect();
            self.define_struct(&effect.inner.identifier, &fields)?;
        }

        for struct_def in &policy.structs {
            self.define_struct(&struct_def.inner.identifier, &struct_def.inner.fields)?;
        }

        for fact in &policy.facts {
            let FactDefinition { key, value, .. } = &fact.inner;

            let fields: Vec<FieldDefinition> = key.iter().chain(value.iter()).cloned().collect();

            self.define_struct(&fact.inner.identifier, &fields)?;
            self.define_fact(&fact.inner)?;
        }

        self.enter_statement_context(StatementContext::PureFunction);
        for function_def in &policy.functions {
            self.compile_function(function_def)?;
        }
        self.exit_statement_context();

        self.enter_statement_context(StatementContext::Finish);
        for function_def in &policy.finish_functions {
            self.compile_finish_function(function_def)?;
        }
        self.exit_statement_context();

        // Commands have several sub-contexts, so `compile_command` handles those.
        for command in &policy.commands {
            self.compile_command(command)?;
        }

        self.enter_statement_context(StatementContext::Action);
        for action in &policy.actions {
            self.compile_action(action)?;
        }
        self.exit_statement_context();

        self.resolve_targets()?;

        Ok(())
    }

    /// Finish compilation; return the internal machine
    pub fn into_machine(self) -> Machine {
        self.m
    }
}

/// Create a new Machine by compiling a policy AST.
pub fn compile_from_policy(
    policy: &AstPolicy,
    ffi_modules: &[ModuleSchema<'_>],
) -> Result<Machine, CompileError> {
    let codemap = CodeMap::new(&policy.text, policy.ranges.clone());
    let machine = Machine::from_codemap(codemap);
    let mut cs = CompileState::new(machine, ffi_modules);
    cs.compile(policy)?;
    Ok(cs.into_machine())
}

/// Checks whether a vector has duplicate values, and returns the first one, if found.
///
/// Not suitable for large vectors, because complexity is O(n^2).
fn find_duplicate<T, F, E>(vec: &[T], value: F) -> Option<&E>
where
    F: Fn(&T) -> &E,
    E: PartialEq,
{
    if vec.len() < 2 {
        return None;
    }

    for (i, v1) in vec.iter().enumerate() {
        for v2 in &vec[..i] {
            if value(v1) == value(v2) {
                return Some(value(v1));
            }
        }
    }

    None
}

/// Get expression type, e.g. Expression::Int => VType::Int
fn expression_vtype(e: &Expression) -> Option<VType> {
    match e {
        ast::Expression::Int(_) => Some(VType::Int),
        // ast::Expression::Bytes(_) => Ok(VType::Bytes), // TODO: Bytes expression not implemented
        ast::Expression::Bool(_) => Some(VType::Bool),
        ast::Expression::String(_) => Some(VType::String),
        // We can't resolve var names to values at the moment, so we defer to the machine.
        ast::Expression::Identifier(_) => None,
        ast::Expression::NamedStruct(s) => Some(VType::Struct(s.identifier.clone())),
        ast::Expression::Optional(Some(e)) => {
            let interior_type = expression_vtype(e)?;
            Some(VType::Optional(Box::new(interior_type)))
        }
        _ => None,
    }
}
