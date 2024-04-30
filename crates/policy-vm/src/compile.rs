extern crate alloc;

mod error;
mod tests;
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{fmt, ops::Range};

pub use ast::Policy as AstPolicy;
use ast::{
    EnumDefinition, Expression, FactDefinition, FactField, FactLiteral, FieldDefinition,
    MatchPattern, NamedStruct,
};
use buggy::BugExt;
use policy_ast::{self as ast, AstNode, VType};

pub use self::error::{CallColor, CompileError, CompileErrorType};
use crate::{
    ffi::ModuleSchema, CodeMap, ExitReason, Instruction, Label, LabelType, Machine, Struct, Target,
    Value,
};

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
    function_signatures: BTreeMap<&'a str, FunctionSignature>,
    /// The last locator seen, for imprecise source locating.
    // TODO(chip): Push more precise source tracking further down into the AST.
    last_locator: usize,
    /// The current statement context, implemented as a stack so that it can be
    /// hierarchical.
    statement_context: Vec<StatementContext>,
    /// FFI module schemas. Used to validate FFI calls.
    ffi_modules: &'a [ModuleSchema<'a>],
    /// name/value mappings for enums
    enum_values: BTreeMap<&'a str, BTreeMap<&'a str, i64>>,
    /// Determines if one compiles with debug functionality,
    is_debug: bool,
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
            enum_values: BTreeMap::new(),
            is_debug: false,
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

        // ensure key identifiers are unique
        let mut identifiers = BTreeSet::new();
        for key in fact.key.iter() {
            if !identifiers.insert(key.identifier.as_str()) {
                return Err(CompileError::from_locator(
                    CompileErrorType::AlreadyDefined(key.identifier.to_owned()),
                    self.last_locator,
                    self.m.codemap.as_ref(),
                ));
            }
        }

        // ensure value identifiers are unique
        for value in fact.value.iter() {
            if !identifiers.insert(value.identifier.as_str()) {
                return Err(CompileError::from_locator(
                    CompileErrorType::AlreadyDefined(value.identifier.to_owned()),
                    self.last_locator,
                    self.m.codemap.as_ref(),
                ));
            }
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
            Entry::Vacant(e) => {
                e.insert(fields.to_vec());
                Ok(())
            }
            Entry::Occupied(_) => Err(CompileError::from_locator(
                CompileErrorType::AlreadyDefined(identifier.to_string()),
                self.last_locator,
                self.m.codemap.as_ref(),
            )),
        }
    }

    fn compile_enum_definition(
        &mut self,
        enum_def: &'a EnumDefinition,
    ) -> Result<(), CompileError> {
        let enum_name = enum_def.identifier.as_ref();
        // ensure enum name is unique
        if self.enum_values.contains_key(enum_name) {
            return Err(CompileError::from_locator(
                CompileErrorType::AlreadyDefined(enum_def.identifier.to_owned()),
                self.last_locator,
                self.m.codemap.as_ref(),
            ));
        }

        // Map value names to integers
        let mut map = BTreeMap::<&'a str, i64>::new();
        for value_name in enum_def.values.iter() {
            let value_name: &'a str = value_name.as_ref();
            let num = i64::try_from(map.len()).expect("usize to i64 conversion failed");
            match map.entry(value_name) {
                Entry::Occupied(_) => Err(CompileError::from_locator(
                    CompileErrorType::AlreadyDefined(format!("{}::{}", enum_name, value_name)),
                    self.last_locator,
                    self.m.codemap.as_ref(),
                )),
                Entry::Vacant(e) => Ok(e.insert(num)),
            }?;
        }

        self.enum_values.insert(enum_name, map);

        Ok(())
    }

    /// Turn a [FunctionDefinition](ast::FunctionDefinition) into a
    /// [FunctionSignature].
    fn define_function_signature(
        &mut self,
        function_node: &'a AstNode<ast::FunctionDefinition>,
    ) -> Result<&FunctionSignature, CompileError> {
        let def = &function_node.inner;
        match self.function_signatures.entry(def.identifier.as_str()) {
            Entry::Vacant(e) => {
                let signature = FunctionSignature {
                    args: def.arguments.iter().map(|a| a.field_type.clone()).collect(),
                    color: FunctionColor::Pure(def.return_type.clone()),
                };
                Ok(e.insert(signature))
            }
            Entry::Occupied(_) => Err(CompileError::from_locator(
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
        function_node: &'a AstNode<ast::FinishFunctionDefinition>,
    ) -> Result<&FunctionSignature, CompileError> {
        let def = &function_node.inner;
        match self.function_signatures.entry(def.identifier.as_str()) {
            Entry::Vacant(e) => {
                let signature = FunctionSignature {
                    args: def.arguments.iter().map(|a| a.field_type.clone()).collect(),
                    color: FunctionColor::Finish,
                };
                Ok(e.insert(signature))
            }
            Entry::Occupied(_) => Err(CompileError::from_locator(
                CompileErrorType::AlreadyDefined(def.identifier.clone()),
                function_node.locator,
                self.m.codemap.as_ref(),
            )),
        }
    }

    /// Define a named Label.
    pub fn define_label(&mut self, label: Label, addr: usize) -> Result<(), CompileError> {
        match self.m.labels.entry(label.clone()) {
            Entry::Vacant(e) => {
                e.insert(addr);
                Ok(())
            }
            Entry::Occupied(_) => Err(CompileError::from_locator(
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
    fn compile_struct_literal(&mut self, s: &NamedStruct) -> Result<(), CompileError> {
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
    /// - the keys and values defined in the schema are present, and have the correct types
    /// - there are no duplicate keys or values
    fn verify_fact_against_schema(&self, fact: &FactLiteral) -> Result<(), CompileError> {
        // Fetch schema
        let fact_def = self.get_fact_def(&fact.identifier)?;

        // Note: Bind values exist at compile time (as FactField::Bind), so we can expect the literal
        // key/value sets to match the schema. E.g. given `fact Foo[i int, j int]` and `query Foo[i:1, j:?]`,
        // we will get two sequences with the same number of items. If not, abort.

        // key sets must have the same length
        if fact.key_fields.len() != fact_def.key.len() {
            return Err(CompileError::from_locator(
                CompileErrorType::Unknown(String::from("Fact keys don't match definition")),
                self.last_locator,
                self.m.codemap.as_ref(),
            ));
        }

        // Ensure the fact has all keys defined in the schema, and they have matching types.
        for (schema_key, lit_key) in fact_def.key.iter().zip(fact.key_fields.iter()) {
            if schema_key.identifier != lit_key.0 {
                return Err(CompileError::from_locator(
                    CompileErrorType::Unknown(format!(
                        "Invalid fact key: expected {}, got {}",
                        schema_key.identifier, lit_key.0
                    )),
                    self.last_locator,
                    self.m.codemap.as_ref(),
                ));
            }

            let Some(vtype) = field_vtype(&lit_key.1) else {
                // If the type cannot be determined, e.g. it's an expression or query, ignore it. The machine will verify the type at runtime.
                // TODO should we allow expressions/queries for key values?
                continue;
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
        values: &[(String, FactField)],
        fact_def: &FactDefinition,
    ) -> Result<(), CompileError> {
        // Ensure values exist in schema, and have matching types
        for (lit_value, schema_value) in values.iter().zip(fact_def.value.iter()) {
            if lit_value.0 != schema_value.identifier {
                return Err(CompileError::from_locator(
                    CompileErrorType::Unknown(format!(
                        "Expected {}, got {}",
                        schema_value.identifier, lit_value.0
                    )),
                    self.last_locator,
                    self.m.codemap.as_ref(),
                ));
            }

            let Some(lit_type) = field_vtype(&lit_value.1) else {
                // Let complex expressions through, the machine will resolve and verify them.
                continue;
            };
            if lit_type != schema_value.field_type {
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
            if let FactField::Expression(e) = &field.1 {
                self.compile_expression(e)?;
            } else {
                // Skip bind values
                continue;
            }
            self.append_instruction(Instruction::Const(Value::String(field.0.clone())));
            self.append_instruction(Instruction::FactKeySet);
        }
        if let Some(value_fields) = &f.value_fields {
            for field in value_fields {
                if let FactField::Expression(e) = &field.1 {
                    self.compile_expression(e)?;
                } else {
                    // Skip bind values
                    continue;
                }
                self.append_instruction(Instruction::Const(Value::String(field.0.clone())));
                self.append_instruction(Instruction::FactValueSet);
            }
        }
        Ok(())
    }

    /// Compile an expression
    fn compile_expression(&mut self, expression: &Expression) -> Result<(), CompileError> {
        match expression {
            Expression::Int(n) => self.append_instruction(Instruction::Const(Value::Int(*n))),
            Expression::String(s) => {
                self.append_instruction(Instruction::Const(Value::String(s.clone())))
            }
            Expression::Bool(b) => self.append_instruction(Instruction::Const(Value::Bool(*b))),
            Expression::Optional(o) => match o {
                None => self.append_instruction(Instruction::Const(Value::None)),
                Some(v) => {
                    self.compile_expression(v)?;
                }
            },
            Expression::NamedStruct(s) => {
                self.compile_struct_literal(s)?;
            }
            Expression::InternalFunction(f) => match f {
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
            Expression::FunctionCall(f) => {
                let signature = self.function_signatures.get(&f.identifier.as_str()).ok_or(
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
            Expression::ForeignFunctionCall(f) => {
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
            Expression::Identifier(i) => {
                self.append_instruction(Instruction::Const(Value::String(i.clone())));
                self.append_instruction(Instruction::Get);
            }
            Expression::EnumReference(e) => {
                // get enum by name
                let enum_def = self.enum_values.get(e.identifier.as_str()).ok_or_else(|| {
                    CompileError::from_locator(
                        CompileErrorType::NotDefined(e.identifier.to_owned()),
                        self.last_locator,
                        self.m.codemap.as_ref(),
                    )
                })?;

                // get integer value of enum member
                let num = enum_def.get(e.value.as_str()).ok_or_else(|| {
                    CompileError::from_locator(
                        CompileErrorType::NotDefined(format!("{}::{}", e.identifier, e.value)),
                        self.last_locator,
                        self.m.codemap.as_ref(),
                    )
                })?;

                self.append_instruction(Instruction::Const(Value::Int(*num)))
            }
            Expression::Parentheses(e) => {
                self.compile_expression(e)?;
            }
            Expression::Dot(t, s) => {
                self.compile_expression(t)?;
                let sr: &str = s.as_ref();
                self.append_instruction(Instruction::Const(sr.into()));
                self.append_instruction(Instruction::StructGet);
            }
            Expression::Add(a, b)
            | Expression::Subtract(a, b)
            | Expression::And(a, b)
            | Expression::Or(a, b)
            | Expression::Equal(a, b)
            | Expression::GreaterThan(a, b)
            | Expression::LessThan(a, b) => {
                self.compile_expression(a)?;
                self.compile_expression(b)?;
                self.append_instruction(match expression {
                    Expression::Add(_, _) => Instruction::Add,
                    Expression::Subtract(_, _) => Instruction::Sub,
                    Expression::And(_, _) => Instruction::And,
                    Expression::Or(_, _) => Instruction::Or,
                    Expression::Equal(_, _) => Instruction::Eq,
                    Expression::GreaterThan(_, _) => Instruction::Gt,
                    Expression::LessThan(_, _) => Instruction::Lt,
                    _ => unreachable!(),
                });
            }
            Expression::GreaterThanOrEqual(a, b) | Expression::LessThanOrEqual(a, b) => {
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
                    Expression::GreaterThanOrEqual(_, _) => Instruction::Gt,
                    Expression::LessThanOrEqual(_, _) => Instruction::Lt,
                    _ => unreachable!(),
                });
                // Now OR those two binary results together - call this e
                // e
                self.append_instruction(Instruction::Or);
            }
            Expression::NotEqual(a, b) => {
                self.compile_expression(a)?;
                self.compile_expression(b)?;
                self.append_instruction(Instruction::Eq);
                self.append_instruction(Instruction::Not);
            }
            Expression::Negative(e) => {
                if let Expression::Int(value) = **e {
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
            Expression::Not(e) => {
                // Evaluate the expression
                self.compile_expression(e)?;

                // Apply the logical NOT operation
                self.append_instruction(Instruction::Not);
            }
            Expression::Unwrap(e) => {
                self.compile_unwrap(e, ExitReason::Panic)?;
            }
            Expression::CheckUnwrap(e) => {
                self.compile_unwrap(e, ExitReason::Check)?;
            }
            Expression::Is(e, expr_is_some) => {
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
                    | StatementContext::PureFunction
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
                    self.append_instruction(Instruction::Exit(ExitReason::Check));
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
                    let all_values = s
                        .arms
                        .iter()
                        .flat_map(|arm| match &arm.pattern {
                            MatchPattern::Values(values) => values.as_slice(),
                            MatchPattern::Default => &[],
                        })
                        .collect::<Vec<&Expression>>();
                    if find_duplicate(&all_values, |v| v).is_some() {
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
                        let arm_label = self.anonymous_label();
                        arm_labels.push(arm_label.clone());

                        match &arm.pattern {
                            MatchPattern::Values(values) => {
                                for value in values.iter() {
                                    self.append_instruction(Instruction::Dup(0));
                                    self.compile_expression(value)?;

                                    // if value == target, jump to start-of-arm
                                    self.append_instruction(Instruction::Eq);
                                    self.append_instruction(Instruction::Branch(
                                        Target::Unresolved(arm_label.clone()),
                                    ));
                                }
                            }
                            MatchPattern::Default => {
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
                    }

                    // if no match, and no default case, panic
                    if !s.arms.iter().any(|a| a.pattern == MatchPattern::Default) {
                        self.append_instruction(Instruction::Exit(ExitReason::Panic));
                    }

                    // 2. Define arm labels, and compile instructions
                    for (i, arm) in s.arms.iter().enumerate() {
                        let arm_start = arm_labels[i].to_owned();
                        self.define_label(arm_start, self.wp)?;

                        // Drop expression value (It's still around because of the Dup)
                        self.append_instruction(Instruction::Pop);

                        self.compile_statements(&arm.statements)?;

                        // break out of match
                        self.append_instruction(Instruction::Jump(Target::Unresolved(
                            end_label.clone(),
                        )));
                    }

                    self.define_label(end_label, self.wp)?;
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
                (ast::Statement::Publish(s), StatementContext::Action) => {
                    self.compile_expression(s)?;
                    self.append_instruction(Instruction::Publish);
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

                    // Ensure `finish` is the last statement in the block. This also guarantees we can't have more than one finish block.
                    if statement != statements.last().expect("expected statement") {
                        return Err(CompileError::from_locator(
                            CompileErrorType::Unknown(
                                "`finish` must be the last statement in the block".to_owned(),
                            ),
                            statement.locator,
                            self.m.codemap.as_ref(),
                        ));
                    }
                    // Exit after the `finish` block. We need this because there could be more instructions following, e.g. those following `when` or `match`.
                    self.append_instruction(Instruction::Exit(ExitReason::Normal));
                }
                (ast::Statement::Create(s), StatementContext::Finish) => {
                    // Do not allow bind values during fact creation
                    if s.fact.key_fields.iter().any(|f| f.1 == FactField::Bind)
                        || s.fact
                            .value_fields
                            .as_ref()
                            .is_some_and(|v| v.iter().any(|f| f.1 == FactField::Bind))
                    {
                        return Err(CompileError::from_locator(
                            CompileErrorType::BadArgument(String::from(
                                "Cannot create fact with bind values",
                            )),
                            statement.locator,
                            self.m.codemap.as_ref(),
                        ));
                    }

                    self.verify_fact_against_schema(&s.fact)?;
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Create);
                }
                (ast::Statement::Update(s), StatementContext::Finish) => {
                    // ensure fact is mutable
                    let fact_def = self.get_fact_def(&s.fact.identifier)?;
                    if fact_def.immutable {
                        return Err(CompileError::from_locator(
                            CompileErrorType::Unknown(String::from("fact is immutable")),
                            self.last_locator,
                            self.m.codemap.as_ref(),
                        ));
                    }

                    self.verify_fact_against_schema(&s.fact)?;
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Dup(0));

                    // Verify the 'to' fact literal
                    let fact_def = self.get_fact_def(&s.fact.identifier)?;
                    self.verify_fact_values(&s.to, fact_def)?;

                    for (k, v) in &s.to {
                        match v {
                            FactField::Bind => {
                                // Cannot bind in the set statement
                                return Err(CompileError::from_locator(
                                    CompileErrorType::BadArgument(String::from(
                                        "Cannot update fact to a bind value",
                                    )),
                                    statement.locator,
                                    self.m.codemap.as_ref(),
                                ));
                            }
                            FactField::Expression(e) => self.compile_expression(e)?,
                        }
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
                (ast::Statement::Emit(s), StatementContext::Finish) => {
                    self.compile_expression(s)?;
                    self.append_instruction(Instruction::Emit);
                }
                (ast::Statement::FunctionCall(f), StatementContext::Finish) => {
                    let signature = self.function_signatures.get(&f.identifier.as_str()).ok_or(
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
                (ast::Statement::DebugAssert(s), _) => {
                    if self.is_debug {
                        // Compile the expression within `debug_assert(e)`
                        self.compile_expression(s)?;
                        // Now, branch to the next instruction if the top of the stack is true
                        let next = self.wp.checked_add(2).expect("self.wp + 2 must not wrap");
                        self.append_instruction(Instruction::Branch(Target::Resolved(next)));
                        // Append a `Exit::Panic` instruction to exit if the `debug_assert` fails.
                        self.append_instruction(Instruction::Exit(ExitReason::Panic));
                    }
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
        function_node: &'a AstNode<ast::FunctionDefinition>,
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
        self.append_instruction(Instruction::Exit(ExitReason::Panic));
        Ok(())
    }

    /// Compile a finish function
    fn compile_finish_function(
        &mut self,
        function_node: &'a AstNode<ast::FinishFunctionDefinition>,
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

        self.append_instruction(Instruction::Exit(ExitReason::Normal));

        Ok(())
    }

    /// Compile a globally scoped let statement
    fn compile_global_let(
        &mut self,
        global_let: &AstNode<ast::GlobalLetStatement>,
    ) -> Result<(), CompileError> {
        let identifier = &global_let.inner.identifier;
        let expression = &global_let.inner.expression;

        let value = expression_value(expression).ok_or_else(|| {
            CompileError::from_locator(
                CompileErrorType::InvalidExpression(expression.clone()),
                self.last_locator,
                self.m.codemap.as_ref(),
            )
        })?;

        match self.m.globals.entry(identifier.clone()) {
            Entry::Vacant(e) => {
                e.insert(value);
            }
            Entry::Occupied(_) => {
                return Err(CompileError::from_locator(
                    CompileErrorType::AlreadyDefined(identifier.clone()),
                    self.last_locator,
                    self.m.codemap.as_ref(),
                ));
            }
        }

        Ok(())
    }

    /// Unwraps an optional expression, placing its value on the stack. If the value is None, execution will be ended, with the given `exit_reason`.
    fn compile_unwrap(
        &mut self,
        e: &Expression,
        exit_reason: ExitReason,
    ) -> Result<(), CompileError> {
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
        self.append_instruction(Instruction::Exit(exit_reason));
        // Define the target of the branch as the instruction after the Panic
        self.define_label(not_none, self.wp)
    }

    /// Compile a command policy block
    fn compile_command(
        &mut self,
        command_node: &AstNode<ast::CommandDefinition>,
    ) -> Result<(), CompileError> {
        let command = &command_node.inner;
        self.map_range(command_node)?;

        self.define_label(
            Label::new(&command.identifier, LabelType::CommandPolicy),
            self.wp,
        )?;
        self.enter_statement_context(StatementContext::CommandPolicy);
        self.append_instruction(Instruction::Const(Value::String("envelope".to_string())));
        self.append_instruction(Instruction::Def);
        self.compile_statements(&command.policy)?;
        self.exit_statement_context();
        self.append_instruction(Instruction::Exit(ExitReason::Normal));

        self.define_label(
            Label::new(&command.identifier, LabelType::CommandRecall),
            self.wp,
        )?;
        self.enter_statement_context(StatementContext::CommandRecall);
        self.append_instruction(Instruction::Const(Value::String("envelope".to_string())));
        self.append_instruction(Instruction::Def);
        self.compile_statements(&command.recall)?;
        self.exit_statement_context();
        self.append_instruction(Instruction::Exit(ExitReason::Normal));

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
        self.append_instruction(Instruction::Exit(ExitReason::Normal));
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
        self.append_instruction(Instruction::Exit(ExitReason::Panic));

        // Same thing for open.
        self.define_label(
            Label::new(&command.identifier, LabelType::CommandOpen),
            self.wp,
        )?;
        let actual_open = self.anonymous_label();
        self.append_instruction(Instruction::Call(Target::Unresolved(actual_open.clone())));
        self.append_instruction(Instruction::Exit(ExitReason::Normal));
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
        self.append_instruction(Instruction::Exit(ExitReason::Panic));

        Ok(())
    }

    /// Compile a policy into instructions inside the given Machine.
    pub fn compile(&mut self, policy: &'a AstPolicy) -> Result<(), CompileError> {
        for effect in &policy.effects {
            let fields: Vec<FieldDefinition> =
                effect.inner.fields.iter().map(|f| f.into()).collect();
            self.define_struct(&effect.inner.identifier, &fields)?;
        }

        for struct_def in &policy.structs {
            self.define_struct(&struct_def.inner.identifier, &struct_def.inner.fields)?;
        }

        // map enum names to constants
        for enum_def in &policy.enums {
            self.compile_enum_definition(enum_def)?;
        }

        for fact in &policy.facts {
            let FactDefinition { key, value, .. } = &fact.inner;

            let fields: Vec<FieldDefinition> = key.iter().chain(value.iter()).cloned().collect();

            self.define_struct(&fact.inner.identifier, &fields)?;
            self.define_fact(&fact.inner)?;
        }

        // Define command structs before compiling functions
        for command in &policy.commands {
            self.define_struct(&command.identifier, &command.fields)?;
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

/// A builder for creating an instance of [`Machine`]
pub struct Compiler<'a> {
    policy: &'a AstPolicy,
    ffi_modules: &'a [ModuleSchema<'a>],
    is_debug: bool,
}

impl<'a> Compiler<'a> {
    /// Creates a new an instance of [`Compiler`] which compiles into a [`Machine`]
    pub fn new(policy: &'a AstPolicy) -> Self {
        Self {
            policy,
            ffi_modules: &[],
            is_debug: cfg!(debug_assertions),
        }
    }

    /// Sets the FFI modules
    pub fn ffi_modules(mut self, ffi_modules: &'a [ModuleSchema<'a>]) -> Self {
        self.ffi_modules = ffi_modules;
        self
    }

    /// Enables or disables debug mode
    pub fn debug(mut self, is_debug: bool) -> Self {
        self.is_debug = is_debug;
        self
    }

    /// Consumes the builder to create a [`Machine`]
    pub fn compile(self) -> Result<Machine, CompileError> {
        let codemap = CodeMap::new(&self.policy.text, self.policy.ranges.clone());
        let machine = Machine::from_codemap(codemap);
        let mut cs = CompileState {
            m: machine,
            wp: 0,
            c: 0,
            function_signatures: BTreeMap::new(),
            last_locator: 0,
            statement_context: vec![],
            ffi_modules: self.ffi_modules,
            enum_values: BTreeMap::new(),
            is_debug: self.is_debug,
        };

        // Compile global let statements
        for global_let in &self.policy.global_lets {
            cs.compile_global_let(global_let)?;
        }

        cs.compile(self.policy)?;
        Ok(cs.into_machine())
    }
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

/// Get the `VType` of a fact field. For values that cannot be represented as `VType`, including `Bind`, we return `None`.
fn field_vtype(f: &FactField) -> Option<VType> {
    match f {
        FactField::Expression(e) => {
            match e {
                Expression::Int(_) => Some(VType::Int),
                // Expression::Bytes(_) => Ok(VType::Bytes), // TODO: Bytes expression not implemented
                Expression::Bool(_) => Some(VType::Bool),
                Expression::String(_) => Some(VType::String),
                // We can't resolve var names to values at the moment, so we defer to the machine.
                Expression::Identifier(_) => None,
                Expression::NamedStruct(s) => Some(VType::Struct(s.identifier.clone())),
                Expression::Optional(Some(expr)) => {
                    let field_expr = FactField::Expression(expr.as_ref().to_owned());
                    let interior_type = field_vtype(&field_expr)?;
                    Some(VType::Optional(Box::new(interior_type)))
                }
                _ => None,
            }
        }
        FactField::Bind => None,
    }
}

/// Get expression value, e.g. Expression::Int => Value::Int
fn expression_value(e: &Expression) -> Option<Value> {
    match e {
        Expression::Int(v) => Some(Value::Int(*v)),
        Expression::Bool(v) => Some(Value::Bool(*v)),
        Expression::String(v) => Some(Value::String(v.clone())),
        Expression::NamedStruct(NamedStruct {
            identifier: identfier,
            fields,
        }) => Some(Value::Struct(Struct {
            name: identfier.clone(),
            fields: {
                let mut value_fields = BTreeMap::new();
                for field in fields {
                    value_fields.insert(field.0.clone(), expression_value(&field.1)?);
                }
                value_fields
            },
        })),
        _ => None,
    }
}
