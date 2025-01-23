mod error;
mod target;
mod types;

use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt,
    ops::Range,
};

use aranya_buggy::{Bug, BugExt};
use aranya_policy_ast::{self as ast, AstNode, FactCountType, FunctionCall, VType};
use aranya_policy_module::{
    ffi::ModuleSchema, CodeMap, ExitReason, Instruction, Label, LabelType, Meta, Module, Struct,
    Target, Value,
};
pub use ast::Policy as AstPolicy;
use ast::{
    EnumDefinition, Expression, FactDefinition, FactField, FactLiteral, FieldDefinition,
    MatchPattern, NamedStruct,
};
pub(crate) use target::CompileTarget;

pub use self::error::{CompileError, CompileErrorType, InvalidCallColor};
use self::types::{IdentifierTypeStack, Typeish};

enum FunctionColor {
    /// Function has no side-effects and returns a value
    Pure(VType),
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
#[derive(Clone, Debug, PartialEq)]
pub enum StatementContext {
    /// An action
    Action(ast::ActionDefinition),
    /// A command policy block
    CommandPolicy(ast::CommandDefinition),
    /// A command recall block
    CommandRecall(ast::CommandDefinition),
    /// A pure function
    PureFunction(ast::FunctionDefinition),
    /// A finish function or finish block
    Finish,
}

impl fmt::Display for StatementContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StatementContext::Action(_) => write!(f, "action"),
            StatementContext::CommandPolicy(_) => write!(f, "command policy block"),
            StatementContext::CommandRecall(_) => write!(f, "command recall block"),
            StatementContext::PureFunction(_) => write!(f, "pure function"),
            StatementContext::Finish => write!(f, "finish block/function"),
        }
    }
}

/// The "compile state" of the machine.
struct CompileState<'a> {
    /// Policy being compiled
    policy: &'a AstPolicy,
    /// The underlying machine
    m: CompileTarget,
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
    /// Keeps track of identifier types in a stack of scopes
    identifier_types: IdentifierTypeStack,
    /// FFI module schemas. Used to validate FFI calls.
    ffi_modules: &'a [ModuleSchema<'a>],
    /// name/value mappings for enums, e.g. `"Color"->["Red", "Green"]`
    enum_values: BTreeMap<&'a str, Vec<&'a str>>,
    /// Determines if one compiles with debug functionality,
    is_debug: bool,
    /// Auto-defines FFI modules for testing purposes
    stub_ffi: bool,
}

impl<'a> CompileState<'a> {
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
            .ok_or_else(|| {
                self.err(CompileErrorType::Bug(Bug::new(
                    "compiling statement without statement context",
                )))
            })?
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

    fn append_var(&mut self, identifier: String, vtype: VType) -> Result<(), CompileError> {
        self.append_instruction(Instruction::Meta(Meta::Let(identifier.clone())));
        self.append_instruction(Instruction::Def(identifier.clone()));
        self.identifier_types
            .add(identifier, Typeish::Type(vtype))?;
        Ok(())
    }

    /// Inserts a fact definition
    fn define_fact(&mut self, fact: &FactDefinition) -> Result<(), CompileError> {
        if self.m.fact_defs.contains_key(&fact.identifier) {
            return Err(self.err(CompileErrorType::AlreadyDefined(fact.identifier.clone())));
        }

        // ensure key identifiers are unique
        let mut identifiers = BTreeSet::new();
        for key in fact.key.iter() {
            if !identifiers.insert(key.identifier.as_str()) {
                return Err(self.err(CompileErrorType::AlreadyDefined(key.identifier.to_owned())));
            }
        }

        // ensure value identifiers are unique
        for value in fact.value.iter() {
            if !identifiers.insert(value.identifier.as_str()) {
                return Err(self.err(CompileErrorType::AlreadyDefined(
                    value.identifier.to_owned(),
                )));
            }
        }

        self.m
            .fact_defs
            .insert(fact.identifier.clone(), fact.to_owned());
        Ok(())
    }

    /// Insert a struct definition while preventing duplicates of the struct name and fields
    pub fn define_struct(
        &mut self,
        identifier: &str,
        fields: &[FieldDefinition],
    ) -> Result<(), CompileError> {
        match self.m.struct_defs.entry(identifier.to_string()) {
            Entry::Vacant(e) => {
                let mut identifiers = BTreeSet::new();

                for field in fields {
                    if !identifiers.insert(field.identifier.as_str()) {
                        return Err(CompileError::from_locator(
                            CompileErrorType::AlreadyDefined(field.identifier.to_string()),
                            self.last_locator,
                            self.m.codemap.as_ref(),
                        ));
                    }
                }
                e.insert(fields.to_vec());
                Ok(())
            }
            Entry::Occupied(_) => {
                Err(self.err(CompileErrorType::AlreadyDefined(identifier.to_string())))
            }
        }
    }

    fn compile_enum_definition(
        &mut self,
        enum_def: &'a EnumDefinition,
    ) -> Result<(), CompileError> {
        let enum_name = enum_def.identifier.as_ref();
        // ensure enum name is unique
        if self.enum_values.contains_key(enum_name) {
            return Err(self.err(CompileErrorType::AlreadyDefined(
                enum_def.identifier.to_owned(),
            )));
        }

        // Add values to enum, checking for duplicates
        let mut values = Vec::<&str>::new();
        for value_name in enum_def.values.iter() {
            if values.contains(&value_name.as_str()) {
                return Err(self.err(CompileErrorType::AlreadyDefined(format!(
                    "{}::{}",
                    enum_name, value_name
                ))));
            }
            values.push(value_name);
        }

        self.enum_values.insert(enum_name, values);

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
            Entry::Occupied(_) => Err(self.err(CompileErrorType::AlreadyDefined(label.name))),
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
                    self.err_loc(
                        CompileErrorType::Unknown(format!(
                            "could not map address {} to text range {}",
                            self.wp, node.locator
                        )),
                        node.locator,
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
                    .ok_or_else(|| CompileErrorType::BadTarget(s.name.clone()))?;

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
            return Err(self.err(CompileErrorType::BadArgument(s.identifier.clone())));
        }
        self.append_instruction(Instruction::StructNew(s.identifier.clone()));
        for field in &s.fields {
            self.compile_expression(&field.1)?;
            self.append_instruction(Instruction::StructSet(field.0.clone()));
        }
        Ok(())
    }

    fn err(&self, err_type: CompileErrorType) -> CompileError {
        self.err_loc(err_type, self.last_locator)
    }

    fn err_loc(&self, err_type: CompileErrorType, locator: usize) -> CompileError {
        CompileError::from_locator(err_type, locator, self.m.codemap.as_ref())
    }

    fn get_fact_def(&self, name: &String) -> Result<&FactDefinition, CompileError> {
        self.m
            .fact_defs
            .get(name)
            .ok_or_else(|| self.err(CompileErrorType::NotDefined(name.clone())))
    }

    /// Make sure fact literal matches its schema. Checks that:
    /// - a fact with this name was defined
    /// - the keys and values defined in the schema are present, and have the correct types
    /// - there are no duplicate keys or values
    fn verify_fact_against_schema(
        &self,
        fact: &FactLiteral,
        require_value: bool,
    ) -> Result<(), CompileError> {
        // Fetch schema
        let fact_def = self.get_fact_def(&fact.identifier)?;

        // Note: Bind values exist at compile time (as FactField::Bind), so we can expect the literal
        // key/value sets to match the schema. E.g. given `fact Foo[i int, j int]` and `query Foo[i:1, j:?]`,
        // we will get two sequences with the same number of items. If not, abort.

        // key sets must have the same length
        if fact.key_fields.len() != fact_def.key.len() {
            return Err(self.err(CompileErrorType::InvalidFactLiteral(String::from(
                "Fact keys don't match definition",
            ))));
        }

        // Ensure the fact has all keys defined in the schema, and they have matching types.
        for (schema_key, lit_key) in fact_def.key.iter().zip(fact.key_fields.iter()) {
            if schema_key.identifier != lit_key.0 {
                return Err(self.err(CompileErrorType::InvalidFactLiteral(format!(
                    "Invalid key: expected {}, got {}",
                    schema_key.identifier, lit_key.0
                ))));
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
                return Err(self.err(CompileErrorType::InvalidType(format!(
                    "Fact field `{}` must be {}",
                    schema_key.identifier, schema_key.field_type
                ))));
            };
        }

        match &fact.value_fields {
            Some(values) => self.verify_fact_values(values, fact_def)?,
            None => {
                if require_value {
                    return Err(self.err(CompileErrorType::InvalidFactLiteral(
                        "fact literal requires value".to_string(),
                    )));
                }
            }
        }

        Ok(())
    }

    fn verify_fact_values(
        &self,
        values: &[(String, FactField)],
        fact_def: &FactDefinition,
    ) -> Result<(), CompileError> {
        // value block must have the same number of values as the schema
        if values.len() != fact_def.value.len() {
            return Err(CompileError::from_locator(
                CompileErrorType::InvalidFactLiteral(String::from("incorrect number of values")),
                self.last_locator,
                self.m.codemap.as_ref(),
            ));
        }

        // Ensure values exist in schema, and have matching types
        for (lit_value, schema_value) in values.iter().zip(fact_def.value.iter()) {
            if lit_value.0 != schema_value.identifier {
                return Err(self.err(CompileErrorType::InvalidFactLiteral(format!(
                    "Expected value {}, got {}",
                    schema_value.identifier, lit_value.0
                ))));
            }

            let Some(lit_type) = field_vtype(&lit_value.1) else {
                // Let complex expressions through, the machine will resolve and verify them.
                continue;
            };
            if lit_type != schema_value.field_type {
                return Err(self.err(CompileErrorType::InvalidType(format!(
                    "field `{}` type should be {}",
                    schema_value.identifier, schema_value.field_type
                ))));
            }
        }

        Ok(())
    }

    /// Compile instructions to construct a fact literal
    fn compile_fact_literal(&mut self, f: &FactLiteral) -> Result<(), CompileError> {
        self.append_instruction(Instruction::FactNew(f.identifier.clone()));
        for field in &f.key_fields {
            if let FactField::Expression(e) = &field.1 {
                self.compile_expression(e)?;
            } else {
                // Skip bind values
                continue;
            }
            self.append_instruction(Instruction::FactKeySet(field.0.clone()));
        }
        if let Some(value_fields) = &f.value_fields {
            for field in value_fields {
                if let FactField::Expression(e) = &field.1 {
                    self.compile_expression(e)?;
                } else {
                    // Skip bind values
                    continue;
                }
                self.append_instruction(Instruction::FactValueSet(field.0.clone()));
            }
        }
        Ok(())
    }

    /// Compile an expression
    fn compile_expression(&mut self, expression: &Expression) -> Result<Typeish, CompileError> {
        if self.get_statement_context()? == StatementContext::Finish {
            self.check_finish_expression(expression)?;
        }

        let expression_type = self
            .calculate_expression_type(expression)
            .map_err(|e| self.err(e.into()))?;

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
                    self.verify_fact_against_schema(f, false)?;
                    self.compile_fact_literal(f)?;
                    self.append_instruction(Instruction::Query);
                }
                ast::InternalFunction::Exists(f) => {
                    self.verify_fact_against_schema(f, false)?;
                    self.compile_fact_literal(f)?;
                    self.append_instruction(Instruction::Query);
                    self.append_instruction(Instruction::Const(Value::None));
                    self.append_instruction(Instruction::Eq);
                    self.append_instruction(Instruction::Not);
                }
                ast::InternalFunction::FactCount(cmp_type, n, fact) => {
                    self.compile_counting_function(cmp_type, *n, fact)?
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
                    if !matches!(
                        self.get_statement_context()?,
                        StatementContext::PureFunction(_)
                    ) {
                        return Err(self.err(CompileErrorType::InvalidExpression((**e).clone())));
                    }
                    self.compile_expression(e)?;
                    self.append_instruction(Instruction::Serialize);
                }
                ast::InternalFunction::Deserialize(e) => {
                    if !matches!(
                        self.get_statement_context()?,
                        StatementContext::PureFunction(_)
                    ) {
                        return Err(self.err(CompileErrorType::InvalidExpression((**e).clone())));
                    }
                    self.compile_expression(e)?;
                    self.append_instruction(Instruction::Deserialize);
                }
            },
            Expression::FunctionCall(f) => {
                let signature = self
                    .function_signatures
                    .get(&f.identifier.as_str())
                    .ok_or_else(|| self.err(CompileErrorType::NotDefined(f.identifier.clone())))?;
                // Check that this function is the right color - only
                // pure functions are allowed in expressions.
                if let FunctionColor::Finish = signature.color {
                    return Err(
                        self.err(CompileErrorType::InvalidCallColor(InvalidCallColor::Finish))
                    );
                }
                // For now all we can do is check that the argument
                // list has the same length.
                // TODO(chip): Do more deep type analysis to check
                // arguments and return types.
                if signature.args.len() != f.arguments.len() {
                    return Err(self.err(CompileErrorType::BadArgument(format!(
                        "call to `{}` has {} arguments and it should have {}",
                        f.identifier,
                        f.arguments.len(),
                        signature.args.len()
                    ))));
                }
                self.compile_function_call(f, false)?;
            }
            Expression::ForeignFunctionCall(f) => {
                // If the policy hasn't imported this module, don't allow using it
                if !self.policy.ffi_imports.contains(&f.module) {
                    return Err(CompileError::from_locator(
                        CompileErrorType::NotDefined(f.module.to_owned()),
                        self.last_locator,
                        self.m.codemap.as_ref(),
                    ));
                }

                self.append_instruction(Instruction::Meta(Meta::FFI(
                    f.module.clone(),
                    f.identifier.clone(),
                )));
                if !self.stub_ffi {
                    // find module by name
                    let (module_id, module) = self
                        .ffi_modules
                        .iter()
                        .enumerate()
                        .find(|(_, m)| m.name == f.module)
                        .ok_or_else(|| self.err(CompileErrorType::NotDefined(f.module.clone())))?;

                    // find module function by name
                    let (procedure_id, procedure) = module
                        .functions
                        .iter()
                        .enumerate()
                        .find(|(_, proc)| proc.name == f.identifier)
                        .ok_or_else(|| {
                            self.err(CompileErrorType::NotDefined(format!(
                                "{}::{}",
                                f.module, f.identifier
                            )))
                        })?;

                    // verify number of arguments matches the function signature
                    if f.arguments.len() != procedure.args.len() {
                        return Err(self.err(CompileErrorType::BadArgument(f.identifier.clone())));
                    }

                    // push args
                    for a in &f.arguments {
                        self.compile_expression(a)?;
                    }

                    self.append_instruction(Instruction::ExtCall(module_id, procedure_id));
                }
            }
            Expression::Identifier(i) => {
                self.append_instruction(Instruction::Meta(Meta::Get(i.clone())));
                self.append_instruction(Instruction::Get(i.clone()));
            }
            Expression::EnumReference(e) => {
                // get enum by name
                let enum_def = self.enum_values.get(e.identifier.as_str()).ok_or_else(|| {
                    self.err(CompileErrorType::NotDefined(e.identifier.to_owned()))
                })?;

                // verify that the given name is a member of the enum
                if !enum_def.contains(&e.value.as_str()) {
                    return Err(self.err(CompileErrorType::NotDefined(format!(
                        "{}::{}",
                        e.identifier, e.value
                    ))));
                }

                self.append_instruction(Instruction::Const(Value::Enum(
                    e.identifier.to_owned(),
                    e.value.to_owned(),
                )))
            }
            Expression::Dot(t, s) => {
                self.compile_expression(t)?;
                self.append_instruction(Instruction::StructGet(s.clone()));
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

        Ok(expression_type)
    }

    /// Check if finish blocks only use appropriate expressions
    fn check_finish_expression(&mut self, expression: &Expression) -> Result<(), CompileError> {
        match expression {
            Expression::Int(_)
            | Expression::String(_)
            | Expression::Bool(_)
            | Expression::Identifier(_)
            | Expression::NamedStruct(_)
            | Expression::Dot(_, _)
            | Expression::Optional(_)
            | Expression::EnumReference(_) => Ok(()),
            _ => Err(CompileError::from_locator(
                CompileErrorType::InvalidExpression(expression.clone()),
                self.last_locator,
                self.m.codemap.as_ref(),
            )),
        }
    }

    /// Compile policy statements
    fn compile_statements(
        &mut self,
        statements: &[AstNode<ast::Statement>],
        scope: Scope,
    ) -> Result<(), CompileError> {
        if scope == Scope::Layered {
            self.identifier_types.enter_block();
            self.append_instruction(Instruction::Block);
        }
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
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    let et = self.compile_expression(&s.expression)?;
                    self.identifier_types.add(&s.identifier, et)?;
                    self.append_instruction(Instruction::Meta(Meta::Let(s.identifier.clone())));
                    self.append_instruction(Instruction::Def(s.identifier.clone()));
                }
                (
                    ast::Statement::Check(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    let et = self.compile_expression(&s.expression)?;
                    if !et.is_maybe(&VType::Bool) {
                        return Err(self.err(CompileErrorType::InvalidType(String::from(
                            "check must have boolean expression",
                        ))));
                    }
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
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
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
                        return Err(self.err_loc(
                            CompileErrorType::AlreadyDefined(String::from(
                                "duplicate match arm value",
                            )),
                            statement.locator,
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
                                    return Err(self.err(CompileErrorType::Unknown(String::from(
                                        "Default match case must be last.",
                                    ))));
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

                        self.compile_statements(&arm.statements, Scope::Same)?;

                        // break out of match
                        self.append_instruction(Instruction::Jump(Target::Unresolved(
                            end_label.clone(),
                        )));
                    }

                    self.define_label(end_label, self.wp)?;
                }
                (
                    ast::Statement::If(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    let end_label = self.anonymous_label();
                    for (cond, branch) in &s.branches {
                        let next_label = self.anonymous_label();
                        self.compile_expression(cond)?;
                        self.append_instruction(Instruction::Not);
                        self.append_instruction(Instruction::Branch(Target::Unresolved(
                            next_label.clone(),
                        )));
                        self.compile_statements(branch, Scope::Same)?;
                        self.append_instruction(Instruction::Jump(Target::Unresolved(
                            end_label.clone(),
                        )));
                        self.define_label(next_label, self.wp)?;
                    }
                    if let Some(fallback) = &s.fallback {
                        self.compile_statements(fallback, Scope::Same)?;
                    }
                    self.define_label(end_label, self.wp)?;
                }
                (ast::Statement::Publish(s), StatementContext::Action(_)) => {
                    self.compile_expression(s)?;
                    self.append_instruction(Instruction::Publish);
                }
                (ast::Statement::Return(s), StatementContext::PureFunction(fd)) => {
                    let et = self.compile_expression(&s.expression)?;
                    if !et.is_maybe(&fd.return_type) {
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "Return value of `{}()` must be {}",
                            fd.identifier, fd.return_type
                        ))));
                    }
                    self.append_instruction(Instruction::Return);
                }
                (
                    ast::Statement::Finish(s),
                    StatementContext::CommandPolicy(_) | StatementContext::CommandRecall(_),
                ) => {
                    self.enter_statement_context(StatementContext::Finish);
                    self.append_instruction(Instruction::Meta(Meta::Finish(true)));
                    self.compile_statements(s, Scope::Layered)?;
                    self.exit_statement_context();

                    // Ensure `finish` is the last statement in the block. This also guarantees we can't have more than one finish block.
                    if statement != statements.last().expect("expected statement") {
                        return Err(self.err_loc(
                            CompileErrorType::Unknown(
                                "`finish` must be the last statement in the block".to_owned(),
                            ),
                            statement.locator,
                        ));
                    }
                    // Exit after the `finish` block. We need this because there could be more instructions following, e.g. those following `when` or `match`.
                    self.append_instruction(Instruction::Exit(ExitReason::Normal));
                }
                (ast::Statement::Map(map_stmt), StatementContext::Action(_action)) => {
                    self.verify_fact_against_schema(&map_stmt.fact, false)?;
                    // Execute query and store results
                    self.compile_fact_literal(&map_stmt.fact)?;
                    self.append_instruction(Instruction::QueryStart);
                    // Define Struct variable for the `as` clause
                    self.identifier_types.enter_block();
                    self.identifier_types.add(
                        map_stmt.identifier.clone(),
                        Typeish::Type(VType::Struct(map_stmt.fact.identifier.clone())),
                    )?;
                    // Consume results...
                    let top_label = self.anonymous_label();
                    let end_label = self.anonymous_label();
                    self.define_label(top_label.to_owned(), self.wp)?;
                    // Fetch next result
                    self.append_instruction(Instruction::Block);
                    self.append_instruction(Instruction::QueryNext(map_stmt.identifier.clone()));
                    // If no more results, break
                    self.append_instruction(Instruction::Branch(Target::Unresolved(
                        end_label.clone(),
                    )));
                    // body
                    self.compile_statements(&map_stmt.statements, Scope::Same)?;
                    self.append_instruction(Instruction::End);
                    // Jump back to top of loop
                    self.append_instruction(Instruction::Jump(Target::Unresolved(top_label)));
                    // Exit loop
                    self.define_label(end_label, self.wp)?;
                    self.append_instruction(Instruction::End);
                    self.identifier_types.exit_block();
                }
                (ast::Statement::Create(s), StatementContext::Finish) => {
                    // Do not allow bind values during fact creation
                    if s.fact.key_fields.iter().any(|f| f.1 == FactField::Bind)
                        || s.fact
                            .value_fields
                            .as_ref()
                            .is_some_and(|v| v.iter().any(|f| f.1 == FactField::Bind))
                    {
                        return Err(self.err_loc(
                            CompileErrorType::BadArgument(String::from(
                                "Cannot create fact with bind values",
                            )),
                            statement.locator,
                        ));
                    }

                    self.verify_fact_against_schema(&s.fact, true)?;
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Create);
                }
                (ast::Statement::Update(s), StatementContext::Finish) => {
                    // ensure fact is mutable
                    let fact_def = self.get_fact_def(&s.fact.identifier)?;
                    if fact_def.immutable {
                        return Err(
                            self.err(CompileErrorType::Unknown(String::from("fact is immutable")))
                        );
                    }

                    self.verify_fact_against_schema(&s.fact, true)?;
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Dup(0));

                    // Verify the 'to' fact literal
                    let fact_def = self.get_fact_def(&s.fact.identifier)?;
                    self.verify_fact_values(&s.to, fact_def)?;

                    for (k, v) in &s.to {
                        match v {
                            FactField::Bind => {
                                // Cannot bind in the set statement
                                return Err(self.err_loc(
                                    CompileErrorType::BadArgument(String::from(
                                        "Cannot update fact to a bind value",
                                    )),
                                    statement.locator,
                                ));
                            }
                            FactField::Expression(e) => {
                                self.compile_expression(e)?;
                            }
                        }
                        self.append_instruction(Instruction::FactValueSet(k.clone()));
                    }
                    self.append_instruction(Instruction::Update);
                }
                (ast::Statement::Delete(s), StatementContext::Finish) => {
                    self.verify_fact_against_schema(&s.fact, false)?;
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Delete);
                }
                (ast::Statement::Emit(s), StatementContext::Finish) => {
                    let et = self.compile_expression(s)?;
                    if !matches!(et, Typeish::Type(VType::Struct(_))) {
                        return Err(self.err(CompileErrorType::InvalidType(String::from(
                            "Emit must be given a struct",
                        ))));
                    }
                    self.append_instruction(Instruction::Emit);
                }
                (ast::Statement::FunctionCall(f), StatementContext::Finish) => {
                    let signature = self
                        .function_signatures
                        .get(&f.identifier.as_str())
                        .ok_or_else(|| {
                            self.err_loc(
                                CompileErrorType::NotDefined(f.identifier.clone()),
                                statement.locator,
                            )
                        })?;
                    // Check that this function is the right color -
                    // only finish functions are allowed in finish
                    // blocks.
                    if let FunctionColor::Pure(_) = signature.color {
                        return Err(self.err_loc(
                            CompileErrorType::InvalidCallColor(InvalidCallColor::Pure),
                            statement.locator,
                        ));
                    }
                    // For now all we can do is check that the argument
                    // list has the same length.
                    // TODO(chip): Do more deep type analysis to check
                    // arguments and return types.
                    if signature.args.len() != f.arguments.len() {
                        return Err(self.err_loc(
                            CompileErrorType::BadArgument(format!(
                                "call to `{}` has {} arguments but it should have {}",
                                f.identifier,
                                f.arguments.len(),
                                signature.args.len()
                            )),
                            statement.locator,
                        ));
                    }
                    self.compile_function_call(f, true)?;
                }
                (ast::Statement::ActionCall(fc), StatementContext::Action(_)) => {
                    let Some(action_def) = self
                        .policy
                        .actions
                        .iter()
                        .find(|a| a.identifier == fc.identifier)
                    else {
                        return Err(CompileError::from_locator(
                            CompileErrorType::NotDefined(fc.identifier.clone()),
                            statement.locator,
                            self.m.codemap.as_ref(),
                        ));
                    };

                    if action_def.arguments.len() != fc.arguments.len() {
                        return Err(CompileError::from_locator(
                            CompileErrorType::BadArgument(format!(
                                "call to `{}` has {} arguments, but it should have {}",
                                fc.identifier,
                                fc.arguments.len(),
                                action_def.arguments.len()
                            )),
                            statement.locator,
                            self.m.codemap.as_ref(),
                        ));
                    }

                    for (i, arg) in fc.arguments.iter().enumerate() {
                        let arg_type = self.compile_expression(arg)?;
                        match arg_type {
                            Typeish::Type(t) => {
                                let expected_arg = &action_def.arguments[i];
                                if t != expected_arg.field_type {
                                    return Err(CompileError::from_locator(CompileErrorType::BadArgument(format!("invalid argument type for `{}`: expected `{}`, but got `{t}`",
                                            expected_arg.identifier,
                                            expected_arg.field_type)
                                        ),
                                        statement.locator, self.m.codemap.as_ref()));
                                }
                            }
                            Typeish::Indeterminate => {}
                        }
                    }

                    let label = Label::new(&fc.identifier, LabelType::Action);
                    self.append_instruction(Instruction::Call(Target::Unresolved(label)));
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
                    return Err(self.err_loc(
                        CompileErrorType::InvalidStatement(context),
                        statement.locator,
                    ))
                }
            }
        }
        if scope == Scope::Layered {
            self.append_instruction(Instruction::End);
            self.identifier_types.exit_block();
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
        self.define_label(
            Label::new(&function.identifier, LabelType::Function),
            self.wp,
        )?;
        self.map_range(function_node)?;
        self.define_function_signature(function_node)?;

        if let Some(identifier) = find_duplicate(&function.arguments, |a| &a.identifier) {
            return Err(self.err_loc(
                CompileErrorType::AlreadyDefined(identifier.clone()),
                function_node.locator,
            ));
        }

        self.identifier_types.enter_function();
        for arg in function.arguments.iter().rev() {
            self.append_var(arg.identifier.clone(), arg.field_type.clone())?;
        }
        let from = self.wp;
        self.compile_statements(&function.statements, Scope::Same)?;
        // Check that there is a return statement somewhere in the compiled instructions.
        if !self.instruction_range_contains(from..self.wp, |i| matches!(i, Instruction::Return)) {
            return Err(self.err_loc(CompileErrorType::NoReturn, function_node.locator));
        }
        // If execution does not hit a return statement, it will panic here.
        self.append_instruction(Instruction::Exit(ExitReason::Panic));

        self.identifier_types.exit_function();
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
        self.identifier_types.enter_function();
        for arg in function.arguments.iter().rev() {
            self.append_var(arg.identifier.clone(), arg.field_type.clone())?;
        }
        self.compile_statements(&function.statements, Scope::Same)?;
        // Finish functions cannot have return statements, so we add a return instruction
        // manually.
        self.append_instruction(Instruction::Return);

        self.identifier_types.exit_function();
        Ok(())
    }

    fn compile_function_call(
        &mut self,
        fc: &FunctionCall,
        is_finish: bool,
    ) -> Result<(), CompileError> {
        for a in &fc.arguments {
            self.compile_expression(a)?;
        }

        let label = Label::new(
            &fc.identifier,
            if is_finish {
                LabelType::Temporary
            } else {
                LabelType::Function
            },
        );
        self.append_instruction(Instruction::Call(Target::Unresolved(label)));
        Ok(())
    }

    /// Compile an action function
    fn compile_action(
        &mut self,
        action_node: &AstNode<ast::ActionDefinition>,
    ) -> Result<(), CompileError> {
        let action = &action_node.inner;
        self.identifier_types.enter_function();
        self.define_label(Label::new(&action.identifier, LabelType::Action), self.wp)?;
        self.map_range(action_node)?;

        // check for duplicate args
        if let Some(identifier) = find_duplicate(&action.arguments, |a| &a.identifier) {
            return Err(CompileError::from_locator(
                CompileErrorType::AlreadyDefined(identifier.clone()),
                action_node.locator,
                self.m.codemap.as_ref(),
            ));
        }

        for arg in action.arguments.iter().rev() {
            self.append_var(arg.identifier.clone(), arg.field_type.clone())?;
        }

        self.compile_statements(&action.statements, Scope::Same)?;
        self.append_instruction(Instruction::Return);
        self.identifier_types.exit_function();

        match self.m.action_defs.entry(action_node.identifier.clone()) {
            Entry::Vacant(e) => {
                e.insert(action_node.arguments.clone());
            }
            Entry::Occupied(_) => {
                return Err(self.err(CompileErrorType::AlreadyDefined(
                    action_node.identifier.clone(),
                )));
            }
        }
        Ok(())
    }

    /// Compile a globally scoped let statement
    fn compile_global_let(
        &mut self,
        global_let: &AstNode<ast::GlobalLetStatement>,
    ) -> Result<(), CompileError> {
        let identifier = &global_let.inner.identifier;
        let expression = &global_let.inner.expression;

        let value = expression_value(expression)
            .ok_or_else(|| self.err(CompileErrorType::InvalidExpression(expression.clone())))?;
        let vt = value.vtype().expect("global let expression has weird type");

        match self.m.globals.entry(identifier.clone()) {
            Entry::Vacant(e) => {
                e.insert(value);
            }
            Entry::Occupied(_) => {
                return Err(self.err(CompileErrorType::AlreadyDefined(identifier.clone())));
            }
        }

        self.identifier_types
            .add_global(identifier, Typeish::Type(vt))?;

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

    fn compile_command_policy(
        &mut self,
        command: &ast::CommandDefinition,
    ) -> Result<(), CompileError> {
        self.define_label(
            Label::new(&command.identifier, LabelType::CommandPolicy),
            self.wp,
        )?;
        self.enter_statement_context(StatementContext::CommandPolicy(command.clone()));
        self.identifier_types.enter_function();
        self.identifier_types.add(
            "this",
            Typeish::Type(VType::Struct(command.identifier.clone())),
        )?;
        self.identifier_types.add(
            "envelope",
            Typeish::Type(VType::Struct("Envelope".to_string())),
        )?;
        self.append_instruction(Instruction::Def("envelope".into()));
        self.compile_statements(&command.policy, Scope::Same)?;
        self.identifier_types.exit_function();
        self.exit_statement_context();
        self.append_instruction(Instruction::Exit(ExitReason::Normal));
        Ok(())
    }

    fn compile_command_recall(
        &mut self,
        command: &ast::CommandDefinition,
    ) -> Result<(), CompileError> {
        self.define_label(
            Label::new(&command.identifier, LabelType::CommandRecall),
            self.wp,
        )?;
        self.enter_statement_context(StatementContext::CommandRecall(command.clone()));
        self.identifier_types.enter_function();
        self.identifier_types.add(
            "this",
            Typeish::Type(VType::Struct(command.identifier.clone())),
        )?;
        self.identifier_types.add(
            "envelope",
            Typeish::Type(VType::Struct("Envelope".to_string())),
        )?;
        self.append_instruction(Instruction::Def("envelope".into()));
        self.compile_statements(&command.recall, Scope::Same)?;
        self.identifier_types.exit_function();
        self.exit_statement_context();
        self.append_instruction(Instruction::Exit(ExitReason::Normal));
        Ok(())
    }

    fn compile_command_seal(
        &mut self,
        command: &ast::CommandDefinition,
        locator: usize,
    ) -> Result<(), CompileError> {
        if command.seal.is_empty() {
            return Err(self.err_loc(
                CompileErrorType::Unknown(String::from("Empty/missing seal block in command")),
                locator,
            ));
        }

        // fake a function def for the seal block
        let seal_function_definition = ast::FunctionDefinition {
            identifier: String::from("seal"),
            arguments: vec![],
            return_type: VType::Struct(String::from("Envelope")),
            statements: vec![],
        };

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
        self.enter_statement_context(StatementContext::PureFunction(seal_function_definition));
        self.identifier_types.enter_function();
        self.identifier_types.add(
            "this",
            Typeish::Type(VType::Struct(command.identifier.clone())),
        )?;
        self.append_instruction(Instruction::Def("this".into()));
        let from = self.wp;
        self.compile_statements(&command.seal, Scope::Same)?;
        if !self.instruction_range_contains(from..self.wp, |i| matches!(i, Instruction::Return)) {
            return Err(self.err_loc(CompileErrorType::NoReturn, locator));
        }
        self.identifier_types.exit_function();
        self.exit_statement_context();
        // If there is no return, this is an error. Panic if we get here.
        self.append_instruction(Instruction::Exit(ExitReason::Panic));
        Ok(())
    }

    fn compile_command_open(
        &mut self,
        command: &ast::CommandDefinition,
        locator: usize,
    ) -> Result<(), CompileError> {
        if command.open.is_empty() {
            return Err(self.err_loc(
                CompileErrorType::Unknown(String::from("Empty/missing open block in command")),
                locator,
            ));
        }

        // fake a function def for the open block
        let open_function_definition = ast::FunctionDefinition {
            identifier: String::from("open"),
            arguments: vec![],
            return_type: VType::Struct(command.identifier.clone()),
            statements: vec![],
        };

        // Same thing for open.
        self.define_label(
            Label::new(&command.identifier, LabelType::CommandOpen),
            self.wp,
        )?;
        let actual_open = self.anonymous_label();
        self.append_instruction(Instruction::Call(Target::Unresolved(actual_open.clone())));
        self.append_instruction(Instruction::Exit(ExitReason::Normal));
        self.define_label(actual_open, self.wp)?;
        self.enter_statement_context(StatementContext::PureFunction(open_function_definition));
        self.identifier_types.enter_function();
        self.identifier_types.add(
            "envelope",
            Typeish::Type(VType::Struct("Envelope".to_string())),
        )?;
        self.append_instruction(Instruction::Def("envelope".into()));
        let from = self.wp;
        self.compile_statements(&command.open, Scope::Same)?;
        if !self.instruction_range_contains(from..self.wp, |i| matches!(i, Instruction::Return)) {
            return Err(self.err_loc(CompileErrorType::NoReturn, locator));
        }
        self.identifier_types.exit_function();
        self.exit_statement_context();
        self.append_instruction(Instruction::Exit(ExitReason::Panic));
        Ok(())
    }

    /// Compile a command policy block
    fn compile_command(
        &mut self,
        command_node: &AstNode<ast::CommandDefinition>,
    ) -> Result<(), CompileError> {
        let command = &command_node.inner;
        self.map_range(command_node)?;

        self.compile_command_policy(command)?;
        self.compile_command_recall(command)?;
        self.compile_command_seal(command, command_node.locator)?;
        self.compile_command_open(command, command_node.locator)?;

        // command attributes

        let attr_map = self
            .m
            .command_attributes
            .entry(command.identifier.to_owned())
            .or_default();

        for attr in &command.attributes {
            match attr_map.entry(attr.0.clone()) {
                Entry::Vacant(e) => {
                    if let Some(value) = expression_value(&attr.1) {
                        e.insert(value);
                    } else {
                        return Err(self.err(CompileErrorType::InvalidExpression(attr.1.clone())));
                    }
                }
                Entry::Occupied(_) => {
                    return Err(self.err(CompileErrorType::AlreadyDefined(attr.0.clone())));
                }
            }
        }

        // add command fields to compile target
        match self.m.command_defs.entry(command_node.identifier.clone()) {
            Entry::Vacant(e) => {
                let map = command_node
                    .fields
                    .iter()
                    .map(|f| (f.identifier.clone(), f.field_type.clone()))
                    .collect();
                e.insert(map);
            }
            Entry::Occupied(_) => {
                return Err(self.err(CompileErrorType::AlreadyDefined(
                    command_node.identifier.clone(),
                )));
            }
        }
        Ok(())
    }

    fn compile_counting_function(
        &mut self,
        cmp_type: &FactCountType,
        limit: i64,
        fact: &FactLiteral,
    ) -> Result<(), CompileError> {
        if limit <= 0 {
            return Err(self.err(CompileErrorType::BadArgument(
                "count limit must be greater than zero".to_string(),
            )));
        }
        self.verify_fact_against_schema(fact, false)?;
        self.compile_fact_literal(fact)?;
        match cmp_type {
            FactCountType::UpTo => self.append_instruction(Instruction::FactCount(limit)),
            FactCountType::AtLeast => {
                self.append_instruction(Instruction::FactCount(limit));
                self.append_instruction(Instruction::Const(Value::Int(limit)));
                self.append_instruction(Instruction::Lt);
                self.append_instruction(Instruction::Not);
            }
            FactCountType::AtMost => {
                self.append_instruction(Instruction::FactCount(
                    limit.checked_add(1).assume("fact count too large")?,
                ));
                self.append_instruction(Instruction::Const(Value::Int(limit)));
                self.append_instruction(Instruction::Gt);
                self.append_instruction(Instruction::Not);
            }
            FactCountType::Exactly => {
                self.append_instruction(Instruction::FactCount(
                    limit.checked_add(1).assume("fact count too large")?,
                ));
                self.append_instruction(Instruction::Const(Value::Int(limit)));
                self.append_instruction(Instruction::Eq);
            }
        }
        Ok(())
    }

    /// Compile a policy into instructions inside the given Machine.
    pub fn compile(&mut self) -> Result<(), CompileError> {
        // Panic when running a module without setup.
        self.append_instruction(Instruction::Exit(ExitReason::Panic));

        // Compile global let statements
        for global_let in &self.policy.global_lets {
            self.compile_global_let(global_let)?;
        }

        for effect in &self.policy.effects {
            let fields: Vec<FieldDefinition> =
                effect.inner.fields.iter().map(|f| f.into()).collect();
            self.define_struct(&effect.inner.identifier, &fields)?;
        }

        for struct_def in &self.policy.structs {
            self.define_struct(&struct_def.inner.identifier, &struct_def.inner.fields)?;
        }

        // define the structs provided by FFI schema
        for ffi_mod in self.ffi_modules {
            for s in ffi_mod.structs {
                let fields: Vec<FieldDefinition> = s
                    .fields
                    .iter()
                    .map(|a| FieldDefinition {
                        identifier: a.name.to_string(),
                        field_type: VType::from(&a.vtype),
                    })
                    .collect();
                self.define_struct(s.name, &fields)?;
            }
        }

        // map enum names to constants
        for enum_def in &self.policy.enums {
            self.compile_enum_definition(enum_def)?;
        }

        for fact in &self.policy.facts {
            let FactDefinition { key, value, .. } = &fact.inner;

            let fields: Vec<FieldDefinition> = key.iter().chain(value.iter()).cloned().collect();

            self.define_struct(&fact.inner.identifier, &fields)?;
            self.define_fact(&fact.inner)?;
        }

        // Define command structs before compiling functions
        for command in &self.policy.commands {
            self.define_struct(&command.identifier, &command.fields)?;
        }

        // Define the finish function signatures before compiling them, so that they can be
        // used to catch usage errors in regular functions.
        for function_def in &self.policy.finish_functions {
            self.define_finish_function_signature(function_def)?;
        }

        for function_def in &self.policy.functions {
            self.enter_statement_context(StatementContext::PureFunction(
                function_def.inner.clone(),
            ));
            self.compile_function(function_def)?;
            self.exit_statement_context();
        }

        self.enter_statement_context(StatementContext::Finish);
        for function_def in &self.policy.finish_functions {
            self.compile_finish_function(function_def)?;
        }
        self.exit_statement_context();

        // Commands have several sub-contexts, so `compile_command` handles those.
        for command in &self.policy.commands {
            self.compile_command(command)?;
        }

        for action in &self.policy.actions {
            self.enter_statement_context(StatementContext::Action(action.inner.clone()));
            self.compile_action(action)?;
            self.exit_statement_context();
        }

        self.resolve_targets()?;

        Ok(())
    }

    /// Finish compilation; return the internal machine
    pub fn into_module(self) -> Module {
        self.m.into_module()
    }
}

/// Flag for controling scope when compiling statement blocks.
#[derive(PartialEq)]
enum Scope {
    /// Enter a new layered scope.
    Layered,
    /// Remain in the same scope.
    Same,
}

/// A builder for creating an instance of [`Module`]
pub struct Compiler<'a> {
    policy: &'a AstPolicy,
    ffi_modules: &'a [ModuleSchema<'a>],
    is_debug: bool,
    stub_ffi: bool,
}

impl<'a> Compiler<'a> {
    /// Creates a new an instance of [`Compiler`] which compiles into a [`Module`]
    pub fn new(policy: &'a AstPolicy) -> Self {
        Self {
            policy,
            ffi_modules: &[],
            is_debug: cfg!(debug_assertions),
            stub_ffi: false,
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

    pub fn stub_ffi(mut self, flag: bool) -> Self {
        self.stub_ffi = flag;
        self
    }

    /// Consumes the builder to create a [`Module`]
    pub fn compile(self) -> Result<Module, CompileError> {
        let codemap = CodeMap::new(&self.policy.text, self.policy.ranges.clone());
        let machine = CompileTarget::new(codemap);
        let mut cs = CompileState {
            policy: self.policy,
            m: machine,
            wp: 0,
            c: 0,
            function_signatures: BTreeMap::new(),
            last_locator: 0,
            statement_context: vec![],
            identifier_types: IdentifierTypeStack::new(),
            ffi_modules: self.ffi_modules,
            enum_values: BTreeMap::new(),
            is_debug: self.is_debug,
            stub_ffi: self.stub_ffi,
        };

        cs.compile()?;

        Ok(cs.into_module())
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
        Expression::EnumReference(e) => Some(Value::Enum(e.identifier.clone(), e.value.clone())),
        _ => None,
    }
}
