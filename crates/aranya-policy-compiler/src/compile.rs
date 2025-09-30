mod error;
pub mod target;
mod types;

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, btree_map::Entry},
    fmt,
    num::NonZeroUsize,
    ops::Range,
    vec,
};

use aranya_policy_ast::{
    self as ast, EnumDefinition, ExprKind, Expression, FactCountType, FactDefinition, FactField,
    FactLiteral, FieldDefinition, FunctionCall, Ident, Identifier, LanguageContext,
    MatchExpression, MatchPattern, MatchStatement, NamedStruct, Span, Spanned as _, Statement,
    StmtKind, StructItem, TypeKind, VType, ident,
};
use aranya_policy_module::{
    ActionDef, Attribute, CodeMap, CommandDef, ExitReason, Field, Instruction, Label, LabelType,
    Meta, Module, Param, Struct, Target, Value, ffi::ModuleSchema, named::NamedMap,
};
pub use ast::Policy as AstPolicy;
use buggy::{Bug, BugExt as _, bug};
use indexmap::IndexMap;
use target::CompileTarget;
use tracing::warn;
use types::TypeError;

pub use self::error::{CompileError, CompileErrorType, InvalidCallColor};
use self::types::{DisplayType, IdentifierTypeStack, Typeish};
use crate::compile::types::NullableVType;

#[derive(Clone, Debug)]
enum FunctionColor {
    /// Function has no side-effects and returns a value
    Pure(VType),
    /// Function has side-effects and returns no value
    Finish,
}

/// This is like [FunctionDefinition](ast::FunctionDefinition), but
/// stripped down to only include positional argument names/types and
/// return type. Covers both regular (pure) functions and finish
/// functions.
struct FunctionSignature {
    args: Vec<(Identifier, VType)>,
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
            Self::Action(_) => write!(f, "action"),
            Self::CommandPolicy(_) => write!(f, "command policy block"),
            Self::CommandRecall(_) => write!(f, "command recall block"),
            Self::PureFunction(_) => write!(f, "pure function"),
            Self::Finish => write!(f, "finish block/function"),
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
    function_signatures: BTreeMap<&'a Identifier, FunctionSignature>,
    /// The last span seen, for imprecise source locating.
    last_span: Span,
    /// The current statement context, implemented as a stack so that it can be
    /// hierarchical.
    statement_context: Vec<StatementContext>,
    /// Keeps track of identifier types in a stack of scopes
    identifier_types: IdentifierTypeStack,
    /// FFI module schemas. Used to validate FFI calls.
    ffi_modules: &'a [ModuleSchema<'a>],
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

    fn append_var(&mut self, identifier: Identifier, vtype: VType) -> Result<(), CompileError> {
        self.append_instruction(Instruction::Meta(Meta::Let(identifier.clone())));
        self.append_instruction(Instruction::Def(identifier.clone()));
        self.identifier_types
            .add(identifier, Typeish::known(vtype))
            .map_err(|e| self.err(e))?;
        Ok(())
    }

    /// Inserts a fact definition
    fn define_fact(&mut self, fact: &FactDefinition) -> Result<(), CompileError> {
        if self.m.fact_defs.contains_key(&fact.identifier.name) {
            return Err(self.err(CompileErrorType::AlreadyDefined(
                fact.identifier.to_string(),
            )));
        }

        // ensure key identifiers are unique
        let mut identifiers = BTreeSet::new();
        for key in &fact.key {
            if !key.is_hashable() {
                return Err(self.err(CompileErrorType::InvalidType(format!(
                    "Fact `{}` key field `{}` is not orderable; must be int, bool, string, or id",
                    fact.identifier, key.identifier
                ))));
            }
            if !identifiers.insert(&key.identifier.name) {
                return Err(self.err(CompileErrorType::AlreadyDefined(
                    key.identifier.name.to_string(),
                )));
            }
        }

        // ensure value identifiers are unique
        for value in &fact.value {
            if !identifiers.insert(&value.identifier.name) {
                return Err(self.err(CompileErrorType::AlreadyDefined(
                    value.identifier.to_string(),
                )));
            }
        }

        self.m
            .fact_defs
            .insert(fact.identifier.name.clone(), fact.to_owned());
        Ok(())
    }

    /// Insert a struct definition while preventing duplicates of the struct name and fields
    pub fn define_struct(
        &mut self,
        identifier: Ident,
        items: &[StructItem<FieldDefinition>],
    ) -> Result<(), CompileError> {
        if self.m.struct_defs.contains_key(&identifier.name) {
            return Err(self.err(CompileErrorType::AlreadyDefined(identifier.to_string())));
        }

        let has_struct_refs = items
            .iter()
            .any(|item| matches!(item, StructItem::StructRef(_)));

        // Add explicitly-defined fields and those from struct insertions
        let mut field_definitions = Vec::new();
        for item in items {
            match item {
                StructItem::Field(field) => {
                    if field_definitions
                        .iter()
                        .any(|f: &FieldDefinition| f.identifier.name == field.identifier.name)
                    {
                        return Err(self.err(CompileErrorType::AlreadyDefined(
                            field.identifier.to_string(),
                        )));
                    }
                    // TODO(eric): Use `Span::default()`?
                    if has_struct_refs {
                        field_definitions.push(FieldDefinition {
                            identifier: Ident {
                                name: field.identifier.name.clone(),
                                span: Span::default(),
                            },
                            field_type: VType {
                                kind: field.field_type.kind.clone(),
                                span: Span::default(),
                            },
                        });
                    } else {
                        field_definitions.push(field.clone());
                    }
                }
                StructItem::StructRef(ident) => {
                    let other =
                        self.m.struct_defs.get(&ident.name).ok_or_else(|| {
                            self.err(CompileErrorType::NotDefined(ident.to_string()))
                        })?;
                    for field in other {
                        if field_definitions
                            .iter()
                            .any(|f: &FieldDefinition| f.identifier.name == field.identifier.name)
                        {
                            return Err(self.err(CompileErrorType::AlreadyDefined(
                                field.identifier.to_string(),
                            )));
                        }
                        // TODO(eric): Use `Span::default()`?
                        field_definitions.push(FieldDefinition {
                            identifier: Ident {
                                name: field.identifier.name.clone(),
                                span: Span::default(),
                            },
                            field_type: VType {
                                kind: field.field_type.kind.clone(),
                                span: Span::default(),
                            },
                        });
                    }
                }
            }
        }

        self.m
            .struct_defs
            .insert(identifier.name, field_definitions);
        Ok(())
    }

    fn compile_enum_definition(
        &mut self,
        enum_def: &'a EnumDefinition,
    ) -> Result<(), CompileError> {
        let enum_name = &enum_def.identifier;
        // ensure enum name is unique
        if self.m.enum_defs.contains_key(&enum_name.name) {
            return Err(self.err(CompileErrorType::AlreadyDefined(enum_name.name.to_string())));
        }

        // Add values to enum, checking for duplicates
        let mut values = IndexMap::new();
        for (i, value_name) in enum_def.variants.iter().enumerate() {
            match values.entry(value_name.name.clone()) {
                indexmap::map::Entry::Occupied(_) => {
                    return Err(self.err(CompileErrorType::AlreadyDefined(format!(
                        "{}::{}",
                        enum_name.name, value_name.name
                    ))));
                }
                indexmap::map::Entry::Vacant(e) => {
                    // TODO ensure value is unique. Currently, it always will be, but if enum
                    // variants start allowing specific values, e.g. `enum Color { Red = 100, Green = 200 }`,
                    // then we'll need to ensure those are unique.
                    let n = i64::try_from(i).assume("should set enum value to index")?;
                    e.insert(n);
                }
            }
        }

        self.m.enum_defs.insert(enum_name.name.clone(), values);

        Ok(())
    }

    /// Turn a [FunctionDefinition](ast::FunctionDefinition) into a
    /// [FunctionSignature].
    fn define_function_signature(
        &mut self,
        function_node: &'a ast::FunctionDefinition,
    ) -> Result<&FunctionSignature, CompileError> {
        let def = function_node;
        match self.function_signatures.entry(&def.identifier.name) {
            Entry::Vacant(e) => {
                let signature = FunctionSignature {
                    args: def
                        .arguments
                        .iter()
                        .map(|a| (a.identifier.name.clone(), a.field_type.clone()))
                        .collect(),
                    color: FunctionColor::Pure(def.return_type.clone()),
                };
                Ok(e.insert(signature))
            }
            Entry::Occupied(_) => Err(CompileError::from_span(
                CompileErrorType::AlreadyDefined(def.identifier.to_string()),
                def.span,
                self.m.codemap.as_ref(),
            )),
        }
    }

    /// Turn a [FinishFunctionDefinition](ast::FinishFunctionDefinition)
    /// into a [FunctionSignature].
    fn define_finish_function_signature(
        &mut self,
        function_node: &'a ast::FinishFunctionDefinition,
    ) -> Result<&FunctionSignature, CompileError> {
        let def = function_node;
        match self.function_signatures.entry(&def.identifier.name) {
            Entry::Vacant(e) => {
                let signature = FunctionSignature {
                    args: def
                        .arguments
                        .iter()
                        .map(|a| (a.identifier.name.clone(), a.field_type.clone()))
                        .collect(),
                    color: FunctionColor::Finish,
                };
                Ok(e.insert(signature))
            }
            Entry::Occupied(_) => Err(CompileError::from_span(
                CompileErrorType::AlreadyDefined(def.identifier.to_string()),
                def.span,
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
            Entry::Occupied(_) => {
                Err(self.err(CompileErrorType::AlreadyDefined(label.name.to_string())))
            }
        }
    }

    /// Create an anonymous Label and return its identifier.
    pub fn anonymous_label(&mut self) -> Label {
        let name = format!("anonymous{}", self.c);
        self.c = self.c.checked_add(1).expect("self.c + 1 must not wrap");
        Label::new_temp(name.try_into().expect("must be valid identifier"))
    }

    /// Maps the current write pointer to a text range supplied by a span
    fn map_range(&mut self, span: Span) -> Result<(), CompileError> {
        self.last_span = span;
        let Some(codemap) = &mut self.m.codemap else {
            // If there is no codemap, do nothing.
            return Ok(());
        };
        codemap.map_instruction(self.wp, span).map_err(|_| {
            self.err_loc(
                CompileErrorType::Unknown(format!(
                    "could not map address {} to text range {}",
                    self.wp,
                    span.start()
                )),
                span,
            )
        })?;
        Ok(())
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
                let addr = labels.get(&s).ok_or_else(|| {
                    CompileError::new(CompileErrorType::BadTarget(s.name.clone()))
                })?;

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
                    Self::resolve_target(t, &mut self.m.labels)?;
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
        let Some(struct_def) = self.m.struct_defs.get(&s.identifier.name).cloned() else {
            return Err(self.err(CompileErrorType::NotDefined(format!(
                "Struct `{}` not defined",
                s.identifier
            ))));
        };

        let s = self.evaluate_sources(s, &struct_def)?;

        // Check for duplicate fields in the struct literal
        if let Some(duplicate_field) = find_duplicate(&s.fields, |(ident, _)| &ident.name) {
            return Err(self.err(CompileErrorType::AlreadyDefined(
                duplicate_field.to_string(),
            )));
        }

        self.append_instruction(Instruction::StructNew(s.identifier.name.clone()));
        for (field_name, e) in &s.fields {
            let def_field_type = &struct_def
                .iter()
                .find(|f| f.identifier.name == field_name.name)
                .ok_or_else(|| {
                    self.err(CompileErrorType::InvalidType(format!(
                        "field `{}` not found in `Struct {}`",
                        field_name.name, s.identifier
                    )))
                })?
                .field_type;
            let t = self.compile_expression(e)?;
            if !t.fits_type(def_field_type) {
                return Err(self.err(CompileErrorType::InvalidType(format!(
                    "`Struct {}` field `{}` is not {}",
                    s.identifier,
                    field_name.name,
                    DisplayType(def_field_type)
                ))));
            }
            self.append_instruction(Instruction::StructSet(field_name.name.clone()));
        }
        Ok(())
    }

    fn err(&self, err_type: CompileErrorType) -> CompileError {
        self.err_loc(err_type, self.last_span)
    }

    fn err_loc(&self, err_type: CompileErrorType, span: Span) -> CompileError {
        CompileError::from_span(err_type, span, self.m.codemap.as_ref())
    }

    fn get_fact_def(&self, name: &Identifier) -> Result<&FactDefinition, CompileError> {
        self.m
            .fact_defs
            .get(name)
            .ok_or_else(|| self.err(CompileErrorType::NotDefined(name.to_string())))
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

        // Ensure the fact has all keys defined in the schema.
        for (schema_key, lit_key) in fact_def.key.iter().zip(fact.key_fields.iter()) {
            if schema_key.identifier.name != lit_key.0.name {
                return Err(self.err(CompileErrorType::InvalidFactLiteral(format!(
                    "Invalid key: expected {}, got {}",
                    schema_key.identifier, lit_key.0
                ))));
            }

            // Type checking handled in compile_fact_literal() now
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
        values: &[(Ident, FactField)],
        fact_def: &FactDefinition,
    ) -> Result<(), CompileError> {
        // value block must have the same number of values as the schema
        if values.len() != fact_def.value.len() {
            return Err(self.err(CompileErrorType::InvalidFactLiteral(String::from(
                "incorrect number of values",
            ))));
        }

        // Ensure values exist in schema, and have matching types
        for (lit_value, schema_value) in values.iter().zip(fact_def.value.iter()) {
            if lit_value.0.name != schema_value.identifier.name {
                return Err(self.err(CompileErrorType::InvalidFactLiteral(format!(
                    "Expected value {}, got {}",
                    schema_value.identifier, lit_value.0
                ))));
            }
            // Type checking handled in compile_fact_literal() now
        }

        Ok(())
    }

    /// Compile instructions to construct a fact literal
    fn compile_fact_literal(&mut self, f: &FactLiteral) -> Result<(), CompileError> {
        let fact_def = self.get_fact_def(&f.identifier)?.clone();

        self.append_instruction(Instruction::FactNew(f.identifier.name.clone()));

        let mut bind_found = false;
        for (k, v) in &f.key_fields {
            if let FactField::Expression(e) = v {
                if bind_found {
                    return Err(self.err(CompileErrorType::InvalidFactLiteral(
                        "leading bind values not allowed".to_string(),
                    )));
                }
                let def_field_type = &fact_def
                    .get_key_field(k)
                    .ok_or_else(|| {
                        self.err(CompileErrorType::InvalidType(format!(
                            "field `{}` not found in Fact `{}`",
                            k, f.identifier
                        )))
                    })?
                    .field_type;
                let t = self.compile_expression(e)?;
                if !t.fits_type(def_field_type) {
                    return Err(self.err(CompileErrorType::InvalidType(format!(
                        "Fact `{}` key field `{}` is not `{}`",
                        f.identifier,
                        k,
                        DisplayType(def_field_type)
                    ))));
                }
            } else {
                // Skip bind values
                bind_found = true;
                continue;
            }
            self.append_instruction(Instruction::FactKeySet((**k).clone()));
        }
        if let Some(value_fields) = &f.value_fields {
            for (k, v) in value_fields {
                if let FactField::Expression(e) = &v {
                    let def_field_type = &fact_def
                        .get_value_field(k)
                        .ok_or_else(|| {
                            self.err(CompileErrorType::InvalidType(format!(
                                "field `{}` not found in Fact `{}`",
                                k, f.identifier
                            )))
                        })?
                        .field_type;
                    let t = self.compile_expression(e)?;
                    if !t.fits_type(def_field_type) {
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "Fact `{}` value field `{}` is not `{}`",
                            f.identifier,
                            k,
                            DisplayType(def_field_type)
                        ))));
                    }
                    self.append_instruction(Instruction::FactValueSet((**k).clone()));
                }
            }
        }
        Ok(())
    }

    /// Compile an expression
    fn compile_expression(&mut self, expression: &Expression) -> Result<Typeish, CompileError> {
        if self.get_statement_context()? == StatementContext::Finish {
            self.check_finish_expression(expression)?;
        }

        let expression_type = match &expression.kind {
            ExprKind::Int(n) => {
                self.append_instruction(Instruction::Const(Value::Int(*n)));
                Typeish::known(VType {
                    kind: TypeKind::Int,
                    span: expression.span,
                })
            }
            ExprKind::String(s) => {
                self.append_instruction(Instruction::Const(Value::String(s.clone())));
                Typeish::known(VType {
                    kind: TypeKind::String,
                    span: expression.span,
                })
            }
            ExprKind::Bool(b) => {
                self.append_instruction(Instruction::Const(Value::Bool(*b)));
                Typeish::known(VType {
                    kind: TypeKind::Bool,
                    span: expression.span,
                })
            }
            ExprKind::Optional(o) => match o {
                None => {
                    self.append_instruction(Instruction::Const(Value::None));
                    Typeish::Known(NullableVType::Null)
                }
                Some(v) => self
                    .compile_expression(v)?
                    .try_map(|nty| match nty {
                        NullableVType::Type(ref ty) if matches!(ty.kind, TypeKind::Optional(_)) => {
                            Err(TypeError::new("Cannot wrap option in another option"))
                        }
                        NullableVType::Null => {
                            Err(TypeError::new("Cannot wrap option in another option"))
                        }
                        NullableVType::Type(ty) => Ok(NullableVType::Type(VType {
                            kind: TypeKind::Optional(Box::new(ty)),
                            span: expression.span,
                        })),
                    })
                    .map_err(|err| self.err(err.into()))?,
            },
            ExprKind::NamedStruct(s) => {
                // TODO: Carry intederminism from struct fields? Same for all compile_struct_literals.
                self.compile_struct_literal(s)?;
                let vtype = self.struct_type(s).map_err(|e| self.err(e.into()))?;
                Typeish::known(vtype)
            }
            ExprKind::InternalFunction(f) => match f {
                ast::InternalFunction::Query(f) => {
                    self.verify_fact_against_schema(f, false)?;
                    self.compile_fact_literal(f)?;
                    self.append_instruction(Instruction::Query);

                    let vtype = self.query_fact_type(f).map_err(|e| self.err(e.into()))?;
                    Typeish::known(VType {
                        kind: TypeKind::Optional(Box::new(vtype)),
                        span: expression.span,
                    })
                }
                ast::InternalFunction::Exists(f) => {
                    self.verify_fact_against_schema(f, false)?;
                    self.compile_fact_literal(f)?;
                    self.append_instruction(Instruction::Query);
                    self.append_instruction(Instruction::Const(Value::None));
                    self.append_instruction(Instruction::Eq);
                    self.append_instruction(Instruction::Not);

                    Typeish::known(VType {
                        kind: TypeKind::Bool,
                        span: expression.span,
                    })
                }
                ast::InternalFunction::FactCount(cmp_type, n, fact) => {
                    self.compile_counting_function(cmp_type, *n, fact)?;

                    match cmp_type {
                        FactCountType::UpTo(span) => Typeish::known(VType {
                            kind: TypeKind::Int,
                            span: *span,
                        }),
                        _ => Typeish::known(VType {
                            kind: TypeKind::Bool,
                            span: expression.span,
                        }),
                    }
                }
                ast::InternalFunction::If(c, t, f) => {
                    let else_name = self.anonymous_label();
                    let end_name = self.anonymous_label();
                    let condition_type = self.compile_expression(c)?;
                    if !condition_type.fits_type(&VType {
                        kind: TypeKind::Bool,
                        span: c.span,
                    }) {
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "if condition must be a boolean expression, was type {}",
                            condition_type,
                        ))));
                    }
                    self.append_instruction(Instruction::Branch(Target::Unresolved(
                        else_name.clone(),
                    )));
                    let false_type = self.compile_expression(f)?;
                    self.append_instruction(Instruction::Jump(Target::Unresolved(
                        end_name.clone(),
                    )));
                    self.define_label(else_name, self.wp)?;
                    let true_type = self.compile_expression(t)?;
                    self.define_label(end_name, self.wp)?;

                    // The type of `if` is whatever the subexpressions
                    // are, as long as they are the same type
                    self.unify_pair(true_type, false_type)
                        .map_err(|e| self.err(e.into()))?
                }
                ast::InternalFunction::Serialize(e) => {
                    match self.get_statement_context()? {
                        StatementContext::PureFunction(ast::FunctionDefinition {
                            identifier,
                            ..
                        }) if identifier == "seal" => {}
                        _ => {
                            return Err(
                                self.err(CompileErrorType::InvalidExpression((**e).clone()))
                            );
                        }
                    }

                    let Typeish::Known(NullableVType::Type(
                        struct_type @ VType {
                            kind: TypeKind::Struct(_),
                            ..
                        },
                    )) = self
                        .identifier_types
                        .get(&ident!("this"))
                        .assume("seal must have `this`")?
                    else {
                        bug!("seal::this must be a struct type");
                    };

                    let result_type = self
                        .compile_expression(e)?
                        .try_map(|ty| {
                            if !ty.fits_type(&struct_type) {
                                return Err(CompileErrorType::InvalidType(format!(
                                    "serializing {ty}, expected {}",
                                    DisplayType(&struct_type)
                                )));
                            }
                            Ok(NullableVType::Type(VType {
                                kind: TypeKind::Bytes,
                                span: expression.span,
                            }))
                        })
                        .map_err(|err| self.err(err))?;

                    self.append_instruction(Instruction::Serialize);

                    result_type
                }
                ast::InternalFunction::Deserialize(e) => {
                    // A bit hacky, but you can't manually define a function named "open".
                    let struct_name = match self.get_statement_context()? {
                        StatementContext::PureFunction(ast::FunctionDefinition {
                            identifier,
                            return_type:
                                VType {
                                    kind: TypeKind::Struct(struct_name),
                                    ..
                                },
                            ..
                        }) if identifier == "open" => struct_name,
                        _ => {
                            return Err(
                                self.err(CompileErrorType::InvalidExpression((**e).clone()))
                            );
                        }
                    };

                    let result_type = self
                        .compile_expression(e)?
                        .try_map(|ty| {
                            if !ty.fits_type(&VType {
                                kind: TypeKind::Bytes,
                                span: e.span,
                            }) {
                                return Err(CompileErrorType::InvalidType(format!(
                                    "deserializing {ty}, expected bytes",
                                )));
                            }
                            Ok(NullableVType::Type(VType {
                                kind: TypeKind::Struct(struct_name),
                                span: expression.span,
                            }))
                        })
                        .map_err(|err| self.err(err))?;

                    self.append_instruction(Instruction::Deserialize);

                    result_type
                }
                ast::InternalFunction::Add(a, b) | ast::InternalFunction::Sub(a, b) => {
                    let left_type = self.compile_expression(a)?;
                    let right_type = self.compile_expression(b)?;
                    let _ = self
                        .unify_pair_as(
                            left_type,
                            right_type,
                            VType {
                                kind: TypeKind::Int,
                                span: expression.span,
                            },
                            "Cannot do math on non-int types",
                        )
                        .map_err(|e| self.err(e))?;

                    let instruction = match f {
                        ast::InternalFunction::Add(_, _) => Instruction::Add,
                        ast::InternalFunction::Sub(_, _) => Instruction::Sub,
                        _ => unreachable!(),
                    };
                    self.append_instruction(instruction);

                    // Checked operations return Optional<Int>
                    Typeish::known(VType {
                        kind: TypeKind::Optional(Box::new(VType {
                            kind: TypeKind::Int,
                            span: expression.span,
                        })),
                        span: expression.span,
                    })
                }
                ast::InternalFunction::SaturatingAdd(a, b)
                | ast::InternalFunction::SaturatingSub(a, b) => {
                    let left_type = self.compile_expression(a)?;
                    let right_type = self.compile_expression(b)?;
                    let _ = self
                        .unify_pair_as(
                            left_type,
                            right_type,
                            VType {
                                kind: TypeKind::Int,
                                span: expression.span,
                            },
                            "Cannot do math on non-int types",
                        )
                        .map_err(|e| self.err(e))?;

                    let instruction = match f {
                        ast::InternalFunction::SaturatingAdd(_, _) => Instruction::SaturatingAdd,
                        ast::InternalFunction::SaturatingSub(_, _) => Instruction::SaturatingSub,
                        _ => unreachable!(),
                    };
                    self.append_instruction(instruction);

                    // Saturating operations return Int
                    Typeish::known(VType {
                        kind: TypeKind::Int,
                        span: expression.span,
                    })
                }
                ast::InternalFunction::Todo(_) => {
                    let err = self.err(CompileErrorType::TodoFound);
                    if self.is_debug {
                        warn!("{err}");
                        self.append_instruction(Instruction::Exit(ExitReason::Panic));
                        Typeish::Never
                    } else {
                        return Err(err);
                    }
                }
            },
            ExprKind::FunctionCall(f) => {
                let signature = self
                    .function_signatures
                    .get(&f.identifier.name)
                    .ok_or_else(|| {
                        self.err(CompileErrorType::NotDefined(f.identifier.to_string()))
                    })?;
                // Check that this function is the right color - only
                // pure functions are allowed in expressions.
                let FunctionColor::Pure(return_type) = signature.color.clone() else {
                    return Err(
                        self.err(CompileErrorType::InvalidCallColor(InvalidCallColor::Finish))
                    );
                };
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

                Typeish::known(return_type)
            }
            ExprKind::ForeignFunctionCall(f) => {
                // If the policy hasn't imported this module, don't allow using it
                if !self
                    .policy
                    .ffi_imports
                    .iter()
                    .any(|m| m.name == f.module.name)
                {
                    return Err(self.err(CompileErrorType::NotDefined(f.module.name.to_string())));
                }

                self.append_instruction(Instruction::Meta(Meta::FFI(
                    f.module.name.clone(),
                    f.identifier.name.clone(),
                )));
                if self.stub_ffi {
                    self.append_instruction(Instruction::Exit(ExitReason::Panic));
                    Typeish::Never
                } else {
                    // find module by name
                    let (module_id, module) = self
                        .ffi_modules
                        .iter()
                        .enumerate()
                        .find(|(_, m)| m.name == f.module.name)
                        .ok_or_else(|| {
                            self.err(CompileErrorType::NotDefined(f.module.name.to_string()))
                        })?;

                    // find module function by name
                    let (procedure_id, procedure) = module
                        .functions
                        .iter()
                        .enumerate()
                        .find(|(_, proc)| proc.name == f.identifier.name)
                        .ok_or_else(|| {
                            self.err(CompileErrorType::NotDefined(format!(
                                "{}::{}",
                                f.module.name, f.identifier.name
                            )))
                        })?;

                    // verify number of arguments matches the function signature
                    if f.arguments.len() != procedure.args.len() {
                        return Err(
                            self.err(CompileErrorType::BadArgument(f.identifier.to_string()))
                        );
                    }

                    // push args
                    for (i, (arg_def, arg_e)) in
                        procedure.args.iter().zip(f.arguments.iter()).enumerate()
                    {
                        let arg_t = self.compile_expression(arg_e)?;
                        let arg_def_vtype = (&arg_def.vtype).into();
                        if !arg_t.fits_type(&arg_def_vtype) {
                            let arg_n = i
                                .checked_add(1)
                                .assume("function argument count overflow")?;
                            return Err(self.err(CompileErrorType::InvalidType(format!(
                                "Argument {} (`{}`) in FFI call to `{}::{}` found `{}`, not `{}`",
                                arg_n,
                                arg_def.name,
                                f.module,
                                f.identifier,
                                arg_t,
                                DisplayType(&arg_def_vtype)
                            ))));
                        }
                    }

                    self.append_instruction(Instruction::ExtCall(module_id, procedure_id));

                    Typeish::known(VType::from(&procedure.return_type))
                }
            }
            ExprKind::Identifier(i) => {
                let t = self.identifier_types.get(i).map_err(|_| {
                    self.err(CompileErrorType::NotDefined(format!(
                        "Unknown identifier `{}`",
                        i
                    )))
                })?;

                self.append_instruction(Instruction::Meta(Meta::Get(i.name.clone())));
                self.append_instruction(Instruction::Get(i.name.clone()));

                t
            }
            ExprKind::EnumReference(e) => {
                let value = self.enum_value(e)?;
                self.append_instruction(Instruction::Const(value));
                Typeish::known(VType {
                    kind: TypeKind::Enum(e.identifier.clone()),
                    span: expression.span,
                })
            }
            ExprKind::Dot(t, s) => {
                let left_type = self.compile_expression(t)?;
                self.append_instruction(Instruction::StructGet(s.name.clone()));

                left_type
                    .try_map(|nty| match nty {
                        NullableVType::Type(VType {
                            kind: TypeKind::Struct(name),
                            ..
                        }) => {
                            let struct_def =
                                self.m.struct_defs.get(name.as_str()).ok_or_else(|| {
                                    TypeError::new_owned(format!("Struct `{name}` not defined"))
                                })?;
                            let field_def = struct_def
                                .iter()
                                .find(|f| f.identifier.name == s.name)
                                .ok_or_else(|| {
                                    TypeError::new_owned(format!(
                                        "Struct `{}` has no member `{}`",
                                        name, s.name
                                    ))
                                })?;
                            Ok(NullableVType::Type(field_def.field_type.clone()))
                        }
                        _ => Err(TypeError::new("Expression left of `.` is not a struct")),
                    })
                    .map_err(|err| self.err(err.into()))?
            }
            ExprKind::Substruct(lhs, sub) => {
                self.append_instruction(Instruction::StructNew(sub.name.clone()));

                let Some(sub_field_defns) = self.m.struct_defs.get(&sub.name).cloned() else {
                    return Err(self.err(CompileErrorType::NotDefined(format!(
                        "Struct `{}` not defined",
                        sub.name
                    ))));
                };

                let lhs_expression = self.compile_expression(lhs)?;
                let result_type = lhs_expression
                    .try_map(|nty| match nty {
                        NullableVType::Type(VType {
                            kind: TypeKind::Struct(lhs_struct_name),
                            ..
                        }) => {
                            let Some(lhs_field_defns) =
                                self.m.struct_defs.get(&lhs_struct_name.name)
                            else {
                                return Err(CompileErrorType::NotDefined(format!(
                                    "Struct `{lhs_struct_name}` is not defined",
                                )));
                            };

                            // Check that the struct type on the RHS is a subset of the struct expression on the LHS
                            if !sub_field_defns.iter().all(|field_def| {
                                lhs_field_defns.iter().any(|lhs_field| {
                                    lhs_field.identifier.name == field_def.identifier.name
                                        && lhs_field.field_type.kind == field_def.field_type.kind
                                })
                            }) {
                                return Err(CompileErrorType::InvalidSubstruct(
                                    sub.name.clone(),
                                    lhs_struct_name.name,
                                ));
                            }
                            Ok(NullableVType::Type(VType {
                                kind: TypeKind::Struct(sub.clone()),
                                span: expression.span,
                            }))
                        }
                        _ => Err(CompileErrorType::InvalidType(
                            "Expression to the left of the substruct operator is not a struct"
                                .into(),
                        )),
                    })
                    .map_err(|err| self.err(err))?;

                let field_count = sub_field_defns.len();
                for field in sub_field_defns {
                    self.append_instruction(Instruction::Const(Value::Identifier(
                        field.identifier.name.clone(),
                    )));
                }

                if let Some(field_count) = NonZeroUsize::new(field_count) {
                    self.append_instruction(Instruction::MStructGet(field_count));
                    self.append_instruction(Instruction::MStructSet(field_count));
                }

                result_type
            }
            ExprKind::Cast(lhs, rhs_ident) => {
                // NOTE this is implemented only for structs

                // make sure other struct is defined
                let rhs_fields = self
                    .m
                    .struct_defs
                    .get(&rhs_ident.name)
                    .cloned()
                    .ok_or_else(|| {
                        self.err(CompileErrorType::NotDefined(format!("struct {rhs_ident}")))
                    })?;

                let lhs_type = self.compile_expression(lhs)?;
                _ = lhs_type.try_map(|t| match t {
                    NullableVType::Type(VType {
                        kind: TypeKind::Struct(lhs_struct_name),
                        ..
                    }) => {
                        let lhs_fields =
                            self.m
                                .struct_defs
                                .get(&lhs_struct_name.name)
                                .ok_or_else(|| {
                                    self.err(CompileErrorType::NotDefined(format!(
                                        "struct {lhs_struct_name}"
                                    )))
                                })?;

                        // Check that both structs have the same field names and types (though not necessarily in the same order)
                        if lhs_fields.len() != rhs_fields.len()
                            || !lhs_fields
                                .iter()
                                .all(|f| rhs_fields.iter().any(|v| f.matches(v)))
                        {
                            return Err(self.err(CompileErrorType::InvalidCast(
                                lhs_struct_name.name,
                                rhs_ident.name.clone(),
                            )));
                        }
                        Ok(NullableVType::Type(VType {
                            kind: TypeKind::Struct(rhs_ident.clone()),
                            span: rhs_ident.span(),
                        }))
                    }
                    _ => Err(self.err(CompileErrorType::InvalidType(
                        "Expression to the left of `as` is not a struct".to_string(),
                    ))),
                })?;

                self.append_instruction(Instruction::Cast(rhs_ident.name.clone()));

                Typeish::known(VType {
                    kind: TypeKind::Struct(rhs_ident.clone()),
                    span: rhs_ident.span(),
                })
            }
            ExprKind::And(a, b) | ExprKind::Or(a, b) => {
                // `a && b` becomes `if a { b } else { false }`
                // `a || b` becomes `if a { true } else { b }`

                let left_type = self.compile_expression(a)?;
                let right_type;

                let mid = self.anonymous_label();
                let end = self.anonymous_label();

                match &expression.kind {
                    ExprKind::And(_, _) => {
                        self.append_instruction(Instruction::Branch(Target::Unresolved(
                            mid.clone(),
                        )));

                        self.append_instruction(Instruction::Const(Value::Bool(false)));
                        self.append_instruction(Instruction::Jump(Target::Unresolved(end.clone())));

                        self.define_label(mid, self.wp)?;
                        right_type = self.compile_expression(b)?;
                    }
                    ExprKind::Or(_, _) => {
                        self.append_instruction(Instruction::Branch(Target::Unresolved(
                            mid.clone(),
                        )));
                        right_type = self.compile_expression(b)?;
                        self.append_instruction(Instruction::Jump(Target::Unresolved(end.clone())));

                        self.define_label(mid, self.wp)?;
                        self.append_instruction(Instruction::Const(Value::Bool(true)));
                    }
                    _ => unreachable!(),
                }

                self.define_label(end, self.wp)?;

                self.unify_pair_as(
                    left_type,
                    right_type,
                    VType {
                        kind: TypeKind::Bool,
                        span: expression.span,
                    },
                    "Cannot use boolean operator on non-bool types",
                )
                .map_err(|e| self.err(e))?
            }
            ExprKind::Equal(a, b) => {
                let left_type = self.compile_expression(a)?;
                let right_type = self.compile_expression(b)?;
                self.append_instruction(Instruction::Eq);

                // We don't actually care what types the subexpressions
                // are as long as they can be tested for equality.
                self.unify_pair(left_type, right_type)
                    .map_err(|e| self.err(e.into()))?
                    .map(|_| {
                        NullableVType::Type(VType {
                            kind: TypeKind::Bool,
                            span: expression.span,
                        })
                    })
            }
            ExprKind::NotEqual(a, b) => {
                let left_type = self.compile_expression(a)?;
                let right_type = self.compile_expression(b)?;
                self.append_instruction(Instruction::Eq);
                self.append_instruction(Instruction::Not);

                self.unify_pair(left_type, right_type)
                    .map_err(|e| self.err(e.into()))?
                    .map(|_| {
                        NullableVType::Type(VType {
                            kind: TypeKind::Bool,
                            span: expression.span,
                        })
                    })
            }
            ExprKind::GreaterThan(a, b) | ExprKind::LessThan(a, b) => {
                let left_type = self.compile_expression(a)?;
                let right_type = self.compile_expression(b)?;
                self.append_instruction(match &expression.kind {
                    ExprKind::Equal(_, _) => Instruction::Eq,
                    ExprKind::GreaterThan(_, _) => Instruction::Gt,
                    ExprKind::LessThan(_, _) => Instruction::Lt,
                    _ => unreachable!(),
                });

                self.unify_pair_as(
                    left_type,
                    right_type,
                    VType {
                        kind: TypeKind::Int,
                        span: expression.span,
                    },
                    "Cannot compare non-int expressions",
                )
                .map_err(|e| self.err(e))?
                .map(|_| {
                    NullableVType::Type(VType {
                        kind: TypeKind::Bool,
                        span: expression.span,
                    })
                })
            }
            ExprKind::GreaterThanOrEqual(a, b) | ExprKind::LessThanOrEqual(a, b) => {
                // `a >= b` becomes `!(a < b)`. This relies on total ordering, which integers meet.

                let left_type = self.compile_expression(a)?;
                let right_type = self.compile_expression(b)?;
                self.append_instruction(match &expression.kind {
                    ExprKind::GreaterThanOrEqual(_, _) => Instruction::Lt,
                    ExprKind::LessThanOrEqual(_, _) => Instruction::Gt,
                    _ => unreachable!(),
                });
                self.append_instruction(Instruction::Not);

                self.unify_pair_as(
                    left_type,
                    right_type,
                    VType {
                        kind: TypeKind::Int,
                        span: expression.span,
                    },
                    "Cannot compare non-int expressions",
                )
                .map_err(|e| self.err(e))?
                .map(|_| {
                    NullableVType::Type(VType {
                        kind: TypeKind::Bool,
                        span: expression.span,
                    })
                })
            }
            ExprKind::Not(e) => {
                // Evaluate the expression
                let inner_type = self.compile_expression(e)?;

                // Apply the logical NOT operation
                self.append_instruction(Instruction::Not);

                inner_type
                    .check_type(
                        VType {
                            kind: TypeKind::Bool,
                            span: expression.span,
                        },
                        "",
                    )
                    .map_err(|err| {
                        CompileErrorType::InvalidType(format!(
                            "cannot invert non-boolean expression of type {}",
                            err.left
                        ))
                    })
                    .map_err(|e| self.err(e))?
            }
            ExprKind::Unwrap(e) => self.compile_unwrap(e, ExitReason::Panic)?,
            ExprKind::CheckUnwrap(e) => {
                self.compile_unwrap(e, ExitReason::Check(ident!("default")))?
            }
            ExprKind::Is(e, expr_is_some) => {
                // Evaluate the expression
                let inner_type = self.compile_expression(e)?;
                // Push a None to compare against
                self.append_instruction(Instruction::Const(Value::None));
                // Check if the value is equal to None
                self.append_instruction(Instruction::Eq);
                if *expr_is_some {
                    // If we're checking for not Some, invert the result of the Eq to None
                    self.append_instruction(Instruction::Not);
                }
                // The result true or false is on the stack

                inner_type
                    .try_map(|nty| match nty {
                        NullableVType::Type(VType {
                            kind: TypeKind::Optional(_),
                            ..
                        })
                        | NullableVType::Null => Ok(NullableVType::Type(VType {
                            kind: TypeKind::Bool,
                            span: expression.span,
                        })),
                        NullableVType::Type(_) => Err(TypeError::new(
                            "`is` must operate on an optional expression",
                        )),
                    })
                    .map_err(|err| self.err(err.into()))?
            }
            ExprKind::Block(statements, e) => {
                self.append_instruction(Instruction::Block);
                self.identifier_types.enter_block();
                self.compile_statements(statements, Scope::Same)?;
                let subexpression_type = self.compile_expression(e)?;
                self.identifier_types.exit_block();
                self.append_instruction(Instruction::End);

                subexpression_type
            }
            ExprKind::Match(e) => self
                .compile_match_statement_or_expression(
                    LanguageContext::Expression(&**e),
                    expression.span(),
                )?
                .assume("match expression must return a type")?,
        };

        Ok(expression_type)
    }

    // Get an enum value from an enum reference expression
    fn enum_value(&self, e: &aranya_policy_ast::EnumReference) -> Result<Value, CompileError> {
        let enum_def =
            self.m.enum_defs.get(&e.identifier.name).ok_or_else(|| {
                self.err(CompileErrorType::NotDefined(e.identifier.name.to_string()))
            })?;
        let value = enum_def.get(&e.value.name).ok_or_else(|| {
            self.err(CompileErrorType::NotDefined(format!(
                "{}::{}",
                e.identifier.name, e.value.name
            )))
        })?;
        Ok(Value::Enum(e.identifier.name.clone(), *value))
    }

    /// Check if finish blocks only use appropriate expressions
    fn check_finish_expression(&mut self, expression: &Expression) -> Result<(), CompileError> {
        match &expression.kind {
            ExprKind::Int(_)
            | ExprKind::String(_)
            | ExprKind::Bool(_)
            | ExprKind::Identifier(_)
            | ExprKind::NamedStruct(_)
            | ExprKind::Dot(_, _)
            | ExprKind::Optional(_)
            | ExprKind::EnumReference(_) => Ok(()),
            _ => Err(self.err_loc(
                CompileErrorType::InvalidExpression(expression.clone()),
                expression.span(),
            )),
        }
    }

    /// Compile policy statements
    fn compile_statements(
        &mut self,
        statements: &[Statement],
        scope: Scope,
    ) -> Result<(), CompileError> {
        if scope == Scope::Layered {
            self.identifier_types.enter_block();
            self.append_instruction(Instruction::Block);
        }
        let context = self.get_statement_context()?;
        for statement in statements {
            self.map_range(statement.span)?;
            // This match statement matches on a pair of the statement and its allowable
            // contexts, so that disallowed contexts will fall through to the default at the
            // bottom. This only checks the context at the statement level. It cannot, for
            // example, check whether an expression disallowed in finish context has been
            // evaluated from deep within a call chain. Further static analysis will have to
            // be done to ensure that.
            match (&statement.kind, &context) {
                (
                    StmtKind::Let(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    let et = self.compile_expression(&s.expression)?;
                    self.identifier_types
                        .add(s.identifier.name.clone(), et)
                        .map_err(|e| self.err(e))?;
                    self.append_instruction(Instruction::Meta(Meta::Let(
                        s.identifier.name.clone(),
                    )));
                    self.append_instruction(Instruction::Def(s.identifier.name.clone()));
                }
                // HACK this should be removed when we have asserts. check is only valid in command contexts
                (
                    StmtKind::Check(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    let et = self.compile_expression(&s.expression)?;
                    if !et.fits_type(&VType {
                        kind: TypeKind::Bool,
                        span: s.expression.span,
                    }) {
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

                    self.append_instruction(Instruction::Exit(ExitReason::Check(
                        s.recall_block.name.clone(),
                    )));
                }
                // END HACK
                (StmtKind::Check(s), StatementContext::CommandPolicy(cmd)) => {
                    let et = self.compile_expression(&s.expression)?;
                    if !et.fits_type(&VType {
                        kind: TypeKind::Bool,
                        span: s.expression.span,
                    }) {
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

                    // Make sure named recall block exists
                    // NOTE Unnamed checks do not require recall blocks. But a check without recall is suspicious, and we should warn about it.
                    if s.recall_block.name.as_str() != "default" {
                        cmd.recalls
                            .iter()
                            .find(|c| c.identifier.name == s.recall_block.name)
                            .ok_or_else(|| {
                                self.err(CompileErrorType::Unknown(format!(
                                    "command {}: recall block not found: {}",
                                    cmd.identifier.name, s.recall_block
                                )))
                            })?;
                    }

                    self.append_instruction(Instruction::Exit(ExitReason::Check(
                        s.recall_block.name.clone(),
                    )));
                }
                (
                    StmtKind::Match(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    self.compile_match_statement_or_expression(
                        LanguageContext::Statement(s),
                        statement.span,
                    )?;
                }
                (
                    StmtKind::If(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    let end_label = self.anonymous_label();
                    for (cond, branch) in &s.branches {
                        let next_label = self.anonymous_label();
                        let condition_type = self.compile_expression(cond)?;
                        if !condition_type.fits_type(&VType {
                            kind: TypeKind::Bool,
                            span: cond.span,
                        }) {
                            return Err(self.err(CompileErrorType::InvalidType(format!(
                                "if condition must be a boolean expression, was type {}",
                                condition_type,
                            ))));
                        }

                        self.append_instruction(Instruction::Not);
                        self.append_instruction(Instruction::Branch(Target::Unresolved(
                            next_label.clone(),
                        )));
                        self.compile_statements(branch, Scope::Layered)?;
                        self.append_instruction(Instruction::Jump(Target::Unresolved(
                            end_label.clone(),
                        )));
                        self.define_label(next_label, self.wp)?;
                    }
                    if let Some(fallback) = &s.fallback {
                        self.compile_statements(fallback, Scope::Layered)?;
                    }
                    self.define_label(end_label, self.wp)?;
                }
                (StmtKind::Publish(s), StatementContext::Action(action)) => {
                    let t = self.compile_expression(s)?;
                    let _ty: Typeish = t
                        .try_map(|nty| match nty {
                            NullableVType::Type(VType {
                                kind: TypeKind::Struct(ref ident),
                                ..
                            }) => {
                                if !self.m.command_defs.contains(ident.as_str()) {
                                    return Err(CompileErrorType::InvalidType(format!(
                                        "Struct `{ident}` is not a Command struct",
                                    )));
                                }

                                //  Persistent actions can publish only persistent commands, and vice versa.
                                let command_persistence = &self
                                    .policy
                                    .commands
                                    .iter()
                                    .find(|c| c.identifier.name == ident.name)
                                    .assume("command must be defined")?
                                    .persistence;
                                if !action.persistence.matches(command_persistence) {
                                    return Err(CompileErrorType::InvalidType(format!(
                                        "{} action `{}` cannot publish {} command `{}`",
                                        action.persistence,
                                        action.identifier,
                                        command_persistence,
                                        ident
                                    )));
                                }
                                Ok(nty)
                            }
                            ot => Err(CompileErrorType::InvalidType(format!(
                                "Cannot publish `{ot}`, must be a command struct"
                            ))),
                        })
                        .map_err(|err| self.err(err))?;
                    self.append_instruction(Instruction::Publish);
                }
                (StmtKind::Return(s), StatementContext::PureFunction(fd)) => {
                    // ensure return expression type matches function signature
                    let et = self.compile_expression(&s.expression)?;
                    if !et.fits_type(&fd.return_type) {
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "Return value of `{}()` must be {}",
                            fd.identifier,
                            DisplayType(&fd.return_type)
                        ))));
                    }
                    self.append_instruction(Instruction::Return);
                }
                (
                    StmtKind::Finish(s),
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
                            statement.span,
                        ));
                    }
                    // Exit after the `finish` block. We need this because there could be more instructions following, e.g. those following `when` or `match`.
                    self.append_instruction(Instruction::Exit(ExitReason::Normal));
                }
                (StmtKind::Map(map_stmt), StatementContext::Action(_action)) => {
                    self.verify_fact_against_schema(&map_stmt.fact, false)?;
                    // Execute query and store results
                    self.compile_fact_literal(&map_stmt.fact)?;
                    self.append_instruction(Instruction::QueryStart);
                    // Define Struct variable for the `as` clause
                    self.identifier_types.enter_block();
                    self.identifier_types
                        .add(
                            map_stmt.identifier.name.clone(),
                            Typeish::known(VType {
                                kind: TypeKind::Struct(map_stmt.fact.identifier.clone()),
                                span: map_stmt.fact.identifier.span,
                            }),
                        )
                        .map_err(|e| self.err(e))?;
                    // Consume results...
                    let top_label = self.anonymous_label();
                    let end_label = self.anonymous_label();
                    self.define_label(top_label.clone(), self.wp)?;
                    // Fetch next result
                    self.append_instruction(Instruction::Block);
                    self.append_instruction(Instruction::QueryNext(
                        map_stmt.identifier.name.clone(),
                    ));
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
                (StmtKind::Create(s), StatementContext::Finish) => {
                    // Do not allow bind values during fact creation
                    if s.fact
                        .key_fields
                        .iter()
                        .any(|f| matches!(f.1, FactField::Bind(_)))
                        || s.fact
                            .value_fields
                            .as_ref()
                            .is_some_and(|v| v.iter().any(|f| matches!(f.1, FactField::Bind(_))))
                    {
                        return Err(self.err_loc(
                            CompileErrorType::BadArgument(String::from(
                                "Cannot create fact with bind values",
                            )),
                            statement.span,
                        ));
                    }

                    self.verify_fact_against_schema(&s.fact, true)?;
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Create);
                }
                (StmtKind::Update(s), StatementContext::Finish) => {
                    // See https://github.com/aranya-project/aranya-docs/blob/main/docs/policy-v1.md#update

                    // ensure fact is mutable
                    let fact_def = self.get_fact_def(&s.fact.identifier)?;
                    if fact_def.immutable {
                        return Err(
                            self.err(CompileErrorType::Unknown(String::from("fact is immutable")))
                        );
                    }

                    if s.fact
                        .key_fields
                        .iter()
                        .any(|f| matches!(f.1, FactField::Bind(_)))
                    {
                        return Err(self.err_loc(
                            CompileErrorType::BadArgument(String::from(
                                "Cannot update fact with wildcard keys",
                            )),
                            statement.span,
                        ));
                    }

                    self.verify_fact_against_schema(&s.fact, false)?;
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Dup);

                    // Verify the 'to' fact literal
                    let fact_def = self.get_fact_def(&s.fact.identifier)?.clone();
                    self.verify_fact_values(&s.to, &fact_def)?;

                    for (k, v) in &s.to {
                        match v {
                            FactField::Bind(span) => {
                                // Cannot bind in the set statement
                                return Err(self.err_loc(
                                    CompileErrorType::BadArgument(String::from(
                                        "Cannot update fact to a bind value",
                                    )),
                                    *span,
                                ));
                            }
                            FactField::Expression(e) => {
                                let def_field_type = &fact_def
                                    .get_value_field(k)
                                    .ok_or_else(|| {
                                        self.err(CompileErrorType::InvalidType(format!(
                                            "field `{}` not found in Fact `{}`",
                                            k, s.fact.identifier
                                        )))
                                    })?
                                    .field_type;
                                let t = self.compile_expression(e)?;
                                if !t.fits_type(def_field_type) {
                                    return Err(self.err(CompileErrorType::InvalidType(format!(
                                        "Fact `{}` value field `{}` found `{}`, not `{}`",
                                        s.fact.identifier,
                                        k,
                                        t,
                                        DisplayType(def_field_type)
                                    ))));
                                }
                            }
                        }
                        self.append_instruction(Instruction::FactValueSet((**k).clone()));
                    }
                    self.append_instruction(Instruction::Update);
                }
                (StmtKind::Delete(s), StatementContext::Finish) => {
                    if s.fact
                        .key_fields
                        .iter()
                        .any(|f| matches!(f.1, FactField::Bind(_)))
                    {
                        return Err(self.err_loc(
                            CompileErrorType::BadArgument(String::from(
                                "Cannot delete fact with wildcard keys",
                            )),
                            statement.span,
                        ));
                    }

                    self.verify_fact_against_schema(&s.fact, false)?;
                    self.compile_fact_literal(&s.fact)?;
                    self.append_instruction(Instruction::Delete);
                }
                (StmtKind::Emit(s), StatementContext::Finish) => {
                    let et = self.compile_expression(s)?;
                    let _ty: Typeish = et
                        .try_map(|nty| match nty {
                            NullableVType::Type(VType {
                                kind: TypeKind::Struct(ref struct_name),
                                ..
                            }) => {
                                if !self.m.effects.contains(struct_name.as_str()) {
                                    return Err(CompileErrorType::InvalidType(format!(
                                        "Struct `{struct_name}` is not an effect struct",
                                    )));
                                }
                                Ok(nty)
                            }
                            ot => Err(CompileErrorType::InvalidType(format!(
                                "Cannot emit `{ot}`, must be an effect struct"
                            ))),
                        })
                        .map_err(|err| self.err(err))?;
                    self.append_instruction(Instruction::Emit);
                }
                (StmtKind::FunctionCall(f), StatementContext::Finish) => {
                    let signature = self
                        .function_signatures
                        .get(&f.identifier.name)
                        .ok_or_else(|| {
                            self.err_loc(
                                CompileErrorType::NotDefined(f.identifier.to_string()),
                                statement.span,
                            )
                        })?;
                    // Check that this function is the right color -
                    // only finish functions are allowed in finish
                    // blocks.
                    if let FunctionColor::Pure(_) = signature.color {
                        return Err(self.err_loc(
                            CompileErrorType::InvalidCallColor(InvalidCallColor::Pure),
                            statement.span,
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
                            statement.span,
                        ));
                    }
                    self.compile_function_call(f, true)?;
                }
                (StmtKind::ActionCall(fc), StatementContext::Action(_)) => {
                    let Some(action_def) = self
                        .policy
                        .actions
                        .iter()
                        .find(|a| a.identifier == fc.identifier.name)
                    else {
                        return Err(self.err_loc(
                            CompileErrorType::NotDefined(fc.identifier.name.to_string()),
                            statement.span,
                        ));
                    };

                    if action_def.arguments.len() != fc.arguments.len() {
                        return Err(self.err_loc(
                            CompileErrorType::BadArgument(format!(
                                "call to `{}` has {} arguments, but it should have {}",
                                fc.identifier.name,
                                fc.arguments.len(),
                                action_def.arguments.len()
                            )),
                            statement.span,
                        ));
                    }

                    for (i, arg) in fc.arguments.iter().enumerate() {
                        let arg_type = self.compile_expression(arg)?;
                        let expected_arg = &action_def.arguments[i];
                        if !arg_type.fits_type(&expected_arg.field_type) {
                            return Err(self.err_loc(
                                CompileErrorType::BadArgument(format!(
                                    "invalid argument type for `{}`: expected `{}`, but got `{arg_type}`",
                                    expected_arg.identifier.name,
                                    DisplayType(&expected_arg.field_type)
                                )),
                                statement.span,
                            ));
                        }
                    }

                    let label = Label::new(fc.identifier.name.clone(), LabelType::Action);
                    self.append_instruction(Instruction::Call(Target::Unresolved(label)));
                }
                (StmtKind::DebugAssert(s), _) => {
                    if self.is_debug {
                        // Compile the expression within `debug_assert(e)`
                        let t = self.compile_expression(s)?;
                        let _: Typeish = t
                            .check_type(
                                VType {
                                    kind: TypeKind::Bool,
                                    span: s.span,
                                },
                                "",
                            )
                            .map_err(|err| {
                                CompileErrorType::InvalidType(format!(
                                    "debug assertion must be a boolean expression, was type {}",
                                    err.left
                                ))
                            })
                            .map_err(|e| self.err(e))?;
                        // Now, branch to the next instruction if the top of the stack is true
                        let next = self.wp.checked_add(2).expect("self.wp + 2 must not wrap");
                        self.append_instruction(Instruction::Branch(Target::Resolved(next)));
                        // Append a `Exit::Panic` instruction to exit if the `debug_assert` fails.
                        self.append_instruction(Instruction::Exit(ExitReason::Panic));
                    }
                }
                (_, _) => {
                    return Err(
                        self.err_loc(CompileErrorType::InvalidStatement(context), statement.span)
                    );
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

    /// Checks if the given type is defined. E.g. check struct/enum definitions.
    fn ensure_type_is_defined(&self, vtype: &VType) -> Result<(), CompileError> {
        match &vtype {
            VType {
                kind: TypeKind::Struct(name),
                ..
            } => {
                if name != "Envelope" && !self.m.struct_defs.contains_key(&name.name) {
                    return Err(self.err(CompileErrorType::NotDefined(format!("struct {name}"))));
                }
            }
            VType {
                kind: TypeKind::Enum(name),
                ..
            } => {
                if !self.m.enum_defs.contains_key(&name.name) {
                    return Err(self.err(CompileErrorType::NotDefined(format!("enum {name}"))));
                }
            }
            VType {
                kind: TypeKind::Optional(t),
                ..
            } => return self.ensure_type_is_defined(t),
            _ => {}
        }
        Ok(())
    }

    /// Compile a function
    fn compile_function(
        &mut self,
        function_node: &'a ast::FunctionDefinition,
    ) -> Result<(), CompileError> {
        self.define_label(
            Label::new(function_node.identifier.name.clone(), LabelType::Function),
            self.wp,
        )?;
        self.map_range(function_node.span)?;

        // The signature should have already been added inside
        // `compile`.
        if !self
            .function_signatures
            .contains_key(&function_node.identifier.name)
        {
            return Err(self.err_loc(
                CompileErrorType::NotDefined(function_node.identifier.to_string()),
                function_node.span,
            ));
        }

        if let Some(identifier) = find_duplicate(&function_node.arguments, |a| &a.identifier.name) {
            return Err(self.err_loc(
                CompileErrorType::AlreadyDefined(identifier.to_string()),
                function_node.span,
            ));
        }

        self.identifier_types.enter_function();
        for arg in function_node.arguments.iter().rev() {
            self.ensure_type_is_defined(&arg.field_type)?;
            self.append_var(arg.identifier.name.clone(), arg.field_type.clone())?;
        }
        let from = self.wp;
        self.ensure_type_is_defined(&function_node.return_type)?;
        self.compile_statements(&function_node.statements, Scope::Same)?;

        // Check that there is a return statement somewhere in the compiled instructions.
        if !self.instruction_range_contains(from..self.wp, |i| matches!(i, Instruction::Return)) {
            return Err(self.err_loc(CompileErrorType::NoReturn, function_node.span));
        }
        // If execution does not hit a return statement, it will panic here.
        self.append_instruction(Instruction::Exit(ExitReason::Panic));

        self.identifier_types.exit_function();
        Ok(())
    }

    /// Compile a finish function
    fn compile_finish_function(
        &mut self,
        function_node: &'a ast::FinishFunctionDefinition,
    ) -> Result<(), CompileError> {
        self.define_label(
            Label::new_temp(function_node.identifier.name.clone()),
            self.wp,
        )?;
        self.map_range(function_node.span)?;
        self.identifier_types.enter_function();
        for arg in function_node.arguments.iter().rev() {
            self.append_var(arg.identifier.name.clone(), arg.field_type.clone())?;
        }
        self.compile_statements(&function_node.statements, Scope::Same)?;
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
        let arg_defs = self
            .function_signatures
            .get(&fc.identifier.name)
            .ok_or_else(|| self.err(CompileErrorType::NotDefined(fc.identifier.to_string())))?
            .args
            .clone();

        for (i, ((def_name, def_t), arg_e)) in arg_defs.iter().zip(fc.arguments.iter()).enumerate()
        {
            let arg_t = self.compile_expression(arg_e)?;
            if !arg_t.fits_type(def_t) {
                let arg_n = i
                    .checked_add(1)
                    .assume("function argument count overflow")?;
                return Err(self.err(CompileErrorType::InvalidType(format!(
                    "Argument {} (`{}`) in call to `{}` found `{}`, expected `{}`",
                    arg_n,
                    def_name,
                    fc.identifier,
                    arg_t,
                    DisplayType(def_t)
                ))));
            }
        }

        let label = Label::new(
            fc.identifier.name.clone(),
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
    fn compile_action(&mut self, action_node: &ast::ActionDefinition) -> Result<(), CompileError> {
        self.identifier_types.enter_function();
        self.define_label(
            Label::new(action_node.identifier.name.clone(), LabelType::Action),
            self.wp,
        )?;
        self.map_range(action_node.span)?;

        let mut params = NamedMap::new();
        for param in &action_node.arguments {
            params
                .insert(Param {
                    name: param.identifier.clone(),
                    ty: param.field_type.clone(),
                })
                .map_err(|_| {
                    self.err_loc(
                        CompileErrorType::AlreadyDefined(param.identifier.to_string()),
                        action_node.span,
                    )
                })?;
        }

        for arg in action_node.arguments.iter().rev() {
            self.append_var(arg.identifier.name.clone(), arg.field_type.clone())?;
        }

        self.compile_statements(&action_node.statements, Scope::Same)?;
        self.append_instruction(Instruction::Return);
        self.identifier_types.exit_function();

        self.m
            .action_defs
            .insert(ActionDef {
                name: action_node.identifier.clone(),
                persistence: action_node.persistence.clone(),
                params,
            })
            .map_err(|_| {
                self.err(CompileErrorType::AlreadyDefined(
                    action_node.identifier.to_string(),
                ))
            })?;

        Ok(())
    }

    /// Compile a globally scoped let statement
    fn compile_global_let(
        &mut self,
        global_let: &ast::GlobalLetStatement,
    ) -> Result<(), CompileError> {
        let identifier = &global_let.identifier;
        let expression = &global_let.expression;

        let value = self.expression_value(expression)?;
        let vt = value.vtype().expect("global let expression has weird type");

        match self.m.globals.entry(identifier.name.clone()) {
            Entry::Vacant(e) => {
                e.insert(value);
            }
            Entry::Occupied(_) => {
                return Err(self.err(CompileErrorType::AlreadyDefined(identifier.to_string())));
            }
        }

        self.identifier_types
            .add_global(
                identifier.name.clone(),
                Typeish::known(VType {
                    kind: vt,
                    span: Span::default(),
                }),
            )
            .map_err(|e| self.err(e))?;

        Ok(())
    }

    /// Unwraps an optional expression, placing its value on the stack. If the value is None, execution will be ended, with the given `exit_reason`.
    fn compile_unwrap(
        &mut self,
        e: &Expression,
        exit_reason: ExitReason,
    ) -> Result<Typeish, CompileError> {
        let not_none = self.anonymous_label();
        // evaluate the expression
        let inner_type = self.compile_expression(e)?;
        // Duplicate value for testing
        self.append_instruction(Instruction::Dup);
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
        self.define_label(not_none, self.wp)?;

        inner_type
            .try_map(|nty| match nty {
                NullableVType::Type(VType {
                    kind: TypeKind::Optional(t),
                    ..
                }) => Ok(NullableVType::Type(*t)),
                NullableVType::Null => Err(TypeError::new("Cannot unwrap None")),
                NullableVType::Type(_) => {
                    Err(TypeError::new("Cannot unwrap non-option expression"))
                }
            })
            .map_err(|err| self.err(err.into()))
    }

    fn compile_command_policy(
        &mut self,
        command: &ast::CommandDefinition,
    ) -> Result<(), CompileError> {
        self.define_label(
            Label::new(command.identifier.name.clone(), LabelType::CommandPolicy),
            self.wp,
        )?;
        self.enter_statement_context(StatementContext::CommandPolicy(command.clone()));
        self.identifier_types.enter_function();
        self.identifier_types
            .add(
                ident!("this"),
                Typeish::known(VType {
                    kind: TypeKind::Struct(command.identifier.clone()),
                    span: Span::default(),
                }),
            )
            .map_err(|e| self.err(e))?;
        self.identifier_types
            .add(
                ident!("envelope"),
                Typeish::known(VType {
                    kind: TypeKind::Struct(Ident {
                        name: ident!("Envelope"),
                        span: Span::default(),
                    }),
                    span: Span::default(),
                }),
            )
            .map_err(|e| self.err(e))?;
        self.append_instruction(Instruction::Def(ident!("envelope")));
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
        let mut named_blocks = HashSet::new();

        // Compile each recall block
        for recall_block in &command.recalls {
            // Check for duplicate recall block names
            if !named_blocks.insert(&recall_block.identifier.name) {
                return Err(self.err(CompileErrorType::AlreadyDefined(format!(
                    "recall block '{}'",
                    recall_block.identifier.name
                ))));
            }

            let label_name: Identifier = format!(
                "{}_{}",
                command.identifier.name, recall_block.identifier.name
            )
            .try_into()
            .expect("valid identifier");
            self.define_label(Label::new(label_name, LabelType::CommandRecall), self.wp)?;
            self.enter_statement_context(StatementContext::CommandRecall(command.clone()));
            self.identifier_types.enter_function();
            self.identifier_types
                .add(
                    ident!("this"),
                    Typeish::known(VType {
                        kind: TypeKind::Struct(command.identifier.clone()),
                        span: Span::default(),
                    }),
                )
                .map_err(|e| self.err(e))?;
            self.identifier_types
                .add(
                    ident!("envelope"),
                    Typeish::known(VType {
                        kind: TypeKind::Struct(Ident {
                            name: ident!("Envelope"),
                            span: Span::default(),
                        }),
                        span: Span::default(),
                    }),
                )
                .map_err(|e| self.err(e))?;
            self.append_instruction(Instruction::Def(ident!("envelope")));
            self.compile_statements(&recall_block.statements, Scope::Same)?;
            self.identifier_types.exit_function();
            self.exit_statement_context();
            self.append_instruction(Instruction::Exit(ExitReason::Normal));
        }
        Ok(())
    }

    fn compile_command_seal(
        &mut self,
        command: &ast::CommandDefinition,
        span: Span,
    ) -> Result<(), CompileError> {
        if command.seal.is_empty() {
            return Err(self.err_loc(
                CompileErrorType::Unknown(String::from("Empty/missing seal block in command")),
                span,
            ));
        }

        // fake a function def for the seal block
        let seal_function_definition = ast::FunctionDefinition {
            identifier: Ident {
                name: ident!("seal"),
                span: Span::default(),
            },
            arguments: vec![],
            return_type: VType {
                kind: TypeKind::Struct(Ident {
                    name: ident!("Envelope"),
                    span: Span::default(),
                }),
                span: Span::default(),
            },
            statements: vec![],
            span: command.span,
        };

        // Create a call stub for seal. Because it is function-like and
        // uses "return", we need something on the call stack to return
        // to.
        self.define_label(
            Label::new(command.identifier.name.clone(), LabelType::CommandSeal),
            self.wp,
        )?;
        let actual_seal = self.anonymous_label();
        self.append_instruction(Instruction::Call(Target::Unresolved(actual_seal.clone())));
        self.append_instruction(Instruction::Exit(ExitReason::Normal));
        self.define_label(actual_seal, self.wp)?;
        self.enter_statement_context(StatementContext::PureFunction(seal_function_definition));
        self.identifier_types.enter_function();
        self.identifier_types
            .add(
                ident!("this"),
                Typeish::known(VType {
                    kind: TypeKind::Struct(command.identifier.clone()),
                    span: Span::default(),
                }),
            )
            .map_err(|e| self.err(e))?;
        self.append_instruction(Instruction::Def(ident!("this")));
        let from = self.wp;
        self.compile_statements(&command.seal, Scope::Same)?;
        if !self.instruction_range_contains(from..self.wp, |i| matches!(i, Instruction::Return)) {
            return Err(self.err_loc(CompileErrorType::NoReturn, span));
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
        span: Span,
    ) -> Result<(), CompileError> {
        if command.open.is_empty() {
            return Err(self.err_loc(
                CompileErrorType::Unknown(String::from("Empty/missing open block in command")),
                span,
            ));
        }

        // fake a function def for the open block
        let open_function_definition = ast::FunctionDefinition {
            identifier: Ident {
                name: ident!("open"),
                span: Span::default(),
            },
            arguments: vec![],
            return_type: VType {
                kind: TypeKind::Struct(command.identifier.clone()),
                span: Span::default(),
            },
            statements: vec![],
            span: command.span,
        };

        // Same thing for open.
        self.define_label(
            Label::new(command.identifier.name.clone(), LabelType::CommandOpen),
            self.wp,
        )?;
        let actual_open = self.anonymous_label();
        self.append_instruction(Instruction::Call(Target::Unresolved(actual_open.clone())));
        self.append_instruction(Instruction::Exit(ExitReason::Normal));
        self.define_label(actual_open, self.wp)?;
        self.enter_statement_context(StatementContext::PureFunction(open_function_definition));
        self.identifier_types.enter_function();
        self.identifier_types
            .add(
                ident!("envelope"),
                Typeish::known(VType {
                    kind: TypeKind::Struct(Ident {
                        name: ident!("Envelope"),
                        span: Span::default(),
                    }),
                    span: Span::default(),
                }),
            )
            .map_err(|e| self.err(e))?;
        self.append_instruction(Instruction::Def(ident!("envelope")));
        let from = self.wp;
        self.compile_statements(&command.open, Scope::Same)?;
        if !self.instruction_range_contains(from..self.wp, |i| matches!(i, Instruction::Return)) {
            return Err(self.err_loc(CompileErrorType::NoReturn, span));
        }
        self.identifier_types.exit_function();
        self.exit_statement_context();
        self.append_instruction(Instruction::Exit(ExitReason::Panic));
        Ok(())
    }

    /// Compile a command policy block
    fn compile_command(
        &mut self,
        command_node: &ast::CommandDefinition,
    ) -> Result<(), CompileError> {
        let command = command_node;
        self.map_range(command.span)?;

        self.compile_command_policy(command)?;
        self.compile_command_recall(command)?;
        self.compile_command_seal(command, command.span)?;
        self.compile_command_open(command, command.span)?;

        // attributes
        let mut attributes = NamedMap::new();
        for (name, value_expr) in &command.attributes {
            let value = self.expression_value(value_expr)?;
            attributes
                .insert(Attribute {
                    name: name.clone(),
                    value,
                })
                .map_err(|_| self.err(CompileErrorType::AlreadyDefined(name.to_string())))?;
        }

        // fields
        let mut fields = NamedMap::new();

        let has_struct_refs = command
            .fields
            .iter()
            .any(|item| matches!(item, StructItem::StructRef(_)));

        for si in &command.fields {
            match si {
                StructItem::Field(f) => {
                    // TODO(eric): Use `Span::default()`?
                    let field_type = if has_struct_refs {
                        VType {
                            kind: f.field_type.kind.clone(),
                            span: Span::default(),
                        }
                    } else {
                        f.field_type.clone()
                    };
                    fields
                        .insert(Field {
                            name: f.identifier.clone(),
                            ty: field_type,
                        })
                        .assume("duplicates are prevented by compile_struct")?;
                }
                StructItem::StructRef(ref_name) => {
                    let struct_def = self.m.struct_defs.get(&ref_name.name).ok_or_else(|| {
                        self.err(CompileErrorType::NotDefined(ref_name.to_string()))
                    })?;
                    for fd in struct_def {
                        // Fields from struct refs always get normalized spans
                        let field_type = VType {
                            kind: fd.field_type.kind.clone(),
                            span: Span::default(),
                        };
                        fields
                            .insert(Field {
                                name: fd.identifier.clone(),
                                ty: field_type,
                            })
                            .assume("duplicates are prevented by compile_struct")?;
                    }
                }
            }
        }

        self.m
            .command_defs
            .insert(CommandDef {
                name: command.identifier.clone(),
                persistence: command.persistence.clone(),
                attributes,
                fields,
            })
            .map_err(|_| {
                self.err(CompileErrorType::AlreadyDefined(
                    command.identifier.to_string(),
                ))
            })?;

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
            FactCountType::UpTo(_) => self.append_instruction(Instruction::FactCount(limit)),
            FactCountType::AtLeast(_) => {
                self.append_instruction(Instruction::FactCount(limit));
                self.append_instruction(Instruction::Const(Value::Int(limit)));
                self.append_instruction(Instruction::Lt);
                self.append_instruction(Instruction::Not);
            }
            FactCountType::AtMost(_) => {
                self.append_instruction(Instruction::FactCount(
                    limit.checked_add(1).assume("fact count too large")?,
                ));
                self.append_instruction(Instruction::Const(Value::Int(limit)));
                self.append_instruction(Instruction::Gt);
                self.append_instruction(Instruction::Not);
            }
            FactCountType::Exactly(_) => {
                self.append_instruction(Instruction::FactCount(
                    limit.checked_add(1).assume("fact count too large")?,
                ));
                self.append_instruction(Instruction::Const(Value::Int(limit)));
                self.append_instruction(Instruction::Eq);
            }
        }
        Ok(())
    }

    /// Compile a match statement or expression
    /// Returns the type of the `match` is an expression, or `None` if it's a statement.
    fn compile_match_statement_or_expression(
        &mut self,
        s: LanguageContext<&MatchStatement, &MatchExpression>,
        span: Span,
    ) -> Result<Option<Typeish>, CompileError> {
        let patterns: Vec<MatchPattern> = match s {
            LanguageContext::Statement(s) => s.arms.iter().map(|a| a.pattern.clone()).collect(),
            LanguageContext::Expression(e) => e.arms.iter().map(|a| a.pattern.clone()).collect(),
        };

        // Ensure there are no duplicate arm values.
        // NOTE We don't check for zero arms, because that's enforced by the parser.
        let all_values = patterns
            .iter()
            .flat_map(|pattern| match pattern {
                MatchPattern::Values(values) => values.as_slice(),
                MatchPattern::Default(_) => &[],
            })
            .collect::<Vec<&Expression>>();
        // Check for duplicates by comparing expression kinds, not including spans
        for (i, v1) in all_values.iter().enumerate() {
            for v2 in &all_values[..i] {
                if v1.kind == v2.kind {
                    return Err(self.err_loc(
                        CompileErrorType::AlreadyDefined(String::from("duplicate match arm value")),
                        span,
                    ));
                }
            }
        }
        // find duplicate default arms
        let default_count = patterns
            .iter()
            .filter(|p| matches!(p, MatchPattern::Default(_)))
            .count();
        if default_count > 1 {
            return Err(self.err_loc(
                CompileErrorType::AlreadyDefined(String::from("duplicate match arm default value")),
                span,
            ));
        }

        let expr = match s {
            LanguageContext::Statement(s) => &s.expression,
            LanguageContext::Expression(e) => &e.scrutinee,
        };
        let mut expr_pat_t = self.compile_expression(expr)?;

        let need_default = default_count == 0
            && if let Typeish::Known(NullableVType::Type(ref known_type)) = expr_pat_t {
                let maybe_cardinality = self.m.cardinality(&known_type.kind);

                maybe_cardinality.is_none_or(|c| c > all_values.len() as u64)
            } else {
                true
            };

        if need_default {
            return Err(self.err_loc(CompileErrorType::MissingDefaultPattern, span));
        }

        let end_label = self.anonymous_label();

        // 1. Generate branching instructions, and arm-start labels
        let mut arm_labels: Vec<Label> = vec![];

        let mut n: usize = 0;
        for pattern in &patterns {
            let arm_label = self.anonymous_label();
            arm_labels.push(arm_label.clone());

            match pattern {
                MatchPattern::Values(values) => {
                    for value in values {
                        n = n.checked_add(1).assume("can't have usize::MAX patterns")?;
                        self.append_instruction(Instruction::Dup);
                        if !value.is_literal() {
                            return Err(self.err(CompileErrorType::InvalidType(format!(
                                "match pattern {n} is not a literal expression",
                            ))));
                        }
                        let arm_t = self.compile_expression(value)?;
                        expr_pat_t = self
                            .unify_pair(expr_pat_t, arm_t)
                            .map_err(|err| {
                                CompileErrorType::InvalidType(format!(
                                    "match pattern {n} has type {}, expected type {}",
                                    err.right, err.left
                                ))
                            })
                            .map_err(|err| self.err(err))?;

                        // if value == target, jump to start-of-arm
                        self.append_instruction(Instruction::Eq);
                        self.append_instruction(Instruction::Branch(Target::Unresolved(
                            arm_label.clone(),
                        )));
                    }
                }
                MatchPattern::Default(_) => {
                    self.append_instruction(Instruction::Jump(Target::Unresolved(
                        arm_label.clone(),
                    )));

                    // Ensure this is the last case, and also that it's not the only case.
                    if pattern != patterns.last().expect("last arm") {
                        return Err(self.err(CompileErrorType::Unknown(String::from(
                            "Default match case must be last.",
                        ))));
                    }
                }
            }
        }

        // Match expression/statement type. For statements, it's None; for expressions, it's Some(Typeish)
        let mut expr_type: Option<Typeish> = None;

        // 2. Define arm labels, and compile instructions
        match s {
            LanguageContext::Statement(s) => {
                for (i, arm) in s.arms.iter().enumerate() {
                    let arm_start = arm_labels[i].clone();
                    self.define_label(arm_start, self.wp)?;

                    // Drop expression value (It's still around because of the Dup)
                    self.append_instruction(Instruction::Pop);

                    self.compile_statements(&arm.statements, Scope::Layered)?;

                    // break out of match
                    self.append_instruction(Instruction::Jump(Target::Unresolved(
                        end_label.clone(),
                    )));
                }
            }
            LanguageContext::Expression(e) => {
                for (i, arm) in e.arms.iter().enumerate() {
                    let arm_start = arm_labels[i].clone();
                    self.define_label(arm_start, self.wp)?;

                    // Drop expression value (It's still around because of the Dup)
                    self.append_instruction(Instruction::Pop);

                    let etype = self.compile_expression(&arm.expression)?;
                    match expr_type {
                        None => expr_type = Some(etype),
                        Some(t) => {
                            expr_type = Some(
                                self.unify_pair(t, etype)
                                    .map_err(|err| {
                                        #[allow(
                                            clippy::arithmetic_side_effects,
                                            reason = "can't have usize::MAX arms"
                                        )]
                                        let n = i + 1;
                                        CompileErrorType::InvalidType(format!(
                                            "match arm expression {n} has type {}, expected {}",
                                            err.right, err.left
                                        ))
                                    })
                                    .map_err(|err| self.err(err))?,
                            );
                        }
                    }

                    // break out of match
                    self.append_instruction(Instruction::Jump(Target::Unresolved(
                        end_label.clone(),
                    )));
                }
            }
        }

        self.define_label(end_label, self.wp)?;
        Ok(expr_type)
    }

    /// Compile a policy into instructions inside the given Machine.
    pub fn compile(&mut self) -> Result<(), CompileError> {
        // Panic when running a module without setup.
        self.append_instruction(Instruction::Exit(ExitReason::Panic));

        for struct_def in &self.policy.structs {
            self.define_struct(struct_def.identifier.clone(), &struct_def.items)?;
        }

        // Compile global let statements
        for global_let in &self.policy.global_lets {
            self.compile_global_let(global_let)?;
        }

        for effect in &self.policy.effects {
            let fields: Vec<StructItem<FieldDefinition>> = effect
                .items
                .iter()
                .map(|i| match i {
                    StructItem::Field(f) => StructItem::Field(FieldDefinition {
                        identifier: f.identifier.clone(),
                        field_type: f.field_type.clone(),
                    }),
                    StructItem::StructRef(s) => StructItem::StructRef(s.clone()),
                })
                .collect();
            self.define_struct(effect.identifier.clone(), &fields)?;
            self.m.effects.insert(effect.identifier.name.clone());
        }

        // define the structs provided by FFI schema
        for ffi_mod in self.ffi_modules {
            for s in ffi_mod.structs {
                let fields: Vec<StructItem<FieldDefinition>> = s
                    .fields
                    .iter()
                    .map(|a| {
                        StructItem::Field(FieldDefinition {
                            identifier: Ident {
                                name: a.name.clone(),
                                span: Span::default(),
                            },
                            field_type: VType::from(&a.vtype),
                        })
                    })
                    .collect();
                let ident = Ident {
                    name: s.name.clone(),
                    span: Span::default(),
                };
                self.define_struct(ident, &fields)?;
            }
        }

        // map enum names to constants
        for enum_def in &self.policy.enums {
            self.compile_enum_definition(enum_def)?;
        }

        for fact in &self.policy.facts {
            let FactDefinition { key, value, .. } = fact;

            let fields: Vec<StructItem<FieldDefinition>> = key
                .iter()
                .chain(value.iter())
                .cloned()
                .map(StructItem::Field)
                .collect();

            self.define_struct(fact.identifier.clone(), &fields)?;
            self.define_fact(fact)?;
        }

        // Define command structs before compiling functions
        for command in &self.policy.commands {
            self.define_struct(command.identifier.clone(), &command.fields)?;
        }

        // Define the finish function signatures before compiling them, so that they can be
        // used to catch usage errors in regular functions.
        for function_def in &self.policy.finish_functions {
            self.define_finish_function_signature(function_def)?;
        }

        // Define function signatures before compiling them to
        // support using a function before it's defined.
        //
        // See https://github.com/aranya-project/aranya-core/issues/336
        for function_def in &self.policy.functions {
            self.define_function_signature(function_def)?;
        }

        for function_def in &self.policy.functions {
            self.enter_statement_context(StatementContext::PureFunction(function_def.clone()));
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
            self.enter_statement_context(StatementContext::Action(action.clone()));
            self.compile_action(action)?;
            self.exit_statement_context();
        }

        self.resolve_targets()?;

        Ok(())
    }

    /// Get expression value, e.g. ExprKind::Int => Value::Int
    fn expression_value(&self, e: &Expression) -> Result<Value, CompileError> {
        match &e.kind {
            ExprKind::Int(v) => Ok(Value::Int(*v)),
            ExprKind::Bool(v) => Ok(Value::Bool(*v)),
            ExprKind::String(v) => Ok(Value::String(v.clone())),
            ExprKind::NamedStruct(struct_ast) => {
                let Some(struct_def) = self.m.struct_defs.get(&struct_ast.identifier.name).cloned()
                else {
                    return Err(self.err(CompileErrorType::NotDefined(format!(
                        "Struct `{}` not defined",
                        struct_ast.identifier.name,
                    ))));
                };

                let struct_ast = self.evaluate_sources(struct_ast, &struct_def)?;

                let NamedStruct {
                    identifier, fields, ..
                } = struct_ast.as_ref();

                Ok(Value::Struct(Struct {
                    name: identifier.name.clone(),
                    fields: {
                        let mut value_fields = BTreeMap::new();
                        for (value, expr) in fields {
                            value_fields.insert(value.name.clone(), self.expression_value(expr)?);
                        }
                        value_fields
                    },
                }))
            }
            ExprKind::EnumReference(e) => self.enum_value(e),
            ExprKind::Dot(expr, field_ident) => match &expr.kind {
                ExprKind::Identifier(struct_ident) => self
                    .m
                    .globals
                    .get(&struct_ident.name)
                    .and_then(|val| match val {
                        Value::Struct(Struct { fields, .. }) => {
                            fields.get(&field_ident.name).cloned()
                        }
                        _ => None,
                    })
                    .ok_or_else(|| self.err(CompileErrorType::InvalidExpression(e.clone()))),
                _ => Err(self.err(CompileErrorType::InvalidExpression(e.clone()))),
            },
            _ => Err(self.err(CompileErrorType::InvalidExpression(e.clone()))),
        }
    }

    fn evaluate_sources<'s>(
        &self,
        base_struct: &'s NamedStruct,
        base_struct_defns: &[FieldDefinition],
    ) -> Result<Cow<'s, NamedStruct>, CompileError> {
        // If there are no sources, no evaluation is needed.
        if base_struct.sources.is_empty() {
            return Ok(Cow::Borrowed(base_struct));
        }

        // If the struct is already full, there ought to be no sources.
        if base_struct.fields.len() == base_struct_defns.len() {
            return Err(self.err(CompileErrorType::NoOpStructComp));
        }

        let base_fields: HashSet<&str> = base_struct
            .fields
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        let mut resolved_struct = base_struct.clone();
        let mut seen = HashMap::new();

        for src_var_name in &base_struct.sources {
            // Look up source's type. It should be a struct.
            let src_type = self
                .identifier_types
                .get(src_var_name)
                .map_err(|err| self.err(err))?;

            let src_struct_type_name = match src_type {
                Typeish::Known(NullableVType::Type(VType {
                    kind: TypeKind::Struct(type_name),
                    ..
                })) => type_name,
                // Known type, but not a struct
                Typeish::Known(other_type) => {
                    return Err(self.err(CompileErrorType::InvalidType(format!(
                        "Expected `{src_var_name}` to be a struct, but it's a(n) {other_type}",
                    ))));
                }
                Typeish::Never => {
                    // Never-typed expressions panic at runtime, making this struct composition
                    // operation unreachable. Skip to continue type checking.
                    continue;
                }
            };
            let src_field_defns = self
                .m
                .struct_defs
                .get(&src_struct_type_name.name)
                .assume("identifier with a struct type has that struct already defined")
                .map_err(|err| self.err(err.into()))?;

            for src_field_defn in src_field_defns {
                // Don't resolve fields already in the base struct.
                if base_fields.contains(src_field_defn.identifier.as_str()) {
                    continue;
                }

                // Ensure we haven't already resolved this field from another source.
                if let Some(other) = seen.insert(
                    &src_field_defn.identifier.name,
                    src_struct_type_name.clone(),
                ) {
                    return Err(self.err(CompileErrorType::DuplicateSourceFields(
                        src_struct_type_name.name,
                        other.name,
                    )));
                }

                // Ensure this field has the right type.
                let base_struct_defn = base_struct_defns
                    .iter()
                    .find(|b_defn| b_defn.identifier.name == src_field_defn.identifier.name)
                    .ok_or_else(|| {
                        self.err(CompileErrorType::SourceStructNotSubsetOfBase(
                            src_struct_type_name.name.clone(),
                            base_struct.identifier.name.clone(),
                        ))
                    })?;
                if !base_struct_defn
                    .field_type
                    .matches(&src_field_defn.field_type)
                {
                    return Err(self.err(CompileErrorType::InvalidType(format!(
                        "Expected field `{}` of `{}` to be a `{}`",
                        &src_field_defn.identifier, src_var_name, base_struct_defn.field_type
                    ))));
                }

                // Add field to resolved struct from source.

                // Foo {x: 0, ...bar } -> Foo -> {x: 0, y: bar.y }
                resolved_struct.fields.push((
                    src_field_defn.identifier.clone(),
                    Expression {
                        kind: ExprKind::Dot(
                            Box::new(Expression {
                                kind: ExprKind::Identifier(src_var_name.clone()),
                                span: src_var_name.span,
                            }),
                            src_field_defn.identifier.clone(),
                        ),
                        span: src_field_defn.identifier.span,
                    },
                ));
            }
        }

        Ok(Cow::Owned(resolved_struct))
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
    #[must_use]
    pub fn ffi_modules(mut self, ffi_modules: &'a [ModuleSchema<'a>]) -> Self {
        self.ffi_modules = ffi_modules;
        self
    }

    /// Enables or disables debug mode
    #[must_use]
    pub fn debug(mut self, is_debug: bool) -> Self {
        self.is_debug = is_debug;
        self
    }

    #[must_use]
    pub fn stub_ffi(mut self, flag: bool) -> Self {
        self.stub_ffi = flag;
        self
    }

    /// Consumes the builder to create a [`Module`]
    pub fn compile(self) -> Result<Module, CompileError> {
        let target = self.compile_to_target()?;
        Ok(target.into_module())
    }

    pub fn compile_to_target(self) -> Result<CompileTarget, CompileError> {
        let codemap = CodeMap::new(&self.policy.text);
        let machine = CompileTarget::new(codemap);
        let mut cs = CompileState {
            policy: self.policy,
            m: machine,
            wp: 0,
            c: 0,
            function_signatures: BTreeMap::new(),
            last_span: Span::empty(),
            statement_context: vec![],
            identifier_types: IdentifierTypeStack::new(),
            ffi_modules: self.ffi_modules,
            is_debug: self.is_debug,
            stub_ffi: self.stub_ffi,
        };

        cs.compile()?;
        Ok(cs.m)
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
