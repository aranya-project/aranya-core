mod error;
mod lower;
mod target;
mod types;

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, btree_map::Entry},
    fmt, iter,
    num::NonZeroUsize,
    ops::Range,
    vec,
};

use aranya_policy_ast::{
    self as ast, EnumDefinition, ExprKind, Expression, FactCountType, FactDefinition,
    FieldDefinition, Ident, Identifier, LanguageContext, NamedStruct, Param, Span, Statement,
    StructItem, TypeKind, VType, ident, thir,
};
use aranya_policy_module::{
    ActionDef, Attribute, CodeMap, CommandDef, ExitReason, Field, Instruction, Label, LabelType,
    Meta, Module, Struct, Target, Value, WrapType, ffi::ModuleSchema, named::NamedMap,
};
pub use ast::Policy as AstPolicy;
use buggy::BugExt as _;
use indexmap::IndexMap;
use tracing::warn;

pub use self::{
    error::{CompileError, CompileErrorType, InvalidCallColor},
    target::PolicyInterface,
};
use self::{target::CompileTarget, types::IdentifierTypeStack};

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
#[derive(Clone)]
struct FunctionSignature {
    args: Vec<Param>,
    color: FunctionColor,
}

/// Create a `(Identifier, FunctionSignature)` from a policy function declaration.
macro_rules! sig {
    (
        function $func:ident(
            $($argname:ident $($argty0:ident $($argty1:ident)? $([ $($argty_tt:tt)+ ])?)?),*
        ) $($ret0:ident $($ret1:ident)? $([ $($ret_tt:tt)+ ])?)?
    ) => {
        (
            ident!(stringify!($func)),
            FunctionSignature {
                args: vec![$(
                    Param {
                        name: Ident { name: ident!(stringify!($argname)), span: Span::empty() },
                        ty: vtype!($($argty0 $($argty1)? $([ $($argty_tt)+ ])?)?)
                    }
                ),*],
                color: FunctionColor::Pure(vtype!($($ret0 $($ret1)? $([ $($ret_tt)+ ])?)?)),
            }
        )
    };
}

macro_rules! vtype {
    ($($t:tt)*) => {
        VType {
            kind: typekind!($($t)*),
            span: Span::empty(),
        }
    }
}

macro_rules! typekind {
    (string) => {
        TypeKind::String
    };
    (bytes) => {
        TypeKind::Bytes
    };
    (int) => {
        TypeKind::Int
    };
    (bool) => {
        TypeKind::Bool
    };
    (id) => {
        TypeKind::Id
    };
    (struct $name:ident) => {
        TypeKind::Struct(Ident {
            name: ident!(stringify!($name)),
            span: Span::empty(),
        })
    };
    (enum $name:ident) => {
        TypeKind::Enum(Ident {
            name: ident!(stringify!($name)),
            span: Span::empty(),
        })
    };
    (option [ $inner:ident ]) => {
        TypeKind::Optional(Box::new(vtype!($inner)))
    };
}

mod param {
    use super::{Ident, Param, Span, TypeKind, VType, ident};

    pub fn envelope() -> Param {
        Param {
            name: Ident {
                name: ident!("envelope"),
                span: Span::empty(),
            },
            ty: VType {
                kind: TypeKind::Struct(Ident {
                    name: ident!("Envelope"),
                    span: Span::empty(),
                }),
                span: Span::empty(),
            },
        }
    }

    pub fn this(name: Ident) -> Param {
        Param {
            name: Ident {
                name: ident!("this"),
                span: Span::empty(),
            },
            ty: VType {
                kind: TypeKind::Struct(name),
                span: Span::empty(),
            },
        }
    }
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

/// Called to compile a builtin function call.
type BuiltinHandler = fn(&mut CompileState<'_>) -> Result<(), CompileError>;

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
    function_signatures: BTreeMap<Identifier, FunctionSignature>,
    /// Builtin functions which have special behavior when compiling a function call.
    builtin_functions: BTreeMap<Identifier, BuiltinHandler>,
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
            .add(identifier, vtype)
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
        match self.function_signatures.entry(def.identifier.name.clone()) {
            Entry::Vacant(e) => {
                let signature = FunctionSignature {
                    args: def.arguments.clone(),
                    color: FunctionColor::Pure(def.return_type.clone()),
                };
                Ok(e.insert(signature))
            }
            Entry::Occupied(_) => {
                let mut name = def.identifier.to_string();
                if self.builtin_functions.contains_key(def.identifier.as_str()) {
                    name.push_str(" (builtin)");
                }
                Err(CompileError::from_span(
                    CompileErrorType::AlreadyDefined(name),
                    def.span,
                    self.m.codemap.as_ref(),
                ))
            }
        }
    }

    /// Turn a [FinishFunctionDefinition](ast::FinishFunctionDefinition)
    /// into a [FunctionSignature].
    fn define_finish_function_signature(
        &mut self,
        function_node: &'a ast::FinishFunctionDefinition,
    ) -> Result<&FunctionSignature, CompileError> {
        let def = function_node;
        match self.function_signatures.entry(def.identifier.name.clone()) {
            Entry::Vacant(e) => {
                let signature = FunctionSignature {
                    args: def.arguments.clone(),
                    color: FunctionColor::Finish,
                };
                Ok(e.insert(signature))
            }
            Entry::Occupied(_) => {
                let mut name = def.identifier.to_string();
                if self.builtin_functions.contains_key(def.identifier.as_str()) {
                    name.push_str(" (builtin)");
                }
                Err(CompileError::from_span(
                    CompileErrorType::AlreadyDefined(name),
                    def.span,
                    self.m.codemap.as_ref(),
                ))
            }
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
    fn compile_struct_literal(&mut self, s: thir::NamedStruct) -> Result<(), CompileError> {
        self.append_instruction(Instruction::StructNew(s.identifier.name));
        for (field_name, e) in s.fields {
            self.compile_typed_expression(e)?;
            self.append_instruction(Instruction::StructSet(field_name.name));
        }
        Ok(())
    }

    fn err(&self, err_type: CompileErrorType) -> CompileError {
        self.err_loc(err_type, self.last_span)
    }

    fn err_loc(&self, err_type: CompileErrorType, span: Span) -> CompileError {
        CompileError::from_span(err_type, span, self.m.codemap.as_ref())
    }

    /// Compile instructions to construct a fact literal
    fn compile_fact_literal(&mut self, f: thir::FactLiteral) -> Result<(), CompileError> {
        self.append_instruction(Instruction::FactNew(f.identifier.name.clone()));
        for (k, e) in f.key_fields {
            self.compile_typed_expression(e)?;
            self.append_instruction(Instruction::FactKeySet(k.name));
        }
        if let Some(value_fields) = f.value_fields {
            for (k, e) in value_fields {
                self.compile_typed_expression(e)?;
                self.append_instruction(Instruction::FactValueSet(k.name));
            }
        }
        Ok(())
    }

    fn compile_typed_expression(
        &mut self,
        expression: thir::Expression,
    ) -> Result<(), CompileError> {
        match expression.kind {
            thir::ExprKind::Int(n) => {
                self.append_instruction(Instruction::Const(Value::Int(n)));
            }
            thir::ExprKind::String(s) => {
                self.append_instruction(Instruction::Const(Value::String(s)));
            }
            thir::ExprKind::Bool(b) => {
                self.append_instruction(Instruction::Const(Value::Bool(b)));
            }
            thir::ExprKind::Optional(o) => match o {
                None => {
                    self.append_instruction(Instruction::Const(Value::NONE));
                }
                Some(v) => {
                    self.compile_typed_expression(*v)?;
                    self.append_instruction(Instruction::Some);
                }
            },
            thir::ExprKind::NamedStruct(s) => {
                self.compile_struct_literal(s)?;
            }
            thir::ExprKind::InternalFunction(f) => match f {
                thir::InternalFunction::Query(f) => {
                    self.compile_fact_literal(f)?;
                    self.append_instruction(Instruction::Query);
                }
                thir::InternalFunction::Exists(f) => {
                    self.compile_fact_literal(f)?;
                    self.append_instruction(Instruction::Query);
                    self.append_instruction(Instruction::Const(Value::NONE));
                    self.append_instruction(Instruction::Eq);
                    self.append_instruction(Instruction::Not);
                }
                thir::InternalFunction::FactCount(cmp_type, n, fact) => {
                    self.compile_counting_function(cmp_type, n, fact)?;
                }
                thir::InternalFunction::If(c, t, f) => {
                    let else_name = self.anonymous_label();
                    let end_name = self.anonymous_label();
                    self.compile_typed_expression(*c)?;
                    self.append_instruction(Instruction::Branch(Target::Unresolved(
                        else_name.clone(),
                    )));
                    self.compile_typed_expression(*f)?;
                    self.append_instruction(Instruction::Jump(Target::Unresolved(
                        end_name.clone(),
                    )));
                    self.define_label(else_name, self.wp)?;
                    self.compile_typed_expression(*t)?;
                    self.define_label(end_name, self.wp)?;
                }
                thir::InternalFunction::Serialize(e) => {
                    self.compile_typed_expression(*e)?;
                    self.append_instruction(Instruction::Serialize);
                }
                thir::InternalFunction::Deserialize(e) => {
                    self.compile_typed_expression(*e)?;
                    self.append_instruction(Instruction::Deserialize);
                }
                thir::InternalFunction::Todo(_) => {
                    let err = self.err(CompileErrorType::TodoFound);
                    if self.is_debug {
                        warn!("{err}");
                        self.append_instruction(Instruction::Exit(ExitReason::Panic));
                    } else {
                        return Err(err);
                    }
                }
            },
            thir::ExprKind::FunctionCall(f) => {
                self.compile_function_call(f)?;
            }
            thir::ExprKind::ForeignFunctionCall(f) => {
                self.append_instruction(Instruction::Meta(Meta::FFI(
                    f.module.name.clone(),
                    f.identifier.name.clone(),
                )));

                for arg_e in f.arguments {
                    self.compile_typed_expression(arg_e)?;
                }
                if self.stub_ffi {
                    self.append_instruction(Instruction::Exit(ExitReason::Panic));
                } else {
                    let (module_id, procedure_id) =
                        f.ids.assume("must have IDs when ffi is not stubbed")?;
                    self.append_instruction(Instruction::ExtCall(module_id, procedure_id));
                }
            }
            thir::ExprKind::Return(ret_expr) => {
                self.compile_typed_expression(*ret_expr)?;
                self.append_instruction(Instruction::RestoreSP);
                self.append_instruction(Instruction::Return);
            }
            thir::ExprKind::Identifier(i) => {
                self.append_instruction(Instruction::Meta(Meta::Get(i.name.clone())));
                self.append_instruction(Instruction::Get(i.name));
            }
            thir::ExprKind::EnumReference(e) => {
                self.append_instruction(Instruction::Const(Value::Enum(
                    e.identifier.name,
                    e.value,
                )));
            }
            thir::ExprKind::Dot(t, s) => {
                self.compile_typed_expression(*t)?;
                self.append_instruction(Instruction::StructGet(s.name));
            }
            thir::ExprKind::Substruct(lhs, sub) => {
                let Some(sub_field_defns) = self.m.struct_defs.get(&sub.name) else {
                    return Err(self.err(CompileErrorType::NotDefined(format!(
                        "Struct `{}` not defined",
                        sub
                    ))));
                };
                let field_names: Vec<Identifier> = sub_field_defns
                    .iter()
                    .map(|field| field.identifier.name.clone())
                    .collect();
                let field_count = field_names.len();

                self.append_instruction(Instruction::StructNew(sub.name));

                self.compile_typed_expression(*lhs)?;

                for field_name in field_names {
                    self.append_instruction(Instruction::Const(Value::Identifier(field_name)));
                }

                if let Some(field_count) = NonZeroUsize::new(field_count) {
                    self.append_instruction(Instruction::MStructGet(field_count));
                    self.append_instruction(Instruction::MStructSet(field_count));
                }
            }
            thir::ExprKind::Cast(lhs, rhs_ident) => {
                // NOTE this is implemented only for structs
                self.compile_typed_expression(*lhs)?;
                self.append_instruction(Instruction::Cast(rhs_ident.name));
            }
            thir::ExprKind::And(a, b) => {
                // `a && b` becomes `if a { b } else { false }`

                self.compile_typed_expression(*a)?;

                let mid = self.anonymous_label();
                let end = self.anonymous_label();

                self.append_instruction(Instruction::Branch(Target::Unresolved(mid.clone())));

                self.append_instruction(Instruction::Const(Value::Bool(false)));
                self.append_instruction(Instruction::Jump(Target::Unresolved(end.clone())));

                self.define_label(mid, self.wp)?;
                self.compile_typed_expression(*b)?;

                self.define_label(end, self.wp)?;
            }
            thir::ExprKind::Or(a, b) => {
                // `a || b` becomes `if a { true } else { b }`

                self.compile_typed_expression(*a)?;

                let mid = self.anonymous_label();
                let end = self.anonymous_label();

                self.append_instruction(Instruction::Branch(Target::Unresolved(mid.clone())));
                self.compile_typed_expression(*b)?;
                self.append_instruction(Instruction::Jump(Target::Unresolved(end.clone())));

                self.define_label(mid, self.wp)?;
                self.append_instruction(Instruction::Const(Value::Bool(true)));

                self.define_label(end, self.wp)?;
            }
            thir::ExprKind::Equal(a, b) => {
                self.compile_typed_expression(*a)?;
                self.compile_typed_expression(*b)?;
                self.append_instruction(Instruction::Eq);
            }
            thir::ExprKind::NotEqual(a, b) => {
                self.compile_typed_expression(*a)?;
                self.compile_typed_expression(*b)?;
                self.append_instruction(Instruction::Eq);
                self.append_instruction(Instruction::Not);
            }
            thir::ExprKind::GreaterThan(a, b) => {
                self.compile_typed_expression(*a)?;
                self.compile_typed_expression(*b)?;
                self.append_instruction(Instruction::Gt);
            }
            thir::ExprKind::LessThan(a, b) => {
                self.compile_typed_expression(*a)?;
                self.compile_typed_expression(*b)?;
                self.append_instruction(Instruction::Lt);
            }
            thir::ExprKind::GreaterThanOrEqual(a, b) => {
                // `a >= b` becomes `!(a < b)`. This relies on total ordering, which integers meet.
                self.compile_typed_expression(*a)?;
                self.compile_typed_expression(*b)?;
                self.append_instruction(Instruction::Lt);
                self.append_instruction(Instruction::Not);
            }
            thir::ExprKind::LessThanOrEqual(a, b) => {
                // `a <= b` becomes `!(a > b)`. This relies on total ordering, which integers meet.
                self.compile_typed_expression(*a)?;
                self.compile_typed_expression(*b)?;
                self.append_instruction(Instruction::Gt);
                self.append_instruction(Instruction::Not);
            }
            thir::ExprKind::Not(e) => {
                // Evaluate the expression
                self.compile_typed_expression(*e)?;

                // Apply the logical NOT operation
                self.append_instruction(Instruction::Not);
            }
            thir::ExprKind::Unwrap(e) => self.compile_unwrap(*e, ExitReason::Panic)?,
            thir::ExprKind::CheckUnwrap(e) => self.compile_unwrap(*e, ExitReason::Check)?,
            thir::ExprKind::Is(e, expr_is_some) => {
                // Evaluate the expression
                self.compile_typed_expression(*e)?;

                // Push a None to compare against
                self.append_instruction(Instruction::Const(Value::NONE));
                // Check if the value is equal to None
                self.append_instruction(Instruction::Eq);
                if expr_is_some {
                    // If we're checking for not Some, invert the result of the Eq to None
                    self.append_instruction(Instruction::Not);
                }
            }
            thir::ExprKind::Block(statements, e) => {
                self.append_instruction(Instruction::Block);
                self.compile_typed_statements(statements, Scope::Same)?;
                self.compile_typed_expression(*e)?;
                self.append_instruction(Instruction::End);
            }
            thir::ExprKind::Match(e) => {
                self.compile_match_statement_or_expression(LanguageContext::Expression(*e))?;
            }
            thir::ExprKind::ResultOk(e) => {
                // Compile the inner expression and wrap it in Ok
                self.compile_typed_expression(*e)?;
                // We need to wrap the value in a result variant, i.e Int(42) becomes Ok(Int(42))
                self.append_instruction(Instruction::Wrap(WrapType::Ok));
            }
            thir::ExprKind::ResultErr(e) => {
                // Compile the inner expression and wrap it in Err
                self.compile_typed_expression(*e)?;
                self.append_instruction(Instruction::Wrap(WrapType::Err));
            }
        }

        Ok(())
    }

    // Get an enum value from an enum reference expression
    fn enum_value(&self, e: &aranya_policy_ast::EnumReference) -> Result<i64, CompileError> {
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
        Ok(*value)
    }

    fn compile_statements(
        &mut self,
        statements: &[Statement],
        scope: Scope,
    ) -> Result<(), CompileError> {
        let stmts = self.lower_statements(statements, scope)?;
        self.compile_typed_statements(stmts, scope)
    }

    fn compile_typed_statements(
        &mut self,
        statements: Vec<thir::Statement>,
        scope: Scope,
    ) -> Result<(), CompileError> {
        if scope == Scope::Layered {
            self.append_instruction(Instruction::Block);
        }
        for statement in statements {
            self.compile_typed_statement(statement)?;
        }
        if scope == Scope::Layered {
            self.append_instruction(Instruction::End);
        }
        Ok(())
    }

    fn compile_typed_statement(&mut self, statement: thir::Statement) -> Result<(), CompileError> {
        self.map_range(statement.span)?;
        match statement.kind {
            thir::StmtKind::Let(s) => {
                self.compile_typed_expression(s.expression)?;
                // Note: Never type check is done during lowering
                self.append_instruction(Instruction::Meta(Meta::Let(s.identifier.name.clone())));
                self.append_instruction(Instruction::Def(s.identifier.name));
            }
            thir::StmtKind::Check(s) => {
                self.compile_typed_expression(s.expression)?;
                // The current instruction is the branch. The next
                // instruction is the following panic you arrive at
                // if the expression is false. The instruction you
                // branch to if the check succeeds is the
                // instruction after that - current instruction + 2.
                let next = self.wp.checked_add(2).assume("self.wp + 2 must not wrap")?;
                self.append_instruction(Instruction::Branch(Target::Resolved(next)));
                self.append_instruction(Instruction::Exit(ExitReason::Check));
            }
            thir::StmtKind::Match(s) => {
                self.compile_match_statement_or_expression(LanguageContext::Statement(s))?;
            }
            thir::StmtKind::If(s) => {
                let end_label = self.anonymous_label();
                for (cond, branch) in s.branches {
                    let next_label = self.anonymous_label();
                    self.compile_typed_expression(cond)?;

                    self.append_instruction(Instruction::Not);
                    self.append_instruction(Instruction::Branch(Target::Unresolved(
                        next_label.clone(),
                    )));
                    self.compile_typed_statements(branch, Scope::Layered)?;
                    self.append_instruction(Instruction::Jump(Target::Unresolved(
                        end_label.clone(),
                    )));
                    self.define_label(next_label, self.wp)?;
                }
                if let Some(fallback) = s.fallback {
                    self.compile_typed_statements(fallback, Scope::Layered)?;
                }
                self.define_label(end_label, self.wp)?;
            }
            thir::StmtKind::Publish(s) => {
                self.compile_typed_expression(s)?;
                self.append_instruction(Instruction::Publish);
            }
            thir::StmtKind::Finish(s) => {
                self.enter_statement_context(StatementContext::Finish);
                self.append_instruction(Instruction::Meta(Meta::Finish(true)));
                self.compile_typed_statements(s, Scope::Layered)?;
                self.exit_statement_context();
                // Exit after the `finish` block. We need this because there could be more instructions following, e.g. those following `when` or `match`.
                self.append_instruction(Instruction::Exit(ExitReason::Normal));
            }
            thir::StmtKind::Map(map_stmt) => {
                // Execute query and store results
                self.compile_fact_literal(map_stmt.fact)?;
                self.append_instruction(Instruction::QueryStart);
                // Consume results...
                let top_label = self.anonymous_label();
                let end_label = self.anonymous_label();
                self.define_label(top_label.clone(), self.wp)?;
                // Fetch next result
                self.append_instruction(Instruction::Block);
                self.append_instruction(Instruction::QueryNext(map_stmt.identifier.name.clone()));
                // If no more results, break
                self.append_instruction(Instruction::Branch(Target::Unresolved(end_label.clone())));
                // body
                self.compile_typed_statements(map_stmt.statements, Scope::Same)?;
                self.append_instruction(Instruction::End);
                // Jump back to top of loop
                self.append_instruction(Instruction::Jump(Target::Unresolved(top_label)));
                // Exit loop
                self.define_label(end_label, self.wp)?;
                self.append_instruction(Instruction::End);
            }
            thir::StmtKind::Create(s) => {
                self.compile_fact_literal(s.fact)?;
                self.append_instruction(Instruction::Create);
            }
            thir::StmtKind::Update(s) => {
                self.compile_fact_literal(s.fact)?;
                self.append_instruction(Instruction::Dup);

                for (k, e) in s.to {
                    self.compile_typed_expression(e)?;
                    self.append_instruction(Instruction::FactValueSet(k.name));
                }
                self.append_instruction(Instruction::Update);
            }
            thir::StmtKind::Delete(s) => {
                self.compile_fact_literal(s.fact)?;
                self.append_instruction(Instruction::Delete);
            }
            thir::StmtKind::Emit(s) => {
                self.compile_typed_expression(s)?;
                self.append_instruction(Instruction::Emit);
            }
            thir::StmtKind::FunctionCall(f) => {
                self.compile_function_call(f)?;
            }
            thir::StmtKind::ActionCall(fc) => {
                for arg in fc.arguments {
                    self.compile_typed_expression(arg)?;
                }
                let label = Label::new(fc.identifier.name, LabelType::Action);
                self.append_instruction(Instruction::Call(Target::Unresolved(label)));
            }
            thir::StmtKind::DebugAssert(s) => {
                if self.is_debug {
                    // Compile the expression within `debug_assert(e)`
                    self.compile_typed_expression(s)?;
                    // Now, branch to the next instruction if the top of the stack is true
                    let next = self.wp.checked_add(2).expect("self.wp + 2 must not wrap");
                    self.append_instruction(Instruction::Branch(Target::Resolved(next)));
                    // Append a `Exit::Panic` instruction to exit if the `debug_assert` fails.
                    self.append_instruction(Instruction::Exit(ExitReason::Panic));
                }
            }
            thir::StmtKind::Expr(expr) => {
                // Compile the expression. For return expressions with Never type,
                // this will emit a Return instruction and never leave a value on the stack.
                self.compile_typed_expression(expr)?;
                // Expression statements are not meant to produce values - they're used for control flow only.
                // Note: No need to pop the value - expressions with Never type
                // (like return) don't leave values on the stack.
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
        self.enter_statement_context(StatementContext::PureFunction(function_node.clone()));
        self.compile_function_like(
            &function_node.arguments,
            Some(&function_node.return_type),
            function_node.span,
            &function_node.statements,
            Label::new(function_node.identifier.name.clone(), LabelType::Function),
        )?;
        self.exit_statement_context();
        Ok(())
    }

    /// Compile a finish function
    fn compile_finish_function(
        &mut self,
        function_node: &'a ast::FinishFunctionDefinition,
    ) -> Result<(), CompileError> {
        self.enter_statement_context(StatementContext::Finish);
        self.compile_function_like(
            &function_node.arguments,
            None,
            function_node.span,
            &function_node.statements,
            Label::new(function_node.identifier.name.clone(), LabelType::Function),
        )?;
        // Finish functions cannot have return statements, so we add a return instruction manually.
        self.append_instruction(Instruction::Return);
        self.exit_statement_context();
        Ok(())
    }

    fn compile_function_call(&mut self, fc: thir::FunctionCall) -> Result<(), CompileError> {
        for arg_e in fc.arguments {
            self.compile_typed_expression(arg_e)?;
        }

        if let Some(handler) = self.builtin_functions.get(fc.identifier.as_str()).copied() {
            handler(self)?;
        } else {
            let label = Label::new(fc.identifier.name, LabelType::Function);
            self.append_instruction(Instruction::Call(Target::Unresolved(label)));
        }

        Ok(())
    }

    /// Define an action function
    fn define_action(&mut self, action_node: &ast::ActionDefinition) -> Result<(), CompileError> {
        let mut params = NamedMap::new();
        for param in &action_node.arguments {
            params.insert(param.clone()).map_err(|_| {
                self.err_loc(
                    CompileErrorType::AlreadyDefined(param.name.to_string()),
                    action_node.span,
                )
            })?;
        }

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

    /// Compile an action function
    fn compile_action(&mut self, action_node: &ast::ActionDefinition) -> Result<(), CompileError> {
        self.enter_statement_context(StatementContext::Action(action_node.clone()));
        self.compile_function_like(
            &action_node.arguments,
            None,
            action_node.span,
            &action_node.statements,
            Label::new(action_node.identifier.name.clone(), LabelType::Action),
        )?;
        // Actions cannot have return statements, so we add a return instruction manually.
        self.append_instruction(Instruction::Return);
        self.exit_statement_context();
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
                VType {
                    kind: vt,
                    span: Span::default(),
                },
            )
            .map_err(|e| self.err(e))?;

        Ok(())
    }

    /// Unwraps an optional expression, placing its value on the stack. If the value is None, execution will be ended, with the given `exit_reason`.
    fn compile_unwrap(
        &mut self,
        e: thir::Expression,
        exit_reason: ExitReason,
    ) -> Result<(), CompileError> {
        let not_none = self.anonymous_label();
        // evaluate the expression
        self.compile_typed_expression(e)?;
        // Duplicate value for testing
        self.append_instruction(Instruction::Dup);
        // Push a None to compare against
        self.append_instruction(Instruction::Const(Value::NONE));
        // Is the value not equal to None?
        self.append_instruction(Instruction::Eq);
        self.append_instruction(Instruction::Not);
        // Then branch over the Panic
        self.append_instruction(Instruction::Branch(Target::Unresolved(not_none.clone())));
        // If the value is equal to None, panic
        self.append_instruction(Instruction::Exit(exit_reason));
        // Define the target of the branch as the instruction after the Panic
        self.define_label(not_none, self.wp)?;
        self.append_instruction(Instruction::Unwrap);

        Ok(())
    }

    fn compile_command_policy(
        &mut self,
        command: &ast::CommandDefinition,
    ) -> Result<(), CompileError> {
        self.enter_statement_context(StatementContext::CommandPolicy(command.clone()));
        self.compile_function_like(
            &[param::this(command.identifier.clone()), param::envelope()],
            None,
            Span::empty(),
            &command.policy,
            Label::new(command.identifier.name.clone(), LabelType::CommandPolicy),
        )?;
        // Policy blocks should exit via a finish block, so panic if it doesn't.
        self.append_instruction(Instruction::Exit(ExitReason::Panic));
        self.exit_statement_context();
        Ok(())
    }

    fn compile_command_recall(
        &mut self,
        command: &ast::CommandDefinition,
    ) -> Result<(), CompileError> {
        self.enter_statement_context(StatementContext::CommandRecall(command.clone()));
        self.compile_function_like(
            &[param::this(command.identifier.clone()), param::envelope()],
            None,
            Span::empty(),
            &command.recall,
            Label::new(command.identifier.name.clone(), LabelType::CommandRecall),
        )?;
        if command.recall.is_empty() {
            // TODO(#544): Handle absent/empty recall properly.
            // Return for now so that absent/empty recall blocks don't panic.
            self.append_instruction(Instruction::Return);
        } else {
            // Recall blocks should exit via a finish block, so panic if it doesn't.
            self.append_instruction(Instruction::Exit(ExitReason::Panic));
        }
        self.exit_statement_context();
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
        let args = &[param::this(command.identifier.clone())];
        let ret = VType {
            kind: TypeKind::Struct(Ident {
                name: ident!("Envelope"),
                span: Span::default(),
            }),
            span: Span::default(),
        };
        let seal_function_definition = ast::FunctionDefinition {
            identifier: Ident {
                name: ident!("seal"),
                span: Span::default(),
            },
            arguments: args.to_vec(),
            return_type: ret.clone(),
            statements: vec![],
            span: command.span,
        };

        self.enter_statement_context(StatementContext::PureFunction(seal_function_definition));
        self.compile_function_like(
            args,
            Some(&ret),
            span,
            &command.seal,
            Label::new(command.identifier.name.clone(), LabelType::CommandSeal),
        )?;
        self.exit_statement_context();

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
        let args = &[param::envelope()];
        let ret = VType {
            kind: TypeKind::Struct(command.identifier.clone()),
            span: Span::default(),
        };
        let open_function_definition = ast::FunctionDefinition {
            identifier: Ident {
                name: ident!("open"),
                span: Span::default(),
            },
            arguments: args.to_vec(),
            return_type: ret.clone(),
            statements: vec![],
            span: command.span,
        };

        self.enter_statement_context(StatementContext::PureFunction(open_function_definition));
        self.compile_function_like(
            args,
            Some(&ret),
            span,
            &command.open,
            Label::new(command.identifier.name.clone(), LabelType::CommandOpen),
        )?;
        self.exit_statement_context();

        Ok(())
    }

    fn compile_function_like(
        &mut self,
        params: &[Param],
        ret: Option<&VType>,
        span: Span,
        body: &[Statement],
        label: Label,
    ) -> Result<(), CompileError> {
        self.define_label(label, self.wp)?;
        self.map_range(span)?;

        if let Some(identifier) = find_duplicate(params, |p| &p.name) {
            return Err(self.err_loc(
                CompileErrorType::AlreadyDefined(identifier.to_string()),
                span,
            ));
        }

        self.identifier_types.enter_function();
        for param in params.iter().rev() {
            self.ensure_type_is_defined(&param.ty)?;
            self.append_var(param.name.name.clone(), param.ty.clone())?;
        }
        if let Some(return_type) = ret {
            self.ensure_type_is_defined(return_type)?;
            self.append_instruction(Instruction::SaveSP);
        }
        let from = self.wp;
        self.compile_statements(body, Scope::Same)?;

        if ret.is_some() {
            // Check that there is a return statement somewhere in the compiled instructions.
            if !self.instruction_range_contains(from..self.wp, |i| matches!(i, Instruction::Return))
            {
                return Err(self.err_loc(CompileErrorType::NoReturn, span));
            }
            // If execution does not hit a return statement, it will panic here.
            self.append_instruction(Instruction::Exit(ExitReason::Panic));
        }

        self.identifier_types.exit_function();
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
        cmp_type: FactCountType,
        limit: i64,
        fact: thir::FactLiteral,
    ) -> Result<(), CompileError> {
        if limit <= 0 {
            return Err(self.err(CompileErrorType::BadArgument(
                "count limit must be greater than zero".to_string(),
            )));
        }
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

    fn compile_result_pattern_binding(
        &mut self,
        pattern: &thir::ResultPattern,
        scrutinee_type: &VType,
    ) -> Result<(), CompileError> {
        // Make sure the scrutinee is actually a Result, and extract the identifier.
        let ident = match pattern {
            thir::ResultPattern::Ok(ident) => {
                if !matches!(&scrutinee_type.kind, TypeKind::Result { .. }) {
                    return Err(self.err(CompileErrorType::InvalidType(
                        "Ok pattern requires Result type".to_string(),
                    )));
                }
                ident
            }
            thir::ResultPattern::Err(ident) => {
                if !matches!(&scrutinee_type.kind, TypeKind::Result { .. }) {
                    return Err(self.err(CompileErrorType::InvalidType(
                        "Err pattern requires Result type".to_string(),
                    )));
                }
                ident
            }
        };

        // Unwrap the Result value and bind it to the identifier in the pattern, e.g. Ok(value) or Err(err)
        self.append_instruction(Instruction::Unwrap);
        self.append_instruction(Instruction::Meta(Meta::Let(ident.name.clone())));
        self.append_instruction(Instruction::Def(ident.name.clone()));
        // NOTE: We don't call identifier_types.add() here because the pattern variable
        // was already added during the lowering phase. Adding it again during compilation
        // would conflict with any outer variables that were added after lowering the match.

        Ok(())
    }

    /// Exit match arm (exit scope, jump to end)
    fn compile_match_arm_epilogue(&mut self, end_label: &Label) -> Result<(), CompileError> {
        self.identifier_types.exit_block();
        self.append_instruction(Instruction::End);
        self.append_instruction(Instruction::Jump(Target::Unresolved(end_label.clone())));

        Ok(())
    }

    /// Compile a match statement or expression
    /// Returns the type of the `match` is an expression, or `None` if it's a statement.
    fn compile_match_statement_or_expression(
        &mut self,
        m: LanguageContext<thir::MatchStatement, thir::MatchExpression>,
    ) -> Result<(), CompileError> {
        let (scrutinee, patterns, bodies): (_, Vec<_>, LanguageContext<Vec<_>, Vec<_>>) = match m {
            LanguageContext::Statement(s) => {
                let (patterns, bodies) = s
                    .arms
                    .into_iter()
                    .map(|arm| (arm.pattern, arm.statements))
                    .collect();
                (s.expression, patterns, LanguageContext::Statement(bodies))
            }
            LanguageContext::Expression(e) => {
                let (patterns, bodies) = e
                    .arms
                    .into_iter()
                    .map(|arm| (arm.pattern, arm.expression))
                    .collect();
                (e.scrutinee, patterns, LanguageContext::Expression(bodies))
            }
        };

        let expr_pat_t = scrutinee.vtype.clone();
        self.compile_typed_expression(scrutinee)?;

        let end_label = self.anonymous_label();

        // 1. Generate branching instructions, and arm-start labels
        let mut arm_labels: Vec<Label> = vec![];

        for pattern in &patterns {
            let arm_label = self.anonymous_label();
            arm_labels.push(arm_label.clone());

            match pattern {
                thir::MatchPattern::Values(values) => {
                    for value in values {
                        self.append_instruction(Instruction::Dup);
                        self.compile_typed_expression(value.clone())?;

                        // if value == target, jump to start-of-arm
                        self.append_instruction(Instruction::Eq);
                        self.append_instruction(Instruction::Branch(Target::Unresolved(
                            arm_label.clone(),
                        )));
                    }
                }
                thir::MatchPattern::Default(_) => {
                    self.append_instruction(Instruction::Jump(Target::Unresolved(
                        arm_label.clone(),
                    )));
                }
                thir::MatchPattern::ResultPattern(pattern) => match pattern {
                    thir::ResultPattern::Ok(_) => {
                        self.append_instruction(Instruction::Dup);
                        self.append_instruction(Instruction::IsOk);
                        self.append_instruction(Instruction::Branch(Target::Unresolved(
                            arm_label.clone(),
                        )));
                    }
                    thir::ResultPattern::Err(_) => {
                        self.append_instruction(Instruction::Dup);
                        self.append_instruction(Instruction::IsOk);
                        self.append_instruction(Instruction::Not);
                        self.append_instruction(Instruction::Branch(Target::Unresolved(
                            arm_label.clone(),
                        )));
                    }
                },
            }
        }

        // 2. Define arm labels, and compile instructions
        match bodies {
            LanguageContext::Statement(s) => {
                for ((arm_start, pattern), statements) in
                    iter::zip(iter::zip(arm_labels, &patterns), s)
                {
                    self.define_label(arm_start, self.wp)?;

                    // Enter a new scope for this match arm
                    self.identifier_types.enter_block();
                    self.append_instruction(Instruction::Block);

                    match pattern {
                        thir::MatchPattern::ResultPattern(pattern) => {
                            self.compile_result_pattern_binding(pattern, &expr_pat_t)?;
                        }
                        _ => {
                            // Pop the scrutinee value that was duplicated for the branch test (see Dup above)
                            // Result patterns consume the value during unwrapping, but other patterns don't.
                            self.append_instruction(Instruction::Pop);
                        }
                    }

                    self.compile_typed_statements(statements, Scope::Same)?;
                    self.compile_match_arm_epilogue(&end_label)?;
                }
            }
            LanguageContext::Expression(e) => {
                let mut expr_type: Option<VType> = None;
                for (i, ((arm_start, pattern), expression)) in
                    iter::zip(iter::zip(arm_labels, &patterns), e).enumerate()
                {
                    self.define_label(arm_start, self.wp)?;

                    // Enter a new scope for this match arm
                    self.identifier_types.enter_block();
                    self.append_instruction(Instruction::Block);

                    match pattern {
                        thir::MatchPattern::ResultPattern(pattern) => {
                            self.compile_result_pattern_binding(pattern, &expr_pat_t)?;
                        }
                        _ => {
                            // Pop the scrutinee value
                            self.append_instruction(Instruction::Pop);
                        }
                    }

                    let etype = expression.vtype.clone();
                    self.compile_typed_expression(expression)?;
                    match expr_type {
                        None => expr_type = Some(etype),
                        Some(t) => {
                            expr_type = Some(
                                types::unify_pair(t, etype)
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

                    self.compile_match_arm_epilogue(&end_label)?;
                }
            }
        }

        self.define_label(end_label, self.wp)?;

        Ok(())
    }

    fn define_interfaces(&mut self) -> Result<(), CompileError> {
        for struct_def in &self.policy.structs {
            self.define_struct(struct_def.identifier.clone(), &struct_def.items)?;
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

        for action in &self.policy.actions {
            self.define_action(action)?;
        }

        debug_assert!(self.m.progmem.is_empty(), "{:?}", self.m.progmem);

        Ok(())
    }

    /// Compile a policy into instructions inside the given Machine.
    pub fn compile(&mut self) -> Result<(), CompileError> {
        self.define_interfaces()?;

        // Panic when running a module without setup.
        self.append_instruction(Instruction::Exit(ExitReason::Panic));

        // Compile global let statements
        for global_let in &self.policy.global_lets {
            self.compile_global_let(global_let)?;
        }

        self.define_builtins()?;

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
            self.compile_function(function_def)?;
            self.exit_statement_context();
        }

        for function_def in &self.policy.finish_functions {
            self.compile_finish_function(function_def)?;
        }
        self.exit_statement_context();

        // Commands have several sub-contexts, so `compile_command` handles those.
        for command in &self.policy.commands {
            self.compile_command(command)?;
        }

        for action in &self.policy.actions {
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
            ExprKind::EnumReference(e) => {
                let value = self.enum_value(e)?;
                Ok(Value::Enum(e.identifier.name.clone(), value))
            }
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

            let src_struct_type_name = src_type.as_struct().ok_or_else(|| {
                self.err(CompileErrorType::InvalidType(format!(
                    "Expected `{src_var_name}` to be a struct, but it's a(n) {src_type}",
                )))
            })?;
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
                        src_struct_type_name.name.clone(),
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

    /// Define builtin functions which are specially handled when compiling function calls.
    fn define_builtins(&mut self) -> Result<(), CompileError> {
        self.define_builtin(
            sig! {
                function add(x int, y int) option[int]
            },
            |this| {
                this.append_instruction(Instruction::Add);
                Ok(())
            },
        )?;

        self.define_builtin(
            sig! {
                function saturating_add(x int, y int) int
            },
            |this| {
                this.append_instruction(Instruction::SaturatingAdd);
                Ok(())
            },
        )?;

        self.define_builtin(
            sig! {
                function sub(x int, y int) option[int]
            },
            |this| {
                this.append_instruction(Instruction::Sub);
                Ok(())
            },
        )?;

        self.define_builtin(
            sig! {
                function saturating_sub(x int, y int) int
            },
            |this| {
                this.append_instruction(Instruction::SaturatingSub);
                Ok(())
            },
        )?;

        Ok(())
    }

    fn define_builtin(
        &mut self,
        (name, signature): (Identifier, FunctionSignature),
        handler: BuiltinHandler,
    ) -> Result<(), CompileError> {
        let Entry::Vacant(e) = self.function_signatures.entry(name.clone()) else {
            return Err(CompileError::new(CompileErrorType::AlreadyDefined(
                name.to_string(),
            )));
        };
        e.insert(signature);

        let Entry::Vacant(e) = self.builtin_functions.entry(name.clone()) else {
            return Err(CompileError::new(CompileErrorType::AlreadyDefined(
                name.to_string(),
            )));
        };
        e.insert(handler);

        Ok(())
    }
}

/// Flag for controling scope when compiling statement blocks.
#[derive(Copy, Clone, PartialEq)]
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
        let mut cs = self.set_up_compile_state();
        cs.compile()?;
        Ok(cs.m.into_module())
    }

    /// Compile only the public interface of the policy, for use with tools like `aranya-policy-ifgen`.
    pub fn compile_interface(self) -> Result<PolicyInterface, CompileError> {
        let mut cs = self.set_up_compile_state();
        cs.define_interfaces()?;
        Ok(cs.m.into())
    }

    fn set_up_compile_state(&self) -> CompileState<'_> {
        let codemap = CodeMap::new(&self.policy.text);
        let machine = CompileTarget::new(codemap);
        CompileState {
            policy: self.policy,
            m: machine,
            wp: 0,
            c: 0,
            function_signatures: BTreeMap::new(),
            builtin_functions: BTreeMap::new(),
            last_span: Span::empty(),
            statement_context: vec![],
            identifier_types: IdentifierTypeStack::new(),
            ffi_modules: self.ffi_modules,
            is_debug: self.is_debug,
            stub_ffi: self.stub_ffi,
        }
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
