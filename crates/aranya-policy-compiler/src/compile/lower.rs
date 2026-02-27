use aranya_policy_ast::{
    ExprKind, Expression, FactCountType, FactDefinition, FactField, FactLiteral, FunctionCall,
    FunctionDefinition, Ident, InternalFunction, LanguageContext, MatchExpression, MatchPattern,
    MatchStatement, NamedStruct, ResultTypeKind, Span, Spanned as _, Statement, StmtKind, TypeKind,
    VType, ident, thir,
};
use buggy::{Bug, BugExt as _, bug};
use tracing::warn;

use super::{
    CompileError, CompileState, FunctionColor, Scope, StatementContext,
    error::{
        AlreadyDefined, BadArgument, BugError, DuplicateMatchPatterns, InvalidCallColor,
        InvalidCallColorKind, InvalidCast, InvalidExpression, InvalidFactLiteral, InvalidStatement,
        InvalidSubstruct, InvalidType, MissingDefaultPattern, NotDefined, RedundantMatchArm,
        TodoFound, UnknownError, UnreachableMatchArm,
    },
    find_duplicate,
    types::{self, DisplayType},
};

impl CompileState<'_> {
    /// Get the statement context
    fn get_statement_context(&self) -> Result<StatementContext, CompileError> {
        let cs = self
            .statement_context
            .last()
            .ok_or_else(|| {
                self.err(BugError(Bug::new(
                    "compiling statement without statement context",
                )))
            })?
            .clone();
        Ok(cs)
    }

    fn get_fact_def(&self, name: &Ident) -> Result<&FactDefinition, CompileError> {
        self.m.fact_defs.get(&name.inner).ok_or_else(|| {
            let note = format!("fact `{}` not defined", name);
            self.err(NotDefined(note, name.span))
        })
    }

    fn unreachable_match_arm_error(&self, span: Span) -> CompileError {
        self.err(UnreachableMatchArm(span))
    }

    fn redundant_match_arm_error(&self, span: Span) -> CompileError {
        self.err(RedundantMatchArm(span))
    }

    /// Lower a struct literal, ensuring it matches its definition.
    ///
    /// Checks:
    /// - a struct with this name was defined
    /// - the fields defined in the struct are present, and have the correct types
    /// - there are no duplicate fields
    fn lower_struct_literal(&mut self, s: &NamedStruct) -> Result<thir::NamedStruct, CompileError> {
        let Some(struct_def) = self
            .m
            .interface
            .struct_defs
            .get(&s.identifier.inner)
            .cloned()
        else {
            let note = format!("struct `{}` not defined", s.identifier);
            return Err(self.err(NotDefined(note, s.identifier.span)));
        };

        let s = self.evaluate_sources(s, &struct_def)?;

        // Check for duplicate fields in the struct literal
        if let Some((ident1, ident2)) = find_duplicate(&s.fields, |(ident, _)| ident) {
            let err = AlreadyDefined::new(ident1.clone(), ident2.clone());
            return Err(self.err(err));
        }

        let mut fields = Vec::new();
        for (field_name, e) in &s.fields {
            let def_field = &struct_def
                .iter()
                .find(|f| f.identifier.inner == field_name.inner)
                .ok_or_else(|| {
                    let note = format!(
                        "field `{}` not found in `Struct {}`",
                        field_name.inner, s.identifier
                    );
                    self.err(NotDefined(note, field_name.span))
                })?;
            let e = self.lower_expression(e)?;
            if !e.vtype.fits_type(&def_field.field_type) {
                let err = InvalidType::new(
                    def_field.field_type.to_string(),
                    Some(def_field.span()),
                    e.vtype.to_string(),
                    e.span,
                );
                return Err(self.err(err));
            }
            fields.push((field_name.clone(), e));
        }

        Ok(thir::NamedStruct {
            identifier: s.identifier.clone(),
            fields,
            sources: s.sources.clone(),
        })
    }

    /// Lower a fact literal, ensuring it matches its schema.
    ///
    /// Checks:
    /// - a fact with this name was defined
    /// - the keys and values defined in the schema are present, and have the correct types
    /// - there are no duplicate keys or values
    ///
    /// `require_value` should be true for fact literals used in create statements and false otherwise.
    fn lower_fact_literal(
        &mut self,
        fact: &FactLiteral,
        require_value: bool,
    ) -> Result<thir::FactLiteral, CompileError> {
        // Fetch schema
        let fact_def = self.get_fact_def(&fact.identifier)?.clone();

        let key_fields = self.lower_fact_keys(&fact_def, &fact.key_fields)?;

        let value_fields = if let Some(fact_value_fields) = &fact.value_fields {
            Some(self.lower_fact_values(&fact_def, fact_value_fields)?)
        } else if require_value {
            return Err(self.err(InvalidFactLiteral::new(
                "fact literal requires value when used in a create statement",
                fact.span(),
                None::<(&str, _)>,
            )));
        } else {
            None
        };

        Ok(thir::FactLiteral {
            identifier: fact.identifier.clone(),
            key_fields,
            value_fields,
        })
    }

    fn lower_fact_keys(
        &mut self,
        fact_def: &FactDefinition,
        fact_key_fields: &[(Ident, FactField)],
    ) -> Result<Vec<(Ident, thir::Expression)>, CompileError> {
        // Note: Bind values exist at compile time (as FactField::Bind), so we can expect the literal
        // key/value sets to match the schema. E.g. given `fact Foo[i int, j int]` and `query Foo[i:1, j:?]`,
        // we will get two sequences with the same number of items. If not, abort.

        // key sets must have the same length
        if fact_key_fields.len() != fact_def.key.len() {
            // TODO(Steve): Consider replacing this with a new error type (unknown/missing field error)
            // that can be used for struct and fact literals.
            let note = "The number of Fact keys don't match the definition".to_owned();
            return Err(self.err(InvalidFactLiteral::new(
                note,
                fact_key_fields.span(),
                Some((
                    format!(
                        "definition has {} keys but the expression has {} keys",
                        fact_def.key.len(),
                        fact_key_fields.len()
                    ),
                    fact_def.span(),
                )),
            )));
        }
        let mut key_fields = Vec::new();
        let mut bind_found = None;
        for ((lit_key_name, lit_key_field), schema_key) in fact_key_fields.iter().zip(&fact_def.key)
        {
            if schema_key.identifier.inner != lit_key_name.inner {
                // TODO(Steve): Consider replacing this with a new error type (unknown/missing field error)
                // that can be used for struct and fact literals.
                let note = format!(
                    "Invalid key: expected {}, got {}",
                    schema_key.identifier, lit_key_name
                );
                return Err(self.err(InvalidFactLiteral::new(
                    note,
                    lit_key_name.span(),
                    Some(("expected because of this", schema_key.identifier.span)),
                )));
            }

            match lit_key_field {
                FactField::Expression(e) => {
                    if let Some(span) = bind_found {
                        return Err(self.err(InvalidFactLiteral::new(
                            "leading bind values not allowed",
                            span,
                            None::<(&str, _)>,
                        )));
                    }
                    let e = self.lower_expression(e)?;
                    let def_field_type = &schema_key.field_type;
                    if !e.vtype.fits_type(def_field_type) {
                        let err = InvalidType::new(
                            def_field_type.to_string(),
                            Some(def_field_type.span),
                            e.vtype.to_string(),
                            e.span,
                        );
                        return Err(self.err(err));
                    }
                    key_fields.push((lit_key_name.clone(), e));
                }
                FactField::Bind(span) => {
                    // Skip bind values
                    bind_found = Some(*span);
                }
            }
        }
        Ok(key_fields)
    }

    fn lower_fact_values(
        &mut self,
        fact_def: &FactDefinition,
        fact_value_fields: &[(Ident, FactField)],
    ) -> Result<Vec<(Ident, thir::Expression)>, CompileError> {
        // TODO(Steve): Consider replacing this with a new error type (unknown/missing field error)
        // that can be used for struct and fact literals.

        // value block must have the same number of values as the schema
        if fact_value_fields.len() != fact_def.value.len() {
            let note = "The number of Fact values don't match the definition".to_owned();
            return Err(self.err(InvalidFactLiteral::new(
                note,
                fact_value_fields.span(),
                Some((
                    format!(
                        "definition has {} values but the expression has {} values",
                        fact_def.value.len(),
                        fact_value_fields.len()
                    ),
                    fact_def.span(),
                )),
            )));
        }

        let mut value_fields = Vec::new();
        // TODO: Allow any order for values?
        for ((lit_value_name, lit_value_field), schema_value) in
            fact_value_fields.iter().zip(&fact_def.value)
        {
            if lit_value_name.inner != schema_value.identifier.inner {
                let note = format!(
                    "Expected value {}, got {}",
                    schema_value.identifier, lit_value_name.inner
                );
                return Err(self.err(InvalidFactLiteral::new(
                    note,
                    lit_value_name.span,
                    Some(("expected because of this", schema_value.identifier.span)),
                )));
            }
            if let FactField::Expression(e) = &lit_value_field {
                let def_field_type = &schema_value.field_type;
                let e = self.lower_expression(e)?;
                if !e.vtype.fits_type(def_field_type) {
                    let err = InvalidType::new(
                        def_field_type.to_string(),
                        Some(schema_value.identifier.span),
                        e.vtype.to_string(),
                        e.span,
                    );
                    return Err(self.err(err));
                }
                value_fields.push((lit_value_name.clone(), e));
            }
        }
        Ok(value_fields)
    }

    /// Check if finish blocks only use appropriate expressions
    fn check_finish_expression(&mut self, expression: &Expression) -> Result<(), CompileError> {
        match &expression.inner {
            ExprKind::Int(_)
            | ExprKind::String(_)
            | ExprKind::Bool(_)
            | ExprKind::Identifier(_)
            | ExprKind::NamedStruct(_)
            | ExprKind::Dot(_, _)
            | ExprKind::Optional(_)
            | ExprKind::EnumReference(_) => Ok(()),
            _ => {
                let note = "This expression is invalid in finish blocks/functions";
                Err(self.err(InvalidExpression(note, expression.clone(), None)))
            }
        }
    }

    fn lower_expression(
        &mut self,
        expression: &Expression,
    ) -> Result<thir::Expression, CompileError> {
        if matches!(self.get_statement_context()?, StatementContext::Finish(_)) {
            self.check_finish_expression(expression)?;
        }

        Ok(match &expression.inner {
            ExprKind::Int(n) => thir::Expression {
                kind: thir::ExprKind::Int(*n),
                vtype: VType {
                    inner: TypeKind::Int,
                    span: expression.span,
                },
                span: expression.span,
            },
            ExprKind::String(s) => thir::Expression {
                kind: thir::ExprKind::String(s.clone()),
                vtype: VType {
                    inner: TypeKind::String,
                    span: expression.span,
                },
                span: expression.span,
            },
            ExprKind::Bool(b) => thir::Expression {
                kind: thir::ExprKind::Bool(*b),
                vtype: VType {
                    inner: TypeKind::Bool,
                    span: expression.span,
                },
                span: expression.span,
            },
            ExprKind::Optional(o) => {
                let inner_vtype;
                let inner_expr;
                match o {
                    None => {
                        inner_vtype = VType {
                            inner: TypeKind::Never,
                            span: expression.span,
                        };
                        inner_expr = None;
                    }
                    Some(v) => {
                        let inner = self.lower_expression(v)?;
                        inner_vtype = inner.vtype.clone();
                        inner_expr = Some(Box::new(inner));
                    }
                }
                // We allow nested optional types.
                // if matches!(inner_vtype.inner, TypeKind::Optional(_)) {
                //     return Err(self.err(CompileErrorType::InvalidType(
                //         "Cannot wrap option in another option".into(),
                //     )));
                // }
                thir::Expression {
                    kind: thir::ExprKind::Optional(inner_expr),
                    vtype: VType {
                        inner: TypeKind::Optional(Box::new(inner_vtype)),
                        span: expression.span,
                    },
                    span: expression.span,
                }
            }
            ExprKind::NamedStruct(s) => {
                let lit = self.lower_struct_literal(s)?;
                let ty = self.struct_type(s)?;
                thir::Expression {
                    kind: thir::ExprKind::NamedStruct(lit),
                    vtype: ty,
                    span: expression.span,
                }
            }
            ExprKind::InternalFunction(f) => match f {
                InternalFunction::Query(f) => {
                    let fact = self.lower_fact_literal(f, false)?;
                    let vtype = self.query_fact_type(f)?;
                    thir::Expression {
                        kind: thir::ExprKind::InternalFunction(thir::InternalFunction::Query(fact)),
                        vtype: VType {
                            inner: TypeKind::Optional(Box::new(vtype)),
                            span: expression.span,
                        },
                        span: expression.span,
                    }
                }
                InternalFunction::Exists(f) => {
                    let fact = self.lower_fact_literal(f, false)?;
                    thir::Expression {
                        kind: thir::ExprKind::InternalFunction(thir::InternalFunction::Exists(
                            fact,
                        )),
                        vtype: VType {
                            inner: TypeKind::Bool,
                            span: expression.span,
                        },
                        span: expression.span,
                    }
                }
                InternalFunction::FactCount(cmp_type, n, fact) => {
                    let fact = self.lower_fact_literal(fact, false)?;
                    let ty = match cmp_type {
                        FactCountType::UpTo(span) => VType {
                            inner: TypeKind::Int,
                            span: *span,
                        },
                        _ => VType {
                            inner: TypeKind::Bool,
                            span: expression.span,
                        },
                    };
                    thir::Expression {
                        kind: thir::ExprKind::InternalFunction(thir::InternalFunction::FactCount(
                            *cmp_type, *n, fact,
                        )),
                        vtype: ty,
                        span: expression.span,
                    }
                }
                InternalFunction::If(c, t, f) => {
                    let cond = self.lower_expression(c)?;
                    if !cond.vtype.fits_type(&VType {
                        inner: TypeKind::Bool,
                        span: c.span,
                    }) {
                        let err = InvalidType::new(
                            "bool".to_owned(),
                            None,
                            cond.vtype.to_string(),
                            cond.span,
                        );
                        return Err(self.err(err));
                    }
                    let t = self.lower_expression(t)?;
                    let f = self.lower_expression(f)?;

                    // The type of `if` is whatever the subexpressions
                    // are, as long as they are the same type
                    let ty = types::unify_pair(t.vtype.clone(), f.vtype.clone()).map_err(|e| {
                        let err = InvalidType::new(
                            e.left.to_string(),
                            Some(e.left.span()),
                            e.right.to_string(),
                            e.right.span(),
                        );
                        self.err(err)
                    })?;
                    thir::Expression {
                        kind: thir::ExprKind::InternalFunction(thir::InternalFunction::If(
                            Box::new(cond),
                            Box::new(t),
                            Box::new(f),
                        )),
                        vtype: ty,
                        span: expression.span,
                    }
                }
                InternalFunction::Serialize(e) => {
                    match self.get_statement_context()? {
                        StatementContext::PureFunction(FunctionDefinition {
                            identifier, ..
                        }) if identifier == "seal" => {}
                        ctx => {
                            let note =
                                "'serialize' can only be used in the 'seal' block of a command";
                            return Err(self.err(InvalidExpression(
                                note,
                                expression.clone(),
                                Some(ctx.span()),
                            )));
                        }
                    }

                    let struct_type @ VType {
                        inner: TypeKind::Struct(_),
                        ..
                    } = self
                        .identifier_types
                        .get(&ident!("this"))
                        .assume("seal must have `this`")?
                    else {
                        bug!("seal::this must be a struct type");
                    };

                    let e = self.lower_expression(e)?;
                    let ty = &e.vtype;
                    if !ty.fits_type(&struct_type) {
                        let err = InvalidType::new(
                            struct_type.to_string(),
                            Some(struct_type.span),
                            ty.to_string(),
                            e.span,
                        );
                        return Err(self.err(err));
                    }

                    let ty = VType {
                        inner: TypeKind::Bytes,
                        span: expression.span,
                    };
                    thir::Expression {
                        kind: thir::ExprKind::InternalFunction(thir::InternalFunction::Serialize(
                            Box::new(e),
                        )),
                        vtype: ty,
                        span: expression.span,
                    }
                }
                InternalFunction::Deserialize(e) => {
                    // A bit hacky, but you can't manually define a function named "open".
                    let struct_name = match self.get_statement_context()? {
                        StatementContext::PureFunction(FunctionDefinition {
                            identifier,
                            return_type:
                                VType {
                                    inner: TypeKind::Struct(struct_name),
                                    ..
                                },
                            ..
                        }) if identifier == "open" => struct_name,
                        ctx => {
                            let note =
                                "'deserialize' can only be used in the 'open' block of a command";
                            return Err(self.err(InvalidExpression(
                                note,
                                expression.clone(),
                                Some(ctx.span()),
                            )));
                        }
                    };

                    let e = self.lower_expression(e)?;
                    let ty = &e.vtype;
                    if !ty.fits_type(&VType {
                        inner: TypeKind::Bytes,
                        span: e.span,
                    }) {
                        let err =
                            InvalidType::new("bytes".to_owned(), None, ty.to_string(), e.span);
                        return Err(self.err(err));
                    }

                    let ty = VType {
                        inner: TypeKind::Struct(struct_name),
                        span: expression.span,
                    };
                    thir::Expression {
                        kind: thir::ExprKind::InternalFunction(
                            thir::InternalFunction::Deserialize(Box::new(e)),
                        ),
                        vtype: ty,
                        span: expression.span,
                    }
                }
                InternalFunction::Todo(span) => {
                    let err: CompileError = self.err(TodoFound(*span));
                    if !self.is_debug {
                        return Err(err);
                    }
                    warn!("{err}");
                    thir::Expression {
                        kind: thir::ExprKind::InternalFunction(thir::InternalFunction::Todo(*span)),
                        vtype: VType {
                            inner: TypeKind::Never,
                            span: Span::empty(),
                        },
                        span: expression.span,
                    }
                }
            },
            ExprKind::FunctionCall(f) => {
                let signature = self
                    .function_signatures
                    .get(&f.identifier.inner)
                    .ok_or_else(|| {
                        let note = format!("function `{}` not defined", f.identifier);
                        self.err(NotDefined(note, f.identifier.span))
                    })?;
                // Check that this function is the right color - only
                // pure functions are allowed in expressions.
                let FunctionColor::Pure(return_type) = signature.color.clone() else {
                    // Note: `expression.span` is used here instead of `f.span()`
                    // so the parentheses enclosing the params are included.
                    return Err(self.err(InvalidCallColor(
                        InvalidCallColorKind::Finish,
                        expression.span(),
                        None,
                    )));
                };
                // For now all we can do is check that the argument
                // list has the same length.
                // TODO(chip): Do more deep type analysis to check
                // arguments and return types.
                if signature.args.len() != f.arguments.len() {
                    let note = format!(
                        "call to `{}` has {} arguments and it should have {}",
                        f.identifier,
                        f.arguments.len(),
                        signature.args.len()
                    );
                    return Err(self.err(BadArgument(note, f.span())));
                }
                let f = self.lower_function_call(f)?;

                thir::Expression {
                    kind: thir::ExprKind::FunctionCall(f),
                    vtype: return_type,
                    span: expression.span,
                }
            }
            ExprKind::ForeignFunctionCall(f) => {
                // If the policy hasn't imported this module, don't allow using it
                if !self
                    .policy
                    .ffi_imports
                    .iter()
                    .any(|m| m.inner.as_str() == f.module.inner.as_str())
                {
                    let note = format!("module `{}` not imported", f.module);
                    return Err(self.err(NotDefined(note, f.module.span)));
                }

                let mut args = Vec::new();
                let mut ids = None;
                let vtype = if self.stub_ffi {
                    for arg_e in &f.arguments {
                        let arg_e = self.lower_expression(arg_e)?;
                        args.push(arg_e);
                    }
                    VType {
                        inner: TypeKind::Never,
                        span: Span::empty(),
                    }
                } else {
                    // find module by name
                    let (module_id, module) = self
                        .ffi_modules
                        .iter()
                        .enumerate()
                        .find(|(_, m)| m.name == f.module.inner.as_str())
                        .ok_or_else(|| {
                            let note = format!("module `{}` not defined", f.module);
                            self.err(NotDefined(note, f.module.span))
                        })?;

                    // find module function by name
                    let (procedure_id, procedure) = module
                        .functions
                        .iter()
                        .enumerate()
                        .find(|(_, proc)| proc.name == f.identifier.inner.as_str())
                        .ok_or_else(|| {
                            let note =
                                format!("function `{}::{}` not defined", f.module, f.identifier);
                            self.err(NotDefined(note, f.identifier.span))
                        })?;

                    ids = Some((module_id, procedure_id));

                    // verify number of arguments matches the function signature
                    if f.arguments.len() != procedure.args.len() {
                        let note = format!(
                            "call to `{}` has {} arguments but it should have {}",
                            procedure.name.clone(),
                            f.arguments.len(),
                            procedure.args.len()
                        );
                        return Err(self.err(BadArgument(note, f.span())));
                    }

                    // push args
                    for (arg_def, arg_e) in procedure.args.iter().zip(f.arguments.iter()) {
                        let arg_e = self.lower_expression(arg_e)?;
                        let arg_def_vtype = (&arg_def.vtype).into();
                        if !arg_e.vtype.fits_type(&arg_def_vtype) {
                            let err = InvalidType::new(
                                arg_def_vtype.to_string(),
                                None,
                                arg_e.vtype.to_string(),
                                arg_e.span,
                            );
                            return Err(self.err(err));
                        }
                        args.push(arg_e);
                    }

                    VType::from(&procedure.return_type)
                };

                thir::Expression {
                    kind: thir::ExprKind::ForeignFunctionCall(thir::ForeignFunctionCall {
                        module: f.module.clone(),
                        identifier: f.identifier.clone(),
                        ids,
                        arguments: args,
                    }),
                    vtype,
                    span: expression.span,
                }
            }
            ExprKind::Return(ret_expr) => {
                let ctx = self.get_statement_context()?;
                let StatementContext::PureFunction(fd) = ctx else {
                    // TODO(Steve): Add 'InvalidReturn' error.
                    let note = "return expressions can't be used in this context";
                    return Err(self.err(InvalidExpression(note, expression.clone(), None)));
                };
                // ensure return expression type matches function signature
                let et = self.lower_expression(ret_expr)?;
                if !et.vtype.fits_type(&fd.return_type) {
                    let err = InvalidType::new(
                        fd.return_type.to_string(),
                        Some(fd.return_type.span),
                        et.vtype.to_string(),
                        et.span,
                    );
                    return Err(self.err(err));
                }
                thir::Expression {
                    kind: thir::ExprKind::Return(Box::new(et)),
                    vtype: VType {
                        inner: TypeKind::Never,
                        span: expression.span,
                    },
                    span: expression.span,
                }
            }
            ExprKind::Identifier(i) => {
                let ty = self.identifier_types.get(i).map_err(|_| {
                    let note = format!("'{}' not in scope", i);
                    self.err(NotDefined(note, i.span))
                })?;
                thir::Expression {
                    kind: thir::ExprKind::Identifier(i.clone()),
                    vtype: ty,
                    span: expression.span,
                }
            }
            ExprKind::EnumReference(e) => {
                let value = self.enum_value(e)?;
                let ty = VType {
                    inner: TypeKind::Enum(e.identifier.clone()),
                    span: expression.span,
                };
                thir::Expression {
                    kind: thir::ExprKind::EnumReference(thir::EnumReference {
                        identifier: e.identifier.clone(),
                        value,
                    }),
                    vtype: ty,
                    span: expression.span,
                }
            }
            ExprKind::Dot(t, s) => {
                let t = self.lower_expression(t)?;

                let name = t.vtype.as_struct().ok_or_else(|| {
                    self.err(InvalidType::new(
                        "struct T".to_owned(),
                        None,
                        t.vtype.to_string(),
                        t.span,
                    ))
                })?;
                let struct_def = self.m.interface.struct_defs.get(name).ok_or_else(|| {
                    let note = format!("struct `{name}` not defined");
                    self.err(NotDefined(note, name.span))
                })?;
                let field_def = struct_def
                    .iter()
                    .find(|f| f.identifier.inner == s.inner)
                    .ok_or_else(|| {
                        // TODO(Steve): Replace with a new unknown field error type.
                        let note = format!("struct `{}` has no member `{}`", name, s.inner);
                        self.err(NotDefined(note, s.span))
                    })?;
                let ty = field_def.field_type.clone();
                thir::Expression {
                    kind: thir::ExprKind::Dot(Box::new(t), s.clone()),
                    vtype: ty,
                    span: expression.span,
                }
            }
            ExprKind::Substruct(lhs, sub) => {
                let Some(sub_field_defns) = self.m.interface.struct_defs.get(&sub.inner).cloned()
                else {
                    let note = format!("struct `{}` not defined", sub);
                    return Err(self.err(NotDefined(note, sub.span)));
                };

                let lhs_expression = self.lower_expression(lhs)?;
                let lhs_struct_name = lhs_expression.vtype.as_struct().ok_or_else(|| {
                    self.err(InvalidType::new(
                        "struct T".to_owned(),
                        None,
                        lhs_expression.vtype.to_string(),
                        lhs_expression.span,
                    ))
                })?;
                let Some(lhs_field_defns) = self.m.interface.struct_defs.get(&lhs_struct_name.inner)
                else {
                    let note = format!("struct `{lhs_struct_name}` not defined");
                    return Err(self.err(NotDefined(note, lhs_struct_name.span)));
                };

                // Check that the struct type on the RHS is a subset of the struct expression on the LHS
                if !sub_field_defns.iter().all(|field_def| {
                    lhs_field_defns.iter().any(|lhs_field| {
                        lhs_field.identifier.inner == field_def.identifier.inner
                            && lhs_field
                                .field_type.inner
                                .matches(&field_def.field_type.inner)
                    })
                }) {
                    return Err(self.err(InvalidSubstruct {
                        sub: sub.clone(),
                        lhs: (lhs_struct_name.to_string(), lhs_expression.span),
                    }));
                }

                let ty = VType {
                    inner: TypeKind::Struct(sub.clone()),
                    span: expression.span,
                };
                thir::Expression {
                    kind: thir::ExprKind::Substruct(Box::new(lhs_expression), sub.clone()),
                    vtype: ty,
                    span: expression.span,
                }
            }
            ExprKind::Cast(lhs, rhs_ident) => {
                // NOTE this is implemented only for structs

                // make sure other struct is defined
                let rhs_fields = self
                    .m
                    .interface
                    .struct_defs
                    .get(&rhs_ident.inner)
                    .cloned()
                    .ok_or_else(|| {
                        let note = format!("struct `{rhs_ident}` not defined");
                        self.err(NotDefined(note, rhs_ident.span))
                    })?;

                let lhs_expression = self.lower_expression(lhs)?;
                let lhs_struct_name = lhs_expression.vtype.as_struct().ok_or_else(|| {
                    self.err(InvalidType::new(
                        "struct T".to_owned(),
                        None,
                        lhs_expression.vtype.to_string(),
                        lhs_expression.span,
                    ))
                })?;
                let lhs_fields = self
                    .m
                    .interface
                    .struct_defs
                    .get(&lhs_struct_name.inner)
                    .ok_or_else(|| {
                        let note = format!("struct `{lhs_struct_name}` not defined");
                        self.err(NotDefined(note, lhs_struct_name.span))
                    })?;

                // Check that both structs have the same field names and types (though not necessarily in the same order)
                if lhs_fields.len() != rhs_fields.len()
                    || !lhs_fields
                        .iter()
                        .all(|f| rhs_fields.iter().any(|v| f.matches(v)))
                {
                    return Err(self.err(InvalidCast {
                        rhs: rhs_ident.clone(),
                        lhs: (lhs_struct_name.to_string(), lhs_expression.span),
                    }));
                }

                let ty = VType {
                    inner: TypeKind::Struct(rhs_ident.clone()),
                    span: rhs_ident.span(),
                };
                thir::Expression {
                    kind: thir::ExprKind::Cast(Box::new(lhs_expression), rhs_ident.clone()),
                    vtype: ty,
                    span: expression.span,
                }
            }
            kind @ (ExprKind::And(a, b)
            | ExprKind::Or(a, b)
            | ExprKind::Equal(a, b)
            | ExprKind::NotEqual(a, b)
            | ExprKind::GreaterThan(a, b)
            | ExprKind::GreaterThanOrEqual(a, b)
            | ExprKind::LessThan(a, b)
            | ExprKind::LessThanOrEqual(a, b)) => {
                let expected_type = match &kind {
                    ExprKind::Equal(_, _) | ExprKind::NotEqual(_, _) => None,
                    ExprKind::And(_, _) | ExprKind::Or(_, _) => Some(TypeKind::Bool),
                    ExprKind::GreaterThan(_, _)
                    | ExprKind::GreaterThanOrEqual(_, _)
                    | ExprKind::LessThan(_, _)
                    | ExprKind::LessThanOrEqual(_, _) => Some(TypeKind::Int),
                    _ => unreachable!(),
                };
                let constructor = match &kind {
                    ExprKind::Equal(_, _) => thir::ExprKind::Equal,
                    ExprKind::NotEqual(_, _) => thir::ExprKind::NotEqual,
                    ExprKind::And(_, _) => thir::ExprKind::And,
                    ExprKind::Or(_, _) => thir::ExprKind::Or,
                    ExprKind::GreaterThan(_, _) => thir::ExprKind::GreaterThan,
                    ExprKind::GreaterThanOrEqual(_, _) => thir::ExprKind::GreaterThanOrEqual,
                    ExprKind::LessThan(_, _) => thir::ExprKind::LessThan,
                    ExprKind::LessThanOrEqual(_, _) => thir::ExprKind::LessThanOrEqual,
                    _ => unreachable!(),
                };

                let a = self.lower_expression(a)?;
                let b = self.lower_expression(b)?;

                let _operand_type = match expected_type {
                    Some(kind) => types::unify_pair_as(
                        a.vtype.clone(),
                        b.vtype.clone(),
                        VType {
                            inner: kind,
                            span: expression.span,
                        },
                        expression.span,
                    )
                    .map_err(|e| self.err(e))?,
                    None => types::unify_pair(a.vtype.clone(), b.vtype.clone()).map_err(|e| {
                        let err = InvalidType::new(
                            e.left.to_string(),
                            Some(e.left.span()),
                            e.right.to_string(),
                            e.right.span(),
                        );
                        self.err(err)
                    })?,
                };

                thir::Expression {
                    kind: constructor(Box::new(a), Box::new(b)),
                    vtype: VType {
                        inner: TypeKind::Bool,
                        span: expression.span,
                    },
                    span: expression.span,
                }
            }
            ExprKind::Not(e) => {
                // Evaluate the expression
                let e = self.lower_expression(e)?;

                let ty = types::check_type(
                    e.vtype.clone(),
                    VType {
                        inner: TypeKind::Bool,
                        span: expression.span,
                    },
                    "",
                )
                .map_err(|err| {
                    InvalidType::new(err.right.to_string(), None, err.left.to_string(), e.span)
                })
                .map_err(|e| self.err(e))?;

                thir::Expression {
                    kind: thir::ExprKind::Not(Box::new(e)),
                    vtype: ty,
                    span: expression.span,
                }
            }
            ExprKind::Unwrap(e) => self.lower_unwrap(e, thir::ExprKind::Unwrap, expression.span)?,
            ExprKind::CheckUnwrap(e) => {
                self.lower_unwrap(e, thir::ExprKind::CheckUnwrap, expression.span)?
            }
            ExprKind::Is(e, expr_is_some) => {
                // Evaluate the expression
                let e = self.lower_expression(e)?;
                match &e.vtype.inner {
                    TypeKind::Optional(_) => {}
                    _ => {
                        let err = InvalidType::new(
                            "option[T]".to_owned(),
                            None,
                            e.vtype.to_string(),
                            e.span,
                        );
                        return Err(self.err(err));
                    }
                }

                thir::Expression {
                    kind: thir::ExprKind::Is(Box::new(e), *expr_is_some),
                    vtype: VType {
                        inner: TypeKind::Bool,
                        span: expression.span,
                    },
                    span: expression.span,
                }
            }
            ExprKind::Block(statements, e) => {
                self.identifier_types.enter_block();
                let statements = self.lower_statements(statements, Scope::Same)?;
                let subexpr = self.lower_expression(e)?;
                let vtype = subexpr.vtype.clone();
                self.identifier_types.exit_block();

                thir::Expression {
                    kind: thir::ExprKind::Block(statements, Box::new(subexpr)),
                    vtype,
                    span: expression.span,
                }
            }
            ExprKind::Match(e) => match self.lower_match_statement_or_expression(
                LanguageContext::Expression(&**e),
                expression.span(),
            )? {
                LanguageContext::Statement(_) => bug!("expected match expression"),
                LanguageContext::Expression(m) => m,
            },
            ExprKind::Ok(e) => {
                let inner = self.lower_expression(e)?;
                thir::Expression {
                    kind: thir::ExprKind::Ok(Box::new(inner.clone())),
                    vtype: VType {
                        inner: TypeKind::Result(Box::new(ResultTypeKind {
                            ok: inner.vtype,
                            err: VType {
                                inner: TypeKind::Never,
                                span: expression.span,
                            },
                        })),
                        span: expression.span,
                    },
                    span: expression.span,
                }
            }
            ExprKind::Err(e) => {
                let inner = self.lower_expression(e)?;
                thir::Expression {
                    kind: thir::ExprKind::Err(Box::new(inner.clone())),
                    vtype: VType {
                        inner: TypeKind::Result(Box::new(ResultTypeKind {
                            ok: VType {
                                inner: TypeKind::Never,
                                span: expression.span,
                            },
                            err: inner.vtype,
                        })),
                        span: expression.span,
                    },
                    span: expression.span,
                }
            }
        })
    }

    fn lower_function_call(
        &mut self,
        fc: &FunctionCall,
    ) -> Result<thir::FunctionCall, CompileError> {
        let arg_defs = self
            .function_signatures
            .get(&fc.identifier.inner)
            .ok_or_else(|| {
                let note = format!("function `{}` not defined", fc.identifier);
                self.err(NotDefined(note, fc.identifier.span))
            })?
            .args
            .clone();

        let mut arguments = Vec::new();

        for (param, arg_e) in arg_defs.iter().zip(fc.arguments.iter()) {
            let arg_te = self.lower_expression(arg_e)?;
            if !arg_te.vtype.fits_type(&param.ty) {
                let err = InvalidType::new(
                    param.ty.to_string(),
                    Some(param.ty.span),
                    arg_te.vtype.to_string(),
                    arg_e.span,
                );
                return Err(self.err(err));
            }
            arguments.push(arg_te);
        }

        Ok(thir::FunctionCall {
            identifier: fc.identifier.clone(),
            arguments,
        })
    }

    /// Lowers a (check) unwrap expression.
    ///
    /// The `constructor` param is used to wrap the inner expression in either
    /// [`thir::ExprKind::Unwrap`] or [`thir::ExprKind::CheckUnwrap`].
    fn lower_unwrap(
        &mut self,
        e: &Expression,
        constructor: impl FnOnce(Box<thir::Expression>) -> thir::ExprKind,
        span: Span,
    ) -> Result<thir::Expression, CompileError> {
        let e = self.lower_expression(e)?;
        let vtype = match &e.vtype {
            VType {
                inner: TypeKind::Optional(t),
                ..
            } => (**t).clone(),
            _ => {
                let err =
                    InvalidType::new("option[T]".to_owned(), None, e.vtype.to_string(), e.span);
                return Err(self.err(err));
            }
        };
        Ok(thir::Expression {
            kind: constructor(Box::new(e)),
            vtype,
            span,
        })
    }

    fn lower_match_statement_or_expression(
        &mut self,
        s: LanguageContext<&MatchStatement, &MatchExpression>,
        span: Span,
    ) -> Result<LanguageContext<thir::Statement, thir::Expression>, CompileError> {
        let patterns: Vec<MatchPattern> = match s {
            LanguageContext::Statement(s) => s.arms.iter().map(|a| a.pattern.clone()).collect(),
            LanguageContext::Expression(e) => e.arms.iter().map(|a| a.pattern.clone()).collect(),
        };

        // Check for duplicate/unreachable arms.
        // NOTE We don't check for zero arms, because that's enforced by the parser.
        //
        // Across separate arms: literals before bindings is fine (e.g. `Ok(5) => ..`
        // then `Ok(n) => ..`), but a literal following a binding is unreachable.
        //
        // Within a single arm (alternation): mixing literals and bindings for the
        // same result variant is not allowed — the binding subsumes the literal, so
        // e.g. `Ok(5) | Ok(n)` should just be `Ok(n)`.

        let mut all_values: Vec<(ExprKind, Span)> = Vec::new();
        let mut seen_ok_binding = false;
        let mut seen_err_binding = false;
        for pattern in &patterns {
            let MatchPattern::Values(values) = pattern else {
                continue;
            };
            let mut seen_ok_literal = false;
            let mut seen_err_literal = false;
            for v in values {
                let value = &v.inner;
                let v_span = v.span();

                // Check for duplicate values across all prior values.
                if all_values
                    .iter()
                    .any(|(v2, _): &(ExprKind, Span)| value.matches(v2))
                {
                    return Err(self.err(DuplicateMatchPatterns {
                        patt1: v_span,
                        patt2: all_values
                            .iter()
                            .find(|(v2, _)| value.matches(v2))
                            .expect("matched")
                            .1,
                    }));
                }

                // Check for unreachable arms (binding before literal across arms)
                // and subsumed patterns (literal mixed with binding in same arm).
                match value {
                    ExprKind::Ok(inner) if matches!(inner.inner, ExprKind::Identifier(_)) => {
                        if seen_ok_literal {
                            return Err(self.redundant_match_arm_error(v_span));
                        }
                        seen_ok_binding = true;
                    }
                    ExprKind::Ok(_) if seen_ok_binding => {
                        return Err(self.unreachable_match_arm_error(v_span));
                    }
                    ExprKind::Ok(_) => {
                        seen_ok_literal = true;
                    }
                    ExprKind::Err(inner) if matches!(inner.inner, ExprKind::Identifier(_)) => {
                        if seen_err_literal {
                            return Err(self.redundant_match_arm_error(v_span));
                        }
                        seen_err_binding = true;
                    }
                    ExprKind::Err(_) if seen_err_binding => {
                        return Err(self.unreachable_match_arm_error(v_span));
                    }
                    ExprKind::Err(_) => {
                        seen_err_literal = true;
                    }
                    _ => {}
                }

                all_values.push((value.clone(), v_span));
            }
        }

        // find duplicate default arms
        let default_patts: Vec<_> = patterns
            .iter()
            .filter(|p| matches!(p, MatchPattern::Default(_)))
            .collect();
        let default_count = default_patts.len();
        if default_count > 1 {
            let [pattern_1, pattern_2, ..] = default_patts[..] else {
                unreachable!("There's at least 2 items")
            };
            let err = DuplicateMatchPatterns {
                patt1: pattern_1.span(),
                patt2: pattern_2.span(),
            };
            return Err(self.err(err));
        }

        let scrutinee = match s {
            LanguageContext::Statement(s) => &s.expression,
            LanguageContext::Expression(e) => &e.scrutinee,
        };
        let scrutinee = self.lower_expression(scrutinee)?;
        let mut scrutinee_type = scrutinee.vtype.clone();

        // Lower match patterns. Verify that their types are consistent with the scrutinee type.
        let mut n: usize = 0;
        let mut patterns_out = Vec::new();
        for pattern in &patterns {
            let pattern = match pattern {
                MatchPattern::Values(values) => {
                    let mut values_out = Vec::new();
                    for value in values {
                        n = n.checked_add(1).assume("can't have usize::MAX patterns")?;
                        if value.is_literal() {
                            // Literal pattern (including Result patterns with literal inner values)
                            let arm_t = self.lower_expression(value)?;
                            scrutinee_type = types::unify_pair(scrutinee_type, arm_t.vtype.clone())
                                .map_err(|err| {
                                    InvalidType::new(
                                        err.left.to_string(),
                                        None,
                                        err.right.to_string(),
                                        value.span,
                                    )
                                })
                                .map_err(|err| self.err(err))?;
                            values_out.push(arm_t);
                        } else {
                            match &value.inner {
                                ExprKind::Ok(inner) | ExprKind::Err(inner) => {
                                    // Binding pattern: Ok(x) or Err(e) where x/e are identifiers
                                    let is_ok = matches!(&value.inner, ExprKind::Ok(_));
                                    let TypeKind::Result(result_type) = &scrutinee_type.inner else {
                                        return Err(self.err(InvalidType::new(
                                            "result[T, E]".to_owned(),
                                            None,
                                            scrutinee_type.to_string(),
                                            value.span(),
                                        )));
                                    };
                                    let inner_type = if is_ok {
                                        result_type.ok.clone()
                                    } else {
                                        result_type.err.clone()
                                    };
                                    let ExprKind::Identifier(ident) = &inner.inner else {
                                        return Err(self.err(InvalidType::new(
                                            "identifier".to_owned(),
                                            None,
                                            "non-identifier expression".to_owned(),
                                            inner.span(),
                                        )));
                                    };
                                    let inner = thir::Expression {
                                        kind: thir::ExprKind::Identifier(ident.clone()),
                                        vtype: inner_type,
                                        span: inner.span(),
                                    };
                                    let outer = thir::Expression {
                                        kind: if is_ok {
                                            thir::ExprKind::Ok(Box::new(inner))
                                        } else {
                                            thir::ExprKind::Err(Box::new(inner))
                                        },
                                        vtype: scrutinee_type.clone(),
                                        span: value.span(),
                                    };
                                    values_out.push(outer);
                                }
                                _ => {
                                    // Anything else is not a valid pattern. For example, an
                                    // identifier without Ok/Err, function call, property access,
                                    // or other non-literal expression.
                                    return Err(self.err(InvalidExpression(
                                        "match pattern must be a literal expression",
                                        value.clone(),
                                        None,
                                    )));
                                }
                            }
                        }
                    }
                    thir::MatchPattern::Values(values_out)
                }
                MatchPattern::Default(span) => {
                    // Ensure this is the last case, and also that it's not the only case.
                    if !core::ptr::eq(pattern, patterns.last().expect("patterns is not empty")) {
                        return Err(self.err(UnknownError(
                            String::from("Default match case must be last."),
                            Some(*span),
                        )));
                    }
                    thir::MatchPattern::Default(*span)
                }
            };
            patterns_out.push(pattern);
        }

        // Result-pattern exhaustiveness is tracked per variant:
        // - Ok(x)/Err(e) binding patterns cover all values for that variant
        // - literal patterns cover only specific values, so we compare against
        //   variant cardinality when finite.
        let result_exhaustive = if let TypeKind::Result(result_type) = &scrutinee_type.inner {
            let mut has_ok_binding = false;
            let mut has_err_binding = false;
            // Can't use sets because ExprKind doesn't impl Hash/Eq
            let mut ok_literals: Vec<ExprKind> = Vec::new();
            let mut err_literals: Vec<ExprKind> = Vec::new();

            for (v, _) in &all_values {
                match v {
                    ExprKind::Ok(inner) if matches!(inner.inner, ExprKind::Identifier(_)) => {
                        has_ok_binding = true;
                    }
                    ExprKind::Err(inner) if matches!(inner.inner, ExprKind::Identifier(_)) => {
                        has_err_binding = true;
                    }
                    ExprKind::Ok(inner) => ok_literals.push(inner.inner.clone()),
                    ExprKind::Err(inner) => err_literals.push(inner.inner.clone()),
                    _ => {}
                }
            }

            let ok_exhaustive = has_ok_binding
                || self
                    .m
                    .cardinality(&result_type.ok.inner)
                    .is_some_and(|c| c == ok_literals.len() as u64);
            let err_exhaustive = has_err_binding
                || self
                    .m
                    .cardinality(&result_type.err.inner)
                    .is_some_and(|c| c == err_literals.len() as u64);

            ok_exhaustive && err_exhaustive
        } else {
            false
        };

        let missing_default = default_count == 0
            && !result_exhaustive
            && self
                .m
                .cardinality(&scrutinee_type.inner)
                .is_none_or(|c| c > all_values.len() as u64);

        if missing_default {
            return Err(self.err(MissingDefaultPattern(span)));
        }

        // Match expression/statement type. For statements, it's None; for expressions, it's Some(Typeish)
        let mut expr_type: Option<VType> = None;

        let mut patterns = patterns_out.into_iter();
        Ok(match s {
            LanguageContext::Statement(s) => {
                let mut arms = Vec::new();
                for arm in &s.arms {
                    let pattern = patterns.next().assume("expected pattern for match arm")?;

                    // Enter a scope for each match arm (for variable isolation)
                    self.identifier_types.enter_block();

                    // For Result patterns (Ok(x)/Err(e) in Values), add the binding to scope
                    if let thir::MatchPattern::Values(values) = &pattern {
                        for value in values {
                            match &value.kind {
                                thir::ExprKind::Ok(inner) | thir::ExprKind::Err(inner) => {
                                    if let thir::ExprKind::Identifier(ident) = &inner.kind {
                                        self.identifier_types
                                            .add(ident.clone(), inner.vtype.clone())
                                            .map_err(|e| self.err(e))?;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    let stmts = self.lower_statements(&arm.statements, Scope::Same)?;

                    // Exit the scope for this arm
                    self.identifier_types.exit_block();

                    arms.push(thir::MatchArm {
                        pattern,
                        statements: stmts,
                    });
                }
                if patterns.next().is_some() {
                    bug!("too many patterns");
                }
                LanguageContext::Statement(thir::Statement {
                    kind: thir::StmtKind::Match(thir::MatchStatement {
                        expression: scrutinee,
                        arms,
                    }),
                    span,
                })
            }
            LanguageContext::Expression(e) => {
                let mut arms = Vec::new();
                for arm in &e.arms {
                    let pattern = patterns.next().assume("expected pattern for match arm")?;

                    // Enter a scope for each match arm (for variable isolation)
                    self.identifier_types.enter_block();

                    // For Result patterns (Ok(x)/Err(e) in Values), add the binding to scope
                    if let thir::MatchPattern::Values(values) = &pattern {
                        for value in values {
                            match &value.kind {
                                thir::ExprKind::Ok(inner) | thir::ExprKind::Err(inner) => {
                                    if let thir::ExprKind::Identifier(ident) = &inner.kind {
                                        self.identifier_types
                                            .add(ident.clone(), inner.vtype.clone())
                                            .map_err(|e| self.err(e))?;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    let e = self.lower_expression(&arm.expression)?;
                    let etype = e.vtype.clone();

                    // Exit the scope for this arm
                    self.identifier_types.exit_block();

                    match expr_type {
                        None => expr_type = Some(etype),
                        Some(t) => {
                            expr_type = Some(
                                types::unify_pair(t, etype)
                                    .map_err(|err| {
                                        InvalidType::new(
                                            err.left.to_string(),
                                            Some(err.left.span),
                                            err.right.to_string(),
                                            e.span,
                                        )
                                    })
                                    .map_err(|err| self.err(err))?,
                            );
                        }
                    }
                    arms.push(thir::MatchExpressionArm {
                        pattern,
                        expression: e,
                        span: arm.span,
                    });
                }
                if patterns.next().is_some() {
                    bug!("too many patterns");
                }
                LanguageContext::Expression(thir::Expression {
                    kind: thir::ExprKind::Match(Box::new(thir::MatchExpression {
                        scrutinee,
                        arms,
                    })),
                    vtype: expr_type.assume("expression must have type")?,
                    span,
                })
            }
        })
    }

    pub fn lower_statements(
        &mut self,
        statements: &[Statement],
        scope: Scope,
    ) -> Result<Vec<thir::Statement>, CompileError> {
        let mut output = Vec::new();
        if scope == Scope::Layered {
            self.identifier_types.enter_block();
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
            let kind = match (&statement.inner, &context) {
                (
                    StmtKind::Let(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    let et = self.lower_expression(&s.expression)?;
                    self.identifier_types
                        .add(s.identifier.clone(), et.vtype.clone())
                        .map_err(|e| self.err(e))?;
                    // NOTE: We allow assigning Never, which is useful for stubbing out code during development.
                    thir::StmtKind::Let(thir::LetStatement {
                        identifier: s.identifier.clone(),
                        expression: et,
                    })
                }
                (
                    StmtKind::Check(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    let et = self.lower_expression(&s.expression)?;
                    if !et.vtype.fits_type(&VType {
                        inner: TypeKind::Bool,
                        span: s.expression.span,
                    }) {
                        let err = InvalidType::new(
                            "bool".to_owned(),
                            None,
                            et.vtype.to_string(),
                            et.span,
                        );
                        return Err(self.err(err));
                    }
                    thir::StmtKind::Check(thir::CheckStatement { expression: et })
                }
                (
                    StmtKind::Match(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => match self.lower_match_statement_or_expression(
                    LanguageContext::Statement(s),
                    statement.span,
                )? {
                    LanguageContext::Statement(s) => s.kind,
                    LanguageContext::Expression(_) => bug!("expected statement"),
                },
                (
                    StmtKind::If(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    let mut branches = Vec::new();
                    for (cond, branch) in &s.branches {
                        let cond = self.lower_expression(cond)?;
                        if !cond.vtype.fits_type(&VType {
                            inner: TypeKind::Bool,
                            span: cond.span,
                        }) {
                            let err = InvalidType::new(
                                "bool".to_owned(),
                                None,
                                cond.vtype.to_string(),
                                cond.span,
                            );
                            return Err(self.err(err));
                        }
                        let stmts = self.lower_statements(branch, Scope::Layered)?;
                        branches.push((cond, stmts));
                    }
                    let fallback = s
                        .fallback
                        .as_ref()
                        .map(|fallback| self.lower_statements(fallback, Scope::Layered))
                        .transpose()?;
                    thir::StmtKind::If(thir::IfStatement { branches, fallback })
                }
                (StmtKind::Publish(e), StatementContext::Action(action)) => {
                    let e = self.lower_expression(e)?;
                    let ident = e.vtype.as_struct().ok_or_else(|| {
                        self.err(InvalidType::new(
                            "struct T".to_owned(),
                            None,
                            e.vtype.to_string(),
                            e.span,
                        ))
                    })?;
                    if !self.m.command_defs.contains(ident.as_str()) {
                        let err = InvalidType::new(
                            "Command Struct T".to_owned(),
                            None,
                            "Struct T".to_owned(),
                            e.span,
                        );
                        return Err(self.err(err));
                    }

                    //  Persistent actions can publish only persistent commands, and vice versa.
                    let command_persistence = &self
                        .policy
                        .commands
                        .iter()
                        .find(|c| c.identifier.inner == ident.inner)
                        .assume("command must be defined")?
                        .persistence;
                    if !action.persistence.matches(command_persistence) {
                        let err = InvalidType::new(
                            format!("{} command", action.persistence),
                            None,
                            format!("{} command", command_persistence),
                            e.span,
                        );
                        return Err(self.err(err));
                    }
                    thir::StmtKind::Publish(e)
                }
                (StmtKind::Return(s), StatementContext::PureFunction(fd)) => {
                    // ensure return expression type matches function signature
                    let e = self.lower_expression(&s.expression)?;
                    if !e.vtype.fits_type(&fd.return_type) {
                        let err = InvalidType::new(
                            fd.return_type.to_string(),
                            Some(fd.return_type.span),
                            e.vtype.to_string(),
                            e.span,
                        );
                        return Err(self.err(err));
                    }
                    thir::StmtKind::Return(thir::ReturnStatement { expression: e })
                }
                (
                    StmtKind::Finish(s),
                    StatementContext::CommandPolicy(_) | StatementContext::CommandRecall(_),
                ) => {
                    self.enter_statement_context(StatementContext::Finish(statement.span));
                    let s = self.lower_statements(s, Scope::Layered)?;
                    self.exit_statement_context();

                    // Ensure `finish` is the last statement in the block. This also guarantees we can't have more than one finish block.
                    if !core::ptr::eq(
                        statement,
                        statements.last().expect("statements is not empty"),
                    ) {
                        return Err(self.err(UnknownError(
                            "`finish` must be the last statement in the block".to_owned(),
                            Some(statement.span),
                        )));
                    }

                    thir::StmtKind::Finish(s)
                }
                (StmtKind::Map(map_stmt), StatementContext::Action(_action)) => {
                    let fact = self.lower_fact_literal(&map_stmt.fact, false)?;
                    // Define Struct variable for the `as` clause
                    self.identifier_types.enter_block();
                    self.identifier_types
                        .add(
                            map_stmt.identifier.clone(),
                            VType {
                                inner: TypeKind::Struct(map_stmt.fact.identifier.clone()),
                                span: map_stmt.fact.identifier.span,
                            },
                        )
                        .map_err(|e| self.err(e))?;
                    // body
                    let s = self.lower_statements(&map_stmt.statements, Scope::Same)?;
                    self.identifier_types.exit_block();
                    thir::StmtKind::Map(thir::MapStatement {
                        fact,
                        identifier: map_stmt.identifier.clone(),
                        statements: s,
                    })
                }
                (StmtKind::Create(s), StatementContext::Finish(_)) => {
                    // Do not allow bind values during fact creation
                    if let Some(span) = find_bind(&s.fact.key_fields)
                        .or_else(|| s.fact.value_fields.as_ref().and_then(|f| find_bind(f)))
                    {
                        let note = "Cannot create fact with bind values".to_owned();
                        return Err(self.err(BadArgument(note, span)));
                    }

                    let fact = self.lower_fact_literal(&s.fact, true)?;
                    thir::StmtKind::Create(thir::CreateStatement { fact })
                }
                (StmtKind::Update(s), StatementContext::Finish(_)) => {
                    // ensure fact is mutable
                    let fact_def = self.get_fact_def(&s.fact.identifier)?;
                    if fact_def.immutable {
                        // TODO(Steve): This should probably be a new error type
                        let note = format!(
                            "fact `{}` is immutable so it cannot be updated.",
                            fact_def.identifier
                        );
                        return Err(self.err(UnknownError(note, Some(s.span()))));
                    }

                    if let Some(span) = find_bind(&s.fact.key_fields) {
                        let note = "Cannot update fact with wildcard keys".to_owned();
                        return Err(self.err(BadArgument(note, span)));
                    }

                    let fact = self.lower_fact_literal(&s.fact, false)?;

                    // Verify the 'to' fact literal
                    if let Some(span) = find_bind(&s.to) {
                        // Cannot bind in the set statement
                        let note = "Cannot update fact to a bind value".to_owned();
                        return Err(self.err(BadArgument(note, span)));
                    }
                    let fact_def = self.get_fact_def(&s.fact.identifier)?.clone();
                    let to = self.lower_fact_values(&fact_def, &s.to)?;

                    thir::StmtKind::Update(thir::UpdateStatement { fact, to })
                }
                (StmtKind::Delete(s), StatementContext::Finish(_)) => {
                    if let Some(span) = find_bind(&s.fact.key_fields) {
                        let note = "Cannot delete fact with wildcard keys".to_owned();
                        return Err(self.err(BadArgument(note, span)));
                    }

                    let fact = self.lower_fact_literal(&s.fact, false)?;

                    thir::StmtKind::Delete(thir::DeleteStatement { fact })
                }
                (StmtKind::Emit(e), StatementContext::Finish(_)) => {
                    let e = self.lower_expression(e)?;
                    let struct_name = e.vtype.as_struct().ok_or_else(|| {
                        self.err(InvalidType::new(
                            "struct T".to_owned(),
                            None,
                            e.vtype.to_string(),
                            e.span,
                        ))
                    })?;
                    if !self.m.interface.effects.contains(struct_name) {
                        let err = InvalidType::new(
                            "effect struct T".to_owned(),
                            None,
                            "struct T".to_owned(),
                            e.span,
                        );
                        return Err(self.err(err));
                    }
                    thir::StmtKind::Emit(e)
                }
                (StmtKind::FunctionCall(f), StatementContext::Finish(finish_ctx_span)) => {
                    let signature = self
                        .function_signatures
                        .get(&f.identifier.inner)
                        .ok_or_else(|| {
                            let note = format!("function `{}` not defined", f.identifier);
                            self.err(NotDefined(note, f.identifier.span))
                        })?;
                    // Check that this function is the right color -
                    // only finish functions are allowed in finish
                    // blocks.
                    if let FunctionColor::Pure(_) = signature.color {
                        // Note: `statement.span` is used here instead of `f.span()`
                        // so the parentheses enclosing the params are included.
                        return Err(self.err(InvalidCallColor(
                            InvalidCallColorKind::Pure,
                            statement.span,
                            Some(*finish_ctx_span),
                        )));
                    }
                    // For now all we can do is check that the argument
                    // list has the same length.
                    // TODO(chip): Do more deep type analysis to check
                    // arguments and return types.
                    if signature.args.len() != f.arguments.len() {
                        let note = format!(
                            "call to `{}` has {} arguments but it should have {}",
                            f.identifier,
                            f.arguments.len(),
                            signature.args.len()
                        );
                        return Err(self.err(BadArgument(note, statement.span)));
                    }
                    let f = self.lower_function_call(f)?;
                    thir::StmtKind::FunctionCall(f)
                }
                (StmtKind::ActionCall(fc), StatementContext::Action(_)) => {
                    let Some(action_def) = self
                        .policy
                        .actions
                        .iter()
                        .find(|a| a.identifier == fc.identifier.inner)
                    else {
                        let note = format!("action `{}` not defined", fc.identifier);
                        return Err(self.err(NotDefined(note, fc.identifier.span)));
                    };

                    if action_def.arguments.len() != fc.arguments.len() {
                        let note = format!(
                            "call to `{}` has {} arguments, but it should have {}",
                            fc.identifier.inner,
                            fc.arguments.len(),
                            action_def.arguments.len()
                        );
                        return Err(self.err(BadArgument(note, statement.span)));
                    }

                    let mut args = Vec::new();
                    for (i, arg) in fc.arguments.iter().enumerate() {
                        let arg = self.lower_expression(arg)?;
                        let expected_arg = &action_def.arguments[i];
                        if !arg.vtype.fits_type(&expected_arg.ty) {
                            // TODO(Steve): Replace with an 'InvalidType' error to make it consistent with calls to pure functions
                            let note = format!(
                                "invalid argument type for `{}`: expected `{}`, but got `{}`",
                                expected_arg.name,
                                DisplayType(&expected_arg.ty),
                                arg.vtype,
                            );
                            return Err(self.err(BadArgument(note, statement.span)));
                        }
                        args.push(arg);
                    }

                    thir::StmtKind::ActionCall(thir::FunctionCall {
                        identifier: fc.identifier.clone(),
                        arguments: args,
                    })
                }
                (StmtKind::DebugAssert(e), _) => {
                    let e = self.lower_expression(e)?;
                    let _: VType = types::check_type(
                        e.vtype.clone(),
                        VType {
                            inner: TypeKind::Bool,
                            span: e.span,
                        },
                        "",
                    )
                    .map_err(|err| {
                        InvalidType::new(err.right.to_string(), None, err.left.to_string(), e.span)
                    })
                    .map_err(|e| self.err(e))?;
                    thir::StmtKind::DebugAssert(e)
                }
                (_, _) => {
                    return Err(self.err(InvalidStatement(context, statement.span)));
                }
            };
            output.push(thir::Statement {
                kind,
                span: statement.span,
            });
        }
        if scope == Scope::Layered {
            self.identifier_types.exit_block();
        }
        Ok(output)
    }
}

fn find_bind(fields: &[(Ident, FactField)]) -> Option<Span> {
    fields.iter().find_map(|(_, field)| match field {
        FactField::Bind(span) => Some(*span),
        FactField::Expression(_) => None,
    })
}
