use aranya_policy_ast::{
    ExprKind, Expression, FactCountType, FactDefinition, FactField, FactLiteral, FunctionCall,
    FunctionDefinition, Ident, Identifier, InternalFunction, LanguageContext, MatchExpression,
    MatchPattern, MatchStatement, NamedStruct, ResultPattern, Span, Spanned as _, Statement,
    StmtKind, TypeKind, VType, ident, thir,
};
use buggy::{Bug, BugExt as _, bug};
use tracing::warn;

use super::{
    CompileError, CompileErrorType, CompileState, FunctionColor, InvalidCallColor, Scope,
    StatementContext, find_duplicate,
    types::{self, DisplayType},
};

impl CompileState<'_> {
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

    fn get_fact_def(&self, name: &Identifier) -> Result<&FactDefinition, CompileError> {
        self.m
            .fact_defs
            .get(name)
            .ok_or_else(|| self.err(CompileErrorType::NotDefined(name.to_string())))
    }

    /// Lower a struct literal, ensuring it matches its definition.
    ///
    /// Checks:
    /// - a struct with this name was defined
    /// - the fields defined in the struct are present, and have the correct types
    /// - there are no duplicate fields
    fn lower_struct_literal(&mut self, s: &NamedStruct) -> Result<thir::NamedStruct, CompileError> {
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

        let mut fields = Vec::new();
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
            let e = self.lower_expression(e)?;
            if !e.vtype.fits_type(def_field_type) {
                return Err(self.err(CompileErrorType::InvalidType(format!(
                    "`Struct {}` field `{}` is not {}",
                    s.identifier,
                    field_name.name,
                    DisplayType(def_field_type)
                ))));
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
            return Err(self.err(CompileErrorType::InvalidFactLiteral(
                "fact literal requires value".to_string(),
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
        let name = &fact_def.identifier;

        // Note: Bind values exist at compile time (as FactField::Bind), so we can expect the literal
        // key/value sets to match the schema. E.g. given `fact Foo[i int, j int]` and `query Foo[i:1, j:?]`,
        // we will get two sequences with the same number of items. If not, abort.

        // key sets must have the same length
        if fact_key_fields.len() != fact_def.key.len() {
            return Err(self.err(CompileErrorType::InvalidFactLiteral(String::from(
                "Fact keys don't match definition",
            ))));
        }
        let mut key_fields = Vec::new();
        let mut bind_found = false;
        for ((lit_key_name, lit_key_field), schema_key) in fact_key_fields.iter().zip(&fact_def.key)
        {
            if schema_key.identifier.name != lit_key_name.name {
                return Err(self.err(CompileErrorType::InvalidFactLiteral(format!(
                    "Invalid key: expected {}, got {}",
                    schema_key.identifier, lit_key_name
                ))));
            }

            match lit_key_field {
                FactField::Expression(e) => {
                    if bind_found {
                        return Err(self.err(CompileErrorType::InvalidFactLiteral(
                            "leading bind values not allowed".to_string(),
                        )));
                    }
                    let e = self.lower_expression(e)?;
                    let def_field_type = &schema_key.field_type;
                    if !e.vtype.fits_type(def_field_type) {
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "Fact `{name}` value field `{lit_key_name}` found `{}`, not `{}`",
                            e.vtype,
                            DisplayType(def_field_type)
                        ))));
                    }
                    key_fields.push((lit_key_name.clone(), e));
                }
                FactField::Bind(_) => {
                    // Skip bind values
                    bind_found = true;
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
        let name = &fact_def.identifier;

        // value block must have the same number of values as the schema
        if fact_value_fields.len() != fact_def.value.len() {
            return Err(self.err(CompileErrorType::InvalidFactLiteral(String::from(
                "incorrect number of values",
            ))));
        }

        let mut value_fields = Vec::new();
        // TODO: Allow any order for values?
        for ((lit_value_name, lit_value_field), schema_value) in
            fact_value_fields.iter().zip(&fact_def.value)
        {
            if lit_value_name.name != schema_value.identifier.name {
                return Err(self.err(CompileErrorType::InvalidFactLiteral(format!(
                    "Expected value {}, got {}",
                    schema_value.identifier, lit_value_name.name
                ))));
            }
            if let FactField::Expression(e) = &lit_value_field {
                let def_field_type = &schema_value.field_type;
                let e = self.lower_expression(e)?;
                if !e.vtype.fits_type(def_field_type) {
                    return Err(self.err(CompileErrorType::InvalidType(format!(
                        "Fact `{name}` value field `{lit_value_name}` found `{}`, not `{}`",
                        e.vtype,
                        DisplayType(def_field_type)
                    ))));
                }
                value_fields.push((lit_value_name.clone(), e));
            }
        }
        Ok(value_fields)
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

    fn lower_expression(
        &mut self,
        expression: &Expression,
    ) -> Result<thir::Expression, CompileError> {
        if self.get_statement_context()? == StatementContext::Finish {
            self.check_finish_expression(expression)?;
        }

        Ok(match &expression.kind {
            ExprKind::Int(n) => thir::Expression {
                kind: thir::ExprKind::Int(*n),
                vtype: VType {
                    kind: TypeKind::Int,
                    span: expression.span,
                },
                span: expression.span,
            },
            ExprKind::String(s) => thir::Expression {
                kind: thir::ExprKind::String(s.clone()),
                vtype: VType {
                    kind: TypeKind::String,
                    span: expression.span,
                },
                span: expression.span,
            },
            ExprKind::Bool(b) => thir::Expression {
                kind: thir::ExprKind::Bool(*b),
                vtype: VType {
                    kind: TypeKind::Bool,
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
                            kind: TypeKind::Never,
                            span: Span::empty(),
                        };
                        inner_expr = None;
                    }
                    Some(v) => {
                        let inner = self.lower_expression(v)?;
                        inner_vtype = inner.vtype.clone();
                        inner_expr = Some(Box::new(inner));
                    }
                }
                if matches!(inner_vtype.kind, TypeKind::Optional(_)) {
                    return Err(self.err(CompileErrorType::InvalidType(
                        "Cannot wrap option in another option".into(),
                    )));
                }
                thir::Expression {
                    kind: thir::ExprKind::Optional(inner_expr),
                    vtype: VType {
                        kind: TypeKind::Optional(Box::new(inner_vtype)),
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
                            kind: TypeKind::Optional(Box::new(vtype)),
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
                            kind: TypeKind::Bool,
                            span: expression.span,
                        },
                        span: expression.span,
                    }
                }
                InternalFunction::FactCount(cmp_type, n, fact) => {
                    let fact = self.lower_fact_literal(fact, false)?;
                    let ty = match cmp_type {
                        FactCountType::UpTo(span) => VType {
                            kind: TypeKind::Int,
                            span: *span,
                        },
                        _ => VType {
                            kind: TypeKind::Bool,
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
                        kind: TypeKind::Bool,
                        span: c.span,
                    }) {
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "if condition must be a boolean expression, was type {}",
                            cond.vtype,
                        ))));
                    }
                    let t = self.lower_expression(t)?;
                    let f = self.lower_expression(f)?;

                    // The type of `if` is whatever the subexpressions
                    // are, as long as they are the same type
                    let ty = types::unify_pair(t.vtype.clone(), f.vtype.clone())
                        .map_err(|e| self.err(e.into()))?;
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
                        _ => {
                            return Err(
                                self.err(CompileErrorType::InvalidExpression((**e).clone()))
                            );
                        }
                    }

                    let struct_type @ VType {
                        kind: TypeKind::Struct(_),
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
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "serializing {ty}, expected {}",
                            DisplayType(&struct_type)
                        ))));
                    }

                    let ty = VType {
                        kind: TypeKind::Bytes,
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

                    let e = self.lower_expression(e)?;
                    let ty = &e.vtype;
                    if !ty.fits_type(&VType {
                        kind: TypeKind::Bytes,
                        span: e.span,
                    }) {
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "deserializing {ty}, expected bytes",
                        ))));
                    }

                    let ty = VType {
                        kind: TypeKind::Struct(struct_name),
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
                    let err = self.err(CompileErrorType::TodoFound);
                    if !self.is_debug {
                        return Err(err);
                    }
                    warn!("{err}");
                    thir::Expression {
                        kind: thir::ExprKind::InternalFunction(thir::InternalFunction::Todo(*span)),
                        vtype: VType {
                            kind: TypeKind::Never,
                            span: Span::empty(),
                        },
                        span: expression.span,
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
                    .any(|m| m.name == f.module.name)
                {
                    return Err(self.err(CompileErrorType::NotDefined(f.module.name.to_string())));
                }

                let mut args = Vec::new();
                let mut ids = None;
                let vtype = if self.stub_ffi {
                    for arg_e in &f.arguments {
                        let arg_e = self.lower_expression(arg_e)?;
                        args.push(arg_e);
                    }
                    VType {
                        kind: TypeKind::Never,
                        span: Span::empty(),
                    }
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

                    ids = Some((module_id, procedure_id));

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
                        let arg_e = self.lower_expression(arg_e)?;
                        let arg_def_vtype = (&arg_def.vtype).into();
                        if !arg_e.vtype.fits_type(&arg_def_vtype) {
                            let arg_n = i
                                .checked_add(1)
                                .assume("function argument count overflow")?;
                            return Err(self.err(CompileErrorType::InvalidType(format!(
                                "Argument {} (`{}`) in FFI call to `{}::{}` found `{}`, not `{}`",
                                arg_n,
                                arg_def.name,
                                f.module,
                                f.identifier,
                                arg_e.vtype,
                                DisplayType(&arg_def_vtype)
                            ))));
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
                    return Err(self.err(CompileErrorType::InvalidExpression(expression.clone())));
                };
                // ensure return expression type matches function signature
                let et = self.lower_expression(ret_expr)?;
                if !et.vtype.fits_type(&fd.return_type) {
                    return Err(self.err(CompileErrorType::InvalidType(format!(
                        "Return value of `{}()` must be {}",
                        fd.identifier,
                        DisplayType(&fd.return_type)
                    ))));
                }
                thir::Expression {
                    kind: thir::ExprKind::Return(Box::new(et)),
                    vtype: VType {
                        kind: TypeKind::Never,
                        span: expression.span,
                    },
                    span: expression.span,
                }
            }
            ExprKind::Identifier(i) => {
                let ty = self.identifier_types.get(i).map_err(|_| {
                    self.err(CompileErrorType::NotDefined(format!(
                        "Unknown identifier `{}`",
                        i
                    )))
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
                    kind: TypeKind::Enum(e.identifier.clone()),
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
                    self.err(CompileErrorType::InvalidType(
                        "Expression left of `.` is not a struct".into(),
                    ))
                })?;
                let struct_def = self.m.struct_defs.get(name.as_str()).ok_or_else(|| {
                    self.err(CompileErrorType::InvalidType(format!(
                        "Struct `{name}` not defined"
                    )))
                })?;
                let field_def = struct_def
                    .iter()
                    .find(|f| f.identifier.name == s.name)
                    .ok_or_else(|| {
                        self.err(CompileErrorType::InvalidType(format!(
                            "Struct `{}` has no member `{}`",
                            name, s.name
                        )))
                    })?;
                let ty = field_def.field_type.clone();
                thir::Expression {
                    kind: thir::ExprKind::Dot(Box::new(t), s.clone()),
                    vtype: ty,
                    span: expression.span,
                }
            }
            ExprKind::Substruct(lhs, sub) => {
                let Some(sub_field_defns) = self.m.struct_defs.get(&sub.name).cloned() else {
                    return Err(self.err(CompileErrorType::NotDefined(format!(
                        "Struct `{}` not defined",
                        sub.name
                    ))));
                };

                let lhs_expression = self.lower_expression(lhs)?;
                let lhs_struct_name = lhs_expression.vtype.as_struct().ok_or_else(|| {
                    self.err(CompileErrorType::InvalidType(
                        "Expression to the left of the substruct operator is not a struct".into(),
                    ))
                })?;
                let Some(lhs_field_defns) = self.m.struct_defs.get(&lhs_struct_name.name) else {
                    return Err(self.err(CompileErrorType::NotDefined(format!(
                        "Struct `{lhs_struct_name}` is not defined",
                    ))));
                };

                // Check that the struct type on the RHS is a subset of the struct expression on the LHS
                if !sub_field_defns.iter().all(|field_def| {
                    lhs_field_defns.iter().any(|lhs_field| {
                        lhs_field.identifier.name == field_def.identifier.name
                            && lhs_field.field_type.kind == field_def.field_type.kind
                    })
                }) {
                    return Err(self.err(CompileErrorType::InvalidSubstruct(
                        sub.name.clone(),
                        lhs_struct_name.name.clone(),
                    )));
                }

                let ty = VType {
                    kind: TypeKind::Struct(sub.clone()),
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
                    .struct_defs
                    .get(&rhs_ident.name)
                    .cloned()
                    .ok_or_else(|| {
                        self.err(CompileErrorType::NotDefined(format!("struct {rhs_ident}")))
                    })?;

                let lhs_expression = self.lower_expression(lhs)?;
                let lhs_struct_name = lhs_expression.vtype.as_struct().ok_or_else(|| {
                    self.err(CompileErrorType::InvalidType(
                        "Expression to the left of `as` is not a struct".to_string(),
                    ))
                })?;
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
                        lhs_struct_name.name.clone(),
                        rhs_ident.name.clone(),
                    )));
                }

                let ty = VType {
                    kind: TypeKind::Struct(rhs_ident.clone()),
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
                            kind,
                            span: expression.span,
                        },
                        "invalid binary operation",
                    )
                    .map_err(|e| self.err(e))?,
                    None => types::unify_pair(a.vtype.clone(), b.vtype.clone())
                        .map_err(|e| self.err(e.into()))?,
                };

                thir::Expression {
                    kind: constructor(Box::new(a), Box::new(b)),
                    vtype: VType {
                        kind: TypeKind::Bool,
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
                match &e.vtype.kind {
                    TypeKind::Optional(_) => {}
                    _ => {
                        return Err(self.err(CompileErrorType::InvalidType(
                            "`is` must operate on an optional expression".into(),
                        )));
                    }
                }

                thir::Expression {
                    kind: thir::ExprKind::Is(Box::new(e), *expr_is_some),
                    vtype: VType {
                        kind: TypeKind::Bool,
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
            ExprKind::ResultOk(e) => {
                let inner = self.lower_expression(e)?;
                thir::Expression {
                    kind: thir::ExprKind::ResultOk(Box::new(inner.clone())),
                    vtype: VType {
                        kind: TypeKind::Result {
                            ok: Box::new(inner.vtype),
                            err: Box::new(VType {
                                kind: TypeKind::Never,
                                span: Span::empty(),
                            }),
                        },
                        span: expression.span,
                    },
                    span: expression.span,
                }
            }
            ExprKind::ResultErr(e) => {
                let inner = self.lower_expression(e)?;
                thir::Expression {
                    kind: thir::ExprKind::ResultErr(Box::new(inner.clone())),
                    vtype: VType {
                        kind: TypeKind::Result {
                            ok: Box::new(VType {
                                kind: TypeKind::Never,
                                span: Span::empty(),
                            }),
                            err: Box::new(inner.vtype),
                        },
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
            .get(&fc.identifier.name)
            .ok_or_else(|| self.err(CompileErrorType::NotDefined(fc.identifier.to_string())))?
            .args
            .clone();

        let mut arguments = Vec::new();

        for (i, (param, arg_e)) in arg_defs.iter().zip(fc.arguments.iter()).enumerate() {
            let arg_te = self.lower_expression(arg_e)?;
            if !arg_te.vtype.fits_type(&param.ty) {
                let arg_n = i
                    .checked_add(1)
                    .assume("function argument count overflow")?;
                return Err(self.err(CompileErrorType::InvalidType(format!(
                    "Argument {} (`{}`) in call to `{}` found `{}`, expected `{}`",
                    arg_n,
                    param.name,
                    fc.identifier,
                    arg_te.vtype,
                    DisplayType(&param.ty)
                ))));
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
                kind: TypeKind::Optional(t),
                ..
            } => (**t).clone(),
            _ => {
                return Err(self.err(CompileErrorType::InvalidType(
                    "Cannot unwrap non-option expression".into(),
                )));
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

        // Ensure there are no duplicate arm values.
        // NOTE We don't check for zero arms, because that's enforced by the parser.
        // Checking for duplicate result patterns is special, because their associated values are
        // identifiers, which can't be compared, like values can. So we ignore the identifiers, and
        // just make sure the pattern (Ok/Err) isn't duplicated.
        let result_ok_marker = Expression {
            kind: ExprKind::ResultOk(Box::new(Expression {
                kind: ExprKind::Identifier(Ident {
                    name: ident!("result_ok_pattern"),
                    span: Span::empty(),
                }),
                span: Span::empty(),
            })),
            span: Span::empty(),
        };
        let result_err_marker = Expression {
            kind: ExprKind::ResultErr(Box::new(Expression {
                kind: ExprKind::Identifier(Ident {
                    name: ident!("result_err_pattern"),
                    span: Span::empty(),
                }),
                span: Span::empty(),
            })),
            span: Span::empty(),
        };

        let all_values = patterns
            .iter()
            .flat_map(|pattern| match pattern {
                MatchPattern::Values(values) => values.as_slice(),
                MatchPattern::Default(_) => &[],
                MatchPattern::ResultPattern(ResultPattern::Ok(_)) => {
                    std::slice::from_ref(&result_ok_marker)
                }
                MatchPattern::ResultPattern(ResultPattern::Err(_)) => {
                    std::slice::from_ref(&result_err_marker)
                }
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

        let scrutinee = match s {
            LanguageContext::Statement(s) => &s.expression,
            LanguageContext::Expression(e) => &e.scrutinee,
        };
        let scrutinee = self.lower_expression(scrutinee)?;
        let mut scrutinee_t = scrutinee.vtype.clone();

        let mut n: usize = 0;
        let mut patterns_out = Vec::new();
        for pattern in &patterns {
            let pattern = match pattern {
                MatchPattern::Values(values) => {
                    let mut values_out = Vec::new();
                    for value in values {
                        n = n.checked_add(1).assume("can't have usize::MAX patterns")?;
                        if !value.is_literal() {
                            return Err(self.err(CompileErrorType::InvalidType(format!(
                                "match pattern {n} is not a literal expression",
                            ))));
                        }
                        let arm_t = self.lower_expression(value)?;
                        scrutinee_t = types::unify_pair(scrutinee_t, arm_t.vtype.clone())
                            .map_err(|err| {
                                CompileErrorType::InvalidType(format!(
                                    "match pattern {n} has type {}, expected type {}",
                                    err.right, err.left
                                ))
                            })
                            .map_err(|err| self.err(err))?;
                        values_out.push(arm_t);
                    }
                    thir::MatchPattern::Values(values_out)
                }
                MatchPattern::Default(span) => {
                    // Ensure this is the last case, and also that it's not the only case.
                    if pattern != patterns.last().expect("last arm") {
                        return Err(self.err(CompileErrorType::Unknown(String::from(
                            "Default match case must be last.",
                        ))));
                    }
                    thir::MatchPattern::Default(*span)
                }
                MatchPattern::ResultPattern(result_pattern) => {
                    // Verify that the scrutinee is a Result type
                    if !matches!(scrutinee_t.kind, TypeKind::Result { .. }) {
                        return Err(self.err(CompileErrorType::InvalidType(
                            "Result pattern requires scrutinee to be a Result type".to_string(),
                        )));
                    }
                    let thir_pattern = match result_pattern {
                        ResultPattern::Ok(ident) => thir::ResultPattern::Ok(ident.clone()),
                        ResultPattern::Err(ident) => thir::ResultPattern::Err(ident.clone()),
                    };
                    thir::MatchPattern::ResultPattern(thir_pattern)
                }
            };
            patterns_out.push(pattern);
        }

        let need_default = default_count == 0
            && self
                .m
                .cardinality(&scrutinee_t.kind)
                .is_none_or(|c| c > all_values.len() as u64);

        if need_default {
            return Err(self.err_loc(CompileErrorType::MissingDefaultPattern, span));
        }

        // Match expression/statement type. For statements, it's None; for expressions, it's Some(Typeish)
        let mut expr_type: Option<VType> = None;

        let mut patterns = patterns_out.into_iter();
        Ok(match s {
            LanguageContext::Statement(s) => {
                let mut arms = Vec::new();
                for arm in &s.arms {
                    let pattern = patterns.next().assume("same number of patterns")?;

                    // Enter a scope for each match arm (for variable isolation)
                    self.identifier_types.enter_block();

                    // For Result patterns, add the identifier to the scope for type-checking
                    if let thir::MatchPattern::ResultPattern(result_pattern) = &pattern {
                        let (ident, inner_type) = match result_pattern {
                            thir::ResultPattern::Ok(ident) => {
                                if let TypeKind::Result { ok, .. } = &scrutinee_t.kind {
                                    (ident, (**ok).clone())
                                } else {
                                    bug!("Ok pattern without Result type");
                                }
                            }
                            thir::ResultPattern::Err(ident) => {
                                if let TypeKind::Result { err, .. } = &scrutinee_t.kind {
                                    (ident, (**err).clone())
                                } else {
                                    bug!("Err pattern without Result type");
                                }
                            }
                        };
                        self.identifier_types
                            .add(ident.name.clone(), inner_type)
                            .map_err(|e| self.err(e))?;
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
                for (i, arm) in e.arms.iter().enumerate() {
                    let pattern = patterns.next().assume("same number of patterns")?;

                    // Enter a scope for each match arm (for variable isolation)
                    self.identifier_types.enter_block();

                    // For Result patterns, add the identifier to the scope for type-checking
                    if let thir::MatchPattern::ResultPattern(result_pattern) = &pattern {
                        let (inner_type, ident) = match result_pattern {
                            thir::ResultPattern::Ok(ident) => {
                                if let TypeKind::Result { ok, .. } = &scrutinee_t.kind {
                                    ((**ok).clone(), ident)
                                } else {
                                    bug!("Ok pattern without Result type");
                                }
                            }
                            thir::ResultPattern::Err(ident) => {
                                if let TypeKind::Result { err, .. } = &scrutinee_t.kind {
                                    ((**err).clone(), ident)
                                } else {
                                    bug!("Err pattern without Result type");
                                }
                            }
                        };
                        self.identifier_types
                            .add(ident.name.clone(), inner_type)
                            .map_err(|e| self.err(e))?;
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
                                        let n = i.saturating_add(1);
                                        CompileErrorType::InvalidType(format!(
                                            "match arm expression {n} has type {}, expected {}",
                                            err.right, err.left
                                        ))
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
            let kind = match (&statement.kind, &context) {
                (
                    StmtKind::Let(s),
                    StatementContext::Action(_)
                    | StatementContext::PureFunction(_)
                    | StatementContext::CommandPolicy(_)
                    | StatementContext::CommandRecall(_),
                ) => {
                    let et = self.lower_expression(&s.expression)?;
                    self.identifier_types
                        .add(s.identifier.name.clone(), et.vtype.clone())
                        .map_err(|e| self.err(e))?;
                    // Check for Never type after adding to identifier types
                    // This ensures duplicate name errors are caught first (during add())
                    if matches!(et.vtype.kind, TypeKind::Never) {
                        return Err(self.err(CompileErrorType::InvalidType(
                            "Cannot assign a Never value.".to_string(),
                        )));
                    }
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
                        kind: TypeKind::Bool,
                        span: s.expression.span,
                    }) {
                        return Err(self.err(CompileErrorType::InvalidType(String::from(
                            "check must have boolean expression",
                        ))));
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
                            kind: TypeKind::Bool,
                            span: cond.span,
                        }) {
                            return Err(self.err(CompileErrorType::InvalidType(format!(
                                "if condition must be a boolean expression, was type {}",
                                cond.vtype,
                            ))));
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
                        self.err(CompileErrorType::InvalidType(format!(
                            "Cannot publish `{}`, must be a command struct",
                            e.vtype
                        )))
                    })?;
                    if !self.m.command_defs.contains(ident.as_str()) {
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "Struct `{ident}` is not a Command struct",
                        ))));
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
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "{} action `{}` cannot publish {} command `{}`",
                            action.persistence, action.identifier, command_persistence, ident
                        ))));
                    }
                    thir::StmtKind::Publish(e)
                }
                (StmtKind::Expr(e), _) => {
                    // Handle expression statements (like return expressions)
                    let expr = self.lower_expression(e)?;
                    // For return expressions, the type checking happens during lowering
                    // We don't create a separate statement kind for them since they're expressions
                    // They will be compiled as expression statements
                    if let thir::ExprKind::Return(_) = &expr.kind {
                        // Validate return is in a function context
                        let ctx = self.get_statement_context()?;
                        if !matches!(ctx, StatementContext::PureFunction(_)) {
                            return Err(self.err(CompileErrorType::InvalidExpression(e.clone())));
                        }
                    }
                    thir::StmtKind::Expr(expr)
                }
                (
                    StmtKind::Finish(s),
                    StatementContext::CommandPolicy(_) | StatementContext::CommandRecall(_),
                ) => {
                    self.enter_statement_context(StatementContext::Finish);
                    let s = self.lower_statements(s, Scope::Layered)?;
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

                    thir::StmtKind::Finish(s)
                }
                (StmtKind::Map(map_stmt), StatementContext::Action(_action)) => {
                    let fact = self.lower_fact_literal(&map_stmt.fact, false)?;
                    // Define Struct variable for the `as` clause
                    self.identifier_types.enter_block();
                    self.identifier_types
                        .add(
                            map_stmt.identifier.name.clone(),
                            VType {
                                kind: TypeKind::Struct(map_stmt.fact.identifier.clone()),
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
                (StmtKind::Create(s), StatementContext::Finish) => {
                    // Do not allow bind values during fact creation
                    if let Some(span) = find_bind(&s.fact.key_fields)
                        .or_else(|| s.fact.value_fields.as_ref().and_then(|f| find_bind(f)))
                    {
                        return Err(self.err_loc(
                            CompileErrorType::BadArgument(String::from(
                                "Cannot create fact with bind values",
                            )),
                            span,
                        ));
                    }

                    let fact = self.lower_fact_literal(&s.fact, true)?;
                    thir::StmtKind::Create(thir::CreateStatement { fact })
                }
                (StmtKind::Update(s), StatementContext::Finish) => {
                    // ensure fact is mutable
                    let fact_def = self.get_fact_def(&s.fact.identifier)?;
                    if fact_def.immutable {
                        return Err(
                            self.err(CompileErrorType::Unknown(String::from("fact is immutable")))
                        );
                    }

                    if let Some(span) = find_bind(&s.fact.key_fields) {
                        return Err(self.err_loc(
                            CompileErrorType::BadArgument(String::from(
                                "Cannot update fact with wildcard keys",
                            )),
                            span,
                        ));
                    }

                    let fact = self.lower_fact_literal(&s.fact, false)?;

                    // Verify the 'to' fact literal
                    if let Some(span) = find_bind(&s.to) {
                        // Cannot bind in the set statement
                        return Err(self.err_loc(
                            CompileErrorType::BadArgument(String::from(
                                "Cannot update fact to a bind value",
                            )),
                            span,
                        ));
                    }
                    let fact_def = self.get_fact_def(&s.fact.identifier)?.clone();
                    let to = self.lower_fact_values(&fact_def, &s.to)?;

                    thir::StmtKind::Update(thir::UpdateStatement { fact, to })
                }
                (StmtKind::Delete(s), StatementContext::Finish) => {
                    if let Some(span) = find_bind(&s.fact.key_fields) {
                        return Err(self.err_loc(
                            CompileErrorType::BadArgument(String::from(
                                "Cannot delete fact with wildcard keys",
                            )),
                            span,
                        ));
                    }

                    let fact = self.lower_fact_literal(&s.fact, false)?;

                    thir::StmtKind::Delete(thir::DeleteStatement { fact })
                }
                (StmtKind::Emit(e), StatementContext::Finish) => {
                    let e = self.lower_expression(e)?;
                    let struct_name = e.vtype.as_struct().ok_or_else(|| {
                        self.err(CompileErrorType::InvalidType(format!(
                            "Cannot emit `{}`, must be an effect struct",
                            e.vtype
                        )))
                    })?;
                    if !self.m.effects.contains(struct_name.as_str()) {
                        return Err(self.err(CompileErrorType::InvalidType(format!(
                            "Struct `{struct_name}` is not an effect struct",
                        ))));
                    }
                    thir::StmtKind::Emit(e)
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
                    let f = self.lower_function_call(f)?;
                    thir::StmtKind::FunctionCall(f)
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

                    let mut args = Vec::new();
                    for (i, arg) in fc.arguments.iter().enumerate() {
                        let arg = self.lower_expression(arg)?;
                        let expected_arg = &action_def.arguments[i];
                        if !arg.vtype.fits_type(&expected_arg.ty) {
                            return Err(self.err_loc(
                                CompileErrorType::BadArgument(format!(
                                    "invalid argument type for `{}`: expected `{}`, but got `{}`",
                                    expected_arg.name.name,
                                    DisplayType(&expected_arg.ty),
                                    arg.vtype,
                                )),
                                statement.span,
                            ));
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
                            kind: TypeKind::Bool,
                            span: e.span,
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
                    thir::StmtKind::DebugAssert(e)
                }
                (_, _) => {
                    return Err(
                        self.err_loc(CompileErrorType::InvalidStatement(context), statement.span)
                    );
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
