pub mod error;
mod markdown;
mod token;
mod util;

use aranya_policy_ast::{self as ast, WithSpanExt as _, ident};
use chumsky::{Parser as _, input::Input as _, prelude::*};
use logos::Logos as _;

pub use self::markdown::parse_policy_document;
use self::{
    error::{ParseError, Result},
    token::{Token, token},
    util::{Input, Parser, Span, ast_span, just},
};

/// Produce a token stream from policy source.
fn lex<'i>(input: &'i str) -> impl Input<'i> {
    let len = input.len();

    let token_iter = Token::lexer(input).spanned().map(|(tok, span)| match tok {
        Ok(tok) => (tok, span.into()),
        Err(()) => (Token::Error, span.into()),
    });

    chumsky::input::Stream::from_iter(token_iter).map((len..len).into(), |x| x)
}

/// Parse a single chunk of policy, e.g. from a code block in a markdown document.
fn parse_policy_chunk(input: &str, policy: &mut ast::Policy, offset: usize) -> Result<()> {
    if policy.version != ast::Version::V2 {
        let err = ParseError::new(
            error::InvalidVersion {
                found: policy.version.to_string(),
                required: ast::Version::V2,
            },
            ast::Version::help_message(),
            None,
        );
        return Err(err);
    }
    let items = item_parser()
        .repeated()
        .collect::<Vec<_>>()
        .parse(lex(input).map_span(|span| span.add(offset).expect("span fits")))
        .into_result()
        .map_err(ParseError::from_chumsky_errors)?;
    for item in items {
        policy.add(item);
    }
    Ok(())
}

/// Parse plain policy source code.
pub fn parse_policy_str(input: &str, version: ast::Version) -> Result<ast::Policy> {
    let mut policy = ast::Policy::new(version, input);
    parse_policy_chunk(input, &mut policy, 0).map_err(|e| e.with_source(input.into()))?;
    Ok(policy)
}

/// Parse just a vtype.
pub fn parse_vtype(input: &str) -> Result<ast::VType> {
    vtype_parser()
        .parse(lex(input))
        .into_result()
        .map_err(ParseError::from_chumsky_errors)
        .map_err(|e| e.with_source(input.into()))
}

/// Parse just a single expression.
pub fn parse_expression(input: &str) -> Result<ast::Expression> {
    let (expression, _) = expr_and_stmt_block_parsers();
    expression
        .parse(lex(input))
        .into_result()
        .map_err(ParseError::from_chumsky_errors)
        .map_err(|e| e.with_source(input.into()))
}

/// Parse function declarations for FFI.
pub fn parse_ffi_decl(input: &str) -> Result<ast::FunctionDecl> {
    function_decl_parser()
        .parse(lex(input))
        .into_result()
        .map_err(ParseError::from_chumsky_errors)
        .map_err(|e| e.with_source(input.into()))
}

/// A parser of identifiers.
///
/// NB: The lexer won't produce an identifier that is a keyword.
fn ident_parser<'i, I: Input<'i>>() -> impl Parser<'i, I, ast::Ident> + Copy {
    select! { Token::Identifier(ident) => ident.parse().expect("valid identifier") }
        .spanned()
        .labelled("identifier")
}

/// A parser of vtypes.
fn vtype_parser<'i, I: Input<'i>>() -> impl Parser<'i, I, ast::VType> + Clone {
    let ident = ident_parser();
    recursive(|vtype| {
        let primitive = select! {
            token!(unit) => ast::TypeKind::Unit,
            token!(string) => ast::TypeKind::String,
            token!(bytes) => ast::TypeKind::Bytes,
            token!(int) => ast::TypeKind::Int,
            token!(bool) => ast::TypeKind::Bool,
            token!(id) => ast::TypeKind::Id,
        };
        let option = just!(option)
            .ignore_then(vtype.clone().bracket_delimited())
            .map(|inner| ast::TypeKind::Optional(Box::new(inner)));
        let result = just!(result)
            .ignore_then(
                (vtype
                    .comma_separated()
                    .allow_trailing()
                    .collect_exactly::<[ast::VType; 2]>())
                .bracket_delimited(),
            )
            .map(|[ok, err]| ast::TypeKind::Result(Box::new(ast::ResultTypeKind { ok, err })));
        choice((
            primitive,
            just!(struct).ignore_then(ident).map(ast::TypeKind::Struct),
            just!(enum).ignore_then(ident).map(ast::TypeKind::Enum),
            option,
            result,
        ))
        .spanned()
        .labelled("vtype")
    })
}

/// A parser of function parameters, including enclosing parentheses.
fn function_params_parser<'i, I: Input<'i>>() -> impl Parser<'i, I, Vec<ast::Param>> + Clone {
    ident_parser()
        .then_ignore(just!(:))
        .then(vtype_parser())
        .map(|(name, vtype)| ast::Param { name, vtype })
        .comma_separated()
        .allow_trailing()
        .collect()
        .paren_delimited()
}

/// A parser of FFI function declarations.
fn function_decl_parser<'i, I: Input<'i>>() -> impl Parser<'i, I, ast::FunctionDecl> {
    just!(finish)
        .or_not()
        .ignore_then(just!(function))
        .ignore_then(group((
            ident_parser(),
            function_params_parser(),
            vtype_parser().or_not(),
        )))
        .map(|(name, parameters, return_type)| ast::FunctionDecl {
            name,
            parameters,
            return_type,
        })
}

/// A parser of a field value block, including enclosing braces.
fn fields_block_parser<'i, I: Input<'i>>() -> impl Parser<'i, I, Vec<ast::StructItem>> + Clone {
    let ident = ident_parser();
    let vtype = vtype_parser();

    let field_def = ident
        .then_ignore(just!(:))
        .then(vtype)
        .map(|(name, vtype)| ast::FieldDefinition { name, vtype });

    let field_insertion = just!(+).ignore_then(ident);

    choice((
        field_def.map(ast::StructItem::Field),
        field_insertion.map(ast::StructItem::StructRef),
    ))
    .comma_separated()
    .allow_trailing()
    .collect()
    .brace_delimited()
}

/// A parser of a struct definition.
fn struct_def_parser<'i, I: Input<'i>>() -> impl Parser<'i, I, ast::StructDefinition> {
    let ident = ident_parser();
    just!(struct)
        .ignore_then(ident.then(fields_block_parser()))
        .map_with(|(name, items), e| ast::StructDefinition {
            name,
            items,
            span: ast_span(e.span()),
        })
}

/// A parser of an enum definition.
fn enum_def_parser<'i, I: Input<'i>>() -> impl Parser<'i, I, ast::EnumDefinition> {
    let ident = ident_parser();
    just!(enum)
        .ignore_then(group((
            ident,
            ident
                .comma_separated()
                .allow_trailing()
                .collect()
                .brace_delimited(),
        )))
        .map_with(|(name, variants), e| ast::EnumDefinition {
            name,
            variants,
            span: ast_span(e.span()),
        })
}

/// Parsers of expressions and statement blocks.
///
/// NB: These are defined together because they are co-recursive.
fn expr_and_stmt_block_parsers<'i, I: Input<'i>>() -> (
    impl Parser<'i, I, ast::Expression> + Clone,
    impl Parser<'i, I, Vec<ast::Statement>> + Clone,
) {
    let ident = ident_parser();

    let mut expression_raw = Recursive::declare();
    let mut statement = Recursive::declare();

    // We usually want expressions to include structs, so give it the default name.
    let expression = map_ctx(Config::allow_struct, expression_raw.clone());
    // Used to disallow struct literals in match scrutinee and if condition.
    let expression_without_struct = map_ctx(Config::disallow_struct, expression_raw.clone());

    // ==== EXPRESSIONS ====

    let match_pattern = choice((
        just!(_)
            .to_span()
            .map(|span| ast::MatchPattern::Default(ast_span(span))),
        expression
            .clone()
            .separated_by(just!(|))
            .at_least(1)
            .collect()
            .map(ast::MatchPattern::Values),
    ));

    let field = ident
        .then(just!(:).ignore_then(expression.clone()).or_not())
        .map(|(name, maybe_expr)| {
            let expr =
                maybe_expr.unwrap_or_else(|| ast::ExprKind::Identifier(name.clone()).at(name.span));
            (name, expr)
        });
    let source = just!(...).ignore_then(ident);

    // TODO: simplify.
    // This is `{ field,* source,* }`, but requiring a comma between is complex.
    let struct_data = choice((
        group((
            field.comma_separated().at_least(1).collect(),
            just!(,)
                .ignore_then(
                    source
                        .comma_separated()
                        .at_least(1)
                        .allow_trailing()
                        .collect(),
                )
                .or(just!(,).or_not().to(Vec::new())),
        )),
        source
            .comma_separated()
            .allow_trailing()
            .collect()
            .map(|sources| (Vec::new(), sources)),
    ))
    .brace_delimited();

    let function_call = ident
        .then(
            expression
                .clone()
                .comma_separated()
                .allow_trailing()
                .collect()
                .paren_delimited(),
        )
        .map(|(name, arguments)| ast::FunctionCall { name, arguments });

    let fact_fields = ident
        .then(
            just!(:)
                .ignore_then(choice((
                    just!(?)
                        .to_span()
                        .map(|span| ast::FactField::Bind(ast_span(span))),
                    expression.clone().map(ast::FactField::Expression),
                )))
                .or_not(),
        )
        .map(|(name, maybe_field)| {
            let field = maybe_field.unwrap_or_else(|| {
                ast::FactField::Expression(ast::ExprKind::Identifier(name.clone()).at(name.span))
            });
            (name, field)
        })
        .comma_separated()
        .allow_trailing()
        .collect();

    let fact_keys = fact_fields.clone().bracket_delimited();
    let fact_values = fact_fields.brace_delimited();
    let fact_literal = group((
        ident,
        fact_keys,
        just!(=>).ignore_then(fact_values.clone()).or_not(),
    ))
    .map(|(name, key_fields, value_fields)| ast::FactLiteral {
        name,
        key_fields,
        value_fields,
    });

    let atom = {
        let int_literal =
            select! { Token::Number(n) = e => n.at(e.span()) }.labelled("int literal");

        let string_literal = select! { Token::String(s) => s }
            .try_map(|s, span| {
                parse_string_literal(s.at(span))
                    .map_err(|(msg, span)| Rich::custom(Span(span), msg))
            })
            .labelled("string literal");

        let block_expression = statement
            .clone()
            .repeated()
            .collect()
            .then_ignore(just!(:))
            .then(expression.clone())
            .brace_delimited()
            .map(|(stmts, expr)| ast::ExprKind::Block(stmts, Box::new(expr)));

        let match_expression_arm = match_pattern
            .clone()
            .then_ignore(just!(=>))
            .then(expression.clone())
            .map_with(|(pattern, body), e| ast::MatchExpressionArm {
                pattern,
                body,
                span: ast_span(e.span()),
            });

        choice((
            // simple
            select! {
                token!(Unit) => ast::ExprKind::Unit,
                token!(true) => ast::ExprKind::Bool(true),
                token!(false) => ast::ExprKind::Bool(false),
                token!(this) = e => ast::ExprKind::Identifier(ident!("this").at(e.span())),
                token!(envelope) = e => ast::ExprKind::Identifier(ident!("envelope").at(e.span())),
            },
            // int
            int_literal.map(ast::ExprKind::Int),
            // string
            string_literal.map(ast::ExprKind::String),
            // option
            just!(None).to(ast::ExprKind::Optional(None)),
            just!(Some)
                .ignore_then(expression.clone().paren_delimited())
                .map(|expr| ast::ExprKind::Optional(Some(Box::new(expr)))),
            // result
            just!(Ok)
                .ignore_then(expression.clone().paren_delimited())
                .map(|expr| ast::ExprKind::Ok(Box::new(expr))),
            just!(Err)
                .ignore_then(expression.clone().paren_delimited())
                .map(|expr| ast::ExprKind::Err(Box::new(expr))),
            // struct literal
            ident
                .then(struct_data)
                .map_with(|(name, (fields, sources)), e| {
                    ast::ExprKind::NamedStruct(ast::NamedStruct {
                        name,
                        fields,
                        sources,
                        span: ast_span(e.span()),
                    })
                })
                .contextual()
                .configure(|_, ctx| ctx.allow_struct),
            // function call
            function_call.clone().map(ast::ExprKind::FunctionCall),
            // foreign function call
            ident
                .then_ignore(just!(::))
                .then(function_call.clone())
                .map(|(module, call)| ast::ForeignFunctionCall {
                    module,
                    function: call.name,
                    arguments: call.arguments,
                })
                .map(ast::ExprKind::ForeignFunctionCall),
            // action call
            just!(action)
                .ignore_then(function_call.clone())
                .map(ast::ExprKind::ActionCall),
            // recall call
            just!(recall)
                .ignore_then(function_call)
                .map(ast::ExprKind::Recall),
            // return
            just!(return)
                .ignore_then(expression.clone())
                .map(Box::new)
                .map(ast::ExprKind::Return),
            // enum reference
            ident
                .then_ignore(just!(::))
                .then(ident)
                .map(|(enumeration, variant)| ast::EnumReference {
                    enumeration,
                    variant,
                })
                .map(ast::ExprKind::EnumReference),
            // query
            just!(query)
                .ignore_then(fact_literal.clone())
                .map(ast::InternalFunction::Query)
                .map(ast::ExprKind::InternalFunction),
            // exists
            just!(exists)
                .ignore_then(fact_literal.clone())
                .map(ast::InternalFunction::Exists)
                .map(ast::ExprKind::InternalFunction),
            // fact count
            group((
                select! {
                    token!(count_up_to) = e => ast::FactCountType::UpTo(ast_span(e.span())),
                    token!(at_least) = e => ast::FactCountType::AtLeast(ast_span(e.span())),
                    token!(at_most) = e => ast::FactCountType::AtMost(ast_span(e.span())),
                    token!(exactly) = e => ast::FactCountType::Exactly(ast_span(e.span())),
                },
                int_literal,
                fact_literal.clone(),
            ))
            .map(|(ty, count, fact)| ast::InternalFunction::FactCount(ty, count, fact))
            .map(ast::ExprKind::InternalFunction),
            // match
            just!(match)
                .ignore_then(expression_without_struct.clone())
                .then(match_expression_arm.repeated().collect().brace_delimited())
                .map(|(scrutinee, arms)| {
                    ast::ExprKind::Match(Box::new(ast::MatchExpression { scrutinee, arms }))
                }),
            // if
            just!(if)
                .ignore_then(group((
                    expression_without_struct.clone(),
                    block_expression.clone().spanned(),
                    just!(else).ignore_then(block_expression.clone().spanned()),
                )))
                .map(|(c, t, f)| ast::InternalFunction::If(Box::new(c), Box::new(t), Box::new(f)))
                .map(ast::ExprKind::InternalFunction),
            // todo
            just!(todo)
                .then_ignore(empty().paren_delimited())
                .to_span()
                .map(|span| ast::InternalFunction::Todo(ast_span(span)))
                .map(ast::ExprKind::InternalFunction),
            // test_fail
            just!(test_fail)
                .ignore_then(string_literal.or_not().paren_delimited())
                .map_with(|msg, e| ast::InternalFunction::TestFail(msg, ast_span(e.span())))
                .map(ast::ExprKind::InternalFunction),
            // identifier
            ident.map(ast::ExprKind::Identifier),
            // block expression
            block_expression,
        ))
        .spanned()
        // grouping, separated to keep inner span
        .or(expression.clone().paren_delimited())
        .labelled("atom")
    };

    expression_raw.define({
        use chumsky::pratt::{infix, left, none, postfix, prefix, right};
        // NB: chumsky treats its precedence values as "binding power" where a greater value binds
        // more tightly than a lower one. This is reversed from the docs and previous parser.
        atom.pratt((
            (
                // 9 - `?`
                postfix(9, just!(?), |l, _, e| {
                    ast::ExprKind::Try(Box::new(l)).at(e.span())
                })
            ),
            (
                // 8 - `.`
                postfix(8, just!(.).ignore_then(ident), |l, op, e| {
                    ast::ExprKind::Dot(Box::new(l), op).at(e.span())
                })
            ),
            (
                // 7 - `substruct`, `as`
                postfix(7, just!(substruct).ignore_then(ident), |l, op, e| {
                    ast::ExprKind::Substruct(Box::new(l), op).at(e.span())
                }),
                postfix(7, just!(as).ignore_then(ident), |l, op, e| {
                    ast::ExprKind::Cast(Box::new(l), op).at(e.span())
                }),
            ),
            (
                // 6 - `!`
                prefix(6, just!(!), |_, r, e| {
                    ast::ExprKind::Not(Box::new(r)).at(e.span())
                }),
            ),
            // (
            //     // 5 - `+`, `-`
            //     infix(left(5), just!(+), |l, _, r, e| todo!()),
            //     infix(left(5), just!(-), |l, _, r, e| todo!()),
            // ),
            (
                // 4 - `>`, `<`, `>=`, `<=`, `is`
                infix(none(4), just!(>), |l, _, r, e| {
                    ast::ExprKind::GreaterThan(Box::new(l), Box::new(r)).at(e.span())
                }),
                infix(none(4), just!(<), |l, _, r, e| {
                    ast::ExprKind::LessThan(Box::new(l), Box::new(r)).at(e.span())
                }),
                infix(none(4), just!(>=), |l, _, r, e| {
                    ast::ExprKind::GreaterThanOrEqual(Box::new(l), Box::new(r)).at(e.span())
                }),
                infix(none(4), just!(<=), |l, _, r, e| {
                    ast::ExprKind::LessThanOrEqual(Box::new(l), Box::new(r)).at(e.span())
                }),
                postfix(
                    4,
                    just!(is).ignore_then(
                        select! { token!(Some) => true, token!(None) => false }
                            .labelled("None or Some"),
                    ),
                    |l, is_some, e| ast::ExprKind::Is(Box::new(l), is_some).at(e.span()),
                ),
            ),
            (
                // 3 - `==`, `!=`
                infix(none(3), just!(==), |l, _, r, e| {
                    ast::ExprKind::Equal(Box::new(l), Box::new(r)).at(e.span())
                }),
                infix(none(3), just!(!=), |l, _, r, e| {
                    ast::ExprKind::NotEqual(Box::new(l), Box::new(r)).at(e.span())
                }),
            ),
            (
                // 2 - `&&`, `||`
                infix(left(2), just!(&&), |l, _, r, e| {
                    ast::ExprKind::And(Box::new(l), Box::new(r)).at(e.span())
                }),
                infix(left(2), just!(||), |l, _, r, e| {
                    ast::ExprKind::Or(Box::new(l), Box::new(r)).at(e.span())
                }),
            ),
            (
                // 1 - `or` (optional coalescing)
                infix(right(1), just!(or), |l, _, r, e| {
                    ast::ExprKind::Coalesce(Box::new(l), Box::new(r)).at(e.span())
                }),
            ),
        ))
        .labelled("expression")
    });

    // ==== STATEMENTS ====

    let body = statement.clone().repeated().collect().brace_delimited();

    statement.define({
        let publish_statement = just!(publish).ignore_then(expression.clone());

        let let_statement = just!(let)
            .ignore_then(ident)
            .then_ignore(just!(=))
            .then(expression.clone())
            .map(|(name, value)| ast::LetStatement { name, value });

        let check_statement = just!(check)
            .ignore_then(expression.clone())
            .then_ignore(just!(else))
            .then(expression.clone())
            .map(|(condition, else_expression)| ast::CheckStatement {
                condition,
                else_expression,
            });

        let match_arm = match_pattern
            .clone()
            .then_ignore(just!(=>))
            .then(body.clone())
            .map(|(pattern, body)| ast::MatchArm { pattern, body });
        let match_statement = just!(match)
            .ignore_then(expression_without_struct.clone())
            .then(match_arm.repeated().collect().brace_delimited())
            .map(|(scrutinee, arms)| ast::MatchStatement { scrutinee, arms });

        let if_statement = just!(if)
            .ignore_then(expression_without_struct.clone())
            .then(body.clone())
            .separated_by(just!(else))
            .at_least(1)
            .collect()
            .then(just!(else).ignore_then(body.clone()).or_not())
            .map(|(branches, fallback)| ast::IfStatement { branches, fallback });

        let finish_statement = just!(finish).ignore_then(body.clone());

        let map_statement = group((
            just!(map).ignore_then(fact_literal.clone()),
            just!(as).ignore_then(ident),
            body.clone(),
        ))
        .map(|(fact, identifier, body)| ast::MapStatement {
            fact,
            identifier,
            body,
        });

        let create_statement = just!(create)
            .ignore_then(fact_literal.clone())
            .map(|fact| ast::CreateStatement { fact });

        let update_statement = just!(update)
            .ignore_then(fact_literal.clone())
            .then_ignore(just!(to))
            .then(fact_values.clone())
            .map(|(fact, to)| ast::UpdateStatement { fact, to });

        let delete_statement = just!(delete)
            .ignore_then(fact_literal.clone())
            .map(|fact| ast::DeleteStatement { fact });

        let emit_statement = just!(emit).ignore_then(expression.clone());

        let return_statement = just!(return)
            .ignore_then(expression.clone())
            .map(|value| ast::ReturnStatement { value });

        let debug_assert = just!(debug_assert).ignore_then(expression.clone().paren_delimited());

        let function_call = ident
            .then(
                expression
                    .clone()
                    .comma_separated()
                    .allow_trailing()
                    .collect()
                    .paren_delimited(),
            )
            .map(|(name, arguments)| ast::FunctionCall { name, arguments });

        let recall_statement = just!(recall).ignore_then(function_call.clone());

        let action_call = just!(action).ignore_then(function_call.clone());

        choice((
            publish_statement.map(ast::StmtKind::Publish),
            let_statement.map(ast::StmtKind::Let),
            check_statement.map(ast::StmtKind::Check),
            match_statement.map(ast::StmtKind::Match),
            if_statement.map(ast::StmtKind::If),
            finish_statement.map(ast::StmtKind::Finish),
            map_statement.map(ast::StmtKind::Map),
            create_statement.map(ast::StmtKind::Create),
            update_statement.map(ast::StmtKind::Update),
            delete_statement.map(ast::StmtKind::Delete),
            emit_statement.map(ast::StmtKind::Emit),
            return_statement.map(ast::StmtKind::Return),
            recall_statement.map(ast::StmtKind::Recall),
            debug_assert.map(ast::StmtKind::DebugAssert),
            function_call.map(ast::StmtKind::FunctionCall),
            action_call.map(ast::StmtKind::ActionCall),
        ))
        .spanned()
        .labelled("statement")
    });

    (expression, body)
}

/// A top-level-item parser.
fn item_parser<'i, I: Input<'i>>() -> impl Parser<'i, I, ast::TopLevelItem> {
    let ident = ident_parser();
    let vtype = vtype_parser();

    let (expression, body) = expr_and_stmt_block_parsers();

    // ==== TOP LEVEL ITEMS ====

    let flavor = ident.bracket_delimited();

    let function_params = function_params_parser();

    let ffi_import = just!(use).ignore_then(ident);

    // TODO: dedup with `fields_def` in `fields_block_parser`?
    let fact_fields = ident
        .then_ignore(just!(:))
        .then(vtype.clone())
        .map(|(name, vtype)| ast::FieldDefinition { name, vtype })
        .comma_separated()
        .allow_trailing()
        .collect();

    let fact_def = group((
        just!(immutable)
            .ignored()
            .or_not()
            .map(|token| token.is_some()),
        just!(fact).ignore_then(ident),
        fact_fields.clone().bracket_delimited(),
        just!(=>).ignore_then(fact_fields.brace_delimited()),
    ))
    .map_with(|(immutable, name, keys, values), e| ast::FactDefinition {
        immutable,
        name,
        keys,
        values,
        span: ast_span(e.span()),
    });

    let action_def = just!(action)
        .ignore_then(group((
            flavor,
            ident,
            function_params.clone(),
            vtype.clone().or_not(),
            body.clone(),
        )))
        .map_with(
            |(flavor, name, parameters, return_type, body), e| ast::ActionDefinition {
                flavor,
                name,
                parameters,
                return_type: return_type.unwrap_or(ast::TypeKind::Unit.nowhere()),
                body,
                span: ast_span(e.span()),
            },
        );

    let fields_block = fields_block_parser();

    let effect_def = just!(effect)
        .ignore_then(ident.then(fields_block.clone()))
        .map_with(|(name, items), e| ast::EffectDefinition {
            name,
            items,
            span: ast_span(e.span()),
        });

    let struct_def = struct_def_parser();

    let enum_def = enum_def_parser();

    let method_params = {
        let this = just!(this).to_span().map(ast_span);
        let envelope = just!(envelope).to_span().map(ast_span);
        let typed = ident
            .then_ignore(just!(:))
            .then(vtype.clone())
            .map(|(name, vtype)| ast::Param { name, vtype });
        let others = typed.comma_separated().collect().spanned();
        // TODO: Simplify
        choice((
            group((
                this.map(Some),
                just!(,).ignore_then(envelope).or_not(),
                just!(,)
                    .ignore_then(others.clone())
                    .or(empty().to_span().map(|span| Vec::new().at(span))),
            )),
            group((
                empty().to(None),
                envelope.map(Some),
                just!(,)
                    .ignore_then(others.clone())
                    .or(empty().to_span().map(|span| Vec::new().at(span))),
            )),
            group((empty().to(None), empty().to(None), others)),
        ))
        .paren_delimited()
        .map(|(this, envelope, other_params)| ast::MethodParams {
            this,
            envelope,
            other_params,
        })
    };

    let command_def = just!(command)
        .ignore_then(group((
            ident,
            just!(with).ignore_then(ident),
            group((
                // attributes
                just!(attributes)
                    .ignore_then(
                        ident
                            .then_ignore(just!(:))
                            .then(expression.clone())
                            .comma_separated()
                            .allow_trailing()
                            .collect()
                            .brace_delimited(),
                    )
                    .or_not()
                    .map(Option::unwrap_or_default)
                    .labelled("attributes block"),
                // fields
                just!(fields)
                    .ignore_then(fields_block.clone())
                    .or_not()
                    .map(Option::unwrap_or_default)
                    .labelled("fields block"),
                // policy
                just!(policy)
                    .ignore_then(method_params.clone())
                    .then(body.clone())
                    .map_with(|(parameters, body), e| ast::PolicyBlockDefinition {
                        parameters,
                        body,
                        span: ast_span(e.span()),
                    })
                    .labelled("policy block"),
                // recalls
                just!(recall)
                    .ignore_then(group((ident, method_params.clone(), body.clone())))
                    .map_with(|(name, parameters, body), e| ast::RecallBlockDefinition {
                        name,
                        parameters,
                        body,
                        span: ast_span(e.span()),
                    })
                    .repeated()
                    .collect()
                    .labelled("recall blocks"),
            ))
            .brace_delimited(),
        )))
        .map_with(|(name, base, (attributes, fields, policy, recalls)), e| {
            ast::CommandDefinition {
                base,
                name,
                attributes,
                fields,
                policy,
                recalls,
                span: ast_span(e.span()),
            }
        });

    let base_command_def = just!(base)
        .ignore_then(group((
            flavor,
            ident,
            group((
                just!(fields)
                    .ignore_then(fields_block.clone())
                    .or_not()
                    .map(Option::unwrap_or_default)
                    .labelled("fields block"),
                just!(get_key)
                    .ignore_then(group((method_params.clone(), vtype.clone(), body.clone())))
                    .map_with(
                        |(parameters, return_type, body), e| ast::GetKeyBlockDefinition {
                            parameters,
                            return_type,
                            body,
                            span: ast_span(e.span()),
                        },
                    )
                    .labelled("get_key block"),
            ))
            .brace_delimited(),
        )))
        .map_with(
            |(flavor, name, (fields, get_key)), e| ast::BaseCommandDefinition {
                flavor,
                name,
                fields,
                get_key,
                span: ast_span(e.span()),
            },
        );

    let function_def = just!(function)
        .ignore_then(group((ident, function_params.clone(), vtype, body.clone())))
        .map_with(
            |(name, parameters, return_type, body), e| ast::FunctionDefinition {
                name,
                parameters,
                return_type,
                body,
                span: ast_span(e.span()),
            },
        );

    let finish_function_def = just!(finish function)
        .ignore_then(group((ident, function_params, body)))
        .map_with(
            |(name, parameters, body), e| ast::FinishFunctionDefinition {
                name,
                parameters,
                body,
                span: ast_span(e.span()),
            },
        );

    let global_let = just!(let)
        .ignore_then(ident)
        .then_ignore(just!(=))
        .then(expression)
        .map_with(|(name, value), e| ast::GlobalLetStatement {
            name,
            value,
            span: ast_span(e.span()),
        });

    choice((
        ffi_import.map(ast::TopLevelItem::FfiImport),
        fact_def.map(ast::TopLevelItem::Fact),
        action_def.map(ast::TopLevelItem::Action),
        effect_def.map(ast::TopLevelItem::Effect),
        struct_def.map(ast::TopLevelItem::Struct),
        enum_def.map(ast::TopLevelItem::Enum),
        command_def.map(ast::TopLevelItem::Command),
        base_command_def.map(ast::TopLevelItem::BaseCommand),
        function_def.map(ast::TopLevelItem::Function),
        finish_function_def.map(ast::TopLevelItem::FinishFunction),
        global_let.map(ast::TopLevelItem::GlobalLet),
    ))
    .labelled("top level item")
}

fn parse_string_literal(full_str: ast::WithSpan<&str>) -> Result<ast::Text, (String, ast::Span)> {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "span calculations are all valid since they are subspans of the full string span"
    )]

    let contents = &full_str[1..full_str.len() - 1];
    let content_span_start = full_str.span.start() + 1;

    let mut it = contents.bytes().enumerate();
    let mut out: Vec<u8> = Vec::new();
    while let Some((idx0, byte0)) = it.next() {
        let byte0_span_start = content_span_start + idx0;
        match byte0 {
            b'\\' => {
                let (idx1, byte1) = it.next().expect("byte must follow escape");
                match byte1 {
                    b'x' => {
                        let mut value = 0_u8;

                        for nibble_idx in 0..2 {
                            let Some((hex_idx, hex_byte)) = it.next() else {
                                let span = ast::Span::new(
                                    byte0_span_start,
                                    byte0_span_start + 2 + nibble_idx,
                                );
                                return Err((
                                    String::from("hex character escape is too short"),
                                    span,
                                ));
                            };
                            let Some(nibble) = hex_char_to_nibble(hex_byte) else {
                                let nonhex_char_length = contents[hex_idx..]
                                    .chars()
                                    .next()
                                    .expect("char is present")
                                    .len_utf8();
                                let start = content_span_start + hex_idx;
                                let span = ast::Span::new(start, start + nonhex_char_length);
                                return Err((
                                    String::from("invalid character in hex character escape"),
                                    span,
                                ));
                            };
                            value = value << 4 | nibble;
                        }

                        if !(0x01..=0x7F).contains(&value) {
                            let span = ast::Span::new(byte0_span_start, byte0_span_start + 4);
                            return Err((
                                String::from("hex character escape is out of range [0x01, 0x7F]"),
                                span,
                            ));
                        }
                        out.push(value);
                    }
                    b'n' => {
                        out.push(b'\n');
                    }
                    b'\\' => {
                        out.push(b'\\');
                    }
                    b'"' => {
                        out.push(b'"');
                    }
                    b'\n' => {
                        let span = ast::Span::new(byte0_span_start, byte0_span_start + 1);
                        return Err((String::from("cannot end line with escape"), span));
                    }
                    _ => {
                        let bad_escape_char =
                            contents[idx1..].chars().next().expect("char is present");
                        let end = byte0_span_start + 1 + bad_escape_char.len_utf8();
                        let span = ast::Span::new(byte0_span_start, end);
                        return Err((
                            format!(
                                "unknown character escape: `{}`",
                                bad_escape_char.escape_default()
                            ),
                            span,
                        ));
                    }
                }
            }
            b'\0' => {
                let span = ast::Span::new(byte0_span_start, byte0_span_start + 1);
                return Err((String::from("string contains null byte"), span));
            }
            b'"' => break,
            _ => out.push(byte0),
        }
    }

    Ok(str::from_utf8(&out)
        .expect("valid utf8")
        .parse()
        .expect("valid text"))
}

fn hex_char_to_nibble(ch: u8) -> Option<u8> {
    #[allow(clippy::arithmetic_side_effects)]
    Some(match ch {
        b'0'..=b'9' => ch - b'0',
        b'a'..=b'f' => ch - b'a' + 10,
        b'A'..=b'F' => ch - b'A' + 10,
        _ => return None,
    })
}

/// Configuration used for contextual parsing.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
struct Config {
    /// Controls whether a named struct literal can be parsed.
    ///
    /// This is used to disambiguate `match name { ... }` and `if name { ... }`.
    /// If you must construct a struct directly in those, add parentheses.
    allow_struct: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { allow_struct: true }
    }
}

impl Config {
    fn allow_struct(&self) -> Self {
        Self {
            allow_struct: true,
            ..*self
        }
    }

    fn disallow_struct(&self) -> Self {
        Self {
            allow_struct: false,
            ..*self
        }
    }
}
