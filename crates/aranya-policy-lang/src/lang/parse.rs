use std::cell::RefCell;

use aranya_policy_ast::{
    self as ast, CheckStatement, CreateStatement, DeleteStatement, EffectFieldDefinition,
    EnumDefinition, EnumReference, ExprKind, Expression, FactField, FactLiteral, FieldDefinition,
    ForeignFunctionCall, FunctionCall, Ident, Identifier, IfStatement, InternalFunction,
    LetStatement, MapStatement, MatchArm, MatchExpression, MatchExpressionArm, MatchPattern,
    MatchStatement, NamedStruct, ReturnStatement, Span as AstSpan, Statement, StmtKind, Text,
    TypeKind, UpdateStatement, VType, Version, ident,
};
use buggy::BugExt;
use pest::{
    Parser, Span,
    error::{InputLocation, LineColLocation},
    iterators::{Pair, Pairs},
    pratt_parser::{Assoc, Op, PrattParser},
};

mod error;
mod markdown;

pub use error::{ParseError, ParseErrorKind};
pub use markdown::{ChunkOffset, extract_policy, parse_policy_document};

mod keywords;
use keywords::KEYWORDS;

mod internal {
    // This is a hack to work around ambiguity between pest_derive::Parser and pest::Parser.
    use pest_derive::Parser;
    #[derive(Parser)]
    #[grammar = "lang/parse/policy.pest"]
    pub struct PolicyParser;
}

// Each of the rules in policy.pest becomes an enumerable value here
// The core parser for policy documents
pub use internal::{PolicyParser, Rule};

/// Captures the iterator over a Pair's contents, and the span
/// information for error reporting.
struct PairContext<'a> {
    pairs: RefCell<Pairs<'a, Rule>>,
    span: Span<'a>,
}

impl<'a> PairContext<'a> {
    fn location_error(&self) -> ParseError {
        ParseError::new(
            ParseErrorKind::Unknown,
            format!("{:?}", &self.span),
            Some(self.span),
        )
    }

    /// Returns the next token from the interior Pairs in case you want
    /// to manipulate it directly.
    fn next(&self) -> Option<Pair<'_, Rule>> {
        self.pairs.borrow_mut().next()
    }

    fn peek(&self) -> Option<Pair<'_, Rule>> {
        self.pairs.borrow_mut().peek()
    }

    /// Consumes the next Pair out of this context and returns it.
    /// Errors if the next pair doesn't exist.
    fn consume(&self) -> Result<Pair<'_, Rule>, ParseError> {
        self.next().ok_or_else(|| self.location_error())
    }

    /// Consumes the next Pair out of this context and returns it if
    /// it matches the given type. Otherwise returns an error.
    fn consume_of_type(&self, rule: Rule) -> Result<Pair<'_, Rule>, ParseError> {
        let token = self.consume()?;
        if token.as_rule() != rule {
            return Err(ParseError::new(
                ParseErrorKind::Unknown,
                format!("Got wrong rule: {:?} expected {:?}", token.as_rule(), rule),
                Some(token.as_span()),
            ));
        }
        Ok(token)
    }

    /// Consumes the next Pair and returns it as a VType. Same error
    /// conditions as [consume]
    fn consume_type(&self, p: &mut ChunkParser<'_>) -> Result<VType, ParseError> {
        let token = self.consume()?;
        let typ = p.parse_type(token)?;
        Ok(typ)
    }

    fn consume_fact(&self, p: &mut ChunkParser<'_>) -> Result<FactLiteral, ParseError> {
        let token = self.consume_of_type(Rule::fact_literal)?;
        p.parse_fact_literal(token)
    }

    /// Consumes the next Pair out of this context and returns it as an
    /// [ast::Expression].
    fn consume_expression(&self, p: &mut ChunkParser<'_>) -> Result<Expression, ParseError> {
        let token = self.consume_of_type(Rule::expression)?;
        p.parse_expression(token)
    }

    /// Consumes the ParserContext and returns the inner Pairs.
    /// Destroys the span context.
    fn into_inner(self) -> Pairs<'a, Rule> {
        self.pairs.into_inner()
    }

    /// Consumes the next Pair out of this context and returns it as a
    /// string that is the identifier if it doesn't collide with a keyword.
    fn consume_identifier(&self) -> Result<Identifier, ParseError> {
        let token = self.consume_of_type(Rule::identifier)?;
        let identifier = token.as_str();

        if KEYWORDS.contains(&identifier) {
            return Err(ParseError::new(
                ParseErrorKind::ReservedIdentifier,
                identifier.to_string(),
                Some(token.as_span()),
            ));
        }

        Ok(identifier
            .parse()
            .assume("grammar produces valid identifiers")?)
    }

    fn consume_optional(&self, rule: Rule) -> Option<Pair<'_, Rule>> {
        self.peek()
            .filter(|p| p.as_rule() == rule)
            .inspect(|_| _ = self.next())
    }
}

/// Helper function which consumes and returns an iterator over the
/// children of a token. Makes the parsing process a little more
/// self-documenting.
fn descend(p: Pair<'_, Rule>) -> PairContext<'_> {
    let span = p.as_span();
    PairContext {
        pairs: RefCell::new(p.into_inner()),
        span,
    }
}

/// Helper function which consumes and returns an iterator over
/// a single token, rather than descending.
fn remain(p: Pair<'_, Rule>) -> PairContext<'_> {
    let span = p.as_span();
    PairContext {
        pairs: RefCell::new(Pairs::single(p)),
        span,
    }
}

/// Context information for partial parsing of a chunk of source
pub struct ChunkParser<'a> {
    offset: usize,
    pratt: &'a PrattParser<Rule>,
    source_len: usize,
}

impl ChunkParser<'_> {
    pub fn new(offset: usize, pratt: &PrattParser<Rule>, source_len: usize) -> ChunkParser<'_> {
        ChunkParser {
            offset,
            pratt,
            source_len,
        }
    }

    /// Convert a Pest span to an AST span with offset
    fn to_ast_span(&self, pest_span: Span<'_>) -> Result<AstSpan, ParseError> {
        let start = pest_span.start().checked_add(self.offset).ok_or_else(|| {
            ParseError::new(
                ParseErrorKind::Unknown,
                String::from("span start overflow"),
                Some(pest_span),
            )
        })?;
        let end = pest_span.end().checked_add(self.offset).ok_or_else(|| {
            ParseError::new(
                ParseErrorKind::Unknown,
                String::from("span end overflow"),
                Some(pest_span),
            )
        })?;

        // Validate that the span doesn't exceed source bounds
        if end > self.source_len {
            return Err(ParseError::new(
                ParseErrorKind::Unknown,
                format!(
                    "Span [{}, {}) exceeds source length {}",
                    start, end, self.source_len
                ),
                Some(pest_span),
            ));
        }

        Ok(AstSpan::new(start, end))
    }

    /// Parse an identifier with span
    #[allow(dead_code)]
    fn parse_ident(&self, token: Pair<'_, Rule>) -> Result<Ident, ParseError> {
        assert_eq!(token.as_rule(), Rule::identifier);
        let span = self.to_ast_span(token.as_span())?;
        let identifier = token.as_str();

        if KEYWORDS.contains(&identifier) {
            return Err(ParseError::new(
                ParseErrorKind::ReservedIdentifier,
                identifier.to_string(),
                Some(token.as_span()),
            ));
        }

        let name = identifier
            .parse()
            .assume("grammar produces valid identifiers")?;
        Ok(Ident::new(name, span))
    }

    /// Parse a type token into the new VType structure with span
    #[allow(dead_code)]
    fn parse_type_new(&self, token: Pair<'_, Rule>) -> Result<VType, ParseError> {
        let span = self.to_ast_span(token.as_span())?;
        let kind = match token.as_rule() {
            Rule::string_t => TypeKind::String,
            Rule::bytes_t => TypeKind::Bytes,
            Rule::int_t => TypeKind::Int,
            Rule::bool_t => TypeKind::Bool,
            Rule::id_t => TypeKind::Id,
            Rule::struct_t => {
                let pc = descend(token.clone());
                let name = pc.consume_identifier()?;
                TypeKind::Struct(name)
            }
            Rule::enum_t => {
                let pc = descend(token.clone());
                let name = pc.consume_identifier()?;
                TypeKind::Enum(name)
            }
            Rule::optional_t => {
                let mut pairs = token.clone().into_inner();
                let inner_token = pairs.next().ok_or_else(|| {
                    ParseError::new(
                        ParseErrorKind::Unknown,
                        String::from("no type following optional"),
                        Some(token.as_span()),
                    )
                })?;
                let inner_type = self.parse_type_new(inner_token)?;
                TypeKind::Optional(Box::new(inner_type))
            }
            _ => {
                return Err(ParseError::new(
                    ParseErrorKind::InvalidType,
                    format!("{:?} {}", token.as_rule(), token.as_str().to_owned()),
                    Some(token.as_span()),
                ));
            }
        };
        Ok(VType::new(kind, span))
    }

    /// Parse a type token (one of the types under Rule::vtype) into a
    /// Parse a type token into a VType.
    fn parse_type(&self, token: Pair<'_, Rule>) -> Result<VType, ParseError> {
        let span = self.to_ast_span(token.as_span())?;
        let kind = match token.as_rule() {
            Rule::string_t => TypeKind::String,
            Rule::bytes_t => TypeKind::Bytes,
            Rule::int_t => TypeKind::Int,
            Rule::bool_t => TypeKind::Bool,
            Rule::id_t => TypeKind::Id,
            Rule::struct_t => {
                let pc = descend(token);
                let name = pc.consume_identifier()?;
                TypeKind::Struct(name)
            }
            Rule::enum_t => {
                let pc = descend(token);
                let name = pc.consume_identifier()?;
                TypeKind::Enum(name)
            }
            Rule::optional_t => {
                let mut pairs = token.clone().into_inner();
                let token = pairs.next().ok_or_else(|| {
                    ParseError::new(
                        ParseErrorKind::Unknown,
                        String::from("no type following optional"),
                        Some(token.as_span()),
                    )
                })?;
                let inner_type = self.parse_type(token)?;
                TypeKind::Optional(Box::new(inner_type))
            }
            _ => {
                return Err(ParseError::new(
                    ParseErrorKind::InvalidType,
                    format!("{:?} {}", token.as_rule(), token.as_str().to_owned()),
                    Some(token.as_span()),
                ));
            }
        };
        Ok(VType { kind, span })
    }

    /// Parse a Rule::field_definition token into a FieldDef.
    fn parse_field_definition(&self, field: Pair<'_, Rule>) -> Result<FieldDefinition, ParseError> {
        let span = self.to_ast_span(field.as_span())?;
        let pc = descend(field);
        let identifier_name = pc.consume_identifier()?;
        let identifier = Ident::new(identifier_name, span);
        let field_type = self.parse_type(pc.pairs.borrow_mut().next().ok_or_else(|| {
            ParseError::new(
                ParseErrorKind::Unknown,
                String::from("missing type in field definition"),
                Some(pc.span),
            )
        })?)?;

        Ok(FieldDefinition {
            identifier,
            field_type,
        })
    }

    fn parse_effect_field_definition(
        &mut self,
        field: Pair<'_, Rule>,
    ) -> Result<EffectFieldDefinition, ParseError> {
        let span = self.to_ast_span(field.as_span())?;
        let pc = descend(field);
        let identifier = pc.consume_identifier()?;
        let field_type = pc.consume_type(self)?;

        let token = pc.next();
        // If there is another token, it has to be the "dynamic" marker
        let dynamic = token.is_some();

        Ok(EffectFieldDefinition {
            identifier: Ident::new(identifier, span),
            field_type,
            dynamic,
        })
    }

    /// Parse a Rule::string_literal into a String.
    ///
    /// Processes \\, \n, and \xNN escapes.
    fn parse_string_literal(string: Pair<'_, Rule>) -> Result<Text, ParseError> {
        let src = string.as_str();
        let it = &mut src.chars();
        let mut out = String::new();
        // consume the first quote character
        if it.next() != Some('"') {
            return Err(ParseError::new(
                ParseErrorKind::InvalidString,
                format!("bad string: {}", src),
                Some(string.as_span()),
            ));
        }
        while let Some(c) = it.next() {
            match c {
                '\\' => {
                    if let Some(next) = it.next() {
                        match next {
                            'x' => {
                                let s: String = it.take(2).collect();
                                let v = u8::from_str_radix(&s, 16).map_err(|e| {
                                    ParseError::new(
                                        ParseErrorKind::InvalidNumber,
                                        format!("{}: {}", s, e),
                                        Some(string.as_span()),
                                    )
                                })?;
                                out.push(v as char);
                            }
                            'n' => {
                                out.push('\n');
                            }
                            _ => {
                                return Err(ParseError::new(
                                    ParseErrorKind::InvalidString,
                                    format!("invalid escape: {}", next),
                                    Some(string.as_span()),
                                ));
                            }
                        }
                    } else {
                        return Err(ParseError::new(
                            ParseErrorKind::InvalidString,
                            String::from("end of string while processing escape"),
                            Some(string.as_span()),
                        ));
                    }
                }
                '"' => break,
                _ => out.push(c),
            }
        }

        out.try_into().map_err(|_| {
            ParseError::new(
                ParseErrorKind::InvalidString,
                String::from("string contained nul byte"),
                Some(string.as_span()),
            )
        })
    }

    fn parse_named_struct_literal(
        &mut self,
        named_struct: Pair<'_, Rule>,
    ) -> Result<NamedStruct, ParseError> {
        let pc = descend(named_struct.clone());
        let identifier_str = pc.consume_identifier()?;
        let identifier_span = self.to_ast_span(named_struct.as_span())?;
        let identifier = Ident::new(identifier_str, identifier_span);

        // key/expression pairs follow the identifier
        let fields = self.parse_kv_literal_fields_new(pc.into_inner())?;
        Ok(NamedStruct { identifier, fields })
    }

    fn parse_function_call(&mut self, call: Pair<'_, Rule>) -> Result<FunctionCall, ParseError> {
        let pc = descend(call.clone());
        let identifier_str = pc.consume_identifier()?;
        let identifier_span = self.to_ast_span(call.as_span())?;
        let identifier = Ident::new(identifier_str, identifier_span);

        // all following tokens are function arguments
        let mut arguments = vec![];
        for arg in pc.into_inner() {
            let expr = self.parse_expression(arg)?;
            arguments.push(expr);
        }
        Ok(FunctionCall {
            identifier,
            arguments,
        })
    }

    fn parse_foreign_function_call(
        &mut self,
        call: Pair<'_, Rule>,
    ) -> Result<ForeignFunctionCall, ParseError> {
        let pc = descend(call.clone());
        let module_str = pc.consume_identifier()?;
        let module_span = self.to_ast_span(call.as_span())?;
        let module = Ident::new(module_str, module_span);
        let function_call = pc.consume_of_type(Rule::function_call)?;

        let function = self.parse_function_call(function_call)?;
        let identifier = function.identifier;
        let arguments = function.arguments;

        Ok(ForeignFunctionCall {
            module,
            identifier,
            arguments,
        })
    }

    /// Parses a Rule::expression into an Expression
    ///
    /// This uses the PrattParser to parse the syntax tree. As a part of
    /// that process, it will further parse some atoms like function calls
    /// and queries.
    ///
    /// The resulting expression tree is degree 2 - all operations are
    /// either unary or binary. That means a string of operators with
    /// equivalent precedence will create a lopsided tree. For example:
    ///
    /// `A + B + C` => `Add(Add(A, B), C)`
    pub fn parse_expression(&mut self, expr: Pair<'_, Rule>) -> Result<Expression, ParseError> {
        assert_eq!(expr.as_rule(), Rule::expression);
        let pairs = expr.into_inner();
        let offset = self.offset;

        // Helper to convert pest span to AST span with offset
        let to_ast_span = move |pest_span: Span<'_>| -> Result<AstSpan, ParseError> {
            let start = pest_span.start().checked_add(offset).ok_or_else(|| {
                ParseError::new(
                    ParseErrorKind::Unknown,
                    String::from("span start overflow"),
                    Some(pest_span),
                )
            })?;
            let end = pest_span.end().checked_add(offset).ok_or_else(|| {
                ParseError::new(
                    ParseErrorKind::Unknown,
                    String::from("span end overflow"),
                    Some(pest_span),
                )
            })?;
            Ok(AstSpan::new(start, end))
        };

        self.pratt
            .map_primary(|primary| match primary.as_rule() {
                Rule::int_literal => {
                    let n = primary.as_str().parse::<i64>().map_err(|e| {
                        ParseError::new(
                            ParseErrorKind::InvalidNumber,
                            e.to_string(),
                            Some(primary.as_span()),
                        )
                    })?;
                    let span = to_ast_span(primary.as_span())?;
                    Ok(Expression::new(ExprKind::Int(n), span))
                }
                Rule::string_literal => {
                    let span = to_ast_span(primary.as_span())?;
                    let s = Self::parse_string_literal(primary)?;
                    Ok(Expression::new(ExprKind::String(s), span))
                }
                Rule::bool_literal => {
                    let mut pairs = primary.clone().into_inner();
                    let token = pairs.next().ok_or_else(|| {
                        ParseError::new(
                            ParseErrorKind::Unknown,
                            String::from("bad bool expression"),
                            Some(primary.as_span()),
                        )
                    })?;
                    match token.as_rule() {
                        Rule::btrue => {
                            let span = to_ast_span(primary.as_span())?;
                            Ok(Expression::new(ExprKind::Bool(true), span))
                        }
                        Rule::bfalse => {
                            let span = to_ast_span(primary.as_span())?;
                            Ok(Expression::new(ExprKind::Bool(false), span))
                        }
                        t => Err(ParseError::new(
                            ParseErrorKind::Unknown,
                            format!("impossible token: {:?}", t),
                            Some(primary.as_span()),
                        )),
                    }
                }
                Rule::optional_literal => {
                    let mut pairs = primary.clone().into_inner();
                    let token = pairs.next().ok_or_else(|| {
                        ParseError::new(
                            ParseErrorKind::Unknown,
                            String::from("no token in optional literal"),
                            Some(primary.as_span()),
                        )
                    })?;
                    let span = to_ast_span(primary.as_span())?;
                    let opt_expr = match token.as_rule() {
                        Rule::none => None,
                        Rule::some => {
                            let token = pairs.next().ok_or_else(|| {
                                ParseError::new(
                                    ParseErrorKind::Unknown,
                                    String::from("bad Some expression"),
                                    Some(primary.as_span()),
                                )
                            })?;
                            let e = self.parse_expression(token)?;
                            Some(Box::new(e))
                        }
                        t => {
                            return Err(ParseError::new(
                                ParseErrorKind::Unknown,
                                format!("invalid token in optional: {:?}", t),
                                Some(primary.as_span()),
                            ))
                        }
                    };
                    Ok(Expression::new(ExprKind::Optional(opt_expr), span))
                }
                Rule::named_struct_literal => {
                    let span = to_ast_span(primary.as_span())?;
                    let ns = self.parse_named_struct_literal(primary)?;
                    Ok(Expression::new(ExprKind::NamedStruct(ns), span))
                }
                Rule::function_call => {
                    let span = to_ast_span(primary.as_span())?;
                    let fc = self.parse_function_call(primary)?;
                    Ok(Expression::new(ExprKind::FunctionCall(fc), span))
                }
                Rule::foreign_function_call => {
                    let span = to_ast_span(primary.as_span())?;
                    let ffc = self.parse_foreign_function_call(primary)?;
                    Ok(Expression::new(ExprKind::ForeignFunctionCall(ffc), span))
                }
                Rule::enum_reference => {
                    let span = to_ast_span(primary.as_span())?;
                    let er = self.parse_enum_reference(primary)?;
                    Ok(Expression::new(ExprKind::EnumReference(er), span))
                }
                Rule::query => {
                    let mut pairs = primary.clone().into_inner();
                    let token = pairs.next().ok_or_else(|| {
                        ParseError::new(
                            ParseErrorKind::InvalidFunctionCall,
                            String::from("query requires fact literal"),
                            Some(primary.as_span()),
                        )
                    })?;
                    let fact_literal = self.parse_fact_literal(token)?;
                    let span = to_ast_span(primary.as_span())?;
                    Ok(Expression::new(ExprKind::InternalFunction(InternalFunction::Query(
                        fact_literal,
                    )), span))
                }
                Rule::exists => {
                    let mut pairs = primary.clone().into_inner();
                    let token = pairs.next().ok_or_else(|| {
                        ParseError::new(
                            ParseErrorKind::InvalidFunctionCall,
                            String::from("exists requires fact literal"),
                            Some(primary.as_span()),
                        )
                    })?;
                    let fact_literal = self.parse_fact_literal(token)?;
                    let span = to_ast_span(primary.as_span())?;
                    Ok(Expression::new(ExprKind::InternalFunction(InternalFunction::Exists(
                        fact_literal,
                    )), span))
                }
                Rule::count_up_to => self.parse_counting_fn(primary, ast::FactCountType::UpTo),
                Rule::at_least => self.parse_counting_fn(primary, ast::FactCountType::AtLeast),
                Rule::at_most => self.parse_counting_fn(primary, ast::FactCountType::AtMost),
                Rule::exactly => self.parse_counting_fn(primary, ast::FactCountType::Exactly),
                Rule::match_expression => self.parse_match_expression(primary),
                Rule::if_expr => self.parse_if_expression(primary),
                Rule::serialize => {
                    let mut pairs = primary.clone().into_inner();
                    let token = pairs.next().ok_or_else(|| {
                        ParseError::new(
                            ParseErrorKind::InvalidFunctionCall,
                            String::from("empty serialize function"),
                            Some(primary.as_span()),
                        )
                    })?;
                    let inner = self.parse_expression(token)?;
                    let span = to_ast_span(primary.as_span())?;
                    Ok(Expression::new(ExprKind::InternalFunction(
                        InternalFunction::Serialize(Box::new(inner)),
                    ), span))
                }
                Rule::deserialize => {
                    let mut pairs = primary.clone().into_inner();
                    let token = pairs.next().ok_or_else(|| {
                        ParseError::new(
                            ParseErrorKind::InvalidFunctionCall,
                            String::from("empty deserialize function"),
                            Some(primary.as_span()),
                        )
                    })?;
                    let inner = self.parse_expression(token)?;
                    let span = to_ast_span(primary.as_span())?;
                    Ok(Expression::new(ExprKind::InternalFunction(
                        InternalFunction::Deserialize(Box::new(inner)),
                    ), span))
                }
                Rule::this => {
                    let span = to_ast_span(primary.as_span())?;
                    Ok(Expression::new(ExprKind::Identifier(ident!("this")), span))
                }
                Rule::todo => {
                    let span = to_ast_span(primary.as_span())?;
                    Ok(Expression::new(ExprKind::InternalFunction(InternalFunction::Todo), span))
                }
                Rule::identifier => {
                    let span = to_ast_span(primary.as_span())?;
                    let ident = remain(primary).consume_identifier()?;
                    Ok(Expression::new(ExprKind::Identifier(ident), span))
                }
                Rule::block_expression => self.parse_block_expression(primary),
                Rule::expression => self.parse_expression(primary),
                _ => Err(ParseError::new(
                    ParseErrorKind::Expression,
                    format!("bad atom: {:?}", primary.as_rule()),
                    Some(primary.as_span()),
                )),
            })
            .map_prefix(|op, rhs| {
                let rhs = rhs?;
                let op_span = to_ast_span(op.as_span())?;
                let combined_span = op_span.merge(&rhs.span);

                let kind = match op.as_rule() {
                    Rule::neg => {
                        match &rhs.kind {
                            ExprKind::Int(n) => {
                                let neg_n = n.checked_neg().ok_or_else(|| {
                                    ParseError::new(
                                        ParseErrorKind::InvalidNumber,
                                        format!("Negation of {} overflows", n),
                                        Some(op.as_span()),
                                    )
                                })?;
                                ExprKind::Int(neg_n)
                            }
                            _ => ExprKind::Negative(Box::new(rhs))
                        }
                    }
                    Rule::not => ExprKind::Not(Box::new(rhs)),
                    Rule::unwrap => ExprKind::Unwrap(Box::new(rhs)),
                    Rule::check_unwrap => ExprKind::CheckUnwrap(Box::new(rhs)),
                    _ => {
                        return Err(ParseError::new(
                            ParseErrorKind::Expression,
                            format!("bad prefix: {:?}", op.as_rule()),
                            Some(op.as_span()),
                        ))
                    }
                };
                Ok(Expression::new(kind, combined_span))
            })
            .map_infix(|lhs, op, rhs| {
                let lhs = lhs?;
                let rhs = rhs?;
                let combined_span = lhs.span.merge(&rhs.span);

                let kind = match op.as_rule() {
                    Rule::add => ExprKind::Add(Box::new(lhs), Box::new(rhs)),
                    Rule::subtract => ExprKind::Subtract(Box::new(lhs), Box::new(rhs)),
                    Rule::and => ExprKind::And(Box::new(lhs), Box::new(rhs)),
                    Rule::or => ExprKind::Or(Box::new(lhs), Box::new(rhs)),
                    Rule::equal => ExprKind::Equal(Box::new(lhs), Box::new(rhs)),
                    Rule::not_equal => ExprKind::NotEqual(Box::new(lhs), Box::new(rhs)),
                    Rule::greater_than => ExprKind::GreaterThan(Box::new(lhs), Box::new(rhs)),
                    Rule::less_than => ExprKind::LessThan(Box::new(lhs), Box::new(rhs)),
                    Rule::greater_than_or_equal => ExprKind::GreaterThanOrEqual(Box::new(lhs), Box::new(rhs)),
                    Rule::less_than_or_equal => ExprKind::LessThanOrEqual(Box::new(lhs), Box::new(rhs)),
                    Rule::dot => match &rhs.kind {
                        ExprKind::Identifier(s) => ExprKind::Dot(Box::new(lhs), Ident::new(s.clone(), rhs.span)),
                        _ => {
                            return Err(ParseError::new(
                                ParseErrorKind::InvalidMember,
                                format!("Expected identifier after dot, got {:?}", rhs.kind),
                                Some(op.as_span()),
                            ))
                        }
                    },
                    Rule::substruct => match &rhs.kind {
                        ExprKind::Identifier(s) => ExprKind::Substruct(Box::new(lhs), Ident::new(s.clone(), rhs.span)),
                        _ => {
                            return Err(ParseError::new(
                                ParseErrorKind::InvalidSubstruct,
                                format!("Expression to the right of the substruct operator must be an identifier, got {:?}", rhs.kind),
                                Some(op.as_span()),
                            ))
                        }
                    },
                    _ => {
                        return Err(ParseError::new(
                            ParseErrorKind::Expression,
                            format!("bad infix: {:?}", op.as_rule()),
                            Some(op.as_span()),
                        ))
                    }
                };
                Ok(Expression::new(kind, combined_span))
            })
            .map_postfix(|lhs, op| {
                let lhs = lhs?;
                let op_pest_span = op.as_span();
                let op_span = to_ast_span(op_pest_span)?;
                let combined_span = lhs.span.merge(&op_span);

                let kind = match op.as_rule() {
                    Rule::is => {
                        let mut pairs = op.into_inner();
                        let token = pairs.next().ok_or_else(|| {
                            ParseError::new(
                                ParseErrorKind::InvalidFunctionCall,
                                String::from("is requires some or none"),
                                Some(op_pest_span),
                            )
                        })?;
                        let some = match token.as_rule() {
                            Rule::some => true,
                            Rule::none => false,
                            _ => {
                                return Err(ParseError::new(
                                    ParseErrorKind::Unknown,
                                    format!("not none or some after is: {:?}", token.as_rule()),
                                    Some(token.as_span()),
                                ))
                            }
                        };
                        ExprKind::Is(Box::new(lhs), some)
                    }
                    _ => {
                        return Err(ParseError::new(
                            ParseErrorKind::Expression,
                            format!("bad postfix: {:?}", op.as_rule()),
                            Some(op_pest_span),
                        ))
                    }
                };
                Ok(Expression::new(kind, combined_span))
            })
            .parse(pairs)
    }

    fn parse_block_expression(&mut self, expr: Pair<'_, Rule>) -> Result<Expression, ParseError> {
        let pc = descend(expr.clone());
        let statements = pc.consume()?.into_inner();
        let statement_list = self.parse_statement_list(statements)?;
        let inner_expr = pc.consume_expression(self)?;
        let span = self.to_ast_span(expr.as_span())?;
        let stmt_vec = statement_list;
        Ok(Expression::new(
            ExprKind::Block(stmt_vec, Box::new(inner_expr)),
            span,
        ))
    }

    fn parse_match_expression(&mut self, expr: Pair<'_, Rule>) -> Result<Expression, ParseError> {
        let span = self.to_ast_span(expr.as_span())?;
        let pc = descend(expr);
        let scrutinee = pc.consume_expression(self)?;

        // All remaining tokens are match arms
        let mut arms = vec![];
        for arm in pc.into_inner() {
            assert_eq!(arm.as_rule(), Rule::match_expression_arm);
            let pc = descend(arm.to_owned());
            let token = pc.consume()?;

            let pattern = match token.as_rule() {
                Rule::match_default => MatchPattern::Default,
                Rule::match_arm_expression => {
                    let values = token
                        .into_inner()
                        .map(|token| self.parse_expression(token.to_owned()))
                        .collect::<Result<Vec<Expression>, ParseError>>()?;

                    MatchPattern::Values(values)
                }
                _ => {
                    return Err(ParseError::new(
                        ParseErrorKind::Unknown,
                        String::from("invalid token in match arm"),
                        Some(token.as_span()),
                    ));
                }
            };

            // Remaining tokens are policy statements
            let expression = self.parse_expression(pc.consume()?)?;

            let arm_span = self.to_ast_span(arm.as_span())?;
            arms.push(MatchExpressionArm {
                pattern,
                expression,
                span: arm_span,
            });
        }

        Ok(Expression::new(
            ExprKind::Match(Box::new(MatchExpression { scrutinee, arms })),
            span,
        ))
    }

    fn parse_counting_fn(
        &mut self,
        statement: Pair<'_, Rule>,
        cmp_type: ast::FactCountType,
    ) -> Result<Expression, ParseError> {
        let mut pairs = statement.clone().into_inner();
        let token = pairs.next().ok_or_else(|| {
            ParseError::new(
                ParseErrorKind::Expression,
                format!("{} requires count limit (int)", cmp_type),
                Some(statement.as_span()),
            )
        })?;
        let limit = token.as_str().parse::<i64>().map_err(|e| {
            ParseError::new(
                ParseErrorKind::InvalidNumber,
                e.to_string(),
                Some(statement.as_span()),
            )
        })?;
        let token = pairs.next().ok_or_else(|| {
            ParseError::new(
                ParseErrorKind::Expression,
                format!("{} requires fact literal", cmp_type),
                Some(statement.as_span()),
            )
        })?;
        let fact = self.parse_fact_literal(token)?;
        let span = self.to_ast_span(statement.as_span())?;
        Ok(Expression::new(
            ExprKind::InternalFunction(InternalFunction::FactCount(cmp_type, limit, fact)),
            span,
        ))
    }

    fn parse_if_expression(&mut self, expr: Pair<'_, Rule>) -> Result<Expression, ParseError> {
        let mut pairs = expr.clone().into_inner();
        let token = pairs.next().ok_or_else(|| {
            ParseError::new(
                ParseErrorKind::InvalidFunctionCall,
                String::from("if requires expression"),
                Some(expr.as_span()),
            )
        })?;
        let condition = self.parse_expression(token)?;

        let token = pairs.next().ok_or_else(|| {
            ParseError::new(
                ParseErrorKind::InvalidFunctionCall,
                String::from("if requires then case"),
                Some(expr.as_span()),
            )
        })?;
        let then_expr = self.parse_block_expression(token)?;

        let token = pairs.next().ok_or_else(|| {
            ParseError::new(
                ParseErrorKind::InvalidFunctionCall,
                String::from("if requires else case"),
                Some(expr.as_span()),
            )
        })?;
        let else_expr = self.parse_block_expression(token)?;

        let span = self.to_ast_span(expr.as_span())?;
        Ok(Expression::new(
            ExprKind::InternalFunction(InternalFunction::If(
                Box::new(condition),
                Box::new(then_expr),
                Box::new(else_expr),
            )),
            span,
        ))
    }

    /// Parses a list of Rule::struct_literal_field items into (String,
    /// Expression) pairs.
    ///
    /// This is used any place where something looks like a struct literal -
    /// fact key/values, publish, and effects.
    #[allow(dead_code)]
    fn parse_kv_literal_fields(
        &mut self,
        fields: Pairs<'_, Rule>,
    ) -> Result<Vec<(Identifier, Expression)>, ParseError> {
        let mut out = vec![];

        for field in fields {
            let pc = descend(field);
            let identifier = pc.consume_identifier()?;
            let expression = pc.consume_expression(self)?;
            out.push((identifier, expression));
        }

        Ok(out)
    }

    /// New version that returns new types with spans
    fn parse_kv_literal_fields_new(
        &mut self,
        fields: Pairs<'_, Rule>,
    ) -> Result<Vec<(Ident, Expression)>, ParseError> {
        let mut out = vec![];

        for field in fields {
            let pc = descend(field.clone());
            let identifier_str = pc.consume_identifier()?;
            let field_span = self.to_ast_span(field.as_span())?;
            let identifier = Ident::new(identifier_str, field_span);
            let expression = pc.consume_expression(self)?;
            out.push((identifier, expression));
        }

        Ok(out)
    }

    fn parse_fact_literal_fields(
        &mut self,
        fields: Pairs<'_, Rule>,
    ) -> Result<Vec<(Identifier, FactField)>, ParseError> {
        let mut out = vec![];

        for field in fields {
            let pc = descend(field);
            let identifier = pc.consume_identifier()?;

            let token = pc.consume()?;
            let field = match token.as_rule() {
                Rule::expression => FactField::Expression(self.parse_expression(token)?),
                Rule::bind => FactField::Bind,
                _ => {
                    return Err(ParseError::new(
                        ParseErrorKind::Unknown,
                        String::from("invalid token in fact field"),
                        Some(token.as_span()),
                    ));
                }
            };
            out.push((identifier, field));
        }

        Ok(out)
    }

    /// New version that returns new types with spans
    fn parse_fact_literal_fields_new(
        &mut self,
        fields: Pairs<'_, Rule>,
    ) -> Result<Vec<(Ident, FactField)>, ParseError> {
        let mut out = vec![];

        for field in fields {
            let pc = descend(field.clone());
            let identifier_str = pc.consume_identifier()?;
            let span = self.to_ast_span(field.as_span())?;
            let identifier = Ident::new(identifier_str, span);

            let token = pc.consume()?;
            let field_value = match token.as_rule() {
                Rule::expression => FactField::Expression(self.parse_expression(token)?),
                Rule::bind => FactField::Bind,
                _ => {
                    return Err(ParseError::new(
                        ParseErrorKind::Unknown,
                        String::from("invalid token in fact field"),
                        Some(token.as_span()),
                    ));
                }
            };
            out.push((identifier, field_value));
        }

        Ok(out)
    }

    fn parse_action_call(&mut self, item: Pair<'_, Rule>) -> Result<FunctionCall, ParseError> {
        assert_eq!(item.as_rule(), Rule::action_call);

        let pc = descend(item);
        let fn_call = pc.consume()?;
        let action_call = self.parse_function_call(fn_call)?;
        Ok(action_call)
    }

    /// Parse a Rule::publish_statement into an PublishStatement.
    fn parse_publish_statement(&mut self, item: Pair<'_, Rule>) -> Result<Expression, ParseError> {
        assert_eq!(item.as_rule(), Rule::publish_statement);

        let pc = descend(item);
        let expression = pc.consume_expression(self)?;

        Ok(expression)
    }

    /// Parse a Rule::fact_literal into a FactLiteral.
    fn parse_fact_literal(&mut self, fact: Pair<'_, Rule>) -> Result<FactLiteral, ParseError> {
        let pc = descend(fact.clone());
        let identifier_str = pc.consume_identifier()?;
        let span = self.to_ast_span(fact.as_span())?;
        let identifier = Ident::new(identifier_str, span);

        let token = pc.consume_of_type(Rule::fact_literal_key)?;
        let key_fields = self.parse_fact_literal_fields_new(token.into_inner())?;

        let value_fields = if pc.peek().is_some() {
            let token = pc.consume_of_type(Rule::fact_literal_value)?;
            Some(self.parse_fact_literal_fields_new(token.into_inner())?)
        } else {
            None
        };

        Ok(FactLiteral {
            identifier,
            key_fields,
            value_fields,
        })
    }

    /// Parse a Rule::let_statement into a LetStatement.
    fn parse_let_statement(&mut self, item: Pair<'_, Rule>) -> Result<LetStatement, ParseError> {
        let pc = descend(item);
        let identifier = pc.consume_identifier()?;
        let expression = pc.consume_expression(self)?;

        Ok(LetStatement {
            identifier,
            expression,
        })
    }

    /// Parse a Rule::check_statement into a CheckStatement.
    fn parse_check_statement(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<CheckStatement, ParseError> {
        let pc = descend(item);
        let token = pc.consume()?;
        let expression = self.parse_expression(token)?;

        Ok(CheckStatement { expression })
    }

    /// Parse a Rule::match_statement into a MatchStatement.
    fn parse_match_statement(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<MatchStatement, ParseError> {
        let pc = descend(item);
        let expression = pc.consume_expression(self)?;

        // All remaining tokens are match arms
        let mut arms = vec![];
        for arm in pc.into_inner() {
            assert_eq!(arm.as_rule(), Rule::match_arm);
            let pc = descend(arm.to_owned());
            let token = pc.consume()?;

            let pattern = match token.as_rule() {
                Rule::match_default => MatchPattern::Default,
                Rule::match_arm_expression => {
                    let values = token
                        .into_inner()
                        .map(|token| {
                            let expr = self.parse_expression(token.to_owned())?;
                            Ok(expr)
                        })
                        .collect::<Result<Vec<Expression>, ParseError>>()?;

                    MatchPattern::Values(values)
                }
                _ => {
                    return Err(ParseError::new(
                        ParseErrorKind::Unknown,
                        String::from("invalid token in match arm"),
                        Some(token.as_span()),
                    ));
                }
            };

            // Remaining tokens are policy statements
            let statements = self.parse_statement_list(pc.into_inner())?;

            arms.push(MatchArm {
                pattern,
                statements,
            });
        }

        Ok(MatchStatement { expression, arms })
    }

    /// Parse a rule::if_statement into a IfStatement
    fn parse_if_statement(&mut self, item: Pair<'_, Rule>) -> Result<IfStatement, ParseError> {
        let pc = descend(item);

        let mut branches = Vec::new();
        let mut fallback = None;

        let mut iter = pc.into_inner();
        while let Some(first) = iter.next() {
            if let Some(second) = iter.next() {
                let cond = self.parse_expression(first)?;
                let block = self.parse_statement_list(second.into_inner())?;
                branches.push((cond, block));
            } else {
                let statements = self.parse_statement_list(first.into_inner())?;
                fallback = Some(statements);
            }
        }

        Ok(IfStatement { branches, fallback })
    }

    /// Parse a Rule::create_statement into a CreateStatement.
    fn parse_create_statement(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<CreateStatement, ParseError> {
        let pc = descend(item);
        let fact = pc.consume_fact(self)?;

        Ok(CreateStatement { fact })
    }

    /// Parse a Rule::update_statement into an UpdateStatement.
    fn parse_update_statement(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<UpdateStatement, ParseError> {
        assert_eq!(item.as_rule(), Rule::update_statement);

        let pc = descend(item);
        let fact = pc.consume_fact(self)?;

        let token = pc.consume_of_type(Rule::fact_literal_value)?;
        let to = self.parse_fact_literal_fields(token.into_inner())?;

        let to_with_idents = to
            .into_iter()
            .map(|(ident, value)| (Ident::new(ident, fact.identifier.span), value))
            .collect();
        Ok(UpdateStatement {
            fact,
            to: to_with_idents,
        })
    }

    /// Parse a Rule::delete_statement into a DeleteStatement.
    fn parse_delete_statement(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<DeleteStatement, ParseError> {
        let pc = descend(item);
        let fact = pc.consume_fact(self)?;

        Ok(DeleteStatement { fact })
    }

    /// Parse a Rule::emit_statement into an EmitStatement.
    fn parse_emit_statement(&mut self, item: Pair<'_, Rule>) -> Result<Expression, ParseError> {
        assert_eq!(item.as_rule(), Rule::emit_statement);

        let pc = descend(item);
        let expression = pc.consume_expression(self)?;

        Ok(expression)
    }

    /// Parse a Rule::return_statementinto a ReturnStatement.
    fn parse_return_statement(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<ReturnStatement, ParseError> {
        let pc = descend(item);
        let expression = pc.consume_expression(self)?;

        Ok(ReturnStatement { expression })
    }

    /// Parse a Rule::effect_statement into an DebugAssert.
    fn parse_debug_assert_statement(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<Expression, ParseError> {
        assert_eq!(item.as_rule(), Rule::debug_assert);

        let pc = descend(item);
        let expression = pc.consume_expression(self)?;

        Ok(expression)
    }

    /// Parse a list of statements inside a finish block.
    ///
    /// Valid in this context:
    /// - [CreateStatement](ast::CreateStatement)
    /// - [UpdateStatement](ast::UpdateStatement)
    /// - [DeleteStatement](ast::DeleteStatement)
    /// - [EffectStatement](ast::EffectStatement)
    fn parse_statement_list(
        &mut self,
        list: Pairs<'_, Rule>,
    ) -> Result<Vec<Statement>, ParseError> {
        let mut statements = vec![];
        for statement in list {
            let span = self.to_ast_span(statement.as_span())?;
            let kind = match statement.as_rule() {
                Rule::let_statement => StmtKind::Let(self.parse_let_statement(statement)?),
                Rule::action_call => StmtKind::ActionCall(self.parse_action_call(statement)?),
                Rule::publish_statement => {
                    StmtKind::Publish(self.parse_publish_statement(statement)?)
                }
                Rule::check_statement => StmtKind::Check(self.parse_check_statement(statement)?),
                Rule::match_statement => StmtKind::Match(self.parse_match_statement(statement)?),
                Rule::if_statement => StmtKind::If(self.parse_if_statement(statement)?),
                Rule::return_statement => StmtKind::Return(self.parse_return_statement(statement)?),
                Rule::finish_statement => {
                    let pairs = statement.into_inner();
                    let finish_stmts = self.parse_statement_list(pairs)?;
                    StmtKind::Finish(finish_stmts)
                }
                Rule::map_statement => StmtKind::Map(self.parse_map_statement(statement)?),
                Rule::create_statement => StmtKind::Create(self.parse_create_statement(statement)?),
                Rule::update_statement => StmtKind::Update(self.parse_update_statement(statement)?),
                Rule::delete_statement => StmtKind::Delete(self.parse_delete_statement(statement)?),
                Rule::emit_statement => StmtKind::Emit(self.parse_emit_statement(statement)?),
                Rule::function_call => StmtKind::FunctionCall(self.parse_function_call(statement)?),
                Rule::debug_assert => {
                    StmtKind::DebugAssert(self.parse_debug_assert_statement(statement)?)
                }
                s => {
                    return Err(ParseError::new(
                        ParseErrorKind::InvalidStatement,
                        format!("found invalid rule `{:?}`", s),
                        Some(statement.as_span()),
                    ));
                }
            };
            statements.push(Statement::new(kind, span));
        }

        Ok(statements)
    }

    fn parse_map_statement(&mut self, field: Pair<'_, Rule>) -> Result<MapStatement, ParseError> {
        assert_eq!(field.as_rule(), Rule::map_statement);
        let pc = descend(field);
        let pair = pc.consume()?;
        let fact = self.parse_fact_literal(pair)?;
        let identifier = pc.consume_identifier()?;
        let statements = self.parse_statement_list(pc.into_inner())?;

        Ok(MapStatement {
            fact,
            identifier,
            statements,
        })
    }

    fn parse_use_definition(&mut self, field: Pair<'_, Rule>) -> Result<Identifier, ParseError> {
        let pc = descend(field);
        let identifier = pc.consume_identifier()?;
        Ok(identifier)
    }

    /// Parse a Rule::fact_definition into a FactDefinition.
    fn parse_fact_definition(
        &mut self,
        field: Pair<'_, Rule>,
    ) -> Result<ast::FactDefinition, ParseError> {
        let span = self.to_ast_span(field.as_span())?;
        let pc = descend(field);
        let token = pc.consume()?;

        let (immutable, token) = if token.as_rule() == Rule::immutable_modifier {
            (true, pc.consume_of_type(Rule::fact_signature)?)
        } else {
            (false, token)
        };

        let pc = descend(token);
        let identifier = pc.consume_identifier()?;
        let token = pc.consume_of_type(Rule::fact_signature_key)?;
        let mut key = vec![];
        for field in token.into_inner() {
            key.push(self.parse_field_definition(field)?);
        }

        let token = pc.consume_of_type(Rule::fact_signature_value)?;
        let mut value = vec![];
        for field in token.into_inner() {
            value.push(self.parse_field_definition(field)?);
        }

        Ok(ast::FactDefinition {
            immutable,
            identifier,
            key,
            value,
            span,
        })
    }

    /// Parse a `Rule::action_definition` into an [ActionDefinition](ast::ActionDefinition).
    fn parse_action_definition(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<ast::ActionDefinition, ParseError> {
        assert_eq!(item.as_rule(), Rule::action_definition);

        let span = self.to_ast_span(item.as_span())?;
        let pc = descend(item);
        let persistence = pc
            .consume_optional(Rule::ephemeral_modifier)
            .map_or(ast::Persistence::Persistent, |_| {
                ast::Persistence::Ephemeral
            });
        let identifier = pc.consume_identifier()?;
        let token = pc.consume_of_type(Rule::function_arguments)?;
        let mut arguments = vec![];
        for field in token.into_inner() {
            arguments.push(self.parse_field_definition(field)?);
        }

        // All remaining tokens are statements
        let list = pc.into_inner();
        let statements = self.parse_statement_list(list)?;

        Ok(ast::ActionDefinition {
            persistence,
            identifier,
            arguments,
            statements,
            span,
        })
    }

    /// Parse a `Rule::effect_definition` into an [EffectDefinition](ast::EffectDefinition).
    fn parse_effect_definition(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<ast::EffectDefinition, ParseError> {
        assert_eq!(item.as_rule(), Rule::effect_definition);

        let span = self.to_ast_span(item.as_span())?;
        let pc = descend(item);
        let identifier = pc.consume_identifier()?;

        // All remaining tokens are fields
        let mut items = vec![];
        for field in pc.into_inner() {
            match field.as_rule() {
                Rule::effect_field_definition => items.push(ast::StructItem::Field(
                    self.parse_effect_field_definition(field)?,
                )),
                Rule::field_insertion => {
                    let ident = descend(field).consume_identifier()?;
                    items.push(ast::StructItem::StructRef(ident));
                }
                _ => {
                    return Err(ParseError::new(
                        ParseErrorKind::Unknown,
                        String::from("invalid token in effect definition"),
                        Some(field.as_span()),
                    ));
                }
            }
        }

        Ok(ast::EffectDefinition {
            identifier,
            items,
            span,
        })
    }

    /// Parse a `Rule::struct_definition` into an [StructDefinition](ast::StructDefinition).
    fn parse_struct_definition(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<ast::StructDefinition, ParseError> {
        assert_eq!(item.as_rule(), Rule::struct_definition);

        let span = self.to_ast_span(item.as_span())?;
        let pc = descend(item);
        let identifier = pc.consume_identifier()?;

        // All remaining tokens are fields
        let mut items = vec![];
        for field in pc.into_inner() {
            match field.as_rule() {
                Rule::field_definition => {
                    items.push(ast::StructItem::Field(self.parse_field_definition(field)?))
                }
                Rule::field_insertion => {
                    let ident = descend(field).consume_identifier()?;
                    items.push(ast::StructItem::StructRef(ident));
                }
                _ => {
                    return Err(ParseError::new(
                        ParseErrorKind::Unknown,
                        String::from("invalid token in struct definition"),
                        Some(field.as_span()),
                    ));
                }
            }
        }

        Ok(ast::StructDefinition {
            identifier,
            items,
            span,
        })
    }

    fn parse_enum_definition(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<EnumDefinition, ParseError> {
        assert_eq!(item.as_rule(), Rule::enum_definition);

        let span = self.to_ast_span(item.as_span())?;
        let pc = descend(item);
        let identifier = pc.consume_identifier()?;
        let mut variants = Vec::<Identifier>::new();
        for value in pc.into_inner() {
            let value = remain(value).consume_identifier()?;
            variants.push(value);
        }

        Ok(EnumDefinition {
            identifier: Ident::new(identifier, span),
            variants: variants.into_iter().map(|v| Ident::new(v, span)).collect(),
            span,
        })
    }

    fn parse_enum_reference(&self, item: Pair<'_, Rule>) -> Result<EnumReference, ParseError> {
        assert_eq!(item.as_rule(), Rule::enum_reference);

        let pc = descend(item.clone());
        let identifier_str = pc.consume_identifier()?;
        let value_str = pc.consume_identifier()?;

        let span = self.to_ast_span(item.as_span())?;
        let identifier = Ident::new(identifier_str, span);
        let value = Ident::new(value_str, span);

        Ok(EnumReference { identifier, value })
    }

    /// Parse a `Rule::command_definition` into an [CommandDefinition](ast::CommandDefinition).
    fn parse_command_definition(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<ast::CommandDefinition, ParseError> {
        assert_eq!(item.as_rule(), Rule::command_definition);

        let span = self.to_ast_span(item.as_span())?;

        let pc = descend(item);
        let persistence = pc
            .consume_optional(Rule::ephemeral_modifier)
            .map_or(ast::Persistence::Persistent, |_| {
                ast::Persistence::Ephemeral
            });
        let identifier = pc.consume_identifier()?;

        let mut attributes = vec![];
        let mut fields = vec![];
        let mut policy = vec![];
        let mut recall = vec![];
        let mut seal = vec![];
        let mut open = vec![];
        for token in pc.into_inner() {
            match token.as_rule() {
                Rule::attributes_block => {
                    let pairs = token.into_inner();
                    for field in pairs {
                        let pc = descend(field);
                        let identifier = pc.consume_identifier()?;
                        let expr = pc.consume_expression(self)?;
                        attributes.push((identifier, expr));
                    }
                }
                Rule::fields_block => {
                    let pairs = token.into_inner();
                    for field in pairs {
                        match field.as_rule() {
                            Rule::field_definition => {
                                fields.push(ast::StructItem::Field(
                                    self.parse_field_definition(field)?,
                                ));
                            }
                            Rule::field_insertion => {
                                let ident = descend(field).consume_identifier()?;
                                fields.push(ast::StructItem::StructRef(ident));
                            }
                            _ => {
                                return Err(ParseError::new(
                                    ParseErrorKind::Unknown,
                                    String::from("invalid token in command definition"),
                                    Some(field.as_span()),
                                ));
                            }
                        }
                    }
                }
                Rule::policy_block => {
                    let pairs = token.into_inner();
                    policy = self.parse_statement_list(pairs)?;
                }
                Rule::recall_block => {
                    let pairs = token.into_inner();
                    recall = self.parse_statement_list(pairs)?;
                }
                Rule::seal_block => {
                    let pairs = token.into_inner();
                    seal = self.parse_statement_list(pairs)?;
                }
                Rule::open_block => {
                    let pairs = token.into_inner();
                    open = self.parse_statement_list(pairs)?;
                }
                t => {
                    return Err(ParseError::new(
                        ParseErrorKind::InvalidStatement,
                        format!("found {:?} in command definition", t),
                        Some(token.as_span()),
                    ));
                }
            }
        }

        Ok(ast::CommandDefinition {
            persistence,
            attributes,
            identifier,
            fields,
            seal,
            open,
            policy,
            recall,
            span,
        })
    }

    /// Parse only the declaration of a function. Works for both `Rule::function_decl` and
    /// `Rule::finish_function_decl`.
    fn parse_function_decl(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<ast::FunctionDecl, ParseError> {
        let rule = item.as_rule();

        assert!(matches!(
            rule,
            Rule::function_decl | Rule::finish_function_decl
        ));

        let pc = descend(item);
        let identifier = pc.consume_identifier()?;

        let token = pc.consume_of_type(Rule::function_arguments)?;
        let mut arguments = vec![];
        for field in token.into_inner() {
            arguments.push(self.parse_field_definition(field)?);
        }

        let return_type = if rule == Rule::function_decl {
            Some(pc.consume_type(self)?)
        } else {
            None
        };

        Ok(ast::FunctionDecl {
            identifier,
            arguments,
            return_type,
        })
    }

    fn parse_function_definition(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<ast::FunctionDefinition, ParseError> {
        let span = self.to_ast_span(item.as_span())?;
        let pc = descend(item);

        let decl = pc.consume()?;
        let decl = self.parse_function_decl(decl)?;
        let return_type = decl.return_type.expect("impossible function definition");

        // All remaining tokens are function statements
        let statements = self.parse_statement_list(pc.into_inner())?;

        Ok(ast::FunctionDefinition {
            identifier: decl.identifier,
            arguments: decl.arguments,
            return_type,
            statements,
            span,
        })
    }

    /// Parse a `Rule::finish_function_definition` into an [FinishFunctionDefinition](ast::FinishFunctionDefinition).
    fn parse_finish_function_definition(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<ast::FinishFunctionDefinition, ParseError> {
        let span = self.to_ast_span(item.as_span())?;
        let pc = descend(item);

        let decl = pc.consume()?;
        let decl = self.parse_function_decl(decl)?;

        // All remaining tokens are function statements
        let statements = self.parse_statement_list(pc.into_inner())?;

        Ok(ast::FinishFunctionDefinition {
            identifier: decl.identifier,
            arguments: decl.arguments,
            statements,
            span,
        })
    }

    /// Parse a `Rule::global_let_statement` into an [GlobalLetStatement](ast::GlobalLetStatement).
    fn parse_global_let_statement(
        &mut self,
        item: Pair<'_, Rule>,
    ) -> Result<ast::GlobalLetStatement, ParseError> {
        let span = self.to_ast_span(item.as_span())?;
        let pc = descend(item);
        let identifier = pc.consume_identifier()?;
        let expression = pc.consume_expression(self)?;

        Ok(ast::GlobalLetStatement {
            identifier,
            expression,
            span,
        })
    }
}

/// Parse a policy document string into an [Policy](ast::Policy) object.
///
/// The version parameter asserts that the code conforms to that
/// version, as the bare code does not have any way to specify its
/// own version. This does not account for any offset for enclosing
/// text.
pub fn parse_policy_str(data: &str, version: Version) -> Result<ast::Policy, ParseError> {
    let mut policy = ast::Policy::new(version, data);

    parse_policy_chunk(data, &mut policy, ChunkOffset::default())?;

    Ok(policy)
}

/// Adjusts the positioning of a Pest [Error](pest::error::Error) to account for any offset
/// in the source text.
fn mangle_pest_error(offset: usize, text: &str, mut e: pest::error::Error<Rule>) -> ParseError {
    let pos = match &mut e.location {
        InputLocation::Pos(p) => {
            *p = match p.checked_add(offset).assume("p + offset must not wrap") {
                Ok(n) => n,
                Err(bug) => return bug.into(),
            };
            *p
        }
        InputLocation::Span((s, e)) => {
            *s = match s.checked_add(offset).assume("s + offset must not wrap") {
                Ok(n) => n,
                Err(bug) => return bug.into(),
            };
            *e = match e.checked_add(offset).assume("e + offset must not wrap") {
                Ok(n) => n,
                Err(bug) => return bug.into(),
            };
            *s
        }
    };

    let line_col = match Span::new(text, pos, pos) {
        Some(s) => s.start_pos().line_col(),
        None => {
            return ParseError::new(
                ParseErrorKind::Unknown,
                "error location error".to_string(),
                None,
            );
        }
    };

    match &mut e.line_col {
        LineColLocation::Pos(p) => *p = line_col,
        // FIXME(chip): I'm not sure if any possible pest error uses the Span case here, so
        // I am not adjusting the endpoint.
        LineColLocation::Span(p, _) => *p = line_col,
    }

    e.into()
}

/// Parse more data into an existing [ast::Policy] object.
pub fn parse_policy_chunk(
    data: &str,
    policy: &mut ast::Policy,
    start: ChunkOffset,
) -> Result<(), ParseError> {
    if policy.version != Version::V2 {
        return Err(ParseError::new(
            ParseErrorKind::InvalidVersion {
                found: policy.version.to_string(),
                required: Version::V2,
            },
            "please update `policy-version` to 2".to_string(),
            None,
        ));
    }
    let chunk = PolicyParser::parse(Rule::file, data)
        .map_err(|e| mangle_pest_error(start.byte, &policy.text, e))?;
    let pratt = get_pratt_parser();
    let mut p = ChunkParser::new(start.byte, &pratt, policy.text.len());
    parse_policy_chunk_inner(chunk, &mut p, policy).map_err(|e| e.adjust_line_number(start.line))
}

fn parse_policy_chunk_inner(
    chunk: Pairs<'_, Rule>,
    p: &mut ChunkParser<'_>,
    policy: &mut ast::Policy,
) -> Result<(), ParseError> {
    for item in chunk {
        match item.as_rule() {
            Rule::use_definition => policy.ffi_imports.push(p.parse_use_definition(item)?),
            Rule::fact_definition => policy.facts.push(p.parse_fact_definition(item)?),
            Rule::action_definition => policy.actions.push(p.parse_action_definition(item)?),
            Rule::effect_definition => policy.effects.push(p.parse_effect_definition(item)?),
            Rule::struct_definition => policy.structs.push(p.parse_struct_definition(item)?),
            Rule::enum_definition => policy.enums.push(p.parse_enum_definition(item)?),
            Rule::command_definition => policy.commands.push(p.parse_command_definition(item)?),
            Rule::function_definition => policy.functions.push(p.parse_function_definition(item)?),
            Rule::finish_function_definition => policy
                .finish_functions
                .push(p.parse_finish_function_definition(item)?),
            Rule::global_let_statement => {
                policy.global_lets.push(p.parse_global_let_statement(item)?)
            }
            Rule::EOI => (),
            _ => {
                return Err(ParseError::new(
                    ParseErrorKind::Unknown,
                    format!("Impossible rule: {:?}", item.as_rule()),
                    Some(item.as_span()),
                ));
            }
        }
    }

    Ok(())
}

/// Parse a function or finish function declaration for the FFI
pub fn parse_ffi_decl(data: &str) -> Result<ast::FunctionDecl, ParseError> {
    let mut def = PolicyParser::parse(Rule::ffi_def, data)?;
    let decl = def.next().ok_or_else(|| {
        ParseError::new(
            ParseErrorKind::Unknown,
            String::from("Not a function declaration"),
            None,
        )
    })?;

    let rule = decl.as_rule();

    assert!(matches!(
        rule,
        Rule::function_decl | Rule::finish_function_decl
    ));

    let pc = descend(decl);
    let identifier = pc.consume_identifier()?;

    let token = pc.consume_of_type(Rule::function_arguments)?;
    let mut arguments = vec![];
    let pratt = get_pratt_parser();
    let mut parser = ChunkParser::new(0, &pratt, data.len());
    for field in token.into_inner() {
        arguments.push(parser.parse_field_definition(field)?);
    }

    let return_type = if rule == Rule::function_decl {
        Some(pc.consume_type(&mut parser)?)
    } else {
        None
    };

    let fn_decl = ast::FunctionDecl {
        identifier,
        arguments,
        return_type,
    };

    Ok(fn_decl)
}

/// A series of Struct or Enum definitions for the FFI
pub struct FfiTypes {
    pub structs: Vec<ast::StructDefinition>,
    pub enums: Vec<EnumDefinition>,
}

/// Parse a series of type definitions for the FFI
pub fn parse_ffi_structs_enums(data: &str) -> Result<FfiTypes, ParseError> {
    let def = PolicyParser::parse(Rule::ffi_struct_or_enum_def, data)?;
    let pratt = get_pratt_parser();
    let mut p = ChunkParser::new(0, &pratt, data.len());
    let mut structs = vec![];
    let mut enums = vec![];
    for s in def {
        match s.as_rule() {
            Rule::struct_definition => {
                structs.push(p.parse_struct_definition(s)?);
            }
            Rule::enum_definition => {
                enums.push(p.parse_enum_definition(s)?);
            }
            Rule::EOI => break,
            _ => break,
        }
    }

    Ok(FfiTypes { structs, enums })
}

/// Creates the default pratt parser ruleset.
///
/// # Operator precedence
///
/// | Priority | Op |
/// |----------|----|
/// | 1        | `.` |
/// | 2        | `-` (prefix), `!`, `unwrap`, `check_unwrap` |
/// | 3        | `%` |
/// | 4        | `+`, `-` (infix) |
/// | 5        | `>`, `<`, `>=`, `<=`, `is` |
/// | 6        | `==`, `!=` |
/// | 7        | `&&`, \|\| (\| conflicts with markdown tables :[) |
pub fn get_pratt_parser() -> PrattParser<Rule> {
    PrattParser::new()
        .op(Op::infix(Rule::and, Assoc::Left) | Op::infix(Rule::or, Assoc::Left))
        .op(Op::infix(Rule::equal, Assoc::Left) | Op::infix(Rule::not_equal, Assoc::Left))
        .op(Op::infix(Rule::greater_than, Assoc::Left)
            | Op::infix(Rule::less_than, Assoc::Left)
            | Op::infix(Rule::greater_than_or_equal, Assoc::Left)
            | Op::infix(Rule::less_than_or_equal, Assoc::Left)
            | Op::postfix(Rule::is))
        .op(Op::infix(Rule::add, Assoc::Left) | Op::infix(Rule::subtract, Assoc::Left))
        .op(Op::prefix(Rule::neg)
            | Op::prefix(Rule::not)
            | Op::prefix(Rule::unwrap)
            | Op::prefix(Rule::check_unwrap))
        .op(Op::infix(Rule::substruct, Assoc::Left))
        .op(Op::infix(Rule::dot, Assoc::Left))
}

#[cfg(test)]
mod tests;
