use core::fmt;

use logos::Logos;

#[expect(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Logos)]
#[logos(skip(r"\s+|//.*|/\*.*\*/", allow_greedy = true))] // TODO: proper multiline comment
pub(super) enum Token<'i> {
    Error,

    #[regex("[_a-zA-Z][_a-zA-Z0-9]*", priority = 0)]
    Identifier(&'i str),

    #[regex(r"-?\d+", |lex| lex.slice().parse().ok())]
    Number(i64),

    #[regex(r#""(\\.|[^"\\])*""#)]
    String(&'i str),

    #[token("Err")]
    Err,
    #[token("None")]
    None,
    #[token("Ok")]
    Ok,
    #[token("Some")]
    Some,
    #[token("Unit")]
    Unit,

    #[token("action")]
    action,
    #[token("as")]
    r#as,
    #[token("at_least")]
    at_least,
    #[token("at_most")]
    at_most,
    #[token("attributes")]
    attributes,
    #[token("base")]
    base,
    #[token("bool")]
    bool,
    #[token("bytes")]
    bytes,
    #[token("check")]
    check,
    #[token("command")]
    command,
    #[token("count_up_to")]
    count_up_to,
    #[token("create")]
    create,
    #[token("debug_assert")]
    debug_assert,
    #[token("delete")]
    delete,
    #[token("effect")]
    effect,
    #[token("else")]
    r#else,
    #[token("emit")]
    emit,
    #[token("enum")]
    r#enum,
    #[token("envelope")]
    envelope,
    #[token("exactly")]
    exactly,
    #[token("exists")]
    exists,
    #[token("fact")]
    fact,
    #[token("false")]
    r#false,
    #[token("fields")]
    fields,
    #[token("finish")]
    finish,
    #[token("function")]
    function,
    #[token("get_key")]
    get_key,
    #[token("id")]
    id,
    #[token("if")]
    r#if,
    #[token("immutable")]
    immutable,
    #[token("int")]
    int,
    #[token("is")]
    is,
    #[token("let")]
    r#let,
    #[token("map")]
    map,
    #[token("match")]
    r#match,
    #[token("option")]
    option,
    #[token("or")]
    or,
    #[token("policy")]
    policy,
    #[token("publish")]
    publish,
    #[token("query")]
    query,
    #[token("recall")]
    recall,
    #[token("result")]
    result,
    #[token("return")]
    r#return,
    #[token("string")]
    string,
    #[token("struct")]
    r#struct,
    #[token("substruct")]
    substruct,
    #[token("test_fail")]
    test_fail,
    #[token("this")]
    this,
    #[token("to")]
    to,
    #[token("todo")]
    todo,
    #[token("true")]
    r#true,
    #[token("unit")]
    unit,
    #[token("update")]
    update,
    #[token("use")]
    r#use,
    #[token("with")]
    with,

    #[token("!")]
    Bang,
    #[token("!=")]
    NEq,
    #[token("&&")]
    Amp2,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("+")]
    Plus,
    #[token(",")]
    Comma,
    #[token("-")]
    Minus,
    #[token(".")]
    Dot,
    #[token("...")]
    Dot3,
    #[token(":")]
    Colon,
    #[token("::")]
    Colon2,
    #[token("<")]
    Lt,
    #[token("<=")]
    LtEq,
    #[token("=")]
    Eq,
    #[token("==")]
    Eq2,
    #[token("=>")]
    Arrow,
    #[token(">")]
    Gt,
    #[token(">=")]
    GtEq,
    #[token("?")]
    Question,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token("_")]
    Underscore,
    #[token("{")]
    LBrace,
    #[token("|")]
    Pipe,
    #[token("||")]
    Pipe2,
    #[token("}")]
    RBrace,
}

impl fmt::Display for Token<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error => f.write_str("<error>"),
            Self::Identifier(i) => write!(f, "identifier {i:?}"),
            Self::Number(n) => write!(f, "number {n}"),
            Self::String(s) => write!(f, "string {s:?}"),
            Self::Err
            | Self::None
            | Self::Ok
            | Self::Some
            | Self::Unit
            | Self::action
            | Self::r#as
            | Self::at_least
            | Self::at_most
            | Self::attributes
            | Self::base
            | Self::bool
            | Self::bytes
            | Self::check
            | Self::command
            | Self::count_up_to
            | Self::create
            | Self::debug_assert
            | Self::delete
            | Self::effect
            | Self::r#else
            | Self::emit
            | Self::r#enum
            | Self::envelope
            | Self::exactly
            | Self::exists
            | Self::fact
            | Self::r#false
            | Self::fields
            | Self::finish
            | Self::function
            | Self::get_key
            | Self::id
            | Self::r#if
            | Self::immutable
            | Self::int
            | Self::is
            | Self::r#let
            | Self::map
            | Self::r#match
            | Self::option
            | Self::or
            | Self::policy
            | Self::publish
            | Self::query
            | Self::recall
            | Self::result
            | Self::r#return
            | Self::string
            | Self::r#struct
            | Self::substruct
            | Self::test_fail
            | Self::this
            | Self::to
            | Self::todo
            | Self::r#true
            | Self::unit
            | Self::update
            | Self::r#use
            | Self::with => write!(f, "{self:?}"),
            Self::Bang => f.write_str("!"),
            Self::NEq => f.write_str("!="),
            Self::Amp2 => f.write_str("&&"),
            Self::LParen => f.write_str("("),
            Self::RParen => f.write_str(")"),
            Self::Plus => f.write_str("+"),
            Self::Comma => f.write_str(","),
            Self::Minus => f.write_str("-"),
            Self::Dot => f.write_str("."),
            Self::Dot3 => f.write_str("..."),
            Self::Colon => f.write_str(":"),
            Self::Colon2 => f.write_str("::"),
            Self::Lt => f.write_str("<"),
            Self::LtEq => f.write_str("<="),
            Self::Eq => f.write_str("="),
            Self::Eq2 => f.write_str("=="),
            Self::Arrow => f.write_str("=>"),
            Self::Gt => f.write_str(">"),
            Self::GtEq => f.write_str(">="),
            Self::Question => f.write_str("?"),
            Self::LBracket => f.write_str("["),
            Self::RBracket => f.write_str("]"),
            Self::Underscore => f.write_str("_"),
            Self::LBrace => f.write_str("{"),
            Self::Pipe => f.write_str("|"),
            Self::Pipe2 => f.write_str("||"),
            Self::RBrace => f.write_str("}"),
        }
    }
}

#[rustfmt::skip]
macro_rules! token {
    (Err)           => { Token::Err };
    (None)          => { Token::None };
    (Ok)            => { Token::Ok };
    (Some)          => { Token::Some };
    (Unit)          => { Token::Unit };

    (action)        => { Token::action };
    (as)            => { Token::r#as };
    (at_least)      => { Token::at_least };
    (at_most)       => { Token::at_most };
    (attributes)    => { Token::attributes };
    (base)          => { Token::base };
    (bool)          => { Token::bool };
    (bytes)         => { Token::bytes };
    (check)         => { Token::check };
    (command)       => { Token::command };
    (count_up_to)   => { Token::count_up_to };
    (create)        => { Token::create };
    (debug_assert)  => { Token::debug_assert };
    (delete)        => { Token::delete };
    (effect)        => { Token::effect };
    (else)          => { Token::r#else };
    (emit)          => { Token::emit };
    (enum)          => { Token::r#enum };
    (envelope)      => { Token::envelope };
    (exactly)       => { Token::exactly };
    (exists)        => { Token::exists };
    (fact)          => { Token::fact };
    (false)         => { Token::r#false };
    (fields)        => { Token::fields };
    (finish)        => { Token::finish };
    (function)      => { Token::function };
    (get_key)       => { Token::get_key };
    (id)            => { Token::id };
    (if)            => { Token::r#if };
    (immutable)     => { Token::immutable };
    (int)           => { Token::int };
    (is)            => { Token::is };
    (let)           => { Token::r#let };
    (map)           => { Token::map };
    (match)         => { Token::r#match };
    (option)        => { Token::option };
    (or)            => { Token::or };
    (policy)        => { Token::policy };
    (publish)       => { Token::publish };
    (query)         => { Token::query };
    (recall)        => { Token::recall };
    (result)        => { Token::result };
    (return)        => { Token::r#return };
    (string)        => { Token::string };
    (struct)        => { Token::r#struct };
    (substruct)     => { Token::substruct };
    (test_fail)     => { Token::test_fail };
    (this)          => { Token::this };
    (to)            => { Token::to };
    (todo)          => { Token::todo };
    (true)          => { Token::r#true };
    (unit)          => { Token::unit };
    (update)        => { Token::update };
    (use)           => { Token::r#use };
    (with)          => { Token::with };

    (!)             => { Token::Bang };
    (!=)            => { Token::NEq };
    (&&)            => { Token::Amp2 };
    (+)             => { Token::Plus };
    (,)             => { Token::Comma };
    (-)             => { Token::Minus };
    (.)             => { Token::Dot };
    (...)           => { Token::Dot3 };
    (:)             => { Token::Colon };
    (::)            => { Token::Colon2 };
    (<)             => { Token::Lt };
    (<=)            => { Token::LtEq };
    (=)             => { Token::Eq };
    (==)            => { Token::Eq2 };
    (=>)            => { Token::Arrow };
    (>)             => { Token::Gt };
    (>=)            => { Token::GtEq };
    (?)             => { Token::Question };
    (_)             => { Token::Underscore };
    (|)             => { Token::Pipe };
    (||)            => { Token::Pipe2 };
}
pub(super) use token;
