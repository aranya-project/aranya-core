use std::num::ParseIntError;

use logos::{Lexer, Logos, Span};

pub type Spanned<Tok, Loc, Error> = Result<(Loc, Tok, Loc), Error>;

#[derive(Default, Debug, Clone, PartialEq)]
pub enum LexicalError {
    ParseIntError(String, Span),
    InvalidToken(char, Span),
    #[default]
    Other,
}

impl LexicalError {
    fn from_lexer(lex: &mut Lexer<'_, Token>) -> Self {
        LexicalError::InvalidToken(lex.slice().chars().next().unwrap(), lex.span())
    }
}

impl std::fmt::Display for LexicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ParseIntError(ref msg, _) => write!(f, "{msg}"),
            Self::InvalidToken(ch, _) => write!(f, "Invalid Token: {ch}"),
            Self::Other => f.write_str("Unknown error"),
        }
    }
}

// TODO(Steve): separate lexer for string literals?
// https://github.com/aranya-project/aranya-core/issues/539

#[derive(Logos, Debug, PartialEq)]
#[logos(skip r"[ \t\n\f]+")] // skip whitespace
#[logos(skip r"//.*\n?", skip r"(?s)/\*.*?\*/")] // skip line and multi-line comments
#[logos(subpattern alpha = r"[a-zA-Z]")]
#[logos(subpattern digit = r"[0-9]")]
#[logos(subpattern alphanum = r"(?&alpha)|(?&digit)")]
#[logos(error(LexicalError, LexicalError::from_lexer))]
pub enum Token {
    #[regex("(?&alpha)((?&alphanum)|_)*", |lex| lex.slice().to_owned())]
    Identifier(String),
    // Escapes allowed: \n, \", \\, and two-digit hex escapes
    #[regex(r#""([^"\\]|\\([n"\\]|x[0-9A-Fa-f]{2}))*""#, |lex| lex.slice().to_owned())]
    StringLit(String),
    #[token("optional")]
    Optional,
    #[token("option")]
    Option,
    #[token("[")]
    OpenBracket,
    #[token("]")]
    CloseBracket,
    #[token("{")]
    OpenBrace,
    #[token("}")]
    CloseBrace,
    #[token("(")]
    OpenParen,
    #[token(")")]
    CloseParen,
    #[token("struct")]
    Struct,
    #[token("enum")]
    Enum,
    #[token("dynamic")]
    Dynamic,
    #[token("None")]
    None,
    #[token("Some")]
    Some,
    #[token("query")]
    Query,
    #[token("exists")]
    Exists,
    #[token("count_up_to")]
    CountUpTo,
    #[token("at_least")]
    AtLeast,
    #[token("at_most")]
    AtMost,
    #[token("exactly")]
    Exactly,
    #[token("match")]
    Match,
    #[token("if")]
    If,
    #[token("else")]
    Else,
    #[token("todo()")]
    Todo,
    #[token("serialize")]
    Serialize,
    #[token("deserialize")]
    Deserialize,
    #[token("return")]
    Return,
    #[token("this")]
    This,
    #[token(".")]
    Dot,
    #[token("...")]
    DotDotDot,
    #[token("+")]
    Plus,
    #[token("-")]
    Minus,
    #[token(">")]
    GreaterThan,
    #[token("<")]
    LessThan,
    #[token(">=")]
    GreaterThanEqual,
    #[token("<=")]
    LessThanEqual,
    #[token("=")]
    Equal,
    #[token("==")]
    EqualEqual,
    #[token("!=")]
    NotEqual,
    #[token("&&")]
    And,
    #[token("||")]
    Or,
    #[token("!")]
    Not,
    #[token("unwrap")]
    Unwrap,
    #[token("check_unwrap")]
    CheckUnwrap,
    #[token("substruct")]
    Substruct,
    #[token("as")]
    Cast,
    #[token("is")]
    Is,
    #[token(",")]
    Comma,
    #[token("=>")]
    Arrow,
    #[token(":")]
    Colon,
    #[token("::")]
    DoubleColon,
    #[regex("-?(?&digit)+", lex_num)]
    Number(i64),
    #[token("false", |_| false)]
    #[token("true", |_| true)]
    Bool(bool),
    #[token("function")]
    Function,
    #[token("action")]
    Action,
    #[token("publish")]
    Publish,
    #[token("let")]
    Let,
    #[token("check")]
    Check,
    #[token("finish")]
    Finish,
    #[token("map")]
    Map,
    #[token("create")]
    Create,
    #[token("update")]
    Update,
    #[token("delete")]
    Delete,
    #[token("emit")]
    Emit,
    #[token("debug_assert")]
    DebugAssert,
    #[token("attributes")]
    Attributes,
    #[token("fields")]
    Fields,
    #[token("policy")]
    Policy,
    #[token("recall")]
    Recall,
    #[token("seal")]
    Seal,
    #[token("open")]
    Open,
    #[token("ephemeral")]
    Ephemeral,
    #[token("immutable")]
    Immutable,
    #[token("fact")]
    Fact,
    #[token("effect")]
    Effect,
    #[token("command")]
    Command,
    #[token("?")]
    BindMarker,
    #[token("_")]
    UnderScore,
}

fn lex_num(lex: &mut Lexer<'_, Token>) -> Result<i64, LexicalError> {
    lex.slice().parse().map_err(|e: ParseIntError| {
        let msg = e.to_string().replace("target_type", "`int`");
        LexicalError::ParseIntError(msg, lex.span())
    })
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_lexer() {
//         let lexer = Token::lexer(source)
//     }
// }
