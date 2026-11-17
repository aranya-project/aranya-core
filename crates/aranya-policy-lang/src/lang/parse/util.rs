use core::fmt;

use aranya_policy_ast::{self as ast, WithSpanExt as _};
use chumsky::{combinator::SeparatedBy, error::Rich, extra, primitive::Just};

use super::Token;

type Extra<'i> = extra::Full<Rich<'i, Token<'i>, Span>, (), super::Config>;

macro_rules! just {
    ($tt:tt) => {
        chumsky::primitive::just(
            crate::lang::parse::token::token!($tt)
        )
    };
    ($($tt:tt)+) => {
        chumsky::primitive::just([
            $(crate::lang::parse::token::token!($tt)),+
        ])
    };
}
pub(super) use just;

// Trait "aliases" to simplify signatures.

pub(super) trait Input<'i>:
    chumsky::input::Input<'i, Token = Token<'i>, Span = Span>
{
}

impl<'i, I> Input<'i> for I where I: chumsky::input::Input<'i, Token = Token<'i>, Span = Span> {}

pub(super) trait Parser<'i, I: Input<'i>, T>:
    chumsky::Parser<'i, I, T, Extra<'i>> + Sized
{
    // Add some helper methods.

    fn comma_separated(
        self,
    ) -> SeparatedBy<Self, Just<Token<'i>, I, Extra<'i>>, T, Token<'i>, I, Extra<'i>> {
        self.separated_by(chumsky::primitive::just(Token::Comma))
    }

    #[allow(clippy::type_complexity)]
    fn paren_delimited(
        self,
    ) -> chumsky::combinator::DelimitedBy<
        Self,
        Just<Token<'i>, I, Extra<'i>>,
        Just<Token<'i>, I, Extra<'i>>,
        Token<'i>,
        Token<'i>,
    > {
        self.delimited_by(
            chumsky::primitive::just(Token::LParen),
            chumsky::primitive::just(Token::RParen),
        )
    }

    #[allow(clippy::type_complexity)]
    fn brace_delimited(
        self,
    ) -> chumsky::combinator::DelimitedBy<
        Self,
        Just<Token<'i>, I, Extra<'i>>,
        Just<Token<'i>, I, Extra<'i>>,
        Token<'i>,
        Token<'i>,
    > {
        self.delimited_by(
            chumsky::primitive::just(Token::LBrace),
            chumsky::primitive::just(Token::RBrace),
        )
    }

    #[allow(clippy::type_complexity)]
    fn bracket_delimited(
        self,
    ) -> chumsky::combinator::DelimitedBy<
        Self,
        Just<Token<'i>, I, Extra<'i>>,
        Just<Token<'i>, I, Extra<'i>>,
        Token<'i>,
        Token<'i>,
    > {
        self.delimited_by(
            chumsky::primitive::just(Token::LBracket),
            chumsky::primitive::just(Token::RBracket),
        )
    }
}

impl<'i, P, I, T> Parser<'i, I, T> for P
where
    P: chumsky::Parser<'i, I, T, Extra<'i>>,
    I: Input<'i>,
{
}

// Span wrapper to add `chumsky` trait impls to `ast::Span`.

#[derive(Copy, Clone)]
#[repr(transparent)]
pub(super) struct Span(pub(super) ast::Span);

impl Span {
    pub(super) fn add(self, amount: usize) -> Option<Self> {
        self.0.add(amount).map(Self)
    }
}

pub(super) fn ast_span(span: Span) -> ast::Span {
    span.0
}

impl From<core::ops::Range<usize>> for Span {
    fn from(range: core::ops::Range<usize>) -> Self {
        Self(range.into())
    }
}

impl From<Span> for ast::Span {
    fn from(span: Span) -> Self {
        span.0
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl chumsky::span::Span for Span {
    type Context = ();

    type Offset = usize;

    fn new((): Self::Context, range: core::ops::Range<Self::Offset>) -> Self {
        range.into()
    }

    fn context(&self) -> Self::Context {}

    fn start(&self) -> Self::Offset {
        self.0.start()
    }

    fn end(&self) -> Self::Offset {
        self.0.end()
    }
}

impl<T> chumsky::span::WrappingSpan<T> for Span {
    type Spanned = ast::WithSpan<T>;

    fn make_wrapped(self, inner: T) -> Self::Spanned {
        inner.at(self)
    }

    fn inner_of(spanned: &Self::Spanned) -> &T {
        &spanned.inner
    }

    fn span_of(spanned: &Self::Spanned) -> &Self {
        // SAFETY: `Span` is transparent repr over `ast::Span`.
        unsafe { (&raw const spanned.span).cast::<Self>().as_ref_unchecked() }
    }
}
