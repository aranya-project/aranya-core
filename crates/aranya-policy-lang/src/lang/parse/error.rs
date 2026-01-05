use std::fmt::Display;

use annotate_snippets::{AnnotationKind, Group, Level, Patch, Renderer, Snippet};
use aranya_policy_ast::{Span as ASTSpan, Version};
use buggy::Bug;
use pest::{Span, error::Error as PestError};
use self_cell::self_cell;
use serde::{Deserialize, Serialize};

use crate::lang::parse::Rule;

/// The kinds of errors a parse operation can produce
///
/// If the case contains a String, it is a message describing the item
/// affected or a general error message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseErrorKind {
    /// An invalid operator was used.
    InvalidOperator {
        lhs: ASTSpan,
        op: ASTSpan,
        rhs: ASTSpan,
    },
    /// Invalid usage of nesting optional types using the old syntax was found.
    InvalidNestedOption { outer: ASTSpan, inner: ASTSpan },
    /// An invalid type specifier was found. The string describes the type.
    InvalidType,
    /// A statement is invalid for its scope.
    InvalidStatement,
    /// A number is out of range or otherwise unparseable. Also used for
    /// invalid hex escapes in strings.
    InvalidNumber,
    /// A string has invalid escapes or other bad formatting.
    InvalidString,
    /// A function call is badly formed.
    // TODO(chip): I'm not sure this is actually reachable.
    InvalidFunctionCall,
    /// The right side of a dot operator is not an identifier.
    InvalidMember,
    /// The right side of a substruct operator is not an identifier.
    InvalidSubstruct,
    /// The policy version expressed in the front matter is not valid.
    InvalidVersion { found: String, required: Version },
    /// Some part of an expression is badly formed.
    Expression,
    /// The Pest parser was unable to parse the document.
    Syntax,
    /// There was some error in the YAML front matter.
    FrontMatter,
    /// An identifier was shared with a keyword
    ReservedIdentifier,
    /// An implementation bug
    Bug,
    /// Every other possible error.
    Unknown,
}

/// Diagnostic Message
#[derive(Debug)]
pub struct Report<'a>(Vec<Group<'a>>);

self_cell!(
    pub struct ReportCell {
        owner: String,

        #[covariant]
        dependent: Report,
    }

    impl {Debug}
);

impl std::error::Error for ReportCell {}

impl Display for ParseErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOperator { .. } => write!(f, "Invalid operator"),
            Self::InvalidNestedOption { .. } => write!(f, "Invalid nested option"),
            Self::InvalidType => write!(f, "Invalid type"),
            Self::InvalidStatement => write!(f, "Invalid statement"),
            Self::InvalidNumber => write!(f, "Invalid number"),
            Self::InvalidString => write!(f, "Invalid string"),
            Self::InvalidFunctionCall => write!(f, "Invalid function call"),
            Self::InvalidMember => write!(f, "Invalid member"),
            Self::InvalidSubstruct => write!(f, "Invalid substruct operation"),
            Self::InvalidVersion { found, required } => {
                write!(
                    f,
                    "Invalid policy version {found}, supported version is {required}"
                )
            }
            Self::Expression => write!(f, "Invalid expression"),
            Self::Syntax => write!(f, "Syntax error"),
            Self::FrontMatter => write!(f, "Front matter YAML parse error"),
            Self::ReservedIdentifier => write!(f, "Reserved identifier"),
            Self::Bug => write!(f, "Bug"),
            Self::Unknown => write!(f, "Unknown error"),
        }
    }
}

// TODO(Steve): Removing trait impls (Serialize/Deserialize) is a breaking change.
#[derive(Debug, Clone)]
pub struct ParseError<'a> {
    pub kind: ParseErrorKind,
    pub message: String,
    /// Line and column location of the error, if available.
    pub span: Option<Span<'a>>,
    pub line_offset: Option<usize>,
}

impl<'a> ParseError<'a> {
    pub(crate) fn new(
        kind: ParseErrorKind,
        message: String,
        span: Option<Span<'a>>,
    ) -> ParseError<'a> {
        Self {
            kind,
            message,
            span,
            line_offset: None,
        }
    }

    pub(crate) fn to_report(self) -> ReportCell {
        let Self {
            kind,
            message,
            span: maybe_span,
            line_offset,
        } = self;
        let title = Level::ERROR.primary_title(kind.to_string());
        let Some(span) = maybe_span else {
            return ReportCell::new("".to_owned(), move |_| {
                Report(vec![title.element(Level::NOTE.message(message))])
            });
        };

        let input = span.get_input().to_owned();

        ReportCell::new(input, move |s| {
            let line_start = line_offset.unwrap_or_default() + 1;

            let source = Snippet::source(s).line_start(line_start).annotation(
                AnnotationKind::Primary
                    .span(span.start()..span.end())
                    .label(message),
            );

            let mut out = Vec::new();
            out.push(title.element(source));

            let source = Snippet::source(s).line_start(line_start);
            match kind {
                ParseErrorKind::InvalidOperator { lhs, op, rhs } => {
                    let elements = if s[op.start()..op.end()] == *"+" {
                        [
                            source
                                .clone()
                                .patch(Patch::new(lhs.merge(rhs).into(), "saturating_add(_, _)")),
                            source.patch(Patch::new(lhs.merge(rhs).into(), "add(_, _)")),
                        ]
                    } else {
                        [
                            source
                                .clone()
                                .patch(Patch::new(lhs.merge(rhs).into(), "saturating_sub(_, _)")),
                            source.patch(Patch::new(lhs.merge(rhs).into(), "sub(_, _)")),
                        ]
                    };

                    let group = Level::HELP
                        .secondary_title("you might have meant to use an arithmetic function")
                        .elements(elements);

                    out.push(group);
                }
                ParseErrorKind::InvalidNestedOption { outer, inner } => {
                    let old_prefix = "optional ";
                    let is_old = |s: &str| s.starts_with(old_prefix);
                    let is_old_outer = is_old(&s[outer.start()..outer.end()]);
                    let is_old_inner = is_old(&s[inner.start()..inner.end()]);

                    let mut snippet = source;

                    if is_old_outer {
                        snippet = snippet
                            .patch(Patch::new(
                                outer.start()..(outer.start() + old_prefix.len()),
                                "option[",
                            ))
                            .patch(Patch::new(outer.end()..outer.end(), "]"))
                    }

                    if is_old_inner {
                        snippet = snippet
                            .patch(Patch::new(
                                inner.start()..(inner.start() + old_prefix.len()),
                                "option[",
                            ))
                            .patch(Patch::new(inner.end()..inner.end(), "]"))
                    }

                    let group = Level::HELP
                        .secondary_title("you might have meant to use `option[T]`")
                        .elements([snippet]);

                    out.push(group);
                }
                _ => {}
            }

            Report(out)
        })
    }

    /// Return a new error with a location starting from the given line.
    #[must_use]
    pub(crate) fn adjust_line_number(self, line_offset: usize) -> Self {
        Self {
            line_offset: Some(line_offset),
            ..self
        }
    }
}

impl Display for ParseError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: ", self.kind)?;
        if let Some((line, column)) = self.span.map(|s| s.start_pos().line_col()) {
            write!(f, "line {line} column {column}: ")?;
        }
        write!(f, "{}", self.message)?;
        Ok(())
    }
}

impl Display for Report<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = Renderer::plain().render(&self.0);
        write!(f, "{message}")
    }
}

impl Display for ReportCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = Renderer::plain().render(&self.borrow_dependent().0);
        write!(f, "{message}")
    }
}

impl From<PestError<Rule>> for ParseError<'static> {
    fn from(e: PestError<Rule>) -> Self {
        Self {
            kind: ParseErrorKind::Syntax,
            message: e.to_string(),
            span: None, // span info is in the `Display` impl for the Pest error
            line_offset: None,
        }
    }
}

impl From<Bug> for ParseError<'_> {
    fn from(bug: Bug) -> Self {
        Self::new(ParseErrorKind::Bug, bug.msg().to_owned(), None)
    }
}

// Implement default Error via Display and Debug
impl core::error::Error for ParseError<'_> {}
