use std::fmt::Display;

use annotate_snippets::{AnnotationKind, Level, Patch, Renderer, Snippet};
use aranya_policy_ast::{Span, Version};
use buggy::Bug;
use pest::error::Error as PestError;
use serde::{Deserialize, Serialize};

use crate::lang::parse::Rule;

/// The kinds of errors a parse operation can produce
///
/// If the case contains a String, it is a message describing the item
/// affected or a general error message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseErrorKind {
    /// An invalid operator was used.
    InvalidOperator { lhs: Span, op: Span, rhs: Span },
    /// Invalid usage of nesting optional types using the old syntax was found.
    InvalidNestedOption { outer: Span, inner: Span },
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

#[derive(Debug, Clone)]
pub struct ParseError {
    pub kind: Box<ParseErrorKind>,
    pub message: String,
    /// Line and column location of the error, if available.
    pub span: Option<Span>,
    /// Text containing the entire policy, if available.
    pub source: Option<String>,
}

impl ParseError {
    pub(crate) fn new(kind: ParseErrorKind, message: String, span: Option<Span>) -> Self {
        Self {
            kind: Box::new(kind),
            message,
            span,
            source: None,
        }
    }

    // Return a new error with the source text.
    #[must_use]
    pub(crate) fn with_source(self, source: String) -> Self {
        Self {
            source: Some(source),
            ..self
        }
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            kind,
            message,
            span: maybe_span,
            source: maybe_source,
        } = self;
        let title = Level::ERROR.primary_title(kind.to_string());
        let (Some(span), Some(input)) = (maybe_span, maybe_source) else {
            let report = vec![title.element(Level::NOTE.message(message))];
            let message = Renderer::plain().render(&report);
            return write!(f, "{message}");
        };

        let mut report = Vec::new();
        let mut annotate_entire_span = || {
            let primary_annoation = Snippet::source(input).annotation(
                AnnotationKind::Primary
                    .span(span.start()..span.end())
                    .label(message),
            );

            report.push(title.clone().element(primary_annoation));
        };

        let source = Snippet::source(input);
        match **kind {
            ParseErrorKind::InvalidOperator { lhs, op, rhs } => {
                report.push(
                    title.elements([
                        // The message should refer specifically to the operator and not the entire expression
                        Snippet::source(input).annotation(
                            AnnotationKind::Primary
                                .span(op.start()..op.end())
                                .label(message),
                        ),
                    ]),
                );

                fn add_patch<'a>(
                    prefix: &'static str,
                    snippet: Snippet<'a, Patch<'a>>,
                    lhs: Span,
                    rhs: Span,
                ) -> Snippet<'a, Patch<'a>> {
                    snippet
                        .patch(Patch::new(lhs.start()..lhs.start(), prefix))
                        .patch(Patch::new(lhs.end()..rhs.start(), ", "))
                        .patch(Patch::new(rhs.end()..rhs.end(), ")"))
                }

                let elements = if input[op.start()..op.end()] == *"+" {
                    [
                        add_patch("saturating_add(", source.clone(), lhs, rhs),
                        add_patch("add(", source, lhs, rhs),
                    ]
                } else {
                    [
                        add_patch("saturating_sub(", source.clone(), lhs, rhs),
                        add_patch("sub(", source, lhs, rhs),
                    ]
                };

                let group = Level::HELP
                    .secondary_title("you might have meant to use an arithmetic function")
                    .elements(elements);

                report.push(group);
            }
            ParseErrorKind::InvalidNestedOption { outer, inner } => {
                annotate_entire_span();

                let old_prefix = "optional ";
                let is_old = |s: &str| s.starts_with(old_prefix);
                let is_old_outer = is_old(&input[outer.start()..outer.end()]);
                let is_old_inner = is_old(&input[inner.start()..inner.end()]);

                let mut snippet = source;

                if is_old_outer {
                    snippet = snippet
                        .patch(Patch::new(
                            outer.start()..(outer.start().saturating_add(old_prefix.len())),
                            "option[",
                        ))
                        .patch(Patch::new(outer.end()..outer.end(), "]"));
                }

                if is_old_inner {
                    snippet = snippet
                        .patch(Patch::new(
                            inner.start()..(inner.start().saturating_add(old_prefix.len())),
                            "option[",
                        ))
                        .patch(Patch::new(inner.end()..inner.end(), "]"));
                }

                let group = Level::HELP
                    .secondary_title("you might have meant to use `option[T]`")
                    .elements([snippet]);

                report.push(group);
            }
            _ => {
                annotate_entire_span();
            }
        }

        let message = Renderer::plain().render(&report);
        write!(f, "{message}")
    }
}

impl From<PestError<Rule>> for ParseError {
    fn from(e: PestError<Rule>) -> Self {
        use pest::error::InputLocation;
        // Assumes that the error location has already been adjusted in `aranya_policy_lang::lang::parse::mangle_pest_error`
        let span = match e.location {
            InputLocation::Pos(start) => Span::new(start, start.saturating_add(1)),
            InputLocation::Span((start, end)) => Span::new(start, end),
        };
        Self::new(
            ParseErrorKind::Syntax,
            e.variant.message().to_string(),
            Some(span),
        )
    }
}

impl From<Bug> for ParseError {
    fn from(bug: Bug) -> Self {
        Self::new(ParseErrorKind::Bug, bug.msg().to_owned(), None)
    }
}

// Implement default Error via Display and Debug
impl core::error::Error for ParseError {}
