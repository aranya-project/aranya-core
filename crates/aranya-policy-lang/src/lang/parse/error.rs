use std::fmt::Display;

use aranya_policy_ast::{Span, Version};
use buggy::Bug;
use pest::error::Error as PestError;
use serde::{Deserialize, Serialize};

use crate::lang::parse::Rule;

pub(crate) mod rendering;

/// Invalid usage of an infix operator (i.e. `+` or `-`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidOperator {
    pub(crate) lhs: Span,
    pub(crate) op: Span,
    pub(crate) rhs: Span,
}

impl Display for InvalidOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid operator")
    }
}

/// Usage of an older policy version
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidVersion {
    pub found: String,
    pub required: Version,
}

impl Display for InvalidVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let found = &self.found;
        let required = &self.required;
        write!(
            f,
            "Invalid policy version {found}, supported version is {required}"
        )
    }
}

/// Invalid usage of option/optional syntax
///
///(crate) `optional option[T]`, `optional optional T`, etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidNestedOption {
    pub(crate) outer: Span,
    pub(crate) inner: Span,
}

impl Display for InvalidNestedOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid nested option")
    }
}

/// The kinds of errors a parse operation can produce
///
/// If the case contains a String, it is a message describing the item
/// affected or a general error message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseErrorKind {
    /// An invalid operator was used.
    InvalidOperator(InvalidOperator),
    /// Invalid usage of nesting optional types using the old syntax was found.
    InvalidNestedOption(InvalidNestedOption),
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
    InvalidVersion(InvalidVersion),
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

impl From<InvalidOperator> for ParseErrorKind {
    fn from(value: InvalidOperator) -> Self {
        Self::InvalidOperator(value)
    }
}

impl From<InvalidVersion> for ParseErrorKind {
    fn from(value: InvalidVersion) -> Self {
        Self::InvalidVersion(value)
    }
}

impl From<InvalidNestedOption> for ParseErrorKind {
    fn from(value: InvalidNestedOption) -> Self {
        Self::InvalidNestedOption(value)
    }
}

impl Display for ParseErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOperator(inner) => write!(f, "{inner}"),
            Self::InvalidNestedOption(inner) => write!(f, "{inner}"),
            Self::InvalidType => write!(f, "Invalid type"),
            Self::InvalidStatement => write!(f, "Invalid statement"),
            Self::InvalidNumber => write!(f, "Invalid number"),
            Self::InvalidString => write!(f, "Invalid string"),
            Self::InvalidFunctionCall => write!(f, "Invalid function call"),
            Self::InvalidSubstruct => write!(f, "Invalid substruct operation"),
            Self::InvalidVersion(inner) => write!(f, "{inner}"),
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
    pub(crate) fn new(
        kind: impl Into<ParseErrorKind>,
        message: String,
        span: Option<Span>,
    ) -> Self {
        Self {
            kind: Box::new(kind.into()),
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
