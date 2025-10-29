use std::fmt::Display;

use aranya_policy_ast::Version;
use buggy::Bug;
use pest::{
    Span,
    error::{Error as PestError, LineColLocation},
};
use serde::{Deserialize, Serialize};

use crate::lang::parse::Rule;

/// The kinds of errors a parse operation can produce
///
/// If the case contains a String, it is a message describing the item
/// affected or a general error message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseErrorKind {
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

impl Display for ParseErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub message: String,
    /// Line and column location of the error, if available.
    pub location: Option<(usize, usize)>,
}

impl ParseError {
    pub(crate) fn new(kind: ParseErrorKind, message: String, span: Option<Span<'_>>) -> Self {
        let location = span.map(|s| s.start_pos().line_col());
        Self {
            kind,
            message,
            location,
        }
    }

    /// Return a new error with a location starting from the given line.
    #[must_use]
    pub fn adjust_line_number(mut self, start_line: usize) -> Self {
        if let Some((line, _)) = &mut self.location {
            *line = line.saturating_add(start_line);
        }
        self
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: ", self.kind)?;
        if let Some((line, column)) = self.location {
            write!(f, "line {line} column {column}: ")?;
        }
        write!(f, "{}", self.message)?;
        Ok(())
    }
}

impl From<PestError<Rule>> for ParseError {
    fn from(e: PestError<Rule>) -> Self {
        let p = match e.line_col {
            LineColLocation::Pos(p) => p,
            LineColLocation::Span(p, _) => p,
        };
        Self {
            kind: ParseErrorKind::Syntax,
            message: e.to_string(),
            location: Some(p),
        }
    }
}

impl From<Bug> for ParseError {
    fn from(bug: Bug) -> Self {
        Self::new(ParseErrorKind::Bug, bug.msg().to_owned(), None)
    }
}

// Implement default Error via Display and Debug
impl core::error::Error for ParseError {}
