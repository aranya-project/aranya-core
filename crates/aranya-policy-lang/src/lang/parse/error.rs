use std::fmt::Display;

use aranya_policy_ast::Version;
use buggy::Bug;
use pest::{
    Span,
    error::{Error as PestError, LineColLocation},
};

use crate::lang::parse::Rule;

/// The kinds of errors a parse operation can produce
///
/// If the case contains a String, it is a message describing the item
/// affected or a general error message.
#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub message: String,
    /// Line and column location of the error, if available.
    pub location: Option<(usize, usize)>,
}

impl ParseError {
    pub(crate) fn new(kind: ParseErrorKind, message: String, span: Option<Span<'_>>) -> ParseError {
        let location = span.map(|s| s.start_pos().line_col());
        ParseError {
            kind,
            message,
            location,
        }
    }

    /// Return a new error with a location starting from the given line.
    pub fn adjust_line_number(&self, start_line: usize) -> ParseError {
        ParseError {
            kind: self.kind.clone(),
            message: self.message.clone(),
            location: self
                .location
                .map(|(line, col)| (line.saturating_add(start_line), col)),
        }
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let location = match self.location {
            Some((line, column)) => format!("line {line} column {column}: "),
            None => String::new(),
        };
        let prefix = match &self.kind {
            ParseErrorKind::InvalidType => "Invalid type",
            ParseErrorKind::InvalidStatement => "Invalid statement",
            ParseErrorKind::InvalidNumber => "Invalid number",
            ParseErrorKind::InvalidString => "Invalid string",
            ParseErrorKind::InvalidFunctionCall => "Invalid function call",
            ParseErrorKind::InvalidMember => "Invalid member",
            ParseErrorKind::InvalidVersion { found, required } => {
                &{ format!("Invalid policy version {found}, supported version is {required}") }
            }
            ParseErrorKind::InvalidSubstruct => "Invalid substruct operation",
            ParseErrorKind::Expression => "Invalid expression",
            ParseErrorKind::Syntax => "Syntax error",
            ParseErrorKind::FrontMatter => "Front matter YAML parse error",
            ParseErrorKind::ReservedIdentifier => "Reserved identifier",
            ParseErrorKind::Bug => "Bug",
            ParseErrorKind::Unknown => "Unknown error",
        };
        write!(f, "{prefix}: {location}{}", self.message)
    }
}

impl From<PestError<Rule>> for ParseError {
    fn from(e: PestError<Rule>) -> Self {
        let (line, column) = match e.line_col {
            LineColLocation::Pos(p) => p,
            LineColLocation::Span(p, _) => p,
        };
        let message = match e.path() {
            Some(path) => format!("in {} line {} column {}: {}", path, line, column, e),
            None => format!("line {} column {}: {}", line, column, e),
        };
        ParseError::new(ParseErrorKind::Syntax, message, None)
    }
}

impl From<Bug> for ParseError {
    fn from(bug: Bug) -> Self {
        ParseError::new(ParseErrorKind::Bug, bug.msg().to_owned(), None)
    }
}

// Implement default Error via Display and Debug
impl core::error::Error for ParseError {}
