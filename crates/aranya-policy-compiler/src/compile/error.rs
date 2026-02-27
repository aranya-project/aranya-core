use std::fmt;

use aranya_policy_ast::{self as ast, Ident, Span};
use buggy::Bug;

use crate::compile::StatementContext;

pub(crate) mod rendering;
use rendering::Error;

/// Describes the call color in an [`InvalidCallColor`] error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidCallColorKind {
    /// The call is a pure function
    Pure,
    /// The call is a finish function
    Finish,
}

impl fmt::Display for InvalidCallColorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pure => write!(f, "pure function not allowed in finish context"),
            Self::Finish => write!(f, "finish function not allowed in expression"),
        }
    }
}

// ---------------------------------------------------------------------------
// Error structs
// ---------------------------------------------------------------------------

/// Invalid statement - a statement was used in an invalid context.
pub(crate) struct InvalidStatement(pub StatementContext, pub Span);

/// Invalid expression - the expression does not make sense in context.
pub(crate) struct InvalidExpression(pub &'static str, pub ast::Expression, pub Option<Span>);

/// Invalid type - found type does not match expected type.
pub(crate) struct InvalidType {
    pub expected: String,
    pub expected_span: Option<Span>,
    pub found_type: String,
    pub found_expr: Span,
}

impl InvalidType {
    pub(crate) fn new(
        expected: String,
        expected_span: Option<Span>,
        found_type: String,
        found_expr: Span,
    ) -> Self {
        Self {
            expected,
            expected_span: expected_span.filter(|s| !s.is_empty()),
            found_type,
            found_expr,
        }
    }
}

/// Invalid call color - Tried to make a function call to the wrong type of function.
pub(crate) struct InvalidCallColor(pub InvalidCallColorKind, pub Span, pub Option<Span>);

/// An argument to a function or an item in an expression did not make sense.
pub(crate) struct BadArgument(pub String, pub Span);

/// A thing referenced is not defined.
pub(crate) struct NotDefined(pub String, pub Span);

/// A thing by that name has already been defined.
pub(crate) struct AlreadyDefined {
    pub prev: Ident,
    pub primary: Ident,
}

impl AlreadyDefined {
    /// Creates an `AlreadyDefined` error with `prev` and `primary` ordered by their spans.
    pub(crate) fn new(mut prev: Ident, mut primary: Ident) -> Self {
        use std::cmp::Ordering;
        match prev.span.cmp(&primary.span) {
            // already in order
            Ordering::Less | Ordering::Equal => {}
            Ordering::Greater => {
                std::mem::swap(&mut prev, &mut primary);
            }
        }

        Self { prev, primary }
    }
}

/// Duplicate match patterns found.
pub(crate) struct DuplicateMatchPatterns {
    pub patt1: Span,
    pub patt2: Span,
}

/// Fact literal doesn't match definition.
pub(crate) struct InvalidFactLiteral {
    pub note: String,
    pub span: Span,
    pub context: Option<(String, Span)>,
}

impl InvalidFactLiteral {
    pub(crate) fn new(
        note: impl Into<String>,
        span: Span,
        context: Option<(impl Into<String>, Span)>,
    ) -> Self {
        Self {
            note: note.into(),
            span,
            context: context.map(|(s, span)| (s.into(), span)),
        }
    }
}

/// A pure function has no return statement.
pub(crate) struct NoReturn(pub Span);

/// Source structs in struct composition have overlapping fields.
pub(crate) struct DuplicateSourceFields {
    /// The first source struct's type name and the span of its source expression.
    pub struct_1: (String, Span),
    /// The second source struct's type name and the span of its source expression.
    pub struct_2: (String, Span),
    pub literal_expr: Span,
}

impl DuplicateSourceFields {
    pub(crate) fn new(
        struct_1: (String, Span),
        struct_2: (String, Span),
        literal_expr: Span,
    ) -> Self {
        Self {
            struct_1,
            struct_2,
            literal_expr,
        }
    }
}

/// The source struct is not a subset of the base struct.
pub(crate) struct SourceStructNotSubsetOfBase {
    pub source: (String, Span),
    pub base: String,
    pub literal_expr: Span,
}

impl SourceStructNotSubsetOfBase {
    pub(crate) fn new(
        source: (impl Into<String>, Span),
        base: impl Into<String>,
        literal_expr: Span,
    ) -> Self {
        Self {
            source: (source.0.into(), source.1),
            base: base.into(),
            literal_expr,
        }
    }
}

/// A struct literal has all its fields explicitly specified while also having compositions.
pub(crate) struct NoOpStructComp(pub Span);

/// Invalid substruct operation - the RHS is not a subset of the LHS.
pub(crate) struct InvalidSubstruct {
    /// The substruct (RHS) type name.
    pub sub: Ident,
    /// The LHS struct type name and the span of the LHS expression.
    pub lhs: (String, Span),
}

/// Missing default pattern in `match` statement/expression.
pub(crate) struct MissingDefaultPattern(pub Span);

/// A match arm can never be reached because a previous arm already covered it.
pub(crate) struct UnreachableMatchArm(pub Span);

/// A literal pattern in an alternation is redundant because a binding
/// in the same arm already matches all values of that variant.
pub(crate) struct RedundantMatchArm(pub Span);

/// Todo found in policy code with debug mode disabled.
pub(crate) struct TodoFound(pub Span);

/// Invalid cast - LHS cannot be converted to RHS.
pub(crate) struct InvalidCast {
    /// The RHS cast target type name.
    pub rhs: Ident,
    /// The LHS struct type name and the span of the LHS expression.
    pub lhs: (String, Span),
}

/// Cyclic type definitions detected.
pub(crate) struct CyclicTypeDefinitions(pub String, pub Vec<Vec<Ident>>);

/// Type mismatch in struct composition — a source struct field has a different type
/// than the corresponding field in the target struct.
pub(crate) struct StructCompositionTypeMismatch {
    pub field_name: String,
    pub expected_type: String,
    pub expected_span: Span,
    pub found_type: String,
    pub found_span: Span,
    pub composition_span: Span,
    pub literal_span: Span,
}

/// An implementation bug.
pub(crate) struct BugError(pub Bug);

/// All other errors.
pub(crate) struct UnknownError(pub String, pub Option<Span>);

// ---------------------------------------------------------------------------
// CompileError
// ---------------------------------------------------------------------------

/// An error produced by the compiler. May contain the textual source of
/// an error.
pub struct CompileError {
    /// The error details
    err_type: Box<dyn Error>,
    // This should only be `None` when encountering an internal compiler bug.
    // The source code should be provided for all other error types.
    /// The source code information, if available
    source: Option<String>,
}

impl CompileError {
    /// Creates a `CompileError`.
    pub(crate) fn new(err_type: impl Error, source: Option<String>) -> Self {
        Self {
            err_type: Box::new(err_type),
            source,
        }
    }
}

impl fmt::Debug for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to Display — the diagnostic message is more useful than struct internals.
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(input) => write!(f, "{}", self.err_type.render(input)),
            None => write!(f, "{}", self.err_type.description()),
        }
    }
}

// Implementing Display and deriving Debug implements
// error::Error with default behavior by declaring this empty
// implementation.
impl core::error::Error for CompileError {}

impl From<Bug> for CompileError {
    fn from(bug: Bug) -> Self {
        Self::new(BugError(bug), None)
    }
}
