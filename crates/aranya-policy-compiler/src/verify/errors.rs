//! Error types for the verification pass.

use std::borrow::Cow;

use aranya_policy_ast as ast;
use buggy::Bug;

use crate::{
    diag::{Diag, DiagCtx, Diagnostic, EmissionGuarantee, MultiSpan, Severity},
    hir::Span,
};

/// An internal bug was discovered during verification.
#[derive(Clone, Debug, thiserror::Error)]
#[error("internal bug: {0}")]
pub(crate) struct VerificationBug(#[from] Bug);

/// A statement was used in an invalid context.
#[derive(Clone, Debug, thiserror::Error)]
#[error("statement not allowed in {actual_context} context")]
pub(crate) struct InvalidStatementContext {
    /// The context where the statement was found.
    pub actual_context: Cow<'static, str>,
    /// The context where this statement is allowed.
    pub expected_context: Cow<'static, str>,
    /// The span of the invalid statement.
    pub span: Span,
}

/// A function call was made in an invalid context.
#[derive(Clone, Debug, thiserror::Error)]
#[error("function call not allowed in {actual_context} context")]
pub(crate) struct InvalidFunctionContext {
    /// The function being called.
    pub function_name: ast::Identifier,
    /// The context where the call was made.
    pub actual_context: Cow<'static, str>,
    /// The context where this function call is allowed.
    pub expected_context: Cow<'static, str>,
    /// The span of the invalid function call.
    pub span: Span,
}

/// A match statement is not exhaustive.
#[derive(Clone, Debug, thiserror::Error)]
#[error("match statement is not exhaustive")]
pub(crate) struct NonExhaustiveMatch {
    /// The span of the match statement.
    pub span: Span,
    /// The missing patterns that should be covered.
    pub missing_patterns: Vec<Cow<'static, str>>,
}

/// A function is missing a return statement on some code paths.
#[derive(Clone, Debug, thiserror::Error)]
#[error("function missing return statement on some code paths")]
pub(crate) struct MissingReturn {
    /// The span of the function definition.
    pub span: Span,
    /// The function name.
    pub function_name: ast::Identifier,
}

/// Unreachable code was detected.
#[derive(Clone, Debug, thiserror::Error)]
#[error("unreachable code detected")]
pub(crate) struct UnreachableCode {
    /// The span of the unreachable code.
    pub span: Span,
    /// The reason why the code is unreachable.
    pub reason: Cow<'static, str>,
}

/// A fact operation violates schema constraints.
#[derive(Clone, Debug, thiserror::Error)]
#[error("fact operation violates schema: {description}")]
pub(crate) struct FactSchemaViolation {
    /// The description of the violation.
    pub description: Cow<'static, str>,
    /// The span of the fact operation.
    pub span: Span,
}

/// A fact operation violates uniqueness constraints.
#[derive(Clone, Debug, thiserror::Error)]
#[error("fact operation violates uniqueness constraints")]
pub(crate) struct FactUniquenessViolation {
    /// The span of the fact operation.
    pub span: Span,
    /// The fact name.
    pub fact_name: ast::Identifier,
}

/// A variable is used before it is initialized.
#[derive(Clone, Debug, thiserror::Error)]
#[error("variable used before initialization")]
pub(crate) struct VariableUsedBeforeInit {
    /// The variable name.
    pub variable_name: ast::Identifier,
    /// The span where the variable is used.
    pub use_span: Span,
    /// The span where the variable is defined.
    pub def_span: Span,
}

/// Invalid variable shadowing was detected.
#[derive(Clone, Debug, thiserror::Error)]
#[error("invalid variable shadowing")]
pub(crate) struct InvalidShadowing {
    /// The variable name being shadowed.
    pub variable_name: ast::Identifier,
    /// The span of the original variable.
    pub original_span: Span,
    /// The span of the shadowing variable.
    pub shadow_span: Span,
}

/// Direct recursion was detected.
#[derive(Clone, Debug, thiserror::Error)]
#[error("direct recursion detected")]
pub(crate) struct DirectRecursion {
    /// The name of the recursively called item.
    pub item_name: ast::Identifier,
    /// The span of the recursive call.
    pub span: Span,
}

/// Indirect recursion was detected.
#[derive(Clone, Debug, thiserror::Error)]
#[error("indirect recursion detected")]
pub(crate) struct IndirectRecursion {
    /// The cycle of function calls that forms the recursion.
    pub cycle: Vec<ast::Identifier>,
    /// The span of one of the calls in the cycle.
    pub span: Span,
}

/// A function call has incorrect arguments.
#[derive(Clone, Debug, thiserror::Error)]
#[error("function call has incorrect arguments")]
pub(crate) struct FunctionCallMismatch {
    /// The function being called.
    pub function_name: ast::Identifier,
    /// The expected number of arguments.
    pub expected_args: usize,
    /// The actual number of arguments.
    pub actual_args: usize,
    /// The span of the function call.
    pub span: Span,
}

// Implement Diagnostic for each error type
impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for VerificationBug {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        Diag::new(ctx, severity, self.to_string())
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for InvalidStatementContext {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut diag_span = MultiSpan::from_span(
            self.span,
            format!("not allowed in {} context", self.actual_context),
        );
        diag_span.push_label(
            self.span,
            format!("expected {} context", self.expected_context),
        );
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for InvalidFunctionContext {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut diag_span = MultiSpan::from_span(
            self.span,
            format!(
                "function '{}' not allowed in {} context",
                self.function_name, self.actual_context
            ),
        );
        diag_span.push_label(
            self.span,
            format!("expected {} context", self.expected_context),
        );
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for NonExhaustiveMatch {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let message = self.to_string();
        let mut diag_span = MultiSpan::from_span(self.span, "missing patterns");
        for pattern in self.missing_patterns {
            diag_span.push_label(self.span, format!("missing: {}", pattern));
        }
        Diag::new(ctx, severity, message).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for MissingReturn {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let message = self.to_string();
        let diag_span = MultiSpan::from_span(
            self.span,
            format!("function '{}' missing return", self.function_name),
        );
        Diag::new(ctx, severity, message).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for UnreachableCode {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let message = self.to_string();
        let diag_span = MultiSpan::from_span(self.span, self.reason);
        Diag::new(ctx, severity, message).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for FactSchemaViolation {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let message = self.to_string();
        let diag_span = MultiSpan::from_span(self.span, self.description);
        Diag::new(ctx, severity, message).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for FactUniquenessViolation {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let diag_span = MultiSpan::from_span(
            self.span,
            format!("fact '{}' violates uniqueness", self.fact_name),
        );
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for VariableUsedBeforeInit {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut diag_span = MultiSpan::from_span(self.use_span, "used here");
        diag_span.push_label(self.def_span, "defined here");
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for InvalidShadowing {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut diag_span = MultiSpan::from_span(
            self.shadow_span,
            format!(
                "variable '{}' shadows previous definition",
                self.variable_name
            ),
        );
        diag_span.push_label(self.original_span, "previous definition is here");
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for DirectRecursion {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let diag_span = MultiSpan::from_span(
            self.span,
            format!("'{}' calls itself directly", self.item_name),
        );
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for IndirectRecursion {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let cycle_str = self
            .cycle
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(" -> ");
        let diag_span = MultiSpan::from_span(
            self.span,
            format!("recursion cycle: {} -> {}", cycle_str, self.cycle[0]),
        );
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for FunctionCallMismatch {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let diag_span = MultiSpan::from_span(
            self.span,
            format!(
                "expected {} arguments, got {}",
                self.expected_args, self.actual_args
            ),
        );
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

/// An invalid type is used in a match expression.
#[derive(Clone, Debug, thiserror::Error)]
#[error("invalid match type: {reason}")]
pub(crate) struct InvalidMatchType {
    /// The reason why this type cannot be matched.
    pub reason: Cow<'static, str>,
    /// The span of the match expression.
    pub span: Span,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for InvalidMatchType {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let diag_span = MultiSpan::from_span(self.span, self.reason.clone());
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

/// A duplicate pattern was found in a match expression.
#[derive(Clone, Debug, thiserror::Error)]
#[error("duplicate match pattern: {pattern_desc}")]
pub(crate) struct DuplicatePattern {
    /// The span of the duplicate pattern.
    pub span: Span,
    /// The span of the previous occurrence (if available).
    pub previous_span: Option<Span>,
    /// Description of the duplicated pattern.
    pub pattern_desc: Cow<'static, str>,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for DuplicatePattern {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut diag_span = MultiSpan::from_span(
            self.span,
            format!("duplicate pattern: {}", self.pattern_desc),
        );
        if let Some(prev_span) = self.previous_span {
            diag_span.push_label(prev_span, "previous occurrence here");
        }
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

/// A query has an invalid leading bind.
#[derive(Clone, Debug, thiserror::Error)]
#[error("query validation error: {description}")]
pub(crate) struct QueryLeadingBind {
    /// The span of the invalid query.
    pub span: Span,
    /// Description of the validation error.
    pub description: Cow<'static, str>,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for QueryLeadingBind {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let diag_span = MultiSpan::from_span(self.span, self.description.clone());
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

/// An impure expression was used where purity is required.
#[derive(Clone, Debug, thiserror::Error)]
#[error("impure expression in {context}")]
pub(crate) struct ImpureExpression {
    /// The context where purity is required.
    pub context: Cow<'static, str>,
    /// The span of the impure expression.
    pub span: Span,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for ImpureExpression {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let diag_span = MultiSpan::from_span(
            self.span,
            format!("impure expression not allowed in {}", self.context),
        );
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

/// A command's persistence marker doesn't match its return type.
#[derive(Clone, Debug, thiserror::Error)]
#[error("command persistence mismatch: expected {expected}, got {actual}")]
pub(crate) struct CommandPersistenceMismatch {
    /// What was expected.
    pub expected: Cow<'static, str>,
    /// What was actually found.
    pub actual: Cow<'static, str>,
    /// The span of the command definition.
    pub span: Span,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for CommandPersistenceMismatch {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let diag_span = MultiSpan::from_span(
            self.span,
            format!("expected {}, got {}", self.expected, self.actual),
        );
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}

/// A pattern that can never be reached.
#[derive(Debug, Clone)]
pub(crate) struct UnreachablePattern {
    /// The span of the unreachable pattern.
    pub span: Span,
    /// The reason why this pattern is unreachable.
    pub reason: Cow<'static, str>,
}

impl std::fmt::Display for UnreachablePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unreachable pattern: {}", self.reason)
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for UnreachablePattern {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let diag_span = MultiSpan::from_span(
            self.span,
            format!("unreachable: {}", self.reason),
        );
        Diag::new(ctx, severity, self.to_string()).with_span(diag_span)
    }
}
