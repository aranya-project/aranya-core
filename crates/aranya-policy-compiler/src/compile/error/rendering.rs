use std::{borrow::Cow, iter::once};

use annotate_snippets::{AnnotationKind, Group, Level, Renderer, Snippet};
use aranya_policy_ast::{Span, Spanned as _};

use super::{
    AlreadyDefined, BadArgument, BugError, CyclicTypeDefinitions, DebugModeRequired,
    DuplicateMatchPatterns, DuplicateSourceFields, InvalidCallColor, InvalidCast,
    InvalidExpression, InvalidFactLiteral, InvalidReturn, InvalidStatement, InvalidSubstruct,
    InvalidType, MissingBaseCommand, MissingDefaultPattern, NoOpStructComp, NoReturn, NotDefined,
    RedundantMatchArm, SourceStructNotSubsetOfBase, StructCompositionTypeMismatch, UnknownError,
    UnreachableMatchArm, UnusedVariable,
};

/// Trait for compiler errors that can render themselves as annotated source snippets.
///
/// Each error type implements this to produce rich diagnostic output via `annotate-snippets`.
pub(crate) trait Error: Send + Sync + 'static {
    /// Short single-line description of the error.
    fn description(&self) -> Cow<'_, str>;

    /// Append annotated snippet groups for this error to `report`.
    ///
    /// `input` is the full policy source text.
    fn add_group<'a>(&'a self, input: &'a str, report: &mut Vec<Group<'a>>);

    /// Render the full diagnostic using `annotate-snippets`.
    ///
    /// Default implementation calls `add_group` and renders with `Renderer::plain()`.
    fn render(&self, input: &str) -> String {
        let mut report = Vec::new();
        self.add_group(input, &mut report);
        Renderer::plain().render(&report)
    }
}

impl<E: SimpleError> Error for E {
    fn description(&self) -> Cow<'_, str> {
        <E as SimpleError>::description(self)
    }

    fn add_group<'a>(&'a self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.title());
        let mut first = true;
        let annotations = self.annotations().into_iter().map(|(span, text)| {
            let kind = if first {
                first = false;
                AnnotationKind::Primary
            } else if text.is_empty() {
                AnnotationKind::Visible
            } else {
                AnnotationKind::Context
            };
            let mut annotation = kind.span(span.into());
            if !text.is_empty() {
                annotation = annotation.label(text).highlight_source(true);
            }
            annotation
        });
        report.push(title.element(Snippet::source(input).annotations(annotations)));
    }
}

trait SimpleError: Send + Sync + 'static {
    fn description(&self) -> Cow<'_, str>;
    fn title(&self) -> Cow<'_, str> {
        self.description()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)>;
}

fn just(span: Span) -> core::iter::Once<(Span, Cow<'static, str>)> {
    once((span, "".into()))
}

impl SimpleError for InvalidStatement {
    fn description(&self) -> Cow<'_, str> {
        format!("statement not allowed in {} context", self.0).into()
    }
    fn title(&self) -> Cow<'_, str> {
        "invalid statement".into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        [
            (self.1, SimpleError::description(self)),
            (self.0.span(), "".into()),
        ]
    }
}

impl SimpleError for InvalidExpression {
    fn description(&self) -> Cow<'_, str> {
        format!("invalid expression: {:?}", self.1).into()
    }
    fn title(&self) -> Cow<'_, str> {
        "invalid expression".into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        once((self.1.span, self.0.into())).chain(self.2.map(|span| (span, "".into())))
    }
}

impl SimpleError for InvalidType {
    fn description(&self) -> Cow<'_, str> {
        format!("invalid type: {}", self.found_type).into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        once((
            self.found_expr,
            format!(
                "expected `{}` but found `{}`",
                self.expected, self.found_type
            )
            .into(),
        ))
        .chain(
            self.expected_span
                .map(|span| (span, "expected because of this".into())),
        )
    }
}

impl SimpleError for InvalidCallColor {
    fn description(&self) -> Cow<'_, str> {
        self.0.to_string().into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        once((self.1, "function call not valid in this context".into()))
            .chain(self.2.map(|x| (x, "".into())))
    }
}

impl SimpleError for BadArgument {
    fn description(&self) -> Cow<'_, str> {
        "bad argument".into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        once((self.1, self.0.as_str().into()))
    }
}

impl SimpleError for NotDefined {
    fn description(&self) -> Cow<'_, str> {
        "a thing being referenced is not in scope".into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        once((self.1, self.0.as_str().into()))
    }
}

impl SimpleError for AlreadyDefined {
    fn description(&self) -> Cow<'_, str> {
        format!("the name `{}` is defined multiple times", self.prev).into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        [
            (self.primary.span, "re-defined here".into()),
            (self.prev.span, "previous defintion here".into()),
        ]
    }
}

impl SimpleError for DuplicateMatchPatterns {
    fn description(&self) -> Cow<'_, str> {
        "duplicate match patterns found".into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        [
            (self.patt2, "duplicate pattern".into()),
            (self.patt1, "first defined here".into()),
        ]
    }
}

impl SimpleError for InvalidFactLiteral {
    fn description(&self) -> Cow<'_, str> {
        format!("fact literal does not match definition: {}", self.note).into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        once((self.span, self.note.as_str().into()))
            .chain(self.context.as_ref().map(|(txt, span)| (*span, txt.into())))
    }
}

impl SimpleError for NoReturn {
    fn description(&self) -> Cow<'_, str> {
        "missing return statement".into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        once((self.0, "no return found in this body".into()))
    }
}

impl SimpleError for DuplicateSourceFields {
    fn description(&self) -> Cow<'_, str> {
        format!(
            "struct `{}` and struct `{}` have at least 1 field with the same name",
            self.struct_1.0, self.struct_2.0
        )
        .into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        let (ref type1, span1) = self.struct_1;
        let (ref type2, span2) = self.struct_2;
        [
            (span1, format!("type `{type1}`").into()),
            (span2, format!("type `{type2}`").into()),
            (self.literal_expr, "".into()),
        ]
    }
}

impl SimpleError for SourceStructNotSubsetOfBase {
    fn description(&self) -> Cow<'_, str> {
        format!(
            "struct `{}` must be a subset of struct `{}`",
            self.source.0, self.base
        )
        .into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        [
            (self.source.1, format!("type `{}`", self.source.0).into()),
            (self.literal_expr, "".into()),
        ]
    }
}

impl SimpleError for NoOpStructComp {
    fn description(&self) -> Cow<'_, str> {
        "A struct literal has all its fields explicitly specified while also having 1 or more struct compositions".into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        just(self.0)
    }
}

impl SimpleError for InvalidSubstruct {
    fn description(&self) -> Cow<'_, str> {
        format!(
            "invalid substruct operation: struct `{}` must be a subset of struct `{}`",
            self.sub, self.lhs.0
        )
        .into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        [
            (
                self.sub.span,
                format!("`{}` is not a subset of `{}`", self.sub, self.lhs.0).into(),
            ),
            (self.lhs.1, format!("type `{}`", self.lhs.0).into()),
        ]
    }
}

impl SimpleError for MissingDefaultPattern {
    fn description(&self) -> Cow<'_, str> {
        "Missing default pattern in `match` statement/expression".into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        just(self.0)
    }
}

impl SimpleError for UnreachableMatchArm {
    fn description(&self) -> Cow<'_, str> {
        "unreachable match arm".into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        just(self.0)
    }
}

impl SimpleError for RedundantMatchArm {
    fn description(&self) -> Cow<'_, str> {
        "redundant literal pattern in same arm — binding already matches all values".into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        just(self.0)
    }
}

impl SimpleError for InvalidReturn {
    fn description(&self) -> Cow<'_, str> {
        self.message.as_str().into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        just(self.span)
    }
}

impl SimpleError for DebugModeRequired {
    fn description(&self) -> Cow<'_, str> {
        format!("`{}` found with debug mode disabled", self.name).into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        just(self.span)
    }
}

impl SimpleError for InvalidCast {
    fn description(&self) -> Cow<'_, str> {
        format!(
            "invalid cast: `{}` cannot be converted to `{}`",
            self.lhs.0, self.rhs
        )
        .into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        [
            (
                self.rhs.span,
                format!("`{}` cannot be converted to `{}`", self.lhs.0, self.rhs).into(),
            ),
            (self.lhs.1, format!("type `{}`", self.lhs.0).into()),
        ]
    }
}

impl Error for CyclicTypeDefinitions {
    fn description(&self) -> Cow<'_, str> {
        self.0.as_str().into()
    }
    fn add_group<'a>(&'a self, input: &'a str, report: &mut Vec<Group<'a>>) {
        for cycle in &self.1 {
            let cycle_names: Vec<_> = cycle.iter().map(ToString::to_string).collect();
            let label = format!("cycle found: [{}]", cycle_names.join(", "));
            let title = Level::ERROR.primary_title(label);

            let annotations: Vec<_> = cycle
                .iter()
                .map(|id| AnnotationKind::Context.span(id.span.into()))
                .collect();

            report.push(title.element(Snippet::source(input).annotations(annotations)));
        }
    }
}

impl SimpleError for StructCompositionTypeMismatch {
    fn description(&self) -> Cow<'_, str> {
        format!(
            "struct composition type mismatch: field `{}` expects `{}` but found `{}`",
            self.field_name, self.expected_type, self.found_type
        )
        .into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        [
            (
                self.found_span,
                format!("but field `{}` is `{}`", self.field_name, self.found_type).into(),
            ),
            (
                self.expected_span,
                format!(
                    "field `{}` expects `{}`",
                    self.field_name, self.expected_type
                )
                .into(),
            ),
            (self.literal_span, "".into()),
            (self.composition_span, "composed here".into()),
        ]
    }
}

impl Error for BugError {
    fn description(&self) -> Cow<'_, str> {
        self.0.to_string().into()
    }
    fn add_group<'a>(&self, _input: &'a str, report: &mut Vec<Group<'a>>) {
        // Bug errors are internal — minimal rendering
        let title = Level::ERROR.primary_title(self.0.to_string());
        report.push(Group::with_title(title));
    }
}

impl Error for UnknownError {
    fn description(&self) -> Cow<'_, str> {
        format!("unknown error: {}", self.0).into()
    }
    fn add_group<'a>(&'a self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title("unknown error");
        match self.1 {
            None => report.push(Group::with_title(title)),
            Some(span) => {
                report.push(
                    title.element(
                        Snippet::source(input).annotation(
                            AnnotationKind::Primary
                                .span(span.into())
                                .label(self.0.clone()),
                        ),
                    ),
                );
            }
        }
    }
}

impl Error for UnusedVariable {
    fn description(&self) -> Cow<'_, str> {
        format!(
            "unused variable(s): {}",
            std::fmt::from_fn(|f| {
                if let Some((x, xs)) = self.names.split_first() {
                    write!(f, "`{x}`")?;
                    for x in xs {
                        write!(f, ", `{x}`")?;
                    }
                }
                Ok(())
            })
        )
        .into()
    }
    fn add_group<'a>(&'a self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());
        report.push(
            title.element(
                Snippet::source(input).annotations(self.names.iter().map(|name| {
                    AnnotationKind::Primary
                        .span(name.span.into())
                        .label("never used")
                })),
            ),
        );
    }
}

impl SimpleError for MissingBaseCommand {
    fn description(&self) -> Cow<'_, str> {
        format!("command {} has no base command", self.command).into()
    }
    fn annotations(&self) -> impl IntoIterator<Item = (Span, Cow<'_, str>)> {
        once((self.command.span, "command defined here".into()))
    }
}
