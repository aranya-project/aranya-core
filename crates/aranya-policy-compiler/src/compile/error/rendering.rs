use annotate_snippets::{AnnotationKind, Group, Level, Renderer, Snippet};
use aranya_policy_ast::Spanned as _;

use super::{
    AlreadyDefined, BadArgument, BugError, CyclicTypeDefinitions, DuplicateMatchPatterns,
    DuplicateSourceFields, InvalidCallColor, InvalidCast, InvalidExpression, InvalidFactLiteral,
    InvalidStatement, InvalidSubstruct, InvalidType, MissingDefaultPattern, NoOpStructComp,
    NoReturn, NotDefined, RedundantMatchArm, SourceStructNotSubsetOfBase,
    StructCompositionTypeMismatch, TodoFound, UnknownError, UnreachableMatchArm,
};

/// Trait for compiler errors that can render themselves as annotated source snippets.
///
/// Each error type implements this to produce rich diagnostic output via `annotate-snippets`.
pub(crate) trait Error: Send + Sync + 'static {
    /// Append annotated snippet groups for this error to `report`.
    ///
    /// `input` is the full policy source text.
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>);

    /// Short single-line description of the error.
    fn description(&self) -> String;

    /// Render the full diagnostic using `annotate-snippets`.
    ///
    /// Default implementation calls `add_group` and renders with `Renderer::plain()`.
    fn render(&self, input: &str) -> String {
        let mut report = Vec::new();
        self.add_group(input, &mut report);
        Renderer::plain().render(&report)
    }
}

impl Error for InvalidStatement {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title("invalid statement");

        report.push(
            title.element(
                Snippet::source(input).annotations([
                    AnnotationKind::Primary
                        .span(self.1.into())
                        .label(self.description())
                        .highlight_source(true),
                    AnnotationKind::Visible.span(self.0.span().into()),
                ]),
            ),
        );
    }
    fn description(&self) -> String {
        format!("statement doesn't make sense in {} context", self.0)
    }
}

impl Error for InvalidExpression {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title("invalid expression");

        let mut annotations = vec![
            AnnotationKind::Primary
                .span(self.1.span.into())
                .label(self.0)
                .highlight_source(true),
        ];

        if let Some(ctx_span) = self.2 {
            annotations.push(AnnotationKind::Visible.span(ctx_span.into()));
        }

        report.push(title.element(Snippet::source(input).annotations(annotations)));
    }
    fn description(&self) -> String {
        format!("invalid expression: {:?}", self.1)
    }
}

impl Error for InvalidType {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        let mut annotations =
            vec![
                AnnotationKind::Primary
                    .span(self.found_expr.into())
                    .label(format!(
                        "expected `{}` but found `{}`",
                        self.expected, self.found_type
                    )),
            ];

        if let Some(expected_span) = self.expected_span {
            annotations.push(
                AnnotationKind::Context
                    .span(expected_span.into())
                    .label("expected because of this"),
            );
        }

        report.push(title.element(Snippet::source(input).annotations(annotations)));
    }
    fn description(&self) -> String {
        format!("invalid type: {}", self.found_type)
    }
}

impl Error for InvalidCallColor {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        let mut annotations = vec![
            AnnotationKind::Primary
                .span(self.1.into())
                .label("function call not valid in this context"),
        ];

        if let Some(ctx_span) = self.2 {
            annotations.push(AnnotationKind::Visible.span(ctx_span.into()));
        }

        report.push(title.element(Snippet::source(input).annotations(annotations)));
    }
    fn description(&self) -> String {
        self.0.to_string()
    }
}

impl Error for BadArgument {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.elements([Snippet::source(input).annotation(
                AnnotationKind::Primary
                    .span(self.1.into())
                    .label(self.0.clone())
                    .highlight_source(true),
            )]),
        );
    }
    fn description(&self) -> String {
        "bad argument".to_owned()
    }
}

impl Error for NotDefined {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.elements([Snippet::source(input).annotation(
                AnnotationKind::Primary
                    .span(self.1.into())
                    .label(self.0.clone()),
            )]),
        );
    }
    fn description(&self) -> String {
        "a thing being referenced is not in scope".to_owned()
    }
}

impl Error for AlreadyDefined {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.elements([Snippet::source(input).annotations([
                AnnotationKind::Context
                    .span(self.prev.span.into())
                    .label("previous defintion here"),
                AnnotationKind::Primary
                    .span(self.primary.span.into())
                    .label("re-defined here"),
            ])]),
        );
    }
    fn description(&self) -> String {
        format!("the name `{}` is defined multiple times", self.prev)
    }
}

impl Error for DuplicateMatchPatterns {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotations([
                    AnnotationKind::Context
                        .span(self.patt1.into())
                        .label("first defined here"),
                    AnnotationKind::Primary
                        .span(self.patt2.into())
                        .label("duplicate pattern"),
                ]),
            ),
        );
    }
    fn description(&self) -> String {
        "duplicate match patterns found".to_owned()
    }
}

impl Error for InvalidFactLiteral {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        let mut annotations = vec![
            AnnotationKind::Primary
                .span(self.span.into())
                .label(self.note.clone()),
        ];

        if let Some((label, span)) = &self.context {
            annotations.push(
                AnnotationKind::Context
                    .span((*span).into())
                    .label(label.clone()),
            );
        }

        report.push(title.element(Snippet::source(input).annotations(annotations)));
    }
    fn description(&self) -> String {
        format!("fact literal does not match definition: {}", self.note)
    }
}

impl Error for NoReturn {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotation(
                    AnnotationKind::Primary
                        .span(self.0.into())
                        .label("No return found in this function body"),
                ),
            ),
        );
    }
    fn description(&self) -> String {
        "pure function has no return statement".to_owned()
    }
}

impl Error for DuplicateSourceFields {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotations([
                    AnnotationKind::Primary
                        .span(self.struct_1.1.into())
                        .label(format!("type `{}`", self.struct_1.0))
                        .highlight_source(true),
                    AnnotationKind::Primary
                        .span(self.struct_2.1.into())
                        .label(format!("type `{}`", self.struct_2.0))
                        .highlight_source(true),
                    AnnotationKind::Visible.span(self.literal_expr.into()),
                ]),
            ),
        );
    }
    fn description(&self) -> String {
        format!(
            "struct `{}` and struct `{}` have at least 1 field with the same name",
            self.struct_1.0, self.struct_2.0
        )
    }
}

impl Error for SourceStructNotSubsetOfBase {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotations([
                    AnnotationKind::Primary
                        .span(self.source.1.into())
                        .label(format!("type `{}`", self.source.0))
                        .highlight_source(true),
                    AnnotationKind::Visible.span(self.literal_expr.into()),
                ]),
            ),
        );
    }
    fn description(&self) -> String {
        format!(
            "struct `{}` must be a subset of struct `{}`",
            self.source.0, self.base
        )
    }
}

impl Error for NoOpStructComp {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotation(
                    AnnotationKind::Primary
                        .span(self.0.into())
                        .highlight_source(true),
                ),
            ),
        );
    }
    fn description(&self) -> String {
        "A struct literal has all its fields explicitly specified while also having 1 or more struct compositions".to_owned()
    }
}

impl Error for InvalidSubstruct {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotations([
                    AnnotationKind::Primary
                        .span(self.sub.span.into())
                        .label(format!(
                            "`{}` is not a subset of `{}`",
                            self.sub, self.lhs.0
                        )),
                    AnnotationKind::Context
                        .span(self.lhs.1.into())
                        .label(format!("type `{}`", self.lhs.0)),
                ]),
            ),
        );
    }
    fn description(&self) -> String {
        format!(
            "invalid substruct operation: struct `{}` must be a subset of struct `{}`",
            self.sub, self.lhs.0
        )
    }
}

impl Error for MissingDefaultPattern {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotation(
                    AnnotationKind::Primary
                        .span(self.0.into())
                        .highlight_source(true),
                ),
            ),
        );
    }
    fn description(&self) -> String {
        "Missing default pattern in `match` statement/expression".to_owned()
    }
}

impl Error for UnreachableMatchArm {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotation(
                    AnnotationKind::Primary
                        .span(self.0.into())
                        .highlight_source(true),
                ),
            ),
        );
    }
    fn description(&self) -> String {
        "unreachable match arm".to_owned()
    }
}

impl Error for RedundantMatchArm {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotation(
                    AnnotationKind::Primary
                        .span(self.0.into())
                        .highlight_source(true),
                ),
            ),
        );
    }
    fn description(&self) -> String {
        "redundant literal pattern in same arm — binding already matches all values".to_owned()
    }
}

impl Error for TodoFound {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotation(
                    AnnotationKind::Primary
                        .span(self.0.into())
                        .highlight_source(true),
                ),
            ),
        );
    }
    fn description(&self) -> String {
        "`todo()` found with debug mode disabled".to_owned()
    }
}

impl Error for InvalidCast {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotations([
                    AnnotationKind::Primary
                        .span(self.rhs.span.into())
                        .label(format!(
                            "`{}` cannot be converted to `{}`",
                            self.lhs.0, self.rhs
                        )),
                    AnnotationKind::Context
                        .span(self.lhs.1.into())
                        .label(format!("type `{}`", self.lhs.0)),
                ]),
            ),
        );
    }
    fn description(&self) -> String {
        format!(
            "invalid cast: `{}` cannot be converted to `{}`",
            self.lhs.0, self.rhs
        )
    }
}

impl Error for CyclicTypeDefinitions {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
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
    fn description(&self) -> String {
        self.0.clone()
    }
}

impl Error for StructCompositionTypeMismatch {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
        let title = Level::ERROR.primary_title(self.description());

        report.push(
            title.element(
                Snippet::source(input).annotations([
                    AnnotationKind::Context
                        .span(self.expected_span.into())
                        .label(format!(
                            "field `{}` expects `{}`",
                            self.field_name, self.expected_type
                        )),
                    AnnotationKind::Primary
                        .span(self.found_span.into())
                        .label(format!(
                            "but field `{}` is `{}`",
                            self.field_name, self.found_type
                        )),
                    AnnotationKind::Visible.span(self.literal_span.into()),
                    AnnotationKind::Context
                        .span(self.composition_span.into())
                        .label("composed here"),
                ]),
            ),
        );
    }

    fn description(&self) -> String {
        format!(
            "struct composition type mismatch: field `{}` expects `{}` but found `{}`",
            self.field_name, self.expected_type, self.found_type
        )
    }
}

impl Error for BugError {
    fn add_group<'a>(&self, _input: &'a str, _report: &mut Vec<Group<'a>>) {
        // Bug errors are internal — minimal rendering
        let title = Level::ERROR.primary_title(self.0.to_string());
        _report.push(Group::with_title(title));
    }
    fn description(&self) -> String {
        format!("bug: {}", self.0)
    }
}

impl Error for UnknownError {
    fn add_group<'a>(&self, input: &'a str, report: &mut Vec<Group<'a>>) {
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
    fn description(&self) -> String {
        format!("unknown error: {}", self.0)
    }
}
