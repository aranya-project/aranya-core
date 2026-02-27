use std::fmt::Display;

use annotate_snippets::{AnnotationKind, Group, Level, Patch, Renderer, Snippet};
use aranya_policy_ast::Span;

use super::{InvalidNestedOption, InvalidOperator, ParseError, ParseErrorKind};

// TODO(Steve): Add helper macros for implementing this trait
// See https://rustc-dev-guide.rust-lang.org/diagnostics/diagnostic-structs.html
trait Report {
    fn add_group<'a>(&self, input: &'a str, message: &'a str, report: &mut Vec<Group<'a>>);
}

impl Report for InvalidOperator {
    fn add_group<'a>(&self, input: &'a str, message: &'a str, report: &mut Vec<Group<'a>>) {
        let Self { lhs, op, rhs } = self;

        let source = Snippet::source(input);
        let title = Level::ERROR.primary_title(self.to_string());

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
            lhs: &Span,
            rhs: &Span,
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
}

impl Report for InvalidNestedOption {
    fn add_group<'a>(&self, input: &'a str, message: &'a str, report: &mut Vec<Group<'a>>) {
        let Self { inner, outer } = &self;

        let source = Snippet::source(input);
        let title = Level::ERROR.primary_title(self.to_string());

        // Get the span of the entire expression
        let span = inner.merge(outer.clone());
        let primary_annoation = Snippet::source(input).annotation(
            AnnotationKind::Primary
                .span(span.start()..span.end())
                .label(message),
        );

        report.push(title.clone().element(primary_annoation));

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

        match **kind {
            ParseErrorKind::InvalidOperator(ref inner) => {
                inner.add_group(input, message, &mut report)
            }
            ParseErrorKind::InvalidNestedOption(ref inner) => {
                inner.add_group(input, message, &mut report)
            }
            _ => {
                let primary_annoation = Snippet::source(input).annotation(
                    AnnotationKind::Primary
                        .span(span.start()..span.end())
                        .label(message),
                );

                report.push(title.clone().element(primary_annoation))
            }
        }

        let message = Renderer::plain().render(&report);
        write!(f, "{message}")
    }
}
