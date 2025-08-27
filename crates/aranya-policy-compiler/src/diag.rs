//! Compiler errors and diagnostics.

#![expect(clippy::unwrap_used, clippy::panic, clippy::panic_in_result_fn)]

use std::{
    borrow::Cow,
    cell::RefCell,
    convert::Infallible,
    fmt,
    hash::Hash,
    marker::PhantomData,
    ops::{ControlFlow, Deref, DerefMut},
    panic,
};

use buggy::Bug;
pub(crate) use codespan_reporting::diagnostic::{Label, Severity};
use codespan_reporting::{
    diagnostic,
    files::SimpleFile,
    term::{
        self,
        termcolor::{ColorChoice, StandardStream},
    },
};

use crate::hir::Span;

/// A trait that guarantees the emission of a diagnostic.
pub(crate) trait EmissionGuarantee: Sized {
    /// The result type of the emission.
    type EmitResult;

    /// An implementation of [`Diag::emit`].
    fn emit_producing_guarantee(diag: Diag<'_, Self>) -> Self::EmitResult;
}

impl EmissionGuarantee for () {
    type EmitResult = Self;

    fn emit_producing_guarantee(mut diag: Diag<'_, Self>) -> Self::EmitResult {
        let inner = diag.take_diag();
        diag.ctx.emit(inner);
    }
}

/// Used with [`Result`] to indicate that an error has been
/// reported and compilation can stop.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ErrorGuaranteed(());

impl ErrorGuaranteed {
    /// Aborts the process with a fatal error.
    pub fn raise_fatal(self) -> ! {
        #[derive(Debug)]
        struct FatalError;

        panic::resume_unwind(Box::new(FatalError))
    }
}

impl EmissionGuarantee for ErrorGuaranteed {
    type EmitResult = Self;

    fn emit_producing_guarantee(mut diag: Diag<'_, Self>) -> Self::EmitResult {
        let inner = diag.take_diag();
        assert_eq!(inner.severity, Severity::Error);
        diag.ctx.emit(inner)
    }
}

// TODO(eric): keep this impl?
impl From<ErrorGuaranteed> for ControlFlow<ErrorGuaranteed> {
    fn from(err: ErrorGuaranteed) -> Self {
        ControlFlow::Break(err)
    }
}

/// Marker type for the `emit_bug` type methods on [`DiagCtx`].
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct BugAbort;

impl EmissionGuarantee for BugAbort {
    type EmitResult = Infallible;

    fn emit_producing_guarantee(mut diag: Diag<'_, Self>) -> Self::EmitResult {
        #[derive(Clone, Debug)]
        struct ExplicitBug;

        let inner = diag.take_diag();
        assert_eq!(inner.severity, Severity::Bug);
        diag.ctx.emit(inner);

        panic::panic_any(ExplicitBug)
    }
}

/// Implemented by error types.
///
/// Only implement this trait for a generic
/// [`EmissionGuarantee`], even if it is only ever used with
/// a specific implementation.
///
/// ```ignore
/// struct MyDiag;
///
/// impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for MyDiag { ... }
/// ```
pub(crate) trait Diagnostic<'a, G: EmissionGuarantee = ErrorGuaranteed>: fmt::Debug {
    /// Converts the error into a [`Diag`].
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G>;
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for Diag<'a, G> {
    fn into_diag(self, _ctx: &'a DiagCtx, _severity: Severity) -> Diag<'a, G> {
        self
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for Bug {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        assert_eq!(severity, Severity::Bug);

        Diag::new(ctx, severity, self.to_string())
    }
}

/// A diagnostic message.
pub(crate) type DiagMsg = Cow<'static, str>;

/// A structured diagnostic.
///
/// `Diag` must either be [emitted][Self::emit] or
/// [cancelled][Self::cancel] before being dropped, otherwise it
/// will panic.
#[must_use]
pub(crate) struct Diag<'a, G: EmissionGuarantee = ErrorGuaranteed> {
    pub ctx: &'a DiagCtx,
    /// This is set to `None` when the diagnostic is consumed
    /// (emitted, canceled, etc.).
    diag: Option<DiagInner>,
    _marker: PhantomData<G>,
}

impl<'a, G: EmissionGuarantee> Diag<'a, G> {
    /// Creates a new diagnostic.
    pub fn new(ctx: &'a DiagCtx, severity: Severity, msg: impl Into<DiagMsg>) -> Self {
        Self {
            ctx,
            diag: Some(DiagInner {
                severity,
                code: None,
                message: msg.into().into_owned(),
                notes: Vec::new(),
                span: MultiSpan::new(),
            }),
            _marker: PhantomData,
        }
    }

    /// Emits and consumes the diagnostic.
    pub fn emit(self) -> G::EmitResult {
        G::emit_producing_guarantee(self)
    }

    /// Cancels and consumes the diagnostic.
    pub fn cancel(mut self) {
        self.diag = None;
        drop(self);
    }

    /// Sets the diagnostic's span.
    pub fn with_span(mut self, span: impl Into<MultiSpan>) -> Self {
        self.span = span.into();
        self
    }

    /// Adds a note to the diagnostic.
    pub fn with_note(mut self, msg: impl Into<DiagMsg>) -> Self {
        self.deref_mut().notes.push(msg.into().into_owned());
        self
    }

    fn take_diag(&mut self) -> DiagInner {
        self.diag.take().unwrap()
    }
}

impl<G: EmissionGuarantee> Deref for Diag<'_, G> {
    type Target = DiagInner;

    fn deref(&self) -> &Self::Target {
        self.diag.as_ref().unwrap()
    }
}

impl<G: EmissionGuarantee> DerefMut for Diag<'_, G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.diag.as_mut().unwrap()
    }
}

impl<G: EmissionGuarantee> fmt::Debug for Diag<'_, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.diag.fmt(f)
    }
}

impl<G: EmissionGuarantee> Drop for Diag<'_, G> {
    fn drop(&mut self) {
        if self.diag.is_some() {
            panic!("Diag was not emitted: {:?}", self);
        }
    }
}

/// The inner part of [`Diag`].
#[must_use]
#[derive(Clone, Debug)]
pub(crate) struct DiagInner {
    /// The severity of the diagnostic.
    pub severity: Severity,
    /// The diagnostic's error code, if any.
    // TODO(eric): Make this required.
    pub code: Option<String>,
    /// The main diagnostic message.
    pub message: String,
    /// Additional notes for the diagnostic.
    /// May include line breaks.
    pub notes: Vec<String>,
    /// The diagnostic's span.
    pub span: MultiSpan,
}

/// Diagnostic context for the compiler.
#[derive(Clone, Debug)]
pub struct DiagCtx {
    file: SimpleFile<Cow<'static, str>, String>,
    errs: RefCell<Vec<ErrorGuaranteed>>,
}

impl DiagCtx {
    /// Creates a diagnostic context.
    pub fn new(src: &str, path: &str) -> Self {
        Self {
            file: SimpleFile::new(fix_path(path.to_string()), src.to_string()),
            errs: RefCell::new(Vec::new()),
        }
    }

    /// Aborts if an error or bug has occurred.
    pub fn abort_if_errors(&self) {
        if let Some(err) = self.has_errors() {
            err.raise_fatal();
        }
    }

    /// Returns `Some` if an error has occurred.
    pub fn has_errors(&self) -> Option<ErrorGuaranteed> {
        self.errs.borrow().first().copied()
    }

    fn emit(&self, inner: DiagInner) -> ErrorGuaranteed {
        let writer = StandardStream::stderr(ColorChoice::Auto);
        let stderr = &mut writer.lock();

        let mut diag = diagnostic::Diagnostic {
            severity: inner.severity,
            code: inner.code,
            message: match inner.severity {
                Severity::Bug => format!("ICE: {}", inner.message),
                _ => inner.message,
            },
            labels: Vec::new(),
            notes: inner.notes,
        };
        for (span, msg) in inner.span.primary {
            let label = Label::primary((), self.fix_span(span)).with_message(msg);
            diag.labels.push(label);
        }
        for (span, msg) in inner.span.labels {
            let label = Label::secondary((), self.fix_span(span)).with_message(msg);
            diag.labels.push(label);
        }

        let mut config = term::Config::default();
        config.styles.header_error.set_intense(true);
        config.styles.line_number.set_intense(true);
        config.styles.note_bullet.set_intense(true);
        config.styles.primary_label_bug.set_intense(true);
        config.styles.primary_label_error.set_intense(true);
        config.styles.secondary_label.set_intense(true);
        config.styles.source_border.set_intense(true);
        let _ = term::emit(stderr, &config, &self.file, &diag);

        self.errs.borrow_mut().push(ErrorGuaranteed(()));

        ErrorGuaranteed(())
    }

    fn fix_span(&self, mut span: Span) -> Span {
        let src = self.file.source().as_str();
        if span.is_empty() {
            // Inflate the empty span to the end of its current
            // line.
            let frag = &src[span.start()..];
            let end = src.find('\n').unwrap_or(frag.len());
            return Span::new(span.start(), end);
        }
        // Chop off trailing whitespace so that our messages
        // don't unnecessarily span multiple lines.
        loop {
            let frag = src[span.into_range()].as_bytes();
            if !frag.last().is_some_and(|v| v.is_ascii_whitespace()) {
                break;
            }
            span = Span::new(span.start(), span.end().saturating_sub(1));
        }
        span
    }
}

impl DiagCtx {
    /// Creates an error diagnostic.
    pub fn create_err(&self, msg: impl Into<DiagMsg>) -> Diag<'_, ErrorGuaranteed> {
        Diag::new(self, Severity::Error, msg)
    }

    /// Emits an error diagnostic.
    pub fn emit_span_err(
        &self,
        span: impl Into<MultiSpan>,
        msg: impl Into<DiagMsg>,
    ) -> ErrorGuaranteed {
        self.create_err(msg).with_span(span).emit()
    }

    /// Emits an error diagnostic.
    pub fn emit_err_diag<'a>(&'a self, diag: impl Diagnostic<'a>) -> ErrorGuaranteed {
        diag.into_diag(self, Severity::Error).emit()
    }
}

impl DiagCtx {
    fn create_bug(&self, msg: impl Into<DiagMsg>) -> Diag<'_, BugAbort> {
        Diag::new(self, Severity::Bug, msg)
    }

    /// Emits an ICE diagnostic.
    pub fn emit_bug_diag<'a>(&'a self, diag: impl Diagnostic<'a, BugAbort>) -> ! {
        diag.into_diag(self, Severity::Bug).emit();
        unreachable!()
    }

    /// Emits an ICE diagnostic.
    pub fn emit_span_bug(&self, span: impl Into<MultiSpan>, msg: impl Into<DiagMsg>) -> ! {
        self.create_bug(msg).with_span(span).emit();
        unreachable!()
    }

    /// Emits an ICE diagnostic.
    pub fn emit_bug(&self, msg: impl Into<DiagMsg>) -> ! {
        self.create_bug(msg).emit();
        unreachable!()
    }
}

fn fix_path(path: String) -> Cow<'static, str> {
    if path == "-" {
        if cfg!(unix) {
            Cow::Borrowed("/dev/stdin")
        } else {
            Cow::Borrowed("stdin")
        }
    } else {
        Cow::Owned(path)
    }
}

/// A collection of spans.
#[derive(Clone, Default, Debug)]
pub(crate) struct MultiSpan {
    // Labels that describe the primary cause of the diagnostic.
    primary: Vec<(Span, DiagMsg)>,
    // Labels that provide additional context for the diagnostic.
    labels: Vec<(Span, DiagMsg)>,
}

impl MultiSpan {
    /// Creates an empty collection of spans.
    pub fn new() -> Self {
        Self {
            primary: Vec::new(),
            labels: Vec::new(),
        }
    }

    /// Creates a collection of spans from a single primary span.
    pub fn from_span(span: Span, msg: impl Into<DiagMsg>) -> Self {
        Self {
            primary: vec![(span, msg.into())],
            labels: Vec::new(),
        }
    }

    /// Adds primary span to the collection of spans.
    pub fn push_primary(&mut self, span: Span, msg: impl Into<DiagMsg>) {
        self.primary.push((span, msg.into()));
    }

    /// Adds a label to the collection of spans.
    pub fn push_label(&mut self, span: Span, msg: impl Into<DiagMsg>) {
        self.labels.push((span, msg.into()));
    }

    /// Are there any spans in this collection?
    pub fn is_empty(&self) -> bool {
        self.primary.is_empty() && self.labels.is_empty()
    }
}

impl From<(Span, &str)> for MultiSpan {
    fn from((span, msg): (Span, &str)) -> Self {
        Self::from_span(span, Cow::Owned(String::from(msg)))
    }
}

impl From<(Span, DiagMsg)> for MultiSpan {
    fn from((span, msg): (Span, DiagMsg)) -> Self {
        Self::from_span(span, msg)
    }
}

impl From<Vec<(Span, DiagMsg)>> for MultiSpan {
    fn from(spans: Vec<(Span, DiagMsg)>) -> Self {
        Self {
            primary: spans,
            labels: Vec::new(),
        }
    }
}

/// Extension trait for [`Result`].
pub(crate) trait ResultExt<T, E> {
    /// Returns the [`Ok`] value, or emits an ICE.
    fn unwrap_or_bug(self, ctx: &DiagCtx, msg: impl Into<DiagMsg>) -> T;
}

impl<T, E> ResultExt<T, E> for Result<T, E>
where
    E: fmt::Debug,
{
    fn unwrap_or_bug(self, ctx: &DiagCtx, msg: impl Into<DiagMsg>) -> T {
        match self {
            Ok(val) => val,
            Err(err) => ctx.emit_bug(UnwrapOrBug {
                msg: msg.into(),
                err,
            }),
        }
    }
}

/// Extension trait for [`Option`].
pub(crate) trait OptionExt<T> {
    /// Returns the [`Some`] value, or emits an ICE.
    fn unwrap_or_bug(self, ctx: &DiagCtx, msg: impl Into<DiagMsg>) -> T;
}

impl<T> OptionExt<T> for Option<T> {
    fn unwrap_or_bug(self, ctx: &DiagCtx, msg: impl Into<DiagMsg>) -> T {
        match self {
            Some(val) => val,
            None => ctx.emit_bug(UnwrapOrBug {
                msg: msg.into(),
                err: (),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{msg}: {err:?}")]
struct UnwrapOrBug<E> {
    msg: DiagMsg,
    err: E,
}

impl<E> From<UnwrapOrBug<E>> for DiagMsg
where
    E: fmt::Debug,
{
    fn from(err: UnwrapOrBug<E>) -> Self {
        DiagMsg::Owned(err.to_string())
    }
}

impl<'a, G, E> Diagnostic<'a, G> for UnwrapOrBug<E>
where
    G: EmissionGuarantee,
    E: fmt::Debug,
{
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        Diag::new(ctx, severity, self)
    }
}
