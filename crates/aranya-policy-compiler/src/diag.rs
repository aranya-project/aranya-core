//! Compiler errors and diagnostics.

use std::{
    borrow::Cow,
    cell::RefCell,
    convert::Infallible,
    fmt,
    hash::Hash,
    marker::PhantomData,
    ops::{ControlFlow, Deref, DerefMut},
    panic::panic_any,
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

pub(crate) trait EmissionGuarantee: Sized {
    type EmitResult;
    fn emit_producing_guarantee(diag: Diag<'_, Self>) -> Self::EmitResult;
}

impl EmissionGuarantee for () {
    type EmitResult = Self;

    fn emit_producing_guarantee(mut diag: Diag<'_, Self>) -> Self::EmitResult {
        let inner = diag.take_diag();
        diag.ctx.emit(inner);
    }
}

/// Used with `Result<>` to indicate that an error has been
/// reported and the compiler should exit.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct ErrorGuaranteed(());

impl ErrorGuaranteed {
    pub fn raise_fatal(self) -> ! {
        std::process::abort()
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

impl From<ErrorGuaranteed> for ControlFlow<ErrorGuaranteed> {
    fn from(err: ErrorGuaranteed) -> Self {
        ControlFlow::Break(err)
    }
}

/// Marker type for the TODO
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

        panic_any(ExplicitBug)
    }
}

pub(crate) trait Diagnostic<'a, G: EmissionGuarantee = ErrorGuaranteed> {
    #[must_use]
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

/// A structured diagnostic error or bug.
#[must_use]
pub(crate) struct Diag<'a, G: EmissionGuarantee = ErrorGuaranteed> {
    pub ctx: &'a DiagCtx,
    diag: Option<DiagInner>,
    _marker: PhantomData<G>,
}

impl<'a, G: EmissionGuarantee> Diag<'a, G> {
    pub fn new(ctx: &'a DiagCtx, severity: Severity, msg: impl Into<DiagMsg>) -> Self {
        Self {
            ctx,
            diag: Some(DiagInner {
                severity,
                code: None,
                message: msg.into().into_owned(),
                labels: Vec::new(),
                notes: Vec::new(),
            }),
            _marker: PhantomData,
        }
    }

    /// Emits and consumes the diagnostic.
    pub fn emit(self) -> G::EmitResult {
        G::emit_producing_guarantee(self)
    }

    /// Adds spans to the diagnostic.
    #[must_use]
    pub fn with_span(mut self, span: impl Into<MultiSpan>) -> Self {
        let span = span.into();
        for (span, msg) in span.labels {
            let label = Label::primary((), span).with_message(msg);
            self = self.with_label(label);
        }
        self
    }

    /// Adds a label to the diagnostic.
    #[must_use]
    pub fn with_label(mut self, label: Label<()>) -> Self {
        self.deref_mut().labels.push(label);
        self
    }

    /// Adds a note to the diagnostic.
    #[must_use]
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

#[derive(Clone, Debug)]
pub(crate) struct DiagInner<FileId = ()> {
    pub severity: Severity,
    pub code: Option<String>,
    pub message: String,
    pub labels: Vec<Label<FileId>>,
    pub notes: Vec<String>,
}

impl<FileId> Into<diagnostic::Diagnostic<FileId>> for DiagInner<FileId> {
    fn into(self) -> diagnostic::Diagnostic<FileId> {
        diagnostic::Diagnostic {
            severity: self.severity,
            code: self.code,
            message: self.message,
            labels: self.labels,
            notes: self.notes,
        }
    }
}

/// Diagnostic context.
#[derive(Clone, Debug)]
pub(crate) struct DiagCtx {
    file: SimpleFile<Cow<'static, str>, String>,
    errs: RefCell<Vec<ErrorGuaranteed>>,
}

impl DiagCtx {
    /// Creates a diagnostic context.
    pub fn new(path: &str, src: &str) -> Self {
        Self {
            file: SimpleFile::new(fix_path(path.to_string()), src.to_string()),
            errs: RefCell::new(Vec::new()),
        }
    }

    /// Aborts if an error or bug has occurred.
    pub fn abort_if_errors(&self) {
        if let Some(err) = self.errs.borrow().first() {
            err.raise_fatal();
        }
    }

    fn emit(&self, diag: DiagInner) -> ErrorGuaranteed {
        let writer = StandardStream::stderr(ColorChoice::Auto);
        let ref mut stderr = writer.lock();

        let mut config = term::Config::default();
        config.styles.header_error.set_intense(true);
        config.styles.line_number.set_intense(true);
        config.styles.note_bullet.set_intense(true);
        config.styles.primary_label_bug.set_intense(true);
        config.styles.primary_label_error.set_intense(true);
        config.styles.secondary_label.set_intense(true);
        config.styles.source_border.set_intense(true);
        let _ = term::emit(stderr, &config, &self.file, &diag.into());

        self.errs.borrow_mut().push(ErrorGuaranteed(()));

        ErrorGuaranteed(())
    }
}

impl DiagCtx {
    fn create_err(&self, msg: impl Into<DiagMsg>) -> Diag<'_, ErrorGuaranteed> {
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
    primary: Vec<Span>,
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
    pub fn from_span(span: Span) -> Self {
        Self {
            primary: vec![span],
            labels: Vec::new(),
        }
    }

    /// Adds a label to the collection of spans.
    pub fn push_label(&mut self, span: Span, msg: impl Into<DiagMsg>) {
        self.labels.push((span, msg.into()));
    }
}

impl From<Span> for MultiSpan {
    fn from(span: Span) -> Self {
        Self::from_span(span)
    }
}

impl From<Vec<Span>> for MultiSpan {
    fn from(spans: Vec<Span>) -> Self {
        Self {
            primary: spans,
            labels: Vec::new(),
        }
    }
}
