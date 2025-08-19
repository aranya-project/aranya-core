//! Error reporting.
//!
//! Largely taken from [`cxx`].
//!
//! [`cxx`]: https://github.com/dtolnay/cxx/blob/a73ec2470e065d6d93817c6957e368c73a8c964d/gen/src/error.rs

#![allow(
    clippy::duplicated_attributes,
    reason = "See https://github.com/rust-lang/rust-clippy/issues/13355"
)]
#![allow(clippy::arithmetic_side_effects, reason = "Borrowed code")]
#![allow(clippy::unwrap_used, reason = "Borrowed code")]
#![allow(clippy::toplevel_ref_arg, reason = "Borrowed code")]

use std::{
    borrow::Cow,
    error::Error,
    fmt,
    io::{self, Write},
    ops::Range,
    path::Path,
};

use codespan_reporting::{
    diagnostic::{Diagnostic, Label},
    files::SimpleFiles,
    term::{
        self,
        termcolor::{ColorChoice, StandardStream, WriteColor},
    },
};

use crate::syntax::ERRORS;

/// An error returned when building.
pub enum BuildError {
    /// An error from `syn`.
    Syn(syn::Error),
    /// Some other error.
    Other(anyhow::Error),
}

impl Error for BuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Syn(err) => Some(err),
            Self::Other(err) => Some(err.as_ref()),
        }
    }
}

impl From<syn::Error> for BuildError {
    fn from(err: syn::Error) -> Self {
        Self::Syn(err)
    }
}

impl From<anyhow::Error> for BuildError {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err)
    }
}

impl fmt::Debug for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unable to generate C API")
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", report(self))
    }
}

impl BuildError {
    /// Displays the error.
    pub fn display(&self, path: &Path, source: &str) {
        match self {
            Self::Syn(err) => {
                let errs = sort_syn_error(err);
                let writer = StandardStream::stderr(ColorChoice::Auto);
                let ref mut stderr = writer.lock();
                for error in errs {
                    let _ = writeln!(stderr);
                    display_syn_error(stderr, path, source, error);
                }
            }
            Self::Other(_) => {
                let _ = writeln!(io::stderr(), "{self}");
            }
        }
    }
}

fn report(err: impl Error) -> impl fmt::Display {
    struct Report<E>(E);
    impl<E: Error> fmt::Display for Report<E> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)?;
            let mut error: &dyn Error = &self.0;

            while let Some(cause) = error.source() {
                write!(f, "\n\nCaused by:\n    {cause}")?;
                error = cause;
            }

            Ok(())
        }
    }
    Report(err)
}

fn sort_syn_error(err: &syn::Error) -> Vec<syn::Error> {
    let mut errors: Vec<_> = err.into_iter().collect();
    errors.sort_by_key(|e| {
        let start = e.span().start();
        (start.line, start.column)
    });
    errors
}

fn display_syn_error(stderr: &mut dyn WriteColor, path: &Path, source: &str, err: syn::Error) {
    let span = err.span();
    let start = span.start();
    let end = span.end();

    let mut start_offset = 0;
    for _ in 1..start.line {
        start_offset += source[start_offset..].find('\n').unwrap() + 1;
    }
    let start_column = source[start_offset..]
        .chars()
        .take(start.column)
        .map(char::len_utf8)
        .sum::<usize>();
    start_offset += start_column;

    let mut end_offset = start_offset;
    if start.line == end.line {
        end_offset -= start_column;
    } else {
        for _ in 0..end.line - start.line {
            end_offset += source[end_offset..].find('\n').unwrap() + 1;
        }
    }
    end_offset += source[end_offset..]
        .chars()
        .take(end.column)
        .map(char::len_utf8)
        .sum::<usize>();

    let mut path = path.to_string_lossy();
    if path == "-" {
        path = Cow::Borrowed(if cfg!(unix) { "/dev/stdin" } else { "stdin" });
    }

    let mut files = SimpleFiles::new();
    let file = files.add(path, source);

    let diagnostic = diagnose(file, start_offset..end_offset, err);

    let mut config = term::Config::default();
    // Make it a little easier to see on dark backgrounds.
    config.styles.header_error.set_intense(true);
    config.styles.line_number.set_intense(true);
    config.styles.note_bullet.set_intense(true);
    config.styles.primary_label_bug.set_intense(true);
    config.styles.primary_label_error.set_intense(true);
    config.styles.secondary_label.set_intense(true);
    config.styles.source_border.set_intense(true);
    let _ = term::emit(stderr, &config, &files, &diagnostic);
}

fn diagnose(file: usize, range: Range<usize>, error: syn::Error) -> Diagnostic<usize> {
    let message = error.to_string();
    let info = ERRORS.iter().find(|e| message.contains(e.msg));
    let mut diagnostic = Diagnostic::error().with_message(&message);
    let mut label = Label::primary(file, range);
    if let Some(info) = info {
        label.message = info.label.map_or(message, str::to_owned);
        diagnostic.labels.push(label);
        diagnostic.notes.extend(info.note.map(str::to_owned));
    } else {
        label.message = message;
        diagnostic.labels.push(label);
    }
    diagnostic.code = Some("capi-codegen".to_owned());
    diagnostic
}
