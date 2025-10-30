extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::cmp::Ordering;

use aranya_policy_ast::Span;
use serde::{Deserialize, Serialize};

/// An error for a range that doesn't exist. Used in [CodeMap].
#[derive(Debug, thiserror::Error)]
#[error("range error")]
pub struct RangeError;

/// This is a simplified version of Pest's `Span`. We can't use Pest's version because we
/// need to work in `no_std` environments.
pub struct SpannedText<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

impl<'a> SpannedText<'a> {
    /// Create a span inside a text reference. `start` and `end` are expressed in bytes. If
    /// the `start` or `end` do not occur on a UTF-8 character boundary, this will return
    /// `None`.
    pub fn new(text: &'a str, start: usize, end: usize) -> Option<Self> {
        if text.get(start..end).is_some() {
            Some(SpannedText { text, start, end })
        } else {
            None
        }
    }

    /// The start of the span, in bytes. This is guaranteed to be on a UTF-8 boundary.
    pub fn start(&self) -> usize {
        self.start
    }

    /// The end of the span, in bytes. This is guaranteed to be on a UTF-8 boundary.
    pub fn end(&self) -> usize {
        self.end
    }

    /// Return the span as a &str. Assumes the start and end positions
    /// are character-aligned.
    pub fn as_str(&self) -> &str {
        &self.text[self.start..self.end]
    }

    /// Calculate the line and column position, in characters.
    fn linecol(&self, pos: usize) -> (usize, usize) {
        assert!(pos < self.text.len());
        let mut line: usize = 1;
        let mut col: usize = 1;
        for c in self.text[0..pos].chars() {
            if c == '\n' {
                line = line.checked_add(1).expect("line + 1 must not wrap");
                col = 1;
            } else {
                col = col.checked_add(1).expect("col + 1 must not wrap");
            }
        }

        (line, col)
    }

    /// Returns the line and column of the start position.
    pub fn start_linecol(&self) -> (usize, usize) {
        self.linecol(self.start)
    }

    /// Returns the line and column of the end position.
    pub fn end_linecol(&self) -> (usize, usize) {
        self.linecol(self.end)
    }
}

/// The code map contains the original source and can map VM instructions to text ranges
/// inside that source.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct CodeMap {
    /// The original policy source code
    text: String,
    /// A mapping between ranges of instructions and source spans.
    mapping: Vec<(usize, Span)>,
}

impl CodeMap {
    /// Create a new, empty CodeMap from a text and a set of ranges.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            mapping: Vec::new(),
        }
    }

    /// Get the original source code.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Add new mapping starting at `instruction` which maps to `span`.
    pub fn map_instruction(&mut self, instruction: usize, span: Span) -> Result<(), RangeError> {
        match self
            .mapping
            .last_mut()
            .map(|last| (instruction.cmp(&last.0), last))
        {
            // Don't break sorting.
            Some((Ordering::Less, _)) => return Err(RangeError),
            // Update existing span to be more specific.
            Some((Ordering::Equal, last)) => last.1 = span,
            // Add new span to end.
            Some((Ordering::Greater, _)) | None => self.mapping.push((instruction, span)),
        }
        Ok(())
    }

    /// Retrieve the [`Span`] containing the given instruction pointer.
    pub fn span_from_instruction(&self, ip: usize) -> Result<SpannedText<'_>, RangeError> {
        let idx = match self.mapping.binary_search_by(|(i, _)| i.cmp(&ip)) {
            Ok(idx) => idx,
            Err(idx) => idx.checked_sub(1).ok_or(RangeError)?,
        };
        let span = self.mapping[idx].1;
        SpannedText::new(&self.text, span.start(), span.end()).ok_or(RangeError)
    }
}
