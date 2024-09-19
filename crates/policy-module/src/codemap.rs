extern crate alloc;

use alloc::{borrow::ToOwned, string::String, vec, vec::Vec};
use core::fmt;

use serde::{Deserialize, Serialize};

/// An error for a range that doesn't exist. Used in [CodeMap].
#[derive(Debug)]
pub struct RangeError;

impl fmt::Display for RangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Range Error")
    }
}

impl core::error::Error for RangeError {}

/// This is a simplified version of Pest's `Span`. We can't use Pest's version because we
/// need to work in `no_std` environments.
pub struct Span<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

impl<'a> Span<'a> {
    /// Create a span inside a text reference. `start` and `end` are expressed in bytes. If
    /// the `start` or `end` do not occur on a UTF-8 character boundary, this will return
    /// `None`.
    pub fn new(text: &'a str, start: usize, end: usize) -> Option<Span<'a>> {
        if text.get(start..end).is_some() {
            Some(Span { text, start, end })
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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodeMap {
    /// The original policy source code
    text: String,
    /// All of the text ranges, mapped by locator. The key is the start
    /// of the range and the value is the end of the range.
    ranges: Vec<(usize, usize)>,
    /// A mapping between ranges of instructions and source code
    /// locators. The instuction ranges should be non-overlapping.
    instruction_mapping: Vec<(usize, usize)>,
}

impl CodeMap {
    /// Create a new, empty CodeMap from a text and a set of ranges.
    pub fn new(text: &str, ranges: Vec<(usize, usize)>) -> CodeMap {
        CodeMap {
            text: text.to_owned(),
            ranges,
            instruction_mapping: vec![],
        }
    }

    /// Add a new text range from its beginning and ending position
    /// A range can only be added if the start position has not already
    /// been added.
    pub fn add_text_range(&mut self, start: usize, end: usize) -> Result<(), RangeError> {
        match self.ranges.binary_search_by(|(s, _)| s.cmp(&start)) {
            Err(_) => {
                self.ranges.push((start, end));
                Ok(())
            }
            Ok(_) => Err(RangeError),
        }
    }

    /// Insert a new mapping between instruction position and text
    /// locator. You can only add a mapping for an instruction
    /// position larger than the last instruction position inserted.
    pub fn map_instruction_range(
        &mut self,
        instruction: usize,
        locator: usize,
    ) -> Result<(), RangeError> {
        if let Some(last_idx) = self.instruction_mapping.last() {
            if instruction == last_idx.0 {
                // Assume this is a more specific mapping and replace it
                self.instruction_mapping.pop();
            } else if instruction <= last_idx.0 {
                return Err(RangeError);
            }
        }
        self.instruction_mapping.push((instruction, locator));
        Ok(())
    }

    /// Retrieve the [Span] from the given locator
    pub fn span_from_locator(&self, locator: usize) -> Result<Span<'_>, RangeError> {
        match self.ranges.binary_search_by(|(s, _)| s.cmp(&locator)) {
            Ok(idx) => {
                let (start, end) = self.ranges[idx];
                if let Some(span) = Span::new(&self.text, start, end) {
                    Ok(span)
                } else {
                    Err(RangeError)
                }
            }
            Err(_) => Err(RangeError),
        }
    }

    /// Retrieve the locator for the given instruction pointer
    pub fn locator_from_instruction(&self, ip: usize) -> Result<usize, RangeError> {
        // Unwrapping the error case of binary_search_by() will get us
        // the closest entry prior to the target.
        let r = self
            .instruction_mapping
            .binary_search_by(|(i, _)| i.cmp(&ip));
        let idx = match r {
            Ok(v) => Ok(v),
            Err(v) => v.checked_sub(1).ok_or(RangeError),
        }?;
        let (_, locator) = self.instruction_mapping[idx];
        Ok(locator)
    }

    /// Retrieve the [Span] containing the given instruction pointer.
    pub fn span_from_instruction(&self, ip: usize) -> Result<Span<'_>, RangeError> {
        let locator = self.locator_from_instruction(ip)?;
        self.span_from_locator(locator)
    }
}
