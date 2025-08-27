use core::{
    cmp::Ordering,
    fmt,
    ops::{Bound, Range, RangeBounds},
};

use serde::{Deserialize, Serialize};

/// A range in the source text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    // [start, end)
    start: usize,
    end: usize,
}

impl Span {
    /// Create a new span
    pub fn new(start: usize, end: usize) -> Self {
        debug_assert!(
            start <= end,
            "invalid span: start ({}) must be <= end ({})",
            start,
            end
        );
        Span { start, end }
    }

    /// Returns the start position.
    pub fn start(&self) -> usize {
        self.start
    }

    /// Returns the end position.
    pub fn end(&self) -> usize {
        self.end
    }

    /// Reports whether `self` contains `other`.
    pub fn contains<U>(&self, other: U) -> bool
    where
        U: RangeBounds<usize>,
    {
        self.intersect(&other.to_bounds()) == other.to_bounds() && !other.is_empty()
    }

    /// Merges two spans into a single span.
    pub fn merge(&self, other: Span) -> Span {
        Self::new(self.start.min(other.start), self.end.max(other.end))
    }

    /// Returns the length of the span.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Reports whether the span is empty.
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Converts the span into a [`Range`].
    pub fn into_range(self) -> Range<usize> {
        self.start..self.end
    }
}

impl Default for Span {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl RangeBounds<usize> for Span {
    fn start_bound(&self) -> Bound<&usize> {
        Bound::Included(&self.start)
    }

    fn end_bound(&self) -> Bound<&usize> {
        Bound::Excluded(&self.end)
    }
}

impl RangeBounds<usize> for &Span {
    fn start_bound(&self) -> Bound<&usize> {
        (**self).start_bound()
    }

    fn end_bound(&self) -> Bound<&usize> {
        (**self).end_bound()
    }
}

impl From<Range<usize>> for Span {
    fn from(range: Range<usize>) -> Self {
        Span::new(range.start, range.end)
    }
}

impl From<Span> for Range<usize> {
    fn from(span: Span) -> Self {
        span.start..span.end
    }
}

impl From<aranya_policy_module::Span<'_>> for Span {
    fn from(span: aranya_policy_module::Span<'_>) -> Self {
        Span::new(span.start(), span.end())
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Range::from(*self).fmt(f)
    }
}

/// Extension trait for [`RangeBounds`].
///
/// Similar to the +nightly `IntoBounds`.
trait RangeBoundsExt<T>: RangeBounds<T> {
    /// Returns the (start, end) bounds.
    fn to_bounds(&self) -> (Bound<&T>, Bound<&T>) {
        (self.start_bound(), self.end_bound())
    }

    /// Reports whether `self` is the empty range.
    fn is_empty(&self) -> bool
    where
        T: PartialOrd,
    {
        use Bound::*;
        !match (self.start_bound(), self.end_bound()) {
            (Unbounded, _) | (_, Unbounded) => true,
            (Included(start), Excluded(end))
            | (Excluded(start), Included(end))
            | (Excluded(start), Excluded(end)) => start < end,
            (Included(start), Included(end)) => start <= end,
        }
    }

    /// Returns the intersection of `self` and `other`.
    fn intersect<'a, U>(&'a self, other: &'a U) -> (Bound<&'a T>, Bound<&'a T>)
    where
        Self: Sized,
        U: RangeBounds<T>,
        T: Ord,
    {
        use Bound::*;

        let (self_start, self_end) = self.to_bounds();
        let (other_start, other_end) = other.to_bounds();

        let start = match (self_start, other_start) {
            (Included(a), Included(b)) => Included(Ord::max(a, b)),
            (Excluded(a), Excluded(b)) => Excluded(Ord::max(a, b)),
            (Unbounded, Unbounded) => Unbounded,
            (x, Unbounded) | (Unbounded, x) => x,
            (Included(i), Excluded(e)) | (Excluded(e), Included(i)) => {
                if i > e {
                    Included(i)
                } else {
                    Excluded(e)
                }
            }
        };
        let end = match (self_end, other_end) {
            (Included(a), Included(b)) => Included(Ord::min(a, b)),
            (Excluded(a), Excluded(b)) => Excluded(Ord::min(a, b)),
            (Unbounded, Unbounded) => Unbounded,
            (x, Unbounded) | (Unbounded, x) => x,
            (Included(i), Excluded(e)) | (Excluded(e), Included(i)) => {
                if i < e {
                    Included(i)
                } else {
                    Excluded(e)
                }
            }
        };
        (start, end)
    }
}
impl<R, T> RangeBoundsExt<T> for R where R: RangeBounds<T> {}

/// A trait for types that can provide a source span.
pub trait Spanned {
    /// Returns a span covering the contents of the item.
    fn span(&self) -> Span;
}

impl<T: Spanned> Spanned for &T {
    fn span(&self) -> Span {
        (**self).span()
    }
}

impl<A, B> Spanned for (A, B)
where
    A: Spanned,
    B: Spanned,
{
    fn span(&self) -> Span {
        self.0.span().merge(self.1.span())
    }
}

impl<T: Spanned> Spanned for [T] {
    fn span(&self) -> Span {
        self.iter()
            .map(Spanned::span)
            .reduce(|acc, span| acc.merge(span))
            .unwrap_or_default()
    }
}

impl<T: Spanned, const N: usize> Spanned for [T; N] {
    fn span(&self) -> Span {
        self.as_slice().span()
    }
}

impl<T: Spanned> Spanned for Vec<T> {
    fn span(&self) -> Span {
        self.as_slice().span()
    }
}

impl<T: Spanned> Spanned for Option<T> {
    fn span(&self) -> Span {
        self.as_ref().map(Spanned::span).unwrap_or_default()
    }
}

macro_rules! spanned {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field:ident : $ty:ty
            ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $(
                $(#[$field_meta])*
                $field_vis $field: $ty,
            )+
        }
        impl Spanned for $name {
            fn span(&self) -> Span {
                let spans = &[ $(self.$field.span()),* ];
                spans
                    .iter()
                    .copied()
                    .reduce(|acc, span| acc.merge(span))
                    .unwrap_or_default()
            }
        }
    };
}
pub(crate) use spanned;

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! span {
        ($start:expr, $end:expr) => {
            Span::new($start, $end)
        };
    }

    #[test]
    #[should_panic(expected = "invalid span")]
    #[cfg(debug_assertions)]
    fn test_span_new_invalid() {
        // This should panic in debug mode
        span!(10, 5);
    }

    #[test]
    fn test_span_contains() {
        let test_cases = [
            (span!(10, 20), 12..18, true),                 // inner range contained
            (span!(10, 20), 5..25, false),                 // outer range not contained
            (span!(10, 20), 15..25, false),                // overlapping range not contained
            (span!(10, 20), 5..15, false),                 // partial overlap not contained
            (span!(10, 20), 10..20, true),                 // span contains itself
            (span!(10, 20), 10..19, true),                 // starts at boundary, ends before
            (span!(10, 20), 11..20, true),                 // ends at boundary (excluded)
            (span!(10, 20), 10..20, true),                 // exact same range
            (span!(10, 20), 15..15, false),                // empty range inside span
            (span!(10, 20), 10..10, false),                // empty range at start
            (span!(10, 20), 20..20, false),                // empty range at end (excluded)
            (span!(10, 10), 10..10, false), // empty span contains empty range at same position
            (span!(0, usize::MAX), 0..100, true), // max span contains regular range
            (span!(0, usize::MAX), 0..(usize::MAX), true), // max span contains almost-max range
        ];
        for (i, (span, other, want)) in test_cases.iter().enumerate() {
            let got = span.contains(other.clone());
            assert_eq!(got, *want, "#{i}: contains({span:?}, {other:?})");
        }

        let inclusive_cases = [
            (span!(10, 20), 12..=17, true),  // inclusive range contained
            (span!(10, 20), 10..=19, true),  // inclusive range at boundaries
            (span!(10, 20), 10..=20, false), // inclusive range extends to excluded end
            (span!(10, 20), 15..=25, false), // inclusive range extends beyond
            (span!(10, 11), 10..=10, true),  // single-element inclusive range
        ];
        for (i, (span, other, want)) in inclusive_cases.iter().enumerate() {
            let got = span.contains(other.clone());
            assert_eq!(got, *want, "#{i}: contains({span:?}, {other:?})");
        }

        let range_full_cases = [
            (span!(10, 20), false),        // regular span can't contain unbounded range
            (span!(0, usize::MAX), false), // even max span can't contain unbounded range
            (Span::default(), false),      // empty span can't contain unbounded range
        ];
        for (i, (span, want)) in range_full_cases.iter().enumerate() {
            let got = span.contains(..);
            assert_eq!(got, *want, "#{i}: contains({span:?}, ..)");
        }

        let range_from_cases = [
            (span!(10, 20), 15, false),         // unbounded end not contained
            (span!(10, 20), 10, false),         // starts at boundary, unbounded end
            (span!(10, 20), 0, false),          // starts before, unbounded end
            (span!(10, 20), 25, false),         // starts after, unbounded end
            (span!(0, usize::MAX), 100, false), // even max span can't contain unbounded end
            (span!(0, usize::MAX), 0, false),   // max span starting at 0, unbounded end
        ];
        for (i, (span, start, want)) in range_from_cases.iter().enumerate() {
            let got = span.contains(*start..);
            assert_eq!(got, *want, "#{i}: contains({span:?}, {start}..)");
        }

        let range_to_cases = [
            (span!(10, 20), 15, false),                // unbounded start not contained
            (span!(10, 20), 20, false),                // unbounded start, ends at boundary
            (span!(10, 20), 25, false),                // unbounded start, ends after
            (span!(10, 20), 5, false),                 // unbounded start, ends before
            (span!(0, usize::MAX), 100, false), // even max span can't contain unbounded start
            (span!(0, usize::MAX), usize::MAX, false), // max span ending at max, unbounded start
        ];
        for (i, (span, end, want)) in range_to_cases.iter().enumerate() {
            let got = span.contains(..*end);
            assert_eq!(got, *want, "#{i}: contains({span:?}, ..{end})");
        }

        let range_to_inclusive_cases = [
            (span!(10, 20), 15, false),         // unbounded start not contained
            (span!(10, 20), 19, false),         // unbounded start, ends at last valid
            (span!(10, 20), 20, false),         // unbounded start, ends at boundary
            (span!(10, 20), 25, false),         // unbounded start, ends after
            (span!(0, usize::MAX), 100, false), // even max span can't contain unbounded start
            (span!(0, usize::MAX), usize::MAX - 1, false), // max span, unbounded start
        ];
        for (i, (span, end, want)) in range_to_inclusive_cases.iter().enumerate() {
            let got = span.contains(..=*end);
            assert_eq!(got, *want, "#{i}: contains({span:?}, ..={end})");
        }
    }

    #[test]
    fn test_span_merge() {
        let test_cases = [
            (span!(10, 20), span!(30, 40), span!(10, 40)), // non-overlapping spans
            (span!(10, 20), span!(15, 35), span!(10, 35)), // overlapping spans
            (span!(30, 40), span!(10, 20), span!(10, 40)), // merge order doesn't matter
            (span!(10, 20), span!(10, 20), span!(10, 20)), // merging with self
            (span!(0, 10), span!(5, 15), span!(0, 15)),    // partial overlap
            (span!(10, 20), span!(5, 12), span!(5, 20)),   // left extension
            (span!(10, 20), span!(18, 25), span!(10, 25)), // right extension
            (span!(15, 25), span!(10, 30), span!(10, 30)), // fully contained by other
            (span!(10, 30), span!(15, 25), span!(10, 30)), // fully contains other
            (Span::default(), span!(10, 20), span!(0, 20)), // empty with non-empty
            (span!(0, usize::MAX), span!(100, 200), span!(0, usize::MAX)), // max span with regular span
        ];
        for (i, (lhs, rhs, want)) in test_cases.iter().enumerate() {
            let got = lhs.merge(*rhs);
            assert_eq!(got, *want, "#{i}: merge({lhs:?}, {rhs:?})");
        }
    }

    #[test]
    fn test_span_len() {
        let test_cases = [
            (span!(0, 10), 10),                     // regular span length
            (span!(5, 5), 0),                       // empty span length
            (span!(100, 150), 50),                  // larger span length
            (Span::default(), 0),                   // default span length
            (span!(0, 1), 1),                       // single unit span
            (span!(usize::MAX - 1, usize::MAX), 1), // max boundary span
        ];
        for (i, (span, want)) in test_cases.iter().enumerate() {
            let got = span.len();
            assert_eq!(got, *want, "#{i}: len({span:?})");
        }
    }

    #[test]
    fn test_span_is_empty() {
        let test_cases = [
            (span!(0, 10), false),                      // regular span is not empty
            (span!(0, 0), true),                        // zero-length span is empty
            (Span::default(), true),                    // default span is empty
            (span!(5, 5), true),                        // same start/end span is empty
            (span!(1, 2), false),                       // single unit span is not empty
            (span!(usize::MAX - 1, usize::MAX), false), // max boundary span is not empty
        ];
        for (i, (span, want)) in test_cases.iter().enumerate() {
            let got = span.is_empty();
            assert_eq!(got, *want, "#{i}: is_empty({span:?})");
        }
    }
}
