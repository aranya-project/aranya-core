//! Sliding anti-replay window for data frames.
//!
//! Every data frame carries a per-channel sequence number
//! (`seq`) in its header. The sender assigns them in strictly
//! increasing order, so the receiver can use a sliding window
//! over `seq` (in the style of TCP's receive window and the
//! IPsec/DTLS anti-replay window; see RFC 4303 §3.4.3 and RFC
//! 6347 §4.1.2.6) to deliver each frame at most once while
//! tolerating reordering.

use aranya_crypto::afc::Seq;

use crate::error::Error;

/// The default [`ReplayWindow`] size, in frames.
///
/// RFC 4303 recommends a window of at least 64 for IPsec.
pub const DEFAULT_REPLAY_WINDOW: u16 = 64;

/// The maximum [`ReplayWindow`] size, in frames.
pub const MAX_REPLAY_WINDOW: u16 = 1024;

/// The number of `u64` words in the bitmap.
const WORDS: usize = (MAX_REPLAY_WINDOW as usize) / u64::BITS as usize;

const _: () = assert!(WORDS * (u64::BITS as usize) == MAX_REPLAY_WINDOW as usize);

/// A sliding anti-replay window over [`Seq`].
///
/// The window tracks `high`, the highest sequence number that
/// has been authenticated so far, and a bitmap recording which
/// of the `W` sequence numbers in `(high - W, high]` have
/// already been accepted.
///
/// A frame with sequence number `seq` is:
///
/// | Condition | Verdict |
/// |---|---|
/// | `seq > high` | accept; becomes the new `high` |
/// | `high - W < seq <= high`, not yet accepted | accept |
/// | `high - W < seq <= high`, already accepted | reject ([`Error::ReplayedSeq`]) |
/// | `seq <= high - W` | reject ([`Error::ReplayedSeq`]) |
///
/// Until the first frame is authenticated there is no `high`
/// and any `seq` is accepted; the first frame establishes the
/// window.
///
/// Use [`check`][Self::check] before decrypting a frame and
/// [`commit`][Self::commit] only after the frame has been
/// authenticated, so that a forged frame cannot move the window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayWindow {
    /// Highest authenticated `seq`; `None` until the first
    /// frame.
    high: Option<u64>,
    /// Bit `i` set ⇔ `high − i` has been accepted (`i < size`).
    bitmap: [u64; WORDS],
    /// `W`, in `1..=MAX_REPLAY_WINDOW`.
    size: u16,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new_unchecked(DEFAULT_REPLAY_WINDOW)
    }
}

impl ReplayWindow {
    /// Creates a window of `size` frames.
    ///
    /// `size` must be in `1..=MAX_REPLAY_WINDOW`.
    pub fn new(size: u16) -> Result<Self, Error> {
        Self::validate(size)?;
        Ok(Self::new_unchecked(size))
    }

    /// Reports whether `size` is a valid window size.
    pub(crate) const fn validate(size: u16) -> Result<(), Error> {
        if size == 0 || size > MAX_REPLAY_WINDOW {
            Err(Error::InvalidArgument(
                "replay window size must be in 1..=MAX_REPLAY_WINDOW",
            ))
        } else {
            Ok(())
        }
    }

    /// Creates a window of `size` frames without checking
    /// `size`.
    ///
    /// The caller must have already validated `size`.
    pub(crate) const fn new_unchecked(size: u16) -> Self {
        Self {
            high: None,
            bitmap: [0; WORDS],
            size,
        }
    }

    /// Returns the window size, `W`.
    #[inline]
    pub const fn size(&self) -> u16 {
        self.size
    }

    /// Returns the highest authenticated sequence number, or
    /// `None` if no frame has been accepted yet.
    #[inline]
    pub fn high(&self) -> Option<Seq> {
        self.high.map(Seq::new)
    }

    /// Reports whether `seq` would be accepted, without
    /// mutating the window.
    ///
    /// Call this before performing any cryptographic work on the
    /// frame.
    pub fn check(&self, seq: Seq) -> Result<(), Error> {
        let seq = seq.to_u64();
        let Some(high) = self.high else {
            return Ok(());
        };
        if seq > high {
            return Ok(());
        }
        // `seq <= high`, so this cannot underflow.
        let dist = high - seq;
        if dist >= u64::from(self.size) || self.bit(dist) {
            return Err(Error::ReplayedSeq { seq: Seq::new(seq) });
        }
        Ok(())
    }

    /// Records `seq` as accepted.
    ///
    /// Only call this after the frame has been authenticated;
    /// [`check`][Self::check] must have returned `Ok` for `seq`.
    pub fn commit(&mut self, seq: Seq) {
        let seq = seq.to_u64();
        match self.high {
            None => {
                self.bitmap = [0; WORDS];
                self.high = Some(seq);
                self.set_bit(0);
            }
            Some(high) if seq > high => {
                // `seq > high`, so this cannot underflow.
                self.shift(seq - high);
                self.high = Some(seq);
                self.set_bit(0);
            }
            Some(high) => {
                // `seq <= high`, so this cannot underflow.
                let dist = high - seq;
                if dist < u64::from(self.size) {
                    self.set_bit(dist);
                }
            }
        }
    }

    /// Reports whether bit `i` is set.
    ///
    /// Bits outside the bitmap are clear.
    fn bit(&self, i: u64) -> bool {
        let Ok(i) = usize::try_from(i) else {
            return false;
        };
        let word = i / (u64::BITS as usize);
        let bit = i % (u64::BITS as usize);
        self.bitmap.get(word).is_some_and(|w| (w >> bit) & 1 == 1)
    }

    /// Sets bit `i`.
    ///
    /// Bits outside the bitmap are ignored.
    fn set_bit(&mut self, i: u64) {
        let Ok(i) = usize::try_from(i) else {
            return;
        };
        let word = i / (u64::BITS as usize);
        let bit = i % (u64::BITS as usize);
        if let Some(w) = self.bitmap.get_mut(word) {
            *w |= 1u64 << bit;
        }
    }

    /// Shifts the bitmap up by `n` positions (bit `i` becomes bit
    /// `i + n`), discarding bits that fall off the end.
    fn shift(&mut self, n: u64) {
        let Ok(n) = usize::try_from(n) else {
            self.bitmap = [0; WORDS];
            return;
        };
        if n >= MAX_REPLAY_WINDOW as usize {
            self.bitmap = [0; WORDS];
            return;
        }
        let word_shift = n / (u64::BITS as usize);
        let bit_shift = (n % (u64::BITS as usize)) as u32;

        let old = self.bitmap;
        for (i, dst) in self.bitmap.iter_mut().enumerate() {
            let lo = i
                .checked_sub(word_shift)
                .and_then(|j| old.get(j))
                .copied()
                .unwrap_or(0);
            let hi = i
                .checked_sub(word_shift.saturating_add(1))
                .and_then(|j| old.get(j))
                .copied()
                .unwrap_or(0);
            *dst = if bit_shift == 0 {
                lo
            } else {
                (lo << bit_shift) | (hi >> (u64::BITS - bit_shift))
            };
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn seq(n: u64) -> Seq {
        Seq::new(n)
    }

    /// Checks and commits `n`.
    fn accept(w: &mut ReplayWindow, n: u64) {
        w.check(seq(n))
            .unwrap_or_else(|err| panic!("seq {n} should be accepted: {err}"));
        w.commit(seq(n));
    }

    /// Asserts that `n` is rejected.
    fn reject(w: &ReplayWindow, n: u64) {
        assert_eq!(
            w.check(seq(n)),
            Err(Error::ReplayedSeq { seq: seq(n) }),
            "seq {n} should be rejected"
        );
    }

    #[test]
    fn test_construction() {
        assert!(ReplayWindow::new(0).is_err());
        assert!(ReplayWindow::new(MAX_REPLAY_WINDOW + 1).is_err());
        assert_eq!(ReplayWindow::new(1).unwrap().size(), 1);
        assert_eq!(
            ReplayWindow::new(MAX_REPLAY_WINDOW).unwrap().size(),
            MAX_REPLAY_WINDOW
        );
        assert_eq!(ReplayWindow::default().size(), DEFAULT_REPLAY_WINDOW);
        assert_eq!(ReplayWindow::default().high(), None);
    }

    #[test]
    fn test_in_order() {
        let mut w = ReplayWindow::default();
        for n in 0..1000 {
            accept(&mut w, n);
            assert_eq!(w.high(), Some(seq(n)));
        }
    }

    #[test]
    fn test_duplicate() {
        let mut w = ReplayWindow::default();
        accept(&mut w, 0);
        reject(&w, 0);
        accept(&mut w, 1);
        reject(&w, 1);
        reject(&w, 0);
    }

    #[test]
    fn test_reorder_within_window() {
        let mut w = ReplayWindow::default();
        accept(&mut w, 0);
        accept(&mut w, 2);
        accept(&mut w, 1);
        reject(&w, 1);
        reject(&w, 2);
        reject(&w, 0);
        assert_eq!(w.high(), Some(seq(2)));
    }

    #[test]
    fn test_gap_and_late_fill() {
        let wsize = u64::from(DEFAULT_REPLAY_WINDOW);
        let mut w = ReplayWindow::default();
        accept(&mut w, 0);
        accept(&mut w, wsize + 5);
        assert_eq!(w.high(), Some(seq(wsize + 5)));
        // Window is `(high - W, high]` = `(5, W + 5]`.
        accept(&mut w, 6);
        reject(&w, 5);
        reject(&w, 0);
        // Everything else in the window is still fresh.
        for n in 7..wsize + 5 {
            accept(&mut w, n);
        }
        // ...and now used.
        for n in 6..=wsize + 5 {
            reject(&w, n);
        }
    }

    #[test]
    fn test_far_ahead_advance() {
        let wsize = u64::from(DEFAULT_REPLAY_WINDOW);
        let mut w = ReplayWindow::default();
        for n in 0..=10 {
            accept(&mut w, n);
        }
        let high = 10 + 2 * wsize;
        accept(&mut w, high);
        for n in 0..=10 {
            reject(&w, n);
        }
        reject(&w, high);
        // The bitmap holds only the new `high`: everything in
        // the window below it is fresh.
        for n in (high - wsize + 1)..high {
            accept(&mut w, n);
        }
        reject(&w, high - wsize);
    }

    #[test]
    fn test_first_frame_high_seq() {
        let wsize = u64::from(DEFAULT_REPLAY_WINDOW);
        let mut w = ReplayWindow::default();
        accept(&mut w, 1000);
        accept(&mut w, 999);
        reject(&w, 1000 - wsize);
        accept(&mut w, 1000 - wsize + 1);
    }

    #[test]
    fn test_check_does_not_mutate() {
        let mut w = ReplayWindow::default();
        accept(&mut w, 5);
        let before = w.clone();
        w.check(seq(5000)).unwrap();
        w.check(seq(4)).unwrap();
        reject(&w, 5);
        assert_eq!(w, before);
    }

    #[test]
    fn test_window_size_one() {
        let mut w = ReplayWindow::new(1).unwrap();
        accept(&mut w, 0);
        accept(&mut w, 1);
        reject(&w, 0);
        reject(&w, 1);
        accept(&mut w, 3);
        reject(&w, 2);
    }

    #[test]
    fn test_window_size_max() {
        let wsize = u64::from(MAX_REPLAY_WINDOW);
        let mut w = ReplayWindow::new(MAX_REPLAY_WINDOW).unwrap();
        accept(&mut w, wsize);
        accept(&mut w, 1);
        reject(&w, 0);
        for n in 2..wsize {
            accept(&mut w, n);
        }
        for n in 0..=wsize {
            reject(&w, n);
        }
        accept(&mut w, wsize + 1);
        reject(&w, 1);
        accept(&mut w, 2 * wsize);
        // `wsize + 1` is exactly `wsize - 1` behind the new
        // `high`, so it survived the shift; everything else in
        // the window is fresh.
        reject(&w, wsize + 1);
        for n in (wsize + 2)..(2 * wsize) {
            accept(&mut w, n);
        }
        reject(&w, wsize);
    }

    /// Shifts across word boundaries preserve bits.
    #[test]
    fn test_shift_across_words() {
        let mut w = ReplayWindow::new(MAX_REPLAY_WINDOW).unwrap();
        // Accept 0..=200 then jump ahead by various amounts,
        // checking that exactly the right bits survive.
        for n in 0..=200 {
            accept(&mut w, n);
        }
        for jump in [1u64, 63, 64, 65, 127, 128, 129, 500, 1023] {
            let mut w = w.clone();
            let high = 200 + jump;
            accept(&mut w, high);
            for n in 0..=200 {
                let dist = high - n;
                if dist < u64::from(MAX_REPLAY_WINDOW) {
                    reject(&w, n);
                } else {
                    // Fell off the window entirely: also
                    // rejected as too old.
                    reject(&w, n);
                }
            }
            // Gaps between 201 and high are fresh.
            for n in 201..high {
                w.check(seq(n))
                    .unwrap_or_else(|err| panic!("jump {jump}: seq {n}: {err}"));
            }
        }
    }

    #[test]
    fn test_near_zero() {
        let mut w = ReplayWindow::default();
        accept(&mut w, 0);
        // `high - W` must not underflow.
        reject(&w, 0);
        accept(&mut w, 1);
    }

    #[test]
    fn test_near_max() {
        let mut w = ReplayWindow::default();
        accept(&mut w, u64::MAX - 1);
        accept(&mut w, u64::MAX);
        reject(&w, u64::MAX);
        reject(&w, u64::MAX - 1);
        accept(&mut w, u64::MAX - 2);
    }
}
