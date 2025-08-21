use core::{cmp, ffi::c_char, fmt, fmt::Write, mem::MaybeUninit, ptr};

use buggy::{Bug, BugExt as _};

/// The error returned by [`write_c_str`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WriteCStrError {
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
    /// The provided buffer is too small.
    #[error("buffer is too small")]
    BufferTooSmall,
}

/// Writes `src` as a null-terminated C string to `dst`.
///
/// If `dst` is long enough to fit the entirety of `src`, it
/// updates `n` with the number of bytes written, less the null
/// terminator and returns `Ok(())`.
///
/// Otherwise, if `dst` is not long enough to contain the
/// entirety of `src`, it updates `n` to the number of bytes
/// needed to fit the entirety of `src` and returns
/// [`Err(WriteCStrError::BufferTooSmall)`][WriteCStrError::BufferTooSmall].
pub fn write_c_str<T: fmt::Display>(
    dst: &mut [MaybeUninit<c_char>],
    src: &T,
    nw: &mut usize,
) -> Result<(), WriteCStrError> {
    let mut w = CStrWriter::new(dst, nw);
    write!(&mut w, "{src:}").assume("`write!` to `Writer` should not fail")?;
    w.finish().map_err(|()| WriteCStrError::BufferTooSmall)
}

/// Implements [`Write`] for a fixed-size C string buffer.
struct CStrWriter<'a> {
    dst: &'a mut [MaybeUninit<c_char>],
    // Number of bytes written.
    nw: &'a mut usize,
}

impl<'a> CStrWriter<'a> {
    fn new(dst: &'a mut [MaybeUninit<c_char>], nw: &'a mut usize) -> Self {
        *nw = 0;
        Self { dst, nw }
    }

    fn write(&mut self, s: &str) {
        // TODO(eric): what if `s` contains a null byte?
        let src = s.as_bytes();
        if src.is_empty() {
            return;
        }

        let end = self.nw.saturating_add(src.len());
        let Some(dst) = self
            .dst
            .split_last_mut() // chop off the null terminator.
            .and_then(|(_, dst)| dst.get_mut(*self.nw..end))
        else {
            // `dst` isn't large enough, so just record the
            // updated number of bytes.
            *self.nw = end;
            return;
        };

        // SAFETY: `u8` and `MaybeUninit<u8>` have the same
        // size in memory.
        let src = unsafe { &*(ptr::from_ref::<[u8]>(src) as *const [MaybeUninit<c_char>]) };
        dst.copy_from_slice(src);
        *self.nw = end;
    }

    /// Returns `Ok(())` if `dst` is large enough, or `Err(())`
    /// otherwise.
    fn finish(self) -> Result<(), ()> {
        // Write the null terminator after the bytes.
        let idx = cmp::min(*self.nw, self.dst.len());
        if let Some(v) = self.dst.get_mut(idx) {
            v.write(0);
        }
        *self.nw = self.nw.saturating_add(1);

        if *self.nw <= self.dst.len() {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Write for CStrWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_c_str() {
        let tests = ["", "hello, world"];
        for (i, input) in tests.into_iter().enumerate() {
            let want = input.to_owned() + "\0";
            let mut dst = vec![0u8; want.len()];
            let mut n = 0xdeadbeef;

            // Check the empty buffer.
            let got = write_c_str(&mut [], &input, &mut n);
            assert_eq!(got, Err(WriteCStrError::BufferTooSmall), "#{i}");
            assert_eq!(n, want.len(), "#{i}: did not return large enough size");

            println!("=== after empty");

            // Check a short buffer.
            n = 0xdeadbeef;
            let got = write_c_str(
                // SAFETY: `u8` and `MaybeUninit<c_char>` have
                // the same memory layout.
                unsafe {
                    &mut *(&mut dst[..want.len() - 1] as *mut [u8] as *mut [MaybeUninit<c_char>])
                },
                &input,
                &mut n,
            );
            assert_eq!(got, Err(WriteCStrError::BufferTooSmall), "#{i}");
            assert_eq!(n, want.len(), "#{i}: output sizes differ");

            println!("=== after too small");

            // Check the correct length.
            n = 0xdeadbeef;
            // Make `dst` a little longer to make sure we place
            // the null terminator correctly.
            dst.extend([1, 2, 3, 4, 5]);
            let got = write_c_str(
                // SAFETY: `u8` and `MaybeUninit<c_char>` have
                // the same memory layout.
                unsafe { &mut *(dst.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<c_char>]) },
                &input,
                &mut n,
            );
            assert_eq!(got, Ok(()), "#{i}");
            assert_eq!(n, want.len(), "#{i}: output sizes differ");
            assert_eq!(&dst[..n], want.as_bytes(), "#{i}");

            println!("=== after too good");
        }
    }
}
