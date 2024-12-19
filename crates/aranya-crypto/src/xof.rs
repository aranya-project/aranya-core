//! Extendable Output Functions.

#[cfg(feature = "alloc")]
extern crate alloc;

use generic_array::{ArrayLength, GenericArray};

/// An extendable output function (XOF).
pub trait Xof: Clone {
    /// Reads output bytes.
    type Reader: XofReader;

    /// Creates a new XOF with the customization string `s`.
    fn new(s: &[u8]) -> Self;

    /// Updates the running hash with `data`.
    fn update(&mut self, data: &[u8]);

    /// Returns the output of the XOF.
    fn finalize_xof(self) -> Self::Reader;

    /// Writes the XOF output to `out`.
    fn finalize_xof_into(self, out: &mut [u8]) {
        self.finalize_xof().read(out);
    }
}

/// Reads output bytes from an [`Xof`].
pub trait XofReader {
    /// Reads output bytes from the XOF into `out`.
    fn read(&mut self, out: &mut [u8]);

    /// Reads `N` output bytes from the XOF into `out`.
    fn read_n<N: ArrayLength>(&mut self) -> GenericArray<u8, N> {
        let mut out = GenericArray::default();
        self.read(&mut out);
        out
    }

    /// Reads `n` output bytes from the XOF.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn read_boxed(&mut self, n: usize) -> Box<[u8]> {
        let mut out = alloc::vec![0u8; n];
        self.read(&mut out);
        out.into_boxed_slice()
    }
}
