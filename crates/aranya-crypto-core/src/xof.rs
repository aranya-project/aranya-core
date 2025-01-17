//! eXtendable Output Function ([XOF]).
//!
//! [XOF]: https://csrc.nist.gov/glossary/term/extendable_output_function

use core::num::NonZeroU16;

use crate::AlgId;

/// Hash algorithm identifiers.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, AlgId)]
pub enum XofId {
    /// Some other XOF.
    #[alg_id(Other)]
    Other(NonZeroU16),
}

/// An extendable output function (XOF).
///
/// Examples of XOFs include SHAKE-128 and SHAKE-256.
pub trait Xof: Clone {
    /// Uniquely identifies the XOF.
    const ID: XofId;

    /// Reads output bytes.
    type Reader: XofReader;

    /// Updates the running hash with `data`.
    fn update(&mut self, data: &[u8]);

    /// Returns the output of the XOF.
    fn finalize_xof(self) -> Self::Reader;

    /// Writes the XOF output to `out`.
    fn finalize_xof_into(self, out: &mut [u8]) {
        self.finalize_xof().read(out);
    }
}

/// Output bytes from an XOF.
pub trait XofReader {
    /// Reads output bytes from the XOF into `out`.
    fn read(&mut self, out: &mut [u8]);

    /// Reads `N` output bytes from the XOF into `out`.
    fn read_fixed<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.read(&mut out);
        out
    }
}
