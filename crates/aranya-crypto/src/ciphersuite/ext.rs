use core::{array, iter::FusedIterator};

use serde::{ser, Deserialize, Deserializer, Serialize, Serializer};
use spideroak_crypto::{
    hash,
    kdf::{self, Expand, Kdf as _, KdfError},
    oid::{Identified, Oid},
    typenum::Unsigned,
};

use crate::ciphersuite::CipherSuite;

macro_rules! encoded_oids {
    ($($name:ident),* $(,)?) => {
        EncodedOids([$(
            // def encode_string(S):
            //     left_encode(len(S)) || S
            // where `len(X)` returns the length of `X` in bits.
            sha3::left_encode_bytes(Self::$name::OID.len()).as_bytes(),
            &Self::$name::OID.as_bytes()
        ),*])
    }
}

/// Extension trait for [`CipherSuite`].
///
/// Its primary purpose is to provide convenience methods that
/// bake in the OIDs of the algorithms used in the cipher suite.
pub(crate) trait CipherSuiteExt: CipherSuite {
    /// OIDs for all algorithms in this cipher suite.
    const OIDS: Oids = Oids {
        aead: Self::Aead::OID,
        hash: Self::Hash::OID,
        kdf: Self::Kdf::OID,
        kem: Self::Kem::OID,
        mac: Self::Mac::OID,
        signer: Self::Signer::OID,
    };

    const ENCODED_OIDS: EncodedOids = encoded_oids!(Aead, Hash, Kdf, Kem, Mac, Signer);

    /// Computes the following hash:
    ///
    /// ```text
    /// digest = TupleHash(
    ///     tag,
    ///     oids[0],
    ///     oids[1],
    ///     ..,
    ///     oids[n],
    ///     context,
    /// )
    /// ```
    fn tuple_hash<const N: usize>(tag: &[u8], context: [&[u8]; N]) -> Digest<Self>;

    /// Performs `LabeledExtract` per [RFC 9180].
    ///
    /// - `domain` provides domain separation. See [RFC 9180]
    ///    section 9.6.
    /// - `salt`, `label`, and `ikm` are regular KDF parameters.
    ///
    /// ```text
    /// def LabeledExtract(salt, label, ikm):
    ///     labeled_ikm = concat(domain, suite_id, label, ikm)
    ///     return Extract(salt, labeled_ikm)
    /// ```
    ///
    /// Note that in [RFC 9180] `suite_id` contains 16-bit HPKE
    /// algorithm identifiers, but in this function it contains
    /// OIDs. Since an OID does not have a fixed length, each OID
    /// is unambiguously encoded per [TupleHash].
    ///
    /// [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html#name-cryptographic-dependencies
    /// [TupleHash]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
    fn labeled_extract(
        domain: &'static [u8],
        salt: &[u8],
        label: &'static str,
        ikm: &[u8],
    ) -> Prk<Self>;

    /// Performs `LabeledExpand` per [RFC 9180].
    ///
    /// - `domain` provides domain separation. See [RFC 9180]
    ///    section 9.6.
    /// - `prk`, `label`, and `info` are regular KDF parameters.
    ///
    /// ```text
    /// def LabeledExpand(prk, label, info):
    ///     labeled_info = concat(I2OSP(L, 2), domain, suite_id,
    ///                   label, info)
    ///     return Expand(prk, labeled_info)
    /// ```
    ///
    /// Note that in [RFC 9180] `suite_id` contains 16-bit HPKE
    /// algorithm identifiers, but in this function it contains
    /// OIDs. Since an OID does not have a fixed length, each OID
    /// is unambiguously encoded per [TupleHash].
    ///
    /// [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html#name-cryptographic-dependencies
    /// [TupleHash]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
    fn labeled_expand<T, const N: usize>(
        domain: &'static [u8],
        prk: &Prk<Self>,
        label: &'static str,
        info: [&[u8]; N],
    ) -> Result<T, KdfError>
    where
        T: Expand;
}

impl<CS: CipherSuite> CipherSuiteExt for CS {
    fn tuple_hash<const N: usize>(tag: &[u8], context: [&[u8]; N]) -> Digest<Self> {
        const { assert!(N <= usize::MAX - 1 - Oids::SIZE) }

        hash::tuple_hash::<Self::Hash, _>(TupleHashItems {
            tag: Some(tag),
            oids: Self::OIDS.into_iter(),
            items: context.into_iter(),
        })
    }

    fn labeled_extract(
        domain: &'static [u8],
        salt: &[u8],
        label: &'static str,
        ikm: &[u8],
    ) -> Prk<Self> {
        // def LabeledExtract(salt, label, ikm):
        //     labeled_ikm = concat(domain, suite_ids, label, ikm)
        //     return Extract(salt, labeled_ikm)
        let labeled_ikm = LabeledIkm {
            domain: Some(domain),
            oids: Self::ENCODED_OIDS.into_iter(),
            items: [label.as_bytes(), ikm].into_iter(),
        };
        Self::Kdf::extract_multi(labeled_ikm, salt)
    }

    fn labeled_expand<T, const N: usize>(
        domain: &'static [u8],
        prk: &Prk<Self>,
        label: &'static str,
        info: [&[u8]; N],
    ) -> Result<T, KdfError>
    where
        T: Expand,
    {
        // def LabeledExpand(prk, label, info):
        //     labeled_info = concat(I2OSP(L, 2), domain, suite_ids,
        //                   label, info)
        //     return Expand(prk, labeled_info)
        let size = T::Size::U16.to_be_bytes();
        let labeled_info = LabeledInfo {
            len: Some(&size),
            domain: Some(domain),
            oids: Self::ENCODED_OIDS.into_iter(),
            label: Some(label.as_bytes()),
            info: info.into_iter(),
        };
        T::expand_multi::<Self::Kdf, _>(prk, labeled_info)
    }
}

/// The items being hashed by [`CipherSuiteExt::tuple_hash`].
#[derive(Clone, Debug)]
struct TupleHashItems<'a, const N: usize> {
    tag: Option<&'a [u8]>,
    // Unlike `labeled_expand` and `labeled_extract`, we can use
    // the raw OIDs because `tuple_hash` ensures that each item
    // is unambiguous.
    oids: <Oids as IntoIterator>::IntoIter,
    items: array::IntoIter<&'a [u8], N>,
}

impl<'a, const N: usize> Iterator for TupleHashItems<'a, N> {
    type Item = &'a [u8];

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ctx) = self.tag.take() {
            Some(ctx)
        } else if let Some(suite) = self.oids.next() {
            Some(suite.as_bytes())
        } else {
            self.items.next()
        }
    }
}

impl<const N: usize> ExactSizeIterator for TupleHashItems<'_, N> {
    #[inline(always)]
    fn len(&self) -> usize {
        // Ensure that the following addition does not overflow.
        const { assert!(N <= usize::MAX - 1 - Oids::SIZE) }

        usize::from(self.tag.is_some()) + self.oids.len() + self.items.len()
    }
}

impl<const N: usize> FusedIterator for TupleHashItems<'_, N> {}

/// For [`CipherSuiteExt::labeled_extract`].
#[derive(Clone, Debug)]
struct LabeledIkm<'a, const N: usize> {
    domain: Option<&'a [u8]>,
    oids: <EncodedOids as IntoIterator>::IntoIter,
    items: array::IntoIter<&'a [u8], N>,
}

impl<'a, const N: usize> Iterator for LabeledIkm<'a, N> {
    type Item = &'a [u8];

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ctx) = self.domain.take() {
            Some(ctx)
        } else if let Some(v) = self.oids.next() {
            Some(v)
        } else {
            self.items.next()
        }
    }
}

impl<const N: usize> ExactSizeIterator for LabeledIkm<'_, N> {
    #[inline(always)]
    fn len(&self) -> usize {
        // Ensure that the following addition does not overflow.
        const { assert!(N <= usize::MAX - 1 - Oids::SIZE) }

        usize::from(self.domain.is_some()) + self.oids.len() + self.items.len()
    }
}

impl<const N: usize> FusedIterator for LabeledIkm<'_, N> {}

/// For [`CipherSuiteExt::labeled_expand`].
#[derive(Clone, Debug)]
struct LabeledInfo<'a, const N: usize> {
    len: Option<&'a [u8; 2]>,
    domain: Option<&'a [u8]>,
    oids: <EncodedOids as IntoIterator>::IntoIter,
    label: Option<&'a [u8]>,
    info: array::IntoIter<&'a [u8], N>,
}

impl<'a, const N: usize> Iterator for LabeledInfo<'a, N> {
    type Item = &'a [u8];

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(len) = self.len.take() {
            Some(len)
        } else if let Some(domain) = self.domain.take() {
            Some(domain)
        } else if let Some(v) = self.oids.next() {
            Some(v)
        } else if let Some(label) = self.label.take() {
            Some(label)
        } else {
            self.info.next()
        }
    }
}

impl<const N: usize> ExactSizeIterator for LabeledInfo<'_, N> {
    #[inline(always)]
    fn len(&self) -> usize {
        // Ensure that the following addition does not overflow.
        const { assert!(N <= usize::MAX - 1 - 1 - EncodedOids::SIZE - 1) }

        usize::from(self.len.is_some())
            + usize::from(self.domain.is_some())
            + self.oids.len()
            + usize::from(self.label.is_some())
            + self.info.len()
    }
}

impl<const N: usize> FusedIterator for LabeledInfo<'_, N> {}

pub(crate) type Digest<CS> = hash::Digest<<<CS as CipherSuite>::Hash as hash::Hash>::DigestSize>;
pub(crate) type Prk<CS> = kdf::Prk<<<CS as CipherSuite>::Kdf as kdf::Kdf>::PrkSize>;

/// A collection of OIDs.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct Oids {
    aead: &'static Oid,
    hash: &'static Oid,
    kdf: &'static Oid,
    kem: &'static Oid,
    mac: &'static Oid,
    signer: &'static Oid,
}

impl Oids {
    /// The number of OIDs in the collection.
    const SIZE: usize = 6;

    pub(crate) const fn to_repr(self) -> OidsRepr<'static> {
        OidsRepr {
            aead: OidIsh::Oid(self.aead),
            hash: OidIsh::Oid(self.hash),
            kdf: OidIsh::Oid(self.kdf),
            kem: OidIsh::Oid(self.kem),
            mac: OidIsh::Oid(self.mac),
            signer: OidIsh::Oid(self.signer),
        }
    }
}

impl IntoIterator for Oids {
    type Item = &'static Oid;
    type IntoIter = array::IntoIter<&'static Oid, 6>;

    fn into_iter(self) -> Self::IntoIter {
        [
            self.aead,
            self.hash,
            self.kdf,
            self.kem,
            self.mac,
            self.signer,
        ]
        .into_iter()
    }
}

/// [`Oid`]s in the same order as [`Oids`], but with each OID
/// encoded via `encode_string` from [TupleHash].
///
/// Each OID is
///
/// Create it with [`encoded_oids`].
///
/// [TupleHash]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
#[derive(Clone, Debug)]
pub(crate) struct EncodedOids(
    // encode_string(S) is defined as
    //    left_encode(len(S)) || S
    //
    // so the array is arranged as follows:
    //
    // v[0] = left_encode(len(Aead::OID))
    // v[1] = Aead::OID
    // v[2] = left_encode(len(Hash::OID))
    // v[3] = Hash::OID
    // ...
    // v[10] = left_encode(len(Signer::OID))
    // v[11] = Signer::OID
    [&'static [u8]; 12],
);

impl EncodedOids {
    /// The number of encoded OID fragments in the collection.
    const SIZE: usize = 12;
}

impl IntoIterator for EncodedOids {
    type Item = &'static [u8];
    type IntoIter = array::IntoIter<&'static [u8], 12>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Serialize/Deserialize repr for [`Oids`].
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct OidsRepr<'a> {
    #[serde(borrow)]
    aead: OidIsh<'a>,

    #[serde(borrow)]
    hash: OidIsh<'a>,

    #[serde(borrow)]
    kdf: OidIsh<'a>,

    #[serde(borrow)]
    kem: OidIsh<'a>,

    #[serde(borrow)]
    mac: OidIsh<'a>,

    #[serde(borrow)]
    signer: OidIsh<'a>,
}

/// Either an [`Oid`] or its string representation.
#[derive(Copy, Clone, Debug)]
pub(crate) enum OidIsh<'a> {
    Oid(&'static Oid),
    Ish(&'a str),
}

impl Serialize for OidIsh<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OidIsh::Oid(oid) => serializer.serialize_bytes(oid.as_bytes()),
            OidIsh::Ish(_) => Err(<S::Error as ser::Error>::custom(
                "got `Ish`, expected `Oid`",
            )),
        }
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for OidIsh<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let oid = <&str>::deserialize(deserializer)?;
        Ok(OidIsh::Ish(oid))
    }
}

impl PartialEq for OidIsh<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (OidIsh::Oid(lhs), OidIsh::Oid(rhs)) => lhs == rhs,
            (OidIsh::Ish(lhs), OidIsh::Ish(rhs)) => lhs == rhs,
            (OidIsh::Oid(lhs), OidIsh::Ish(rhs)) => lhs == rhs,
            (OidIsh::Ish(lhs), OidIsh::Oid(rhs)) => lhs == rhs,
        }
    }
}

/// The following code is adapted from [`sha3-utils`]
///
/// [`sha3-utils`]: https://crates.io/crates/sha3-utils
mod sha3 {
    use core::slice;

    use zerocopy::{Immutable, IntoBytes, KnownLayout, Unaligned};

    /// The size in bytes of [`usize`].
    const USIZE_BYTES: usize = ((usize::BITS + 7) / 8) as usize;

    // This is silly, but it ensures that we're always in
    //    [0, ((2^2040)-1)/8]
    // which is required by SP 800-185, which requires that
    // `left_encode`, `right_encode`, etc. accept integers up to
    // (2^2040)-1.
    //
    // Divide by 8 because of the `*_bytes` routines.
    const _: () = assert!(USIZE_BYTES <= 255);

    /// Encodes `x*8` as a byte string in a way that can be
    /// unambiguously parsed from the beginning.
    ///
    /// # Rationale
    ///
    /// [`left_encode`] is typically used to encode a length in
    /// *bits*. In practice, we usually have a length in *bytes*. The
    /// conversion from bytes to bits might overflow if the number of
    /// bytes is large. This method avoids overflowing.
    #[inline]
    pub(super) const fn left_encode_bytes(x: usize) -> LeftEncodeBytes {
        // Break `x*8` into double word arithmetic.
        let mut hi = (x >> (usize::BITS - 3)) as u8;
        let mut lo = x << 3;

        let n = if hi == 0 {
            // `lo|1` ensures that `n < USIZE_BYTES`. It's cheaper
            // than a conditional.
            let n = (lo | 1).leading_zeros() / 8;
            lo <<= n * 8;
            hi = (lo >> (usize::BITS - 8)) as u8;
            lo <<= 8;
            (n + 1) as usize
        } else {
            0
        };

        LeftEncodeBytes {
            hi,
            mid: (1 + USIZE_BYTES - n) as u8,
            lo,
        }
    }

    /// The result of [`left_encode_bytes`].
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Immutable, KnownLayout, IntoBytes, Unaligned)]
    #[repr(C, packed)]
    pub(super) struct LeftEncodeBytes {
        hi: u8,
        mid: u8,
        lo: usize,
    }

    impl LeftEncodeBytes {
        /// Returns the number of encoded bytes.
        #[inline]
        #[expect(clippy::len_without_is_empty, reason = "Meaningless for this type")]
        const fn len(&self) -> usize {
            (self.hi + 1) as usize
        }

        /// Returns the encoded bytes.
        #[inline]
        pub(super) const fn as_bytes(&self) -> &[u8] {
            let bytes: &[u8; 2 + USIZE_BYTES] = zerocopy::transmute_ref!(self);
            #[allow(unsafe_code, reason = "No other way to do this as `const`")]
            // SAFETY: `self.len()` is in [1, self.buf.len()).
            unsafe {
                slice::from_raw_parts(bytes.as_ptr(), self.len())
            }
        }
    }
}
