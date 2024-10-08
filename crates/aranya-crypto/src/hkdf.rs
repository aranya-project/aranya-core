//! HKDF per [RFC 5869].
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.
//!
//! [RFC 5869]: https://www.rfc-editor.org/rfc/rfc5869

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, doc(cfg(not(fips))))]
#![cfg(not(fips))]

use core::marker::PhantomData;

use aranya_buggy::BugExt;
use generic_array::GenericArray;
use typenum::{Prod, U255};

use crate::{
    hash::Hash,
    hmac::{Hmac, Tag},
    kdf::{KdfError, Prk},
    keys::SecretKeyBytes,
};

/// The size in octets of the maximum expanded output of HKDF.
pub type MaxOutput<D> = Prod<U255, D>;

/// HKDF for some hash `H`.
pub struct Hkdf<H>(PhantomData<H>);

impl<H: Hash> Hkdf<H> {
    /// The maximum nuumber of bytes that can be expanded by
    /// [`Self::expand`] and [`Self::expand_multi`].
    pub const MAX_OUTPUT: usize = 255 * H::DIGEST_SIZE;

    /// The size in bytes of a [`Prk`] returned by this HKDF.
    pub const PRK_SIZE: usize = H::DIGEST_SIZE;

    /// Extracts a fixed-length pseudorandom key (PRK) from the
    /// Input Keying Material (IKM) and an optional salt.
    ///
    /// It handles IKM and salts of an arbitrary length.
    #[inline]
    pub fn extract(ikm: &[u8], salt: &[u8]) -> Prk<H::DigestSize> {
        Self::extract_multi(&[ikm], salt)
    }

    /// Extracts a fixed-length pseudorandom key (PRK) from the
    /// Input Keying Material (IKM) and an optional salt.
    ///
    /// It handles IKM and salts of an arbitrary length.
    #[inline]
    pub fn extract_multi<I>(ikm: I, salt: &[u8]) -> Prk<H::DigestSize>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        // Section 2.2
        //
        // salt: optional salt value (a non-secret random value);
        // if not provided, it is set to a string of HashLen
        // zeros.
        let zero = GenericArray::<u8, H::DigestSize>::default();
        let salt = if salt.is_empty() { &zero } else { salt };

        // PRK = HMAC-Hash(salt, IKM)
        let prk = Hmac::<H>::mac_multi(salt, ikm).into_array();
        Prk::new(SecretKeyBytes::new(prk))
    }

    /// Expands the PRK with an optional info parameter into
    /// a key.
    ///
    /// It handles `info` parameters of an arbitrary length and
    /// outputs up to [`MAX_OUTPUT`][Self::MAX_OUTPUT] bytes.
    ///
    /// It returns an error if the output is too large.
    #[inline]
    pub fn expand(out: &mut [u8], prk: &Prk<H::DigestSize>, info: &[u8]) -> Result<(), KdfError> {
        Self::expand_multi(out, prk, &[info])
    }

    /// Expands the PRK with an optional info parameter into
    /// a key.
    ///
    /// It handles `info` parameters of an arbitrary length and
    /// outputs up to [`MAX_OUTPUT`][Self::MAX_OUTPUT] bytes.
    ///
    /// It returns an error if the output is too large.
    pub fn expand_multi<I>(
        out: &mut [u8],
        prk: &Prk<H::DigestSize>,
        info: I,
    ) -> Result<(), KdfError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
        I::IntoIter: Clone,
    {
        // Section 2.3
        //
        // The output OKM is calculated as follows:
        //
        // N = ceil(L/HashLen)
        // T = T(1) | T(2) | T(3) | ... | T(N)
        // OKM = first L octets of T
        //
        // where:
        // T(0) = empty string (zero length)
        // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
        // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
        // T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
        // ...
        if out.len() > Self::MAX_OUTPUT {
            return Err(KdfError::OutputTooLong);
        }

        let expander = Hmac::<H>::new(prk.as_bytes());
        let info = info.into_iter();

        let mut prev: Option<Tag<H::DigestSize>> = None;
        for (i, chunk) in out.chunks_mut(H::DIGEST_SIZE).enumerate() {
            let mut expander = expander.clone();
            if let Some(prev) = prev {
                expander.update(prev.as_bytes());
            }
            for s in info.clone() {
                expander.update(s.as_ref());
            }
            let next = i.checked_add(1).assume("i + 1 must not wrap")?;
            expander.update(&[next as u8]);
            let tag = expander.tag();
            chunk.copy_from_slice(&tag.as_bytes()[..chunk.len()]);
            prev = Some(tag);
        }
        Ok(())
    }
}

macro_rules! hkdf_impl {
    ($name:ident, $doc_name:expr, $hash:ident) => {
        #[doc = concat!($doc_name, ".")]
        pub struct $name;

        impl $crate::kdf::Kdf for $name {
            const ID: $crate::kdf::KdfId = $crate::kdf::KdfId::$name;

            type MaxOutput = $crate::hkdf::MaxOutput<<$hash as $crate::hash::Hash>::DigestSize>;

            type PrkSize = <$hash as $crate::hash::Hash>::DigestSize;

            fn extract_multi<I>(ikm: I, salt: &[u8]) -> $crate::kdf::Prk<Self::PrkSize>
            where
                I: ::core::iter::IntoIterator,
                I::Item: ::core::convert::AsRef<[u8]>,
            {
                $crate::hkdf::Hkdf::<$hash>::extract_multi(ikm, salt)
            }

            fn expand_multi<I>(
                out: &mut [u8],
                prk: &$crate::kdf::Prk<Self::PrkSize>,
                info: I,
            ) -> Result<(), $crate::kdf::KdfError>
            where
                I: ::core::iter::IntoIterator,
                I::Item: ::core::convert::AsRef<[u8]>,
                I::IntoIter: ::core::clone::Clone,
            {
                $crate::hkdf::Hkdf::<$hash>::expand_multi(out, prk, info)
            }
        }
    };
}
pub(crate) use hkdf_impl;

#[cfg(test)]
#[allow(clippy::wildcard_imports)]
mod tests {
    macro_rules! hkdf_tests {
        () => {
            use crate::test_util::test_kdf;

            hkdf_impl!(HkdfSha256, "HKDF-SHA256", Sha256);
            hkdf_impl!(HkdfSha384, "HKDF-SHA384", Sha384);
            hkdf_impl!(HkdfSha512, "HKDF-SHA512", Sha512);

            test_kdf!(hkdf_sha256, HkdfSha256, HkdfTest::HkdfSha256);
            test_kdf!(hkdf_sha384, HkdfSha384, HkdfTest::HkdfSha384);
            test_kdf!(hkdf_sha512, HkdfSha512, HkdfTest::HkdfSha512);
        };
    }

    #[cfg(feature = "boringssl")]
    mod boringssl {
        use crate::boring::{Sha256, Sha384, Sha512};
        hkdf_tests!();
    }

    #[cfg(feature = "bearssl")]
    mod bearssl {
        use crate::bearssl::{Sha256, Sha384, Sha512};
        hkdf_tests!();
    }

    mod rust {
        use crate::rust::{Sha256, Sha384, Sha512};
        hkdf_tests!();
    }
}
