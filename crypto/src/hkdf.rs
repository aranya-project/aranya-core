//! HKDF per [RFC 5869].
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.
//!
//! [RFC 5869]: https://www.rfc-editor.org/rfc/rfc5869

#![forbid(unsafe_code)]
#![cfg_attr(docs, doc(cfg(not(fips))))]
#![cfg(not(fips))]

use {
    crate::{
        hash::Hash,
        hmac::Hmac,
        kdf::{KdfError, Prk},
        mac::Tag,
    },
    core::marker::PhantomData,
};

/// HKDF for some hash `H` with a `D`-byte digest size.
pub struct Hkdf<H: Hash, const N: usize>(PhantomData<H>);

impl<H: Hash, const D: usize> Hkdf<H, D>
where
    H::Digest: Into<Tag<D>>,
{
    /// The maximum nuumber of bytes that can be expanded by
    /// [`Self::expand`] and [`Self::expand_multi`].
    pub const MAX_OUTPUT: usize = 255 * D;

    /// The size in bytes of a [`Prk`] returned by this HKDF.
    pub const PRK_SIZE: usize = D;

    /// Extracts a fixed-length pseudorandom key (PRK) from the
    /// Input Keying Material (IKM) and an optional salt.
    ///
    /// It handles IKM and salts of an arbitrary length.
    #[inline]
    pub fn extract(ikm: &[u8], salt: &[u8]) -> Prk<D> {
        Self::extract_multi(&[ikm], salt)
    }

    /// Extracts a fixed-length pseudorandom key (PRK) from the
    /// Input Keying Material (IKM) and an optional salt.
    ///
    /// It handles IKM and salts of an arbitrary length.
    #[inline]
    pub fn extract_multi(ikm: &[&[u8]], salt: &[u8]) -> Prk<D> {
        // Section 2.2
        //
        // salt: optional salt value (a non-secret random value);
        // if not provided, it is set to a string of HashLen
        // zeros.
        let salt = if salt.is_empty() { &[0u8; D] } else { salt };

        // PRK = HMAC-Hash(salt, IKM)
        Hmac::<H, D>::mac_multi(salt, ikm).into()
    }

    /// Expands the PRK with an optional info parameter into
    /// a key.
    ///
    /// It handles `info` parameters of an arbitrary length and
    /// outputs up to [`MAX_OUTPUT`][Self::MAX_OUTPUT] bytes.
    ///
    /// It returns an error if the output is too large.
    #[inline]
    pub fn expand(out: &mut [u8], prk: &Prk<D>, info: &[u8]) -> Result<(), KdfError> {
        Self::expand_multi(out, prk, &[info])
    }

    /// Expands the PRK with an optional info parameter into
    /// a key.
    ///
    /// It handles `info` parameters of an arbitrary length and
    /// outputs up to [`MAX_OUTPUT`][Self::MAX_OUTPUT] bytes.
    ///
    /// It returns an error if the output is too large.
    pub fn expand_multi(out: &mut [u8], prk: &Prk<D>, info: &[&[u8]]) -> Result<(), KdfError> {
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

        let expander = Hmac::<H, D>::new(prk.as_ref());

        let mut prev: Option<Tag<D>> = None;
        for (i, chunk) in out.chunks_mut(D).enumerate() {
            let mut expander = expander.clone();
            if let Some(prev) = prev {
                expander.update(prev.as_ref());
            }
            for s in info {
                expander.update(s);
            }
            expander.update(&[(i + 1) as u8]);
            let tag = expander.tag();
            chunk.copy_from_slice(&tag.as_ref()[..chunk.len()]);
            prev = Some(tag);
        }
        Ok(())
    }
}

macro_rules! hkdf_impl {
    ($name:ident, $doc_name:expr, $hash:ident) => {
        #[doc = concat!($doc_name, ".")]
        pub struct $name;

        impl $name {
            const DIGEST_SIZE: usize = <$hash as $crate::hash::Hash>::DIGEST_SIZE;
        }

        impl $crate::kdf::Kdf for $name {
            const ID: $crate::kdf::KdfId = $crate::kdf::KdfId::$name;

            const MAX_OUTPUT: usize =
                $crate::hkdf::Hkdf::<$hash, { Self::DIGEST_SIZE }>::MAX_OUTPUT;

            const PRK_SIZE: usize = Self::DIGEST_SIZE;

            type Prk = $crate::kdf::Prk<{ Self::DIGEST_SIZE }>;

            fn extract_multi(ikm: &[&[u8]], salt: &[u8]) -> Self::Prk {
                $crate::hkdf::Hkdf::<$hash, { Self::DIGEST_SIZE }>::extract_multi(ikm, salt)
            }

            fn expand_multi(
                out: &mut [u8],
                prk: &Self::Prk,
                info: &[&[u8]],
            ) -> Result<(), $crate::kdf::KdfError> {
                $crate::hkdf::Hkdf::<$hash, { Self::DIGEST_SIZE }>::expand_multi(out, prk, info)
            }
        }
    };
}
pub(crate) use hkdf_impl;

#[cfg(test)]
#[allow(clippy::wildcard_imports)]
mod tests {

    #[cfg(feature = "boringssl")]
    mod boringssl {
        use {
            super::*,
            crate::{
                boring::{Sha256, Sha384, Sha512},
                test_util::{hkdf, test_hkdf},
            },
        };

        hkdf_impl!(HkdfSha256, "HKDF-SHA256", Sha256);
        hkdf_impl!(HkdfSha384, "HKDF-SHA384", Sha384);
        hkdf_impl!(HkdfSha512, "HKDF-SHA512", Sha512);

        #[test]
        fn test_hkdf_sha256() {
            test_hkdf::<HkdfSha256>(hkdf::TestName::HkdfSha256);
        }

        #[test]
        fn test_hkdf_sha384() {
            test_hkdf::<HkdfSha384>(hkdf::TestName::HkdfSha384);
        }

        #[test]
        fn test_hkdf_sha512() {
            test_hkdf::<HkdfSha512>(hkdf::TestName::HkdfSha512);
        }
    }

    use {
        super::*,
        crate::{
            bearssl::{Sha256, Sha384, Sha512},
            test_util::{hkdf, test_hkdf},
        },
    };

    hkdf_impl!(HkdfSha256, "HKDF-SHA256", Sha256);
    hkdf_impl!(HkdfSha384, "HKDF-SHA384", Sha384);
    hkdf_impl!(HkdfSha512, "HKDF-SHA512", Sha512);

    #[test]
    fn test_hkdf_sha256() {
        test_hkdf::<HkdfSha256>(hkdf::TestName::HkdfSha256);
    }

    #[test]
    fn test_hkdf_sha384() {
        test_hkdf::<HkdfSha384>(hkdf::TestName::HkdfSha384);
    }

    #[test]
    fn test_hkdf_sha512() {
        test_hkdf::<HkdfSha512>(hkdf::TestName::HkdfSha512);
    }
}
