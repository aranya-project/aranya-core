//! HMAC per [FIPS PUB 198-1]
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.
//!
//! [FIPS PUB 198-1]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf

#![forbid(unsafe_code)]
#![cfg_attr(docs, doc(cfg(not(fips))))]
#![cfg(not(fips))]

use core::{
    borrow::{Borrow, BorrowMut},
    cmp,
};

use crate::{
    hash::Hash,
    mac::{MacKey, Tag},
};

/// HMAC per [FIPS PUB 198-1] for some hash `H` with a `D`-byte
/// digest size.
///
/// [FIPS PUB 198-1]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
#[derive(Clone)]
pub struct Hmac<H: Hash, const D: usize>
where
    H::Digest: Into<Tag<D>>,
{
    /// H(ipad).
    ipad: H,
    /// H(opad).
    opad: H,
}

impl<H: Hash, const D: usize> Hmac<H, D>
where
    H::Digest: Into<Tag<D>>,
{
    /// Creates an HMAC using the provided `key`.
    pub fn new(key: &[u8]) -> Self {
        let mut key = {
            let mut tmp = H::Block::default();
            let tmp_len = tmp.borrow().len();
            if key.len() <= tmp_len {
                // Steps 1 and 3
                tmp.borrow_mut()[..key.len()].copy_from_slice(key);
            } else {
                // Step 2
                let d = H::hash(key);
                let n = cmp::min(d.borrow().len(), tmp_len);
                tmp.borrow_mut()[..n].copy_from_slice(&d.borrow()[..n]);
            };
            tmp
        };

        // Step 4: K_0 ^ ipad (0x36)
        for v in key.borrow_mut() {
            *v ^= 0x36;
        }
        let mut ipad = H::new();
        ipad.update(key.borrow());

        // Step 7: K_0 ^ opad (0x5c)
        for v in key.borrow_mut() {
            *v ^= 0x36 ^ 0x5c;
        }
        let mut opad = H::new();
        opad.update(key.borrow());

        Self { ipad, opad }
    }

    /// Writes `data` to the HMAC.
    pub fn update(&mut self, data: &[u8]) {
        // Step 5: H((K_0 ^ ipad) || text)
        self.ipad.update(data)
    }

    /// Returns the authentication tag.
    pub fn tag(mut self) -> Tag<D> {
        let d = self.ipad.digest();
        // Step 8: (K_0 ^ opad) || H((K_0 ^ ipad) || text)
        self.opad.update(d.borrow());
        // Step 9: H((K_0 ^ opad) || H((K_0 ^ ipad) || text))
        self.opad.digest().into()
    }

    /// Computes the single-shot tag from `data` using `key`.
    pub fn mac_multi(key: &[u8], data: &[&[u8]]) -> Tag<D> {
        let mut h = Self::new(key);
        for s in data {
            h.update(s);
        }
        h.tag()
    }
}

/// An [`Hmac`] key.
pub type HmacKey<const N: usize> = MacKey<N>;

macro_rules! hmac_impl {
    ($name:ident, $doc:expr, $hash:ident) => {
        #[doc = concat!($doc, ".")]
        #[derive(Clone)]
        pub struct $name($crate::hmac::Hmac<$hash, { <$hash as $crate::hash::Hash>::DIGEST_SIZE }>);

        impl $crate::mac::Mac for $name {
            const ID: $crate::mac::MacId = $crate::mac::MacId::$name;

            // Setting len(K) = L ensures that we're always in
            // [L, B].
            type Key = $crate::hmac::HmacKey<{ <$hash as $crate::hash::Hash>::DIGEST_SIZE }>;
            type Tag = $crate::mac::Tag<{ <$hash as $crate::hash::Hash>::DIGEST_SIZE }>;

            fn new(key: &Self::Key) -> Self {
                Self($crate::hmac::Hmac::new(key.as_ref()))
            }

            fn update(&mut self, data: &[u8]) {
                self.0.update(data)
            }

            fn tag(self) -> Self::Tag {
                self.0.tag()
            }
        }
    };
}
pub(crate) use hmac_impl;

#[cfg(test)]
#[allow(clippy::wildcard_imports)]
mod tests {
    macro_rules! hmac_tests {
        () => {
            use crate::test_util::test_mac;

            hmac_impl!(HmacSha256, "HMAC-SHA256", Sha256);
            hmac_impl!(HmacSha384, "HMAC-SHA384", Sha384);
            hmac_impl!(HmacSha512, "HMAC-SHA512", Sha512);

            test_mac!(hmac_sha256, HmacSha256, MacTest::HmacSha256);
            test_mac!(hmac_sha384, HmacSha384, MacTest::HmacSha384);
            test_mac!(hmac_sha512, HmacSha512, MacTest::HmacSha512);
        };
    }

    #[cfg(feature = "boringssl")]
    mod boringssl {
        use crate::boring::{Sha256, Sha384, Sha512};
        hmac_tests!();
    }

    #[cfg(feature = "bearssl")]
    mod bearssl {
        use crate::bearssl::{Sha256, Sha384, Sha512};
        hmac_tests!();
    }

    mod rust {
        use crate::rust::{Sha256, Sha384, Sha512};
        hmac_tests!();
    }
}