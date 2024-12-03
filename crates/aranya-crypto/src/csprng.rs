//! Cryptographically Secure Random Number Generators.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

use generic_array::{ArrayLength, GenericArray};
#[cfg(all(feature = "getrandom", not(target_os = "vxworks")))]
pub use getrandom;
#[cfg(feature = "rand_compat")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_compat")))]
pub use rand;

/// A cryptographically secure pseudorandom number generator
/// (CSPRNG).
pub trait Csprng {
    /// Entirely fills `dst` with cryptographically secure
    /// pseudorandom bytes.
    ///
    /// # Error Handling
    ///
    /// If underlying CSPRNG encounters transient errors (for
    /// example, blocking on startup), it must block until the
    /// error condition subsides.
    ///
    /// If the underlying CSPRNG encounters a fatal error, it
    /// must immediately panic or abort the program.
    fn fill_bytes(&mut self, dst: &mut [u8]);

    /// Returns a fixed-number of cryptographically secure,
    /// pseudorandom bytes.
    ///
    /// # Notes
    ///
    /// Once (if) `const_generic_exprs` is stabilized, `T` will
    /// become `const N: usize`.
    fn bytes<T: AsMut<[u8]> + Default>(&mut self) -> T
    where
        Self: Sized,
    {
        let mut b = T::default();
        self.fill_bytes(b.as_mut());
        b
    }
}

impl<R: Csprng + ?Sized> Csprng for &mut R {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        (**self).fill_bytes(dst)
    }
}

#[cfg(feature = "getrandom")]
#[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
impl Csprng for rand_core::OsRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, dst)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl Csprng for rand::rngs::ThreadRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, dst)
    }
}

#[cfg(feature = "rand_compat")]
impl rand_core::CryptoRng for &mut dyn Csprng {}

#[cfg(feature = "rand_compat")]
impl rand_core::RngCore for &mut dyn Csprng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        Csprng::fill_bytes(self, dst);
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        Csprng::fill_bytes(self, dst);
        Ok(())
    }
}

/// Implemented by types that can generate random instances.
pub trait Random {
    /// Generates a random instance of itself.
    fn random<R: Csprng>(rng: &mut R) -> Self;
}

impl<N: ArrayLength> Random for GenericArray<u8, N> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        let mut v = Self::default();
        rng.fill_bytes(&mut v);
        v
    }
}

impl<const N: usize> Random for [u8; N] {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        let mut v = [0u8; N];
        rng.fill_bytes(&mut v);
        v
    }
}

macro_rules! rand_int_impl {
    ($($name:ty)* $(,)?) => {
        $(
            impl $crate::Random for $name {
                fn random<R: $crate::Csprng>(rng: &mut R) -> Self {
                    let mut v = [0u8; ::core::mem::size_of::<$name>()];
                    rng.fill_bytes(&mut v);
                    <$name>::from_le_bytes(v)
                }
            }
        )*
    };
}
rand_int_impl!(u8 u16 u32 u64 u128 usize);
rand_int_impl!(i8 i16 i32 i64 i128 isize);

#[cfg(feature = "trng")]
pub(crate) mod trng {
    use core::iter::{IntoIterator, Iterator};

    use aes::{
        cipher::{BlockEncrypt, KeyInit},
        Aes256,
    };
    use cfg_if::cfg_if;

    use crate::{csprng::Csprng, kdf::Kdf, zeroize::ZeroizeOnDrop};

    cfg_if! {
        if #[cfg(feature = "bearssl")] {
            use crate::bearssl::HkdfSha512;
        } else {
            use crate::rust::HkdfSha512;
        }
    }

    // If `std` is enabled, use a thread-local CSPRNG.
    #[cfg(feature = "std")]
    mod inner {
        use std::{cell::Cell, rc::Rc};

        use super::{random_key, AesCtrCsprng, Csprng, HkdfSha512, OsTrng};

        thread_local! {
            static THREAD_RNG: Rc<Cell<[u8; 32]>> =
                Rc::new(Cell::new(random_key::<_, HkdfSha512>(OsTrng)));
        }

        pub fn thread_rng() -> ThreadRng {
            let key = THREAD_RNG.with(|t| t.clone());
            ThreadRng { key }
        }

        // See https://github.com/rust-random/rand/blob/f3dd0b885c4597b9617ca79987a0dd899ab29fcb/src/rngs/thread.rs
        #[derive(Clone)]
        pub struct ThreadRng {
            key: Rc<Cell<[u8; 32]>>,
        }

        impl Csprng for ThreadRng {
            fn fill_bytes(&mut self, dst: &mut [u8]) {
                let key = self.key.get();
                let (mut rng, next) = AesCtrCsprng::new(key);
                self.key.set(next);
                rng.fill_bytes(dst)
            }
        }

        #[cfg(test)]
        impl AsMut<ThreadRng> for ThreadRng {
            fn as_mut(&mut self) -> &mut Self {
                self
            }
        }
    }

    // Otherwise, use a single global static with internal
    // mutability.
    #[cfg(not(feature = "std"))]
    mod inner {
        use lazy_static::lazy_static;
        use spin::mutex::SpinMutex;

        use super::{random_key, AesCtrCsprng, Csprng, HkdfSha512, OsTrng};

        lazy_static! {
            static ref THREAD_RNG: SpinMutex<[u8; 32]> =
                SpinMutex::new(random_key::<_, HkdfSha512>(OsTrng));
        }

        fn next_rng() -> AesCtrCsprng {
            let mut key = THREAD_RNG.lock();
            let (rng, next) = AesCtrCsprng::new(*key);
            key.copy_from_slice(&next);
            rng
        }

        pub fn thread_rng() -> ThreadRng {
            ThreadRng
        }

        pub struct ThreadRng;

        impl Csprng for ThreadRng {
            fn fill_bytes(&mut self, dst: &mut [u8]) {
                next_rng().fill_bytes(dst)
            }
        }

        #[cfg(test)]
        impl AsMut<ThreadRng> for ThreadRng {
            fn as_mut(&mut self) -> &mut Self {
                self
            }
        }
    }

    pub(crate) use inner::thread_rng;
    #[cfg(test)]
    pub(crate) use inner::ThreadRng;

    /// The system TRNG.
    struct OsTrng;

    impl Iterator for OsTrng {
        type Item = u32;

        fn next(&mut self) -> Option<u32> {
            extern "C" {
                // Provided by customer.
                fn OS_hardware_rand() -> u32;
            }
            // SAFETY: FFI call, no invariants
            let x = unsafe { OS_hardware_rand() };
            Some(x)
        }
    }

    fn random_key<I, K>(trng: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u32>,
        K: Kdf,
    {
        let mut trng = trng.into_iter();
        // We only need n=256 bits of entropy, but take
        // a hint from BoringSSL and get 10n bits.
        let mut seed = [0u8; 10 * 32];
        for chunk in seed.chunks_exact_mut(4) {
            let x = trng.next().expect("TRNG should not fail");
            chunk.copy_from_slice(&x.to_le_bytes());
        }
        // A KDF is probably overkill here, but this
        // method is only ever called once per RNG, so it
        // doesn't hurt.
        let mut key = [0u8; 32];
        K::extract_and_expand(&mut key, &seed, &[], b"aes-ctr csprng for vxworks")
            .expect("invalid KDF");
        key
    }

    /// A fast key erasure AES-CTR CSPRNG.
    ///
    /// Each instance is ephemeral;
    ///
    /// The implementation is taken from
    /// https://github.com/golang/go/blob/e4aec1fa8a9c57672b783d16dd122cb4e6708089/src/crypto/rand/rand_plan9.go
    ///
    /// For more information, see
    /// https://blog.cr.yp.to/20170723-random.html.
    #[derive(ZeroizeOnDrop)]
    struct AesCtrCsprng {
        cipher: Aes256,
        ctr: u64,
        block: [u8; 16],
    }

    impl AesCtrCsprng {
        /// Creates an AES-CTR CSPRNG using `key` and returns it
        /// as well as the next key.
        #[inline(always)]
        fn new(mut key: [u8; 32]) -> (Self, [u8; 32]) {
            let mut ctr: u64 = 0;
            let mut block = [0u8; 16];

            let cipher = Aes256::new(&key.into());

            // Erase the current key.
            for chunk in key.chunks_exact_mut(16) {
                cipher.encrypt_block_b2b(block.as_ref().into(), chunk.into());
                ctr = ctr.checked_add(1).expect("rng counter wrapped");
                block[..8].copy_from_slice(&ctr.to_le_bytes())
            }

            (Self { cipher, ctr, block }, key)
        }

        /// Fills `dst` with cryptographically secure bytes.
        #[inline(always)]
        fn fill_bytes(&mut self, dst: &mut [u8]) {
            // Read whole chunks
            let mut dst = dst.chunks_exact_mut(16);
            for chunk in dst.by_ref() {
                self.cipher
                    .encrypt_block_b2b(self.block.as_ref().into(), chunk.into());
                self.ctr = self.ctr.checked_add(1).expect("rng counter wrapped");
                self.block[..8].copy_from_slice(&self.ctr.to_le_bytes())
            }

            // Read a partial chunk, if any.
            let rem = dst.into_remainder();
            if !rem.is_empty() {
                self.cipher.encrypt_block(self.block.as_mut().into());
                rem.copy_from_slice(&self.block[..rem.len()]);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use rand::{rngs::OsRng, RngCore};

        use super::{random_key, thread_rng, AesCtrCsprng, ThreadRng};
        use crate::{csprng::Csprng, kdf::Kdf};

        #[no_mangle]
        extern "C" fn OS_hardware_rand() -> u32 {
            OsRng.next_u32()
        }

        /// Test with BearSSL's HKDF.
        #[test]
        #[cfg(feature = "bearssl")]
        fn test_aes_ctr_csprng_bearssl() {
            test_aes_ctr_csprng::<crate::bearssl::HkdfSha512>();
        }

        /// Test our own HKDF.
        #[test]
        fn test_aes_ctr_csprng_hkdf() {
            use crate::{hkdf::hkdf_impl, rust::Sha512};

            hkdf_impl!(HkdfSha512, "HKDF-SHA512", Sha512);

            test_aes_ctr_csprng::<HkdfSha512>();
        }

        // Testing a RNG is a fraught endeavor. As such, we only
        // implement a sanity test against a known-good
        // implementation: https://go.dev/play/p/OAYa9kEqRHb
        fn test_aes_ctr_csprng<K: Kdf>() {
            let trng: &[u32] = &[
                511020118, 3329505517, 3125191978, 2708588248, 2638371024, 1864699458, 1580599177,
                2931669449, 3911170326, 226101514, 3222450133, 2415624280, 3457417331, 2750971359,
                1283438866, 2735092416, 752222522, 531391756, 3105515119, 3499665662, 395492730,
                1606028116, 1422633577, 921326862, 40461932, 1750254861, 2210511461, 524576318,
                2841035765, 3036150926, 1117144028, 1942094251, 406390843, 1022411745, 2181488984,
                174429379, 196375134, 2128445749, 2226654310, 2876855800, 648736228, 4206437523,
                3780770807, 2337460207, 3038254605, 2284497048, 3691784102, 1444544244, 187268599,
                2171708536, 4093616657, 2773863083, 2520031184, 3369335287, 3730932382, 1377172275,
                2557866454, 2729367996, 2129009426, 2713073031, 352831220, 2298512516, 4277364210,
                23336659, 3536517015, 1423492831, 4031290816, 874352915, 2280206248, 2003567320,
                2965184223, 4045591871, 1214173797, 3231248046, 1756949802, 424814597, 1611041307,
                2304187543, 3013626048, 2083074060,
            ];
            let key = random_key::<_, K>(trng.iter().copied());
            let (mut rng, _) = AesCtrCsprng::new(key);
            const WANT: &[u8] = &[
                0x72, 0x36, 0x2b, 0x40, 0x54, 0xf6, 0x81, 0x15, 0xc5, 0x91, 0x3d, 0x58, 0x9f, 0xfd,
                0x19, 0x62, 0x13, 0x99, 0x65, 0x7, 0x53, 0xb1, 0x9c, 0xcc, 0x93, 0x86, 0x71, 0xd2,
                0x6, 0x8, 0xbf, 0x43, 0x40, 0xc2, 0xa7, 0xdf, 0xc3, 0x61, 0xfa, 0xaa,
            ];
            let mut got = [0u8; 16 * 2 + (16 / 2)];
            rng.fill_bytes(&mut got);
            assert_eq!(got, WANT);
        }

        #[test]
        fn test_thread_rng() {
            fn get_bytes<R: AsMut<ThreadRng>>(mut rng: R) -> [u8; 4096] {
                let mut b = [0u8; 4096];
                rng.as_mut().fill_bytes(&mut b);
                b
            }
            let mut rng = thread_rng();
            assert_ne!(get_bytes(&mut rng), get_bytes(&mut rng));
            assert_ne!(get_bytes(thread_rng()), get_bytes(thread_rng()));
            assert_ne!(get_bytes(thread_rng()), [0u8; 4096])
        }
    }
}
