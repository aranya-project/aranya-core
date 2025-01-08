//! Cryptographically Secure Random Number Generators.

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
    fn fill_bytes(&self, dst: &mut [u8]);

    /// Returns a fixed-number of cryptographically secure
    /// pseudorandom bytes.
    ///
    /// # Notes
    ///
    /// Once (if) `const_generic_exprs` is stabilized, `T` will
    /// become `const N: usize`.
    fn bytes<T: AsMut<[u8]> + Default>(&self) -> T
    where
        Self: Sized,
    {
        let mut b = T::default();
        self.fill_bytes(b.as_mut());
        b
    }
}

impl<R: Csprng + ?Sized> Csprng for &R {
    fn fill_bytes(&self, dst: &mut [u8]) {
        (**self).fill_bytes(dst)
    }
}

impl<R: Csprng + ?Sized> Csprng for &mut R {
    fn fill_bytes(&self, dst: &mut [u8]) {
        (**self).fill_bytes(dst)
    }
}

#[cfg(all(feature = "getrandom", feature = "rand_compat"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "getrandom", feature = "rand_compat"))))]
impl Csprng for rand_core::OsRng {
    fn fill_bytes(&self, dst: &mut [u8]) {
        rand_core::RngCore::fill_bytes(&mut Self, dst)
    }
}

#[cfg(all(feature = "rand_compat", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "rand_compat", feature = "std"))))]
impl Csprng for rand::rngs::ThreadRng {
    fn fill_bytes(&self, dst: &mut [u8]) {
        // NB: This clones an `Rc`.
        let mut rng = self.clone();
        rand_core::RngCore::fill_bytes(&mut rng, dst)
    }
}

#[cfg(feature = "rand_compat")]
impl rand_core::CryptoRng for &dyn Csprng {}

#[cfg(feature = "rand_compat")]
impl rand_core::CryptoRng for &mut dyn Csprng {}

#[cfg(feature = "rand_compat")]
impl rand_core::RngCore for &dyn Csprng {
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
    fn random<R: Csprng>(rng: &R) -> Self;
}

impl<N: ArrayLength> Random for GenericArray<u8, N> {
    fn random<R: Csprng>(rng: &R) -> Self {
        let mut v = Self::default();
        rng.fill_bytes(&mut v);
        v
    }
}

impl<const N: usize> Random for [u8; N] {
    fn random<R: Csprng>(rng: &R) -> Self {
        let mut v = [0u8; N];
        rng.fill_bytes(&mut v);
        v
    }
}

macro_rules! rand_int_impl {
    ($($name:ty)* $(,)?) => {
        $(
            impl $crate::csprng::Random for $name {
                fn random<R: $crate::csprng::Csprng>(rng: &R) -> Self {
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
    use core::{
        iter::{IntoIterator, Iterator},
        mem::MaybeUninit,
        ptr,
        sync::atomic::{self, Ordering},
    };

    use cfg_if::cfg_if;
    use rand_chacha::ChaCha8Rng;
    use rand_core::{RngCore, SeedableRng};

    use crate::{csprng::Csprng, kdf::Kdf, zeroize::ZeroizeOnDrop};

    cfg_if! {
        if #[cfg(feature = "bearssl")] {
            use crate::bearssl::HkdfSha512;
        } else {
            use crate::rust::HkdfSha512;
        }
    }

    /// A thread-local (ish) CSPRNG.
    #[derive(Clone)]
    pub struct ThreadRng(inner::ThreadRng);

    /// Returns a thread-local (ish) CSPRNG.
    pub fn thread_rng() -> ThreadRng {
        ThreadRng(inner::thread_rng())
    }

    impl Csprng for ThreadRng {
        fn fill_bytes(&self, dst: &mut [u8]) {
            self.0.fill_bytes_and_reseed(dst);
        }
    }

    // If `std` is enabled, use a true thread-local CSPRNG.
    #[cfg(feature = "std")]
    mod inner {
        use std::{cell::UnsafeCell, rc::Rc};

        use super::{ChaCha8Csprng, HkdfSha512, OsTrng};

        thread_local! {
            static THREAD_RNG: Rc<UnsafeCell<ChaCha8Csprng>> =
                Rc::new(UnsafeCell::new(ChaCha8Csprng::from_trng::<_, HkdfSha512>(OsTrng)));
        }

        pub(super) fn thread_rng() -> ThreadRng {
            let rng = THREAD_RNG.with(|t| t.clone());
            ThreadRng { rng }
        }

        // See https://github.com/rust-random/rand/blob/f3dd0b885c4597b9617ca79987a0dd899ab29fcb/src/rngs/thread.rs
        #[derive(Clone)]
        pub(super) struct ThreadRng {
            rng: Rc<UnsafeCell<ChaCha8Csprng>>,
        }

        impl ThreadRng {
            #[inline(always)]
            pub(super) fn fill_bytes_and_reseed(&self, dst: &mut [u8]) {
                // SAFETY:
                //
                // - `ThreadRng` is `!Sync`, so `self` can't be
                //   accessed concurrently.
                //
                // - `UnsafeCell::get` always returns a non-null
                //   pointer, so the dereference is safe.
                let rng = unsafe { &mut *self.rng.get() };
                rng.fill_bytes_and_reseed(dst);
            }
        }
    }

    // Otherwise, use a single global static with internal
    // mutability.
    #[cfg(not(feature = "std"))]
    mod inner {
        use lazy_static::lazy_static;
        use spin::mutex::SpinMutex;

        use super::{ChaCha8Csprng, HkdfSha512, OsTrng};

        lazy_static! {
            static ref THREAD_RNG: SpinMutex<ChaCha8Csprng> =
                SpinMutex::new(ChaCha8Csprng::from_trng::<_, HkdfSha512>(OsTrng));
        }

        pub(super) fn thread_rng() -> ThreadRng {
            ThreadRng
        }

        #[derive(Clone)]
        pub(super) struct ThreadRng;

        impl ThreadRng {
            #[inline(always)]
            pub(super) fn fill_bytes_and_reseed(&self, dst: &mut [u8]) {
                let mut rng = THREAD_RNG.lock();
                rng.fill_bytes_and_reseed(dst);
            }
        }
    }

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

    /// A ChaCha8 fast key erasure CSPRNG.
    ///
    /// The implementation is taken from
    /// https://github.com/golang/go/blob/b50ccef67a5cd4a2919131cfeb6f3a21d6742385/src/crypto/internal/sysrand/rand_plan9.go
    ///
    /// For more information on "fast key erasure", see
    /// <https://blog.cr.yp.to/20170723-random.html>.
    #[derive(Clone)]
    struct ChaCha8Csprng {
        rng: ChaCha8Rng,
    }

    impl ChaCha8Csprng {
        /// Creates an ChaCha8 CSPRNG from `seed`.
        #[inline(always)]
        fn from_seed(seed: [u8; 32]) -> Self {
            let rng = ChaCha8Rng::from_seed(seed);
            Self { rng }
        }

        /// Creates an ChaCha8 CSPRNG from a TRNG.
        fn from_trng<I, K>(trng: I) -> Self
        where
            I: IntoIterator<Item = u32>,
            K: Kdf,
        {
            let seed = random_seed::<_, K>(trng);
            Self::from_seed(seed)
        }

        /// Fills `dst` with cryptographically secure bytes, then
        /// reseeds itself.
        #[inline(always)]
        fn fill_bytes_and_reseed(&mut self, dst: &mut [u8]) {
            self.rng.fill_bytes(dst);
            self.reseed();
        }

        /// Reseeds the CSPRNG.
        #[inline(always)]
        fn reseed(&mut self) {
            let mut seed = [0; 32];
            self.rng.fill_bytes(&mut seed);
            // NB: This uses a lot less stack space than
            //    *self = Self::from_seed(seed);
            self.rng = ChaCha8Rng::from_seed(seed);
        }
    }

    impl ZeroizeOnDrop for ChaCha8Csprng {}
    impl Drop for ChaCha8Csprng {
        fn drop(&mut self) {
            // Wipe the inner CSPRNG state.
            let size = size_of_val(&self.rng);
            let ptr = ptr::addr_of_mut!(self.rng).cast::<MaybeUninit<u8>>();
            for i in 0..size {
                // SAFETY: this is safe because:
                // - `ptr` points inside the allocated object
                //   because it's bounded to [0, size), which is
                //   as large as the object.
                // - The computed offset cannot overflow `isize`
                //   (unless the size of the object is larger
                //   than `isize`, which is impossible).
                // - The offset cannot wrap.
                let ptr = unsafe { ptr.add(i) };
                // SAFETY: this is safe because:
                // - `ptr` is valid for writes (see above).
                // - `ptr` is is `MaybeUninit<u8>`, which has an
                //   alignment of 1, which is suitably aligned
                //   for all types.
                unsafe {
                    ptr.write_volatile(MaybeUninit::zeroed());
                }
            }
            atomic::compiler_fence(Ordering::SeqCst);
        }
    }

    /// Expands random data from a TRNG into a uniformly random
    /// seed.
    ///
    /// Used by [`ChaCha8Csprng`], but broken out for testing.
    fn random_seed<I, K>(trng: I) -> [u8; 32]
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
        // A KDF is probably overkill here, but this method is
        // only ever called once per CSRNG, so it doesn't hurt.
        let mut key = [0u8; 32];
        K::extract_and_expand(&mut key, &seed, &[], b"seed for chacha8 csprng")
            .expect("invalid KDF");
        key
    }

    #[cfg(test)]
    mod tests {
        use rand::{rngs::OsRng, RngCore};

        use super::{random_seed, thread_rng, ChaCha8Csprng, ThreadRng};
        use crate::{csprng::Csprng, kdf::Kdf};

        #[no_mangle]
        extern "C" fn OS_hardware_rand() -> u32 {
            OsRng.next_u32()
        }

        impl AsMut<ThreadRng> for ThreadRng {
            fn as_mut(&mut self) -> &mut Self {
                self
            }
        }

        /// Test with BearSSL's HKDF.
        #[test]
        #[cfg(feature = "bearssl")]
        fn test_random_seed_bearssl() {
            test_random_seed::<crate::bearssl::HkdfSha512>();
        }

        /// Test our own HKDF.
        #[test]
        fn test_random_seed_rust() {
            use crate::{hkdf::hkdf_impl, rust::Sha512};

            hkdf_impl!(HkdfSha512, "HKDF-SHA512", Sha512);

            test_random_seed::<HkdfSha512>();
        }

        fn test_random_seed<K: Kdf>() {
            // Generated by Go's `math/rand/v2.ChaCha8` RNG with
            // a seed of "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456".
            //
            // See https://go.dev/play/p/NzDatQOf6O0
            const TRNG: [u32; 80] = [
                1028003493, 2792012860, 1099769980, 2128370902, 756815533, 2414602873, 311122750,
                307405647, 2104290982, 530412394, 404676639, 182813750, 3425358440, 1260096186,
                2462344801, 399173164, 2135830142, 2699860934, 887799328, 1433459368, 289238002,
                1683313852, 3676428769, 1357185267, 3661058213, 1833683120, 3822579273, 2285597052,
                958698916, 2519770651, 1572529299, 2790931779, 420475008, 963064624, 1824154675,
                118275351, 4287391074, 1832189034, 50997640, 130225725, 1173499583, 610709929,
                2965402324, 1231825150, 2405225696, 3322754931, 3455205006, 3243476928, 234695516,
                93699511, 3838575301, 4027966375, 2597847841, 3510230663, 519341910, 571863882,
                3553626094, 3335867058, 1729293762, 1283510227, 1952190125, 1170477288, 2418110188,
                540190490, 4215328104, 1922401658, 3651883646, 2015091372, 1155297874, 1031749841,
                3836924763, 3524495878, 3395345112, 111962728, 2269910968, 1987501596, 841111076,
                328762168, 1383411217, 3898745338,
            ];
            let got = random_seed::<_, K>(TRNG);
            const WANT: [u8; 32] = [
                0xe, 0x6b, 0xc5, 0x9d, 0x68, 0x3e, 0x41, 0x16, 0x6b, 0x31, 0x76, 0x82, 0xe, 0xcb,
                0x7c, 0x30, 0x15, 0x6b, 0x72, 0x12, 0xda, 0x7d, 0x23, 0x94, 0x81, 0x5f, 0xe2, 0xc3,
                0xc3, 0x1f, 0x77, 0x2f,
            ];
            assert_eq!(got, WANT);
        }

        /// Test that reseeding `ChaCha8Csprng` changes its
        /// state.
        #[test]
        fn test_chacha8csprng_reseed() {
            const SEED: [u8; 32] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
            let mut rng = ChaCha8Csprng::from_seed(SEED);
            let old = rng.rng.get_seed();
            rng.reseed();
            let new = rng.rng.get_seed();
            assert_ne!(old, new);
        }

        /// Sanity check that two [`ThreadRng`]s are different.
        #[test]
        fn test_thread_rng() {
            fn get_bytes(rng: &mut ThreadRng) -> [u8; 32] {
                let mut b = [0; 32];
                rng.fill_bytes(&mut b);
                b
            }
            let mut rng = thread_rng();
            assert_ne!(get_bytes(&mut rng), get_bytes(&mut rng));
            assert_ne!(get_bytes(&mut thread_rng()), get_bytes(&mut thread_rng()));
            assert_ne!(get_bytes(&mut thread_rng()), [0; 32]);

            let rng = thread_rng();
            let mut a = rng.clone();
            let mut b = thread_rng();
            assert_ne!(get_bytes(&mut a), get_bytes(&mut b));
        }
    }
}
