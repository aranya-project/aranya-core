//! Default implementations.

use cfg_if::cfg_if;

use crate::csprng::Csprng;

/// The default CSPRNG.
///
/// Certain feature flags will change the default CSPRNG:
///
/// - `trng`: Uses a TRNG provided by the system.
/// - `std`: Uses a thread-local CSPRNG seeded from the system
///   CSPRNG.
/// - `libc`: Uses the system CSPRNG.
///
/// The `libc` flag is enabled by default.
///
/// If all of those feature flags are disabled, `Rng` invokes the
/// following routine:
///
/// ```
/// extern "C" {
///     /// Reads `len` cryptographically secure bytes into
///     /// `dst`.
///     fn crypto_getrandom(dst: *mut u8, len: usize);
/// }
/// ```
///
/// In general, `Rng` should be used directly instead of being
/// created with [`Rng::new`]. For example:
///
/// ```
/// # use aranya_crypto::csprng::Csprng;
/// use aranya_crypto::Rng;
///
/// fn foo<R: Csprng>(_rng: &mut R) {}
///
/// foo(&mut Rng);
/// ```
#[derive(Copy, Clone, Debug, Default)]
pub struct Rng;

impl Rng {
    /// Creates a default CSPRNG.
    ///
    /// In general, `Rng` should be used directly instead of
    /// being created with this method.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl Csprng for Rng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        cfg_if! {
            if #[cfg(feature = "trng")] {
                crate::csprng::trng::thread_rng().fill_bytes(dst)
            } else if #[cfg(feature = "std")] {
                // Try to use `ThreadRng` if possible.
                rand_core::RngCore::fill_bytes(&mut rand::thread_rng(), dst)
            } else if #[cfg(feature = "getrandom")] {
                getrandom::getrandom(dst).expect("should not fail")
            } else {
                extern "C" {
                    fn crypto_getrandom(dst: *mut u8, len: usize);
                }
                // SAFETY: FFI call, no invariants.
                unsafe {
                    crypto_getrandom(dst.as_mut_ptr(), dst.len())
                }
            }
        }
    }
}

#[cfg(feature = "rand_compat")]
impl rand_core::CryptoRng for Rng {}

#[cfg(feature = "rand_compat")]
impl rand_core::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        Csprng::fill_bytes(self, dst)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        Csprng::fill_bytes(self, dst);
        Ok(())
    }
}
