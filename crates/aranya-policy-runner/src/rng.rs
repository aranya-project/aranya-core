use aranya_crypto::Csprng;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

/// A RNG that can be configured to use either the default or
/// deterministic RNGs at runtime.
#[allow(clippy::large_enum_variant)]
pub enum SwitchableRng {
    Default,
    Deterministic(StdRng),
}

impl SwitchableRng {
    /// Create a new RNG using [`aranya_crypto::Rng`].
    pub fn new_default() -> Self {
        Self::Default
    }

    /// Create a new RNG using `rand`'s [`StdRng`] implementation (which
    /// is based on ChaCha12).
    pub fn new_deterministic() -> Self {
        Self::Deterministic(StdRng::from_seed([0u8; 32]))
    }
}

impl Csprng for SwitchableRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        match self {
            Self::Default => aranya_crypto::Rng.fill_bytes(dst),
            Self::Deterministic(rng) => rng.fill(dst),
        }
    }
}
