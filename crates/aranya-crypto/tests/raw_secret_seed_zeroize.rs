use core::{mem::MaybeUninit, ptr};

use aranya_crypto::{
    default::DefaultCipherSuite,
    engine::{RawSecret, RawSeed},
};

#[test]
fn raw_secret_seed_should_zeroize_on_drop() {
    const SECRET: [u8; 64] = [0xA5; 64];

    let mut slot = MaybeUninit::new(RawSecret::<DefaultCipherSuite>::Seed(SECRET.into()));
    let secret = slot.as_mut_ptr();

    // Capture a pointer directly to the seed field bytes.
    let seed = unsafe {
        match &mut *secret {
            RawSecret::Seed(seed) => (seed as *mut RawSeed).cast::<[u8; 64]>(),
            _ => unreachable!("constructed as `RawSecret::Seed`"),
        }
    };

    // Drop the enum in place and inspect the same memory.
    //
    // SAFETY:
    // - `secret` points to initialized `RawSecret` storage in `slot`.
    // - `drop_in_place(secret)` drops exactly once.
    // - `seed` points into the same storage, and we only read bytes.
    let after_drop = unsafe {
        ptr::drop_in_place(secret);
        seed.read()
    };

    // Ensure `RawSecret::Seed` is scrubbed on drop.
    assert_eq!(after_drop, [0u8; 64]);
}
