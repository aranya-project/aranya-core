#![cfg(test)]

// Make sure `OS_hardware_rand` is defined for our tests.
#[cfg(feature = "trng")]
#[unsafe(no_mangle)]
extern "C" fn OS_hardware_rand() -> u32 {
    use rand::RngCore;
    rand::rngs::OsRng.next_u32()
}
