#![cfg(feature = "test_util")]

use crypto::{test_util::test_ciphersuite, DefaultCipherSuite, Rng};

#[cfg(feature = "moonshot")]
#[no_mangle]
unsafe extern "C" fn OS_hardware_rand() -> u32 {
    42
}

#[test]
fn test_default_ciphersuite() {
    test_ciphersuite::<DefaultCipherSuite, _>(&mut Rng);
}
