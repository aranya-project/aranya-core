#![cfg(feature = "test_util")]

use crypto::{test_ciphersuite, DefaultCipherSuite};

#[cfg(feature = "moonshot")]
#[no_mangle]
unsafe extern "C" fn OS_hardware_rand() -> u32 {
    42
}

test_ciphersuite!(default_ciphersuite, DefaultCipherSuite);
