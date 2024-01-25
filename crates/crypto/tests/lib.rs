#![cfg(feature = "test_util")]

use crypto::{default::DefaultCipherSuite, test_ciphersuite};

#[cfg(feature = "moonshot")]
#[no_mangle]
unsafe extern "C" fn OS_hardware_rand() -> u32 {
    42
}

test_ciphersuite!(default_ciphersuite, DefaultCipherSuite);
