#![cfg(all(
    test,
    feature = "test_util",
    any(feature = "getrandom", feature = "boringssl"),
))]

use crypto::{test_util::test_ciphersuite, DefaultCipherSuite, Rng};

#[test]
fn test_default_ciphersuite() {
    test_ciphersuite::<DefaultCipherSuite, _>(&mut Rng);
}
