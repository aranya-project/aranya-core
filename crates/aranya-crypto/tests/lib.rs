#![cfg(feature = "test_util")]

use aranya_crypto::{default::DefaultCipherSuite, test_ciphersuite};

#[cfg(feature = "trng")]
#[unsafe(no_mangle)]
extern "C" fn OS_hardware_rand() -> u32 {
    42
}

test_ciphersuite!(default_ciphersuite, DefaultCipherSuite);

mod custom_id_tests {
    aranya_crypto::custom_id! {
        struct MyId;
    }

    #[test]
    fn json_roundtrip() {
        let id: MyId = aranya_crypto::Id::random(&mut aranya_crypto::Rng).into();
        let ser = serde_json::to_string(&id).unwrap();
        assert_eq!(ser, format!("\"{id}\""));
        let got: MyId = serde_json::from_str(&ser).unwrap();
        assert_eq!(id, got);
    }

    #[test]
    fn postcard_roundtrip() {
        let id: MyId = aranya_crypto::Id::random(&mut aranya_crypto::Rng).into();
        let ser = postcard::to_allocvec(&id).unwrap();
        assert_eq!(id.as_bytes(), ser);
        let got: MyId = postcard::from_bytes(&ser).unwrap();
        assert_eq!(id, got);
    }
}
