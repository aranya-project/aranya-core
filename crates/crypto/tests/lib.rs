#![cfg(feature = "test_util")]

use crypto::{default::DefaultCipherSuite, test_ciphersuite};

#[cfg(feature = "moonshot")]
#[no_mangle]
unsafe extern "C" fn OS_hardware_rand() -> u32 {
    42
}

test_ciphersuite!(default_ciphersuite, DefaultCipherSuite);

mod custom_id_tests {
    crypto::custom_id! {
        struct MyId;
    }

    #[test]
    fn json_roundtrip() {
        let id: MyId = crypto::Id::random(&mut crypto::Rng).into();
        let ser = serde_json::to_string(&id).unwrap();
        assert_eq!(ser, format!("\"{id}\""));
        let got: MyId = serde_json::from_str(&ser).unwrap();
        assert_eq!(id, got);
    }

    #[test]
    fn postcard_roundtrip() {
        let id: MyId = crypto::Id::random(&mut crypto::Rng).into();
        let ser = postcard::to_allocvec(&id).unwrap();
        assert_eq!(id.as_bytes(), ser);
        let got: MyId = postcard::from_bytes(&ser).unwrap();
        assert_eq!(id, got);
    }
}
