use super::{Engine, Kdf, Kem, KeySizes, PrivateKey, PublicKey, Signer, SuiteIDs};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::Hmac;
use sha2::Sha512;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
struct TestError {}

impl fmt::Display for TestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TestError")
    }
}

impl Error for TestError {}

struct TestPrivateKey {}

impl PrivateKey<TestPublicKey> for TestPrivateKey {
    fn bytes(&self) -> Vec<u8> {
        vec![b'a']
    }

    fn equal(&self, _key: TestPrivateKey) -> bool {
        true
    }

    fn public(&self) -> TestPublicKey {
        TestPublicKey {}
    }
}

struct TestPublicKey {}

impl PublicKey for TestPublicKey {
    fn bytes(&self) -> Vec<u8> {
        vec![b'a']
    }

    fn equal(&self, _key: TestPublicKey) -> bool {
        true
    }
}

struct TestKdf {}

impl Kdf for TestKdf {
    fn expand(&self, _prk: &[u8], _info: &[u8], _l: usize) -> Vec<u8> {
        vec![b'a']
    }
    fn extract(&self, _ikm: &[u8], _salt: &[u8]) -> Vec<u8> {
        vec![b'a']
    }
    fn size(&self) -> usize {
        0
    }
}

struct TestKem {}

impl Kem<TestPrivateKey, TestPublicKey> for TestKem {
    type Error = TestError;
    fn generate_key(&self) -> Result<TestPrivateKey, Self::Error> {
        Ok(TestPrivateKey {})
    }
    fn key_sizes(&self) -> KeySizes {
        KeySizes {
            public_key: 0,
            private_key: 1,
        }
    }
    fn new_private_key(&self, _key: &[u8]) -> Result<TestPrivateKey, Self::Error> {
        Ok(TestPrivateKey {})
    }
    fn new_public_key(&self, _key: &[u8]) -> Result<TestPublicKey, Self::Error> {
        Ok(TestPublicKey {})
    }
}

struct TestSigner {}

impl Signer<TestPrivateKey, TestPublicKey> for TestSigner {
    type Error = TestError;
    fn generate_key(&self, _rand: String) -> Result<TestPrivateKey, Self::Error> {
        Ok(TestPrivateKey {})
    }
    fn key_sizes(&self) -> KeySizes {
        KeySizes {
            public_key: 0,
            private_key: 1,
        }
    }
    fn new_private_key(&self, _key: &[u8]) -> Result<TestPrivateKey, Self::Error> {
        Ok(TestPrivateKey {})
    }
    fn new_public_key(&self, _key: &[u8]) -> Result<TestPublicKey, Self::Error> {
        Ok(TestPublicKey {})
    }
    fn sign(&self, _sk: TestPrivateKey, _msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![b'a'])
    }
    fn verify(&self, _pk: TestPublicKey, _sign: &[u8]) -> bool {
        true
    }
}

struct TestEngine {}

impl Engine<TestPrivateKey, TestPublicKey> for TestEngine {
    type Error = TestError;
    type Aead = ChaCha20Poly1305;
    type Kdf = TestKdf;
    type Mac = Hmac<Sha512>;
    type Kem = TestKem;
    type Signer = TestSigner;
    type Hash = Sha512;
    fn suite_ids() -> SuiteIDs {
        SuiteIDs {
            aead: 1,
            kdf: 1,
            mac: 1,
            kem: 1,
            signer: 1,
            hash: 1,
            tuple_hash: 1,
        }
    }
    fn tuple_hash(_s: &[u8]) -> [u8; 64] {
        [0; 64]
    }
}

#[test]
fn crypto_engine() -> Result<(), String> {
    let _engine = TestEngine {};
    Ok(())
}
