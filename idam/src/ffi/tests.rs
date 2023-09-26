use {
    crate::{Command, IdamCrypto, KeyStore, KeyStoreError},
    crypto::{
        idam::KeyStoreSecret, DefaultCipherSuite, DefaultEngine, DefaultWrappedKey, EncryptionKey,
        Engine, Error, Id, Rng, SigningKey,
    },
    std::collections::HashMap,
};

pub struct DefaultKeyStore<'a> {
    identity: HashMap<Vec<u8>, &'a DefaultWrappedKey>,
    encryption: HashMap<Vec<u8>, &'a DefaultWrappedKey>,
    signing: HashMap<Vec<u8>, &'a DefaultWrappedKey>,
    group: HashMap<Vec<u8>, &'a DefaultWrappedKey>,
}

impl<'a> DefaultKeyStore<'a> {
    /// Creates a [`KeyStore`].
    pub fn new() -> Self {
        Self {
            identity: HashMap::new(),
            encryption: HashMap::new(),
            signing: HashMap::new(),
            group: HashMap::new(),
        }
    }

    pub fn store_key(
        &mut self,
        key_type: KeyStoreSecret,
        public_key: &[u8],
        wrapped_secret: &'a DefaultWrappedKey,
    ) {
        let map = match key_type {
            KeyStoreSecret::Identify => &mut self.identity,
            KeyStoreSecret::Encrypt => &mut self.encryption,
            KeyStoreSecret::Sign => &mut self.signing,
            KeyStoreSecret::Group => &mut self.group,
        };
        map.insert(public_key.to_vec(), wrapped_secret);
    }
}

impl<'a> KeyStore<DefaultEngine<Rng, DefaultCipherSuite>> for DefaultKeyStore<'a> {
    fn get(
        &self,
        key_type: KeyStoreSecret,
        public_key: &[u8],
    ) -> Result<&'a DefaultWrappedKey, Error> {
        match key_type {
            KeyStoreSecret::Identify => self
                .identity
                .get(public_key)
                .ok_or(KeyStoreError.into())
                .copied(),
            KeyStoreSecret::Encrypt => self
                .encryption
                .get(public_key)
                .ok_or(KeyStoreError.into())
                .copied(),
            KeyStoreSecret::Sign => self
                .signing
                .get(public_key)
                .ok_or(KeyStoreError.into())
                .copied(),
            KeyStoreSecret::Group => self
                .group
                .get(public_key)
                .ok_or(KeyStoreError.into())
                .copied(),
        }
    }
}

// Creates an IdamCrypto FFI
fn create_ffi<'a>() -> IdamCrypto<DefaultEngine<Rng>, DefaultKeyStore<'a>> {
    let (eng, _) = DefaultEngine::from_entropy(Rng);
    let test_key_store = DefaultKeyStore::new();
    IdamCrypto {
        engine: eng,
        key_store: test_key_store,
    }
}

// generates a new EncryptionKey
fn create_enc_key<E: Engine, K: KeyStore<E>>(ffi: &mut IdamCrypto<E, K>) -> EncryptionKey<E> {
    EncryptionKey::<E>::new(&mut ffi.engine)
}

// generates a new SigningKey
fn create_sign_key<E: Engine, K: KeyStore<E>>(ffi: &mut IdamCrypto<E, K>) -> SigningKey<E> {
    SigningKey::<E>::new(&mut ffi.engine)
}

#[test]
fn test_key_store() -> anyhow::Result<()> {
    let mut test_ffi = create_ffi();

    let private_key = create_enc_key(&mut test_ffi);
    let public_key = postcard::to_allocvec(&private_key.public()).expect("should work");
    let want = DefaultEngine::wrap(&mut test_ffi.engine, private_key)
        .expect("should be able to wrap EncryptionKey");

    test_ffi
        .key_store
        .store_key(KeyStoreSecret::Encrypt, &public_key, &want);
    let got = test_ffi
        .key_store
        .get(KeyStoreSecret::Encrypt, &public_key)
        .expect("cannot find stored key");
    assert_eq!(got.ciphertext, want.ciphertext);

    Ok(())
}

#[test]
fn test_idam_crypto() -> anyhow::Result<()> {
    let (eng, _) = DefaultEngine::from_entropy(Rng);
    let test_key_store = DefaultKeyStore::new();
    let mut test_ffi = IdamCrypto {
        engine: eng,
        key_store: test_key_store,
    };

    let group_id = Id::default();
    let enc_key = create_enc_key(&mut test_ffi);
    let sign_key = create_sign_key(&mut test_ffi);

    // Byte serializations of public key certificates
    let pub_enc_key = postcard::to_allocvec(&enc_key.public())
        .expect("should be able to obtain exported public key");
    let pub_sign_key = postcard::to_allocvec(&sign_key.public())
        .expect("should be able to obtain exported public key");

    // Insert secret data to KeyStore
    let wrapped_enc_key = DefaultEngine::wrap(&mut test_ffi.engine, enc_key)
        .expect("should be able to wrap EncryptionKey");
    test_ffi
        .key_store
        .store_key(KeyStoreSecret::Encrypt, &pub_enc_key, &wrapped_enc_key);
    let wrapped_sign_key = DefaultEngine::wrap(&mut test_ffi.engine, sign_key)
        .expect("should be able to wrap EncryptionKey");
    test_ffi
        .key_store
        .store_key(KeyStoreSecret::Sign, &pub_sign_key, &wrapped_sign_key);

    // Test keyId derivation
    let _enc_key_id = test_ffi
        .encryption_key_id(&pub_enc_key)
        .expect("should derive KeyID for EncryptionPublicKey");
    let _sign_key_id = test_ffi
        .signing_key_id(&pub_sign_key)
        .expect("should derive KeyID for VerifyingKey");

    // Test GroupKey generation
    let group_key = test_ffi
        .generate_group_key()
        .expect("should be able to generate a GroupKey");
    let group_key_wrap = group_key.key_wrap;
    test_ffi
        .key_store
        .store_key(KeyStoreSecret::Group, &pub_enc_key, &wrapped_enc_key);

    // Test GroupKey delivery
    let sealed_group_key = test_ffi
        .seal_group_key(&group_key_wrap, &pub_enc_key, group_id)
        .expect("should be able to seal a GroupKey");
    let unsealed_group_key = test_ffi
        .unseal_group_key(sealed_group_key, &pub_enc_key, group_id)
        .expect("should be able to unseal a GroupKey");
    assert_eq!(group_key.key_id, unsealed_group_key.key_id);

    // Test message encryption
    let plaintext = "hello";
    let parent_id = group_id;
    let cmd = Command { name: "Message" };
    let ciphertext = test_ffi
        .encrypt_message(
            plaintext.as_bytes(),
            &group_key_wrap,
            parent_id,
            &pub_sign_key,
            &cmd,
        )
        .expect("should be able to encrypt message");
    let message = test_ffi
        .decrypt_message(&ciphertext, &group_key_wrap, parent_id, &pub_sign_key, &cmd)
        .expect("should be able to decrypt message");
    assert_eq!(plaintext.as_bytes(), message);

    Ok(())
}
