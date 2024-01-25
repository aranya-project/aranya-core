#![cfg(test)]

use std::{borrow::Borrow, collections::HashMap};

use crypto::{
    default::{DefaultCipherSuite, DefaultEngine, WrappedKey as DefaultWrappedKey},
    engine::WrappedKey,
    idam::KeyStoreSecret,
    EncryptionKey, Engine, Error, Id, Identified, Rng, SigningKey,
};

use crate::{ffi::CommandContext, IdamCrypto, KeyStore, KeyStoreError};

pub struct DefaultKeyStore {
    identity: HashMap<Vec<u8>, Vec<u8>>,
    encryption: HashMap<Vec<u8>, Vec<u8>>,
    signing: HashMap<Vec<u8>, Vec<u8>>,
    group: HashMap<Vec<u8>, Vec<u8>>,
}

impl DefaultKeyStore {
    /// Creates a [`KeyStore`].
    pub fn new() -> Self {
        Self {
            identity: HashMap::new(),
            encryption: HashMap::new(),
            signing: HashMap::new(),
            group: HashMap::new(),
        }
    }

    pub fn store_key<E: Engine + ?Sized>(
        &mut self,
        key_type: KeyStoreSecret,
        public_key: &[u8],
        wrapped_secret: &E::WrappedKey,
    ) {
        let map = match key_type {
            KeyStoreSecret::Identify => &mut self.identity,
            KeyStoreSecret::Encrypt => &mut self.encryption,
            KeyStoreSecret::Sign => &mut self.signing,
            KeyStoreSecret::Group => &mut self.group,
        };
        let encoded =
            postcard::to_allocvec(&wrapped_secret).expect("unable to encode `WrappedKey`");
        map.insert(public_key.to_vec(), encoded);
    }
}

impl KeyStore for DefaultKeyStore {
    fn get<E: Engine + ?Sized>(
        &self,
        key_type: KeyStoreSecret,
        public_key: &[u8],
    ) -> Result<E::WrappedKey, Error> {
        let bytes = match key_type {
            KeyStoreSecret::Identify => self.identity.get(public_key),
            KeyStoreSecret::Encrypt => self.encryption.get(public_key),
            KeyStoreSecret::Sign => self.signing.get(public_key),
            KeyStoreSecret::Group => self.group.get(public_key),
        }
        .ok_or(KeyStoreError)?;
        let key = postcard::from_bytes(bytes).expect("unable to decode `WrappedKey`");
        Ok(key)
    }
}

// Creates an IdamCrypto FFI
fn create_ffi() -> IdamCrypto<DefaultKeyStore> {
    let test_key_store = DefaultKeyStore::new();
    IdamCrypto {
        key_store: test_key_store,
    }
}

// generates a new EncryptionKey
fn create_enc_key<E: Engine>(eng: &mut E) -> EncryptionKey<E> {
    EncryptionKey::<E>::new(eng)
}

// generates a new SigningKey
fn create_sign_key<E: Engine>(eng: &mut E) -> SigningKey<E> {
    SigningKey::<E>::new(eng)
}

#[test]
fn test_key_store() -> anyhow::Result<()> {
    let (mut eng, _) = DefaultEngine::<_, DefaultCipherSuite>::from_entropy(Rng);
    let mut test_ffi = create_ffi();

    let private_key = create_enc_key(&mut eng);
    let public_key = postcard::to_allocvec(&private_key.public()).expect("should work");
    let want = eng
        .wrap(private_key)
        .expect("should be able to wrap EncryptionKey");

    test_ffi
        .key_store
        .store_key::<DefaultEngine<Rng>>(KeyStoreSecret::Encrypt, &public_key, &want);
    let got = test_ffi
        .key_store
        .get::<DefaultEngine<Rng>>(KeyStoreSecret::Encrypt, &public_key)
        .expect("cannot find stored key");
    assert_eq!(got.id(), want.id());

    Ok(())
}

#[test]
fn test_idam_crypto() -> anyhow::Result<()> {
    let (mut eng, _) = DefaultEngine::<_, DefaultCipherSuite>::from_entropy(Rng);
    let test_key_store = DefaultKeyStore::new();
    let mut test_ffi = IdamCrypto {
        key_store: test_key_store,
    };

    let group_id = Id::default();
    let enc_key = create_enc_key(&mut eng);
    let sign_key = create_sign_key(&mut eng);

    // Byte serializations of public key certificates
    let pub_enc_key = postcard::to_allocvec(&enc_key.public())
        .expect("should be able to obtain exported public key");
    let pub_sign_key = postcard::to_allocvec(&sign_key.public())
        .expect("should be able to obtain exported public key");

    // Insert secret data to KeyStore
    let wrapped_enc_key =
        DefaultEngine::wrap(&mut eng, enc_key).expect("should be able to wrap EncryptionKey");
    test_ffi.key_store.store_key::<DefaultEngine<Rng>>(
        KeyStoreSecret::Encrypt,
        &pub_enc_key,
        &wrapped_enc_key,
    );
    let wrapped_sign_key =
        DefaultEngine::wrap(&mut eng, sign_key).expect("should be able to wrap EncryptionKey");
    test_ffi.key_store.store_key::<DefaultEngine<Rng>>(
        KeyStoreSecret::Sign,
        &pub_sign_key,
        &wrapped_sign_key,
    );

    // Test keyId derivation
    let _enc_key_id = test_ffi
        .encryption_key_id::<DefaultEngine<Rng>>(&pub_enc_key)
        .expect("should derive KeyID for EncryptionPublicKey");
    let _sign_key_id = test_ffi
        .signing_key_id::<DefaultEngine<Rng>>(&pub_sign_key)
        .expect("should derive KeyID for VerifyingKey");

    // Test GroupKey generation
    let group_key = test_ffi
        .generate_group_key(&mut eng)
        .expect("should be able to generate a GroupKey");
    let group_key_wrap = group_key.key_wrap;
    test_ffi.key_store.store_key::<DefaultEngine<Rng>>(
        KeyStoreSecret::Group,
        &pub_enc_key,
        &wrapped_enc_key,
    );

    let mut ctx = CommandContext {
        name: "GroupKey",
        id: Id::default(),
        author: Id::default().into(),
        version: Id::default(),
        engine: &mut eng,
    };

    // Test GroupKey delivery
    let sealed_group_key = test_ffi
        .seal_group_key(&group_key_wrap, &pub_enc_key, group_id, &mut ctx)
        .expect("should be able to seal a GroupKey");
    let unsealed_group_key = test_ffi
        .unseal_group_key(sealed_group_key, &pub_enc_key, group_id, &mut ctx)
        .expect("should be able to unseal a GroupKey");
    assert_eq!(group_key.key_id, unsealed_group_key.key_id);

    // Test message encryption
    let plaintext = "hello";
    let parent_id = group_id;
    let mut ctx = CommandContext {
        name: "Message",
        id: Id::default(),
        author: Id::default().into(),
        version: Id::default(),
        engine: &mut eng,
    };
    let ciphertext = test_ffi
        .encrypt_message(
            plaintext.as_bytes(),
            &group_key_wrap,
            parent_id,
            &pub_sign_key,
            &mut ctx,
        )
        .expect("should be able to encrypt message");
    let message = test_ffi
        .decrypt_message(
            &ciphertext,
            &group_key_wrap,
            parent_id,
            &pub_sign_key,
            &mut ctx,
        )
        .expect("should be able to decrypt message");
    assert_eq!(plaintext.as_bytes(), message);

    Ok(())
}
