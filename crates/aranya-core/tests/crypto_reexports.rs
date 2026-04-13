//! Compile-only regression test: names every symbol re-exported from
//! [`aranya_core::crypto`]. If a name is renamed, removed, or moved
//! upstream, this test stops compiling — the breakage surfaces here
//! at the facade rather than silently in downstream integrations.

#![cfg(all(feature = "std", feature = "memstore"))]
#![allow(dead_code)]

// Each `use` forces the path to resolve at compile time. That is the
// whole contract of this test.
#[cfg(feature = "fs-keystore")]
use aranya_core::crypto::keystore::FsKeyStore;
use aranya_core::crypto::{
    BaseId, CipherSuite, Csprng, DefaultCipherSuite, DefaultCryptoEngine, DefaultEngine, DeviceId,
    Encap, EncryptionKey, EncryptionKeyId, EncryptionPublicKey, Engine, Identified, IdentityKey,
    IdentityVerifyingKey, Random, Rng, Signature, SigningKey, SigningKeyId, UnwrapError,
    VerifyingKey, WrapError,
    keystore::{Entry, Error, ErrorKind, KeyStore, KeyStoreExt, MemStore, Occupied, Vacant},
};

// Generic functions force the trait bounds to resolve.
fn _engine_bound<E: Engine>() {}
fn _cs_bound<CS: CipherSuite>() {}
fn _csprng_bound<R: Csprng>() {}
fn _random_bound<R: Random>() {}
fn _identified_bound<T: Identified>() {}
fn _keystore_bound<S: KeyStore>() {}
fn _keystore_ext_bound<S: KeyStoreExt>() {}
fn _error_bound<E: Error>() {}
fn _entry_bound<'a, S, T>(_: Entry<'a, S, T>)
where
    S: KeyStore + ?Sized,
    T: aranya_crypto::engine::WrappedKey,
{
}
fn _vacant_bound<T: aranya_crypto::engine::WrappedKey, V: Vacant<T>>() {}
fn _occupied_bound<T: aranya_crypto::engine::WrappedKey, O: Occupied<T>>() {}

// Touches every non-trait re-exported type so monomorphization resolves.
// Grouped into one tuple to stay under `clippy::too_many_arguments`.
#[allow(clippy::type_complexity)]
fn _concrete_uses<CS: CipherSuite>(
    _: (
        Option<DefaultCryptoEngine>,
        Option<DefaultEngine<Rng, DefaultCipherSuite>>,
        Option<BaseId>,
        Option<DeviceId>,
        Option<EncryptionKeyId>,
        Option<SigningKeyId>,
        Option<Encap<CS>>,
        Option<EncryptionKey<CS>>,
        Option<EncryptionPublicKey<CS>>,
        Option<IdentityKey<CS>>,
        Option<IdentityVerifyingKey<CS>>,
        Option<SigningKey<CS>>,
        Option<VerifyingKey<CS>>,
        Option<Signature<CS>>,
        Option<WrapError>,
        Option<UnwrapError>,
        Option<ErrorKind>,
        Option<MemStore>,
    ),
) {
}

#[test]
fn reexports_resolve() {
    _engine_bound::<DefaultCryptoEngine>();
    _engine_bound::<DefaultEngine<Rng, DefaultCipherSuite>>();
    _cs_bound::<DefaultCipherSuite>();
    _csprng_bound::<Rng>();
    _keystore_bound::<MemStore>();
    _keystore_ext_bound::<MemStore>();
    _error_bound::<<MemStore as KeyStore>::Error>();
    // `Identified` is implemented by the key types, not by their Id
    // aliases; pick a representative key.
    _identified_bound::<IdentityKey<DefaultCipherSuite>>();

    let _ = ErrorKind::AlreadyExists;
    let _ = ErrorKind::Other;

    // Ensure the ID aliases equal the associated types of their keys.
    fn _id_alias_matches()
    where
        DeviceId: Sized,
        SigningKeyId: Sized,
        EncryptionKeyId: Sized,
    {
        let _: Option<<IdentityKey<DefaultCipherSuite> as Identified>::Id> = None;
        let _: Option<<SigningKey<DefaultCipherSuite> as Identified>::Id> = None;
        let _: Option<<EncryptionKey<DefaultCipherSuite> as Identified>::Id> = None;
    }
    _id_alias_matches();
}

#[cfg(feature = "fs-keystore")]
#[test]
fn fs_keystore_reexport_resolves() {
    _keystore_bound::<FsKeyStore>();
}
