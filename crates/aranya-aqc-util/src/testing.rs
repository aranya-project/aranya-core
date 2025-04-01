//! Utilities for testing [`Handler`] and [`Ffi`].

#![cfg(any(test, feature = "testing"))]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::panic)]

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    mem::{self, MaybeUninit},
    ops::Deref,
    result::Result,
};

use aranya_crypto::{
    self,
    engine::WrappedKey,
    keystore::{memstore, Entry, Occupied, Vacant},
    CipherSuite, DeviceId, EncryptionKey, EncryptionKeyId, EncryptionPublicKey, Engine, Id,
    IdentityKey, KeyStore, Rng,
};
use aranya_policy_vm::{ActionContext, CommandContext};
use spin::Mutex;

use crate::{
    ffi::{AqcBidiChannel, AqcUniChannel, Ffi},
    handler::{
        BidiChannelCreated, BidiChannelReceived, Handler, UniChannelCreated, UniChannelReceived,
        UniPsk,
    },
    shared::Label,
};

/// Encodes a [`EncryptionPublicKey`].
fn encode_enc_pk<CS: CipherSuite>(pk: &EncryptionPublicKey<CS>) -> Vec<u8> {
    postcard::to_allocvec(pk).expect("should be able to encode an `EncryptionPublicKey`")
}

/// [`memstore::MemStore`], but wrapped in `Arc<Mutex<..>>`.
#[derive(Clone, Default)]
pub struct MemStore(Arc<MemStoreInner>);

impl MemStore {
    /// Creates a new `MemStore`.
    pub fn new() -> Self {
        Self(Default::default())
    }
}

impl KeyStore for MemStore {
    type Error = memstore::Error;

    type Vacant<'a, T: WrappedKey> = VacantEntry<'a, T>;
    type Occupied<'a, T: WrappedKey> = OccupiedEntry<'a, T>;

    fn entry<T: WrappedKey>(&mut self, id: Id) -> Result<Entry<'_, Self, T>, Self::Error> {
        let entry = match self.0.entry(id)? {
            GuardedEntry::Vacant(v) => Entry::Vacant(VacantEntry(v)),
            GuardedEntry::Occupied(v) => Entry::Occupied(OccupiedEntry(v)),
        };
        Ok(entry)
    }

    fn get<T: WrappedKey>(&self, id: Id) -> Result<Option<T>, Self::Error> {
        match self.0.entry(id)? {
            GuardedEntry::Vacant(_) => Ok(None),
            GuardedEntry::Occupied(v) => Ok(Some(v.get()?)),
        }
    }
}

/// A vacant entry.
pub struct VacantEntry<'a, T>(Guard<'a, memstore::VacantEntry<'a, T>>);

impl<T: WrappedKey> Vacant<T> for VacantEntry<'_, T> {
    type Error = memstore::Error;

    fn insert(self, key: T) -> Result<(), Self::Error> {
        self.0.with_data(|entry| entry.insert(key))
    }
}

/// An occupied entry.
pub struct OccupiedEntry<'a, T>(Guard<'a, memstore::OccupiedEntry<'a, T>>);

impl<T: WrappedKey> Occupied<T> for OccupiedEntry<'_, T> {
    type Error = memstore::Error;

    fn get(&self) -> Result<T, Self::Error> {
        self.0.get()
    }

    fn remove(self) -> Result<T, Self::Error> {
        self.0.with_data(memstore::OccupiedEntry::remove)
    }
}

/// The Totally Not Sketchy impl of [`MemStore`].
#[derive(Default)]
struct MemStoreInner {
    mutex: Mutex<()>,
    store: UnsafeCell<memstore::MemStore>,
}

impl MemStoreInner {
    fn entry<T: WrappedKey>(&self, id: Id) -> Result<GuardedEntry<'_, T>, memstore::Error> {
        mem::forget(self.mutex.lock());

        // SAFETY: we've locked `self.mutex`, so access to
        // `self.store` is exclusive.
        let store = unsafe { &mut *self.store.get() };

        let entry = match store.entry(id)? {
            Entry::Vacant(entry) => {
                let entry = Guard::new(&self.mutex, entry);
                GuardedEntry::Vacant(entry)
            }
            Entry::Occupied(entry) => {
                let entry = Guard::new(&self.mutex, entry);
                GuardedEntry::Occupied(entry)
            }
        };
        Ok(entry)
    }
}

enum GuardedEntry<'a, T> {
    Vacant(Guard<'a, memstore::VacantEntry<'a, T>>),
    Occupied(Guard<'a, memstore::OccupiedEntry<'a, T>>),
}

#[clippy::has_significant_drop]
struct Guard<'a, T> {
    // NB: `mutex` is locked.
    mutex: &'a Mutex<()>,
    data: MaybeUninit<T>,
}

impl<'a, T> Guard<'a, T> {
    const fn new(mutex: &'a Mutex<()>, data: T) -> Self {
        Self {
            mutex,
            data: MaybeUninit::new(data),
        }
    }

    fn with_data<F, R>(mut self, f: F) -> R
    where
        F: FnOnce(T) -> R,
    {
        let data = mem::replace(&mut self.data, MaybeUninit::uninit());
        // SAFETY: `self` was constructed with `new`, which
        // ensures that `self.data` is initialized. This method
        // replaces `data`, but it also consumes `self` which
        // prevents `self.data` from being used twice. The sole
        // exception is `Drop`, but that impl only accesses
        // `self.mutex`.
        f(unsafe { data.assume_init() })
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: we're single threaded, hopefully...
        unsafe { self.mutex.force_unlock() }
    }
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `self` was constructed with `new`, which
        // ensures that `self.data` is initialized.
        unsafe { self.data.assume_init_ref() }
    }
}

/// Test configuration.
pub trait TestImpl: Sized {
    /// The [`Engine`] to use.
    type Engine: Engine;
    /// The [`KeyStore`] to use.
    type Store: KeyStore + Clone;

    /// Configures a device for the test.
    fn new() -> Device<Self>;
}

/// A test device.
pub struct Device<T: TestImpl> {
    eng: T::Engine,
    /// The device's ID.
    device_id: DeviceId,
    /// The device's encryption key ID.
    enc_key_id: EncryptionKeyId,
    /// The device's encoded `EncryptionPublicKey`.
    enc_pk: Vec<u8>,
    /// Makes FFI calls.
    ffi: Ffi<T::Store>,
    /// Handles effects.
    handler: Handler<T::Store>,
}

impl<T: TestImpl> Device<T> {
    /// Creates a new [`Device`].
    pub fn new(mut eng: T::Engine, mut store: T::Store) -> Self {
        let device_id = IdentityKey::<<T::Engine as Engine>::CS>::new(&mut eng)
            .id()
            .expect("device ID should be valid");

        let enc_sk = EncryptionKey::new(&mut eng);
        let enc_key_id = enc_sk.id().expect("encryption key ID should be valid");
        let enc_pk = encode_enc_pk(
            &enc_sk
                .public()
                .expect("encryption public key should be valid"),
        );

        let wrapped = eng
            .wrap(enc_sk)
            .expect("should be able to wrap `EncryptionKey`");
        store
            .try_insert(enc_key_id.into(), wrapped)
            .expect("should be able to insert wrapped `EncryptionKey`");

        Self {
            eng,
            device_id,
            enc_key_id,
            enc_pk,
            ffi: Ffi::new(store.clone()),
            handler: Handler::new(device_id, store),
        }
    }
}

/// Performs all of the tests in this module.
///
/// # Example
///
/// ```rust
///
/// use aranya_aqc_util::testing::{test_all, MemStore, TestImpl, Device};
/// use aranya_crypto::{
///     default::{DefaultCipherSuite, DefaultEngine},
///     Rng,
/// };
///
/// struct DefaultImpl;
///
/// impl TestImpl for DefaultImpl {
///     type Engine = DefaultEngine<Rng, DefaultCipherSuite>;
///     type Store = MemStore;
///
///     fn new() -> Device<Self> {
///         let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
///         let store = MemStore::new();
///         Device::new(eng, store)
///     }
/// }
///
/// test_all!(default_engine, DefaultImpl);
/// ```
#[macro_export]
macro_rules! test_all {
    ($name:ident, $impl:ty) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            macro_rules! test {
                ($test:ident) => {
                    #[test]
                    fn $test() {
                        $crate::testing::$test::<$impl>();
                    }
                };
            }

            test!(test_create_bidi_channel);
            test!(test_create_seal_only_uni_channel);
            test!(test_create_open_only_uni_channel);
        }
    };
}
pub use test_all;

/// A basic positive test for creating a bidirectional channel.
pub fn test_create_bidi_channel<T: TestImpl>() {
    let mut author = T::new();
    let mut peer = T::new();

    let label = Label::new(42);
    let parent_cmd_id = Id::random(&mut Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: "CreateBidiChannel",
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AqcBidiChannel { peer_encap, key_id } = author
        .ffi
        .create_bidi_channel(
            &ctx,
            &mut author.eng,
            parent_cmd_id,
            author.enc_key_id,
            author.device_id,
            peer.enc_pk.clone(),
            peer.device_id,
            label,
        )
        .expect("author should be able to create a bidi channel");

    // This is called by the author of the channel after
    // receiving the effect.
    let author_psk = author
        .handler
        .bidi_channel_created(
            &mut author.eng,
            &BidiChannelCreated {
                psk_length_in_bytes: 32,
                parent_cmd_id,
                author_id: author.device_id,
                author_enc_key_id: author.enc_key_id,
                peer_id: peer.device_id,
                peer_enc_pk: &peer.enc_pk,
                label,
                key_id: key_id.into(),
            },
        )
        .expect("author should be able to load bidi PSK");

    // This is called by the channel peer after receiving the
    // effect.
    let peer_psk = peer
        .handler
        .bidi_channel_received(
            &mut peer.eng,
            &BidiChannelReceived {
                psk_length_in_bytes: 32,
                parent_cmd_id,
                author_id: author.device_id,
                author_enc_pk: &author.enc_pk,
                peer_id: peer.device_id,
                peer_enc_key_id: peer.enc_key_id,
                label,
                encap: &peer_encap,
            },
        )
        .expect("peer should be able to load bidi keys");

    assert_eq!(author_psk.identity(), peer_psk.identity());
    assert_eq!(author_psk.raw_secret_bytes(), peer_psk.raw_secret_bytes());
}

/// A basic positive test for creating a unidirectional channel
/// where the author is seal-only.
pub fn test_create_seal_only_uni_channel<T: TestImpl>() {
    let mut author = T::new();
    let mut peer = T::new();

    let label = Label::new(42);
    let parent_cmd_id = Id::random(&mut Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: "CreateSendOnlyChannel",
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AqcUniChannel { peer_encap, key_id } = author
        .ffi
        .create_uni_channel(
            &ctx,
            &mut author.eng,
            parent_cmd_id,
            author.enc_key_id,
            peer.enc_pk.clone(),
            author.device_id,
            peer.device_id,
            label,
        )
        .expect("author should be able to create a uni channel");

    // This is called by the author of the channel after
    // receiving the effect.
    let author_psk = author
        .handler
        .uni_channel_created(
            &mut author.eng,
            &UniChannelCreated {
                psk_length_in_bytes: 32,
                parent_cmd_id,
                author_id: author.device_id,
                send_id: author.device_id,
                recv_id: peer.device_id,
                author_enc_key_id: author.enc_key_id,
                peer_enc_pk: &peer.enc_pk,
                label,
                key_id: key_id.into(),
            },
        )
        .expect("author should be able to load encryption key");
    assert!(matches!(author_psk, UniPsk::SendOnly(_)));

    // This is called by the channel peer after receiving the
    // effect.
    let peer_psk = peer
        .handler
        .uni_channel_received(
            &mut peer.eng,
            &UniChannelReceived {
                psk_length_in_bytes: 32,
                parent_cmd_id,
                author_id: author.device_id,
                send_id: author.device_id,
                recv_id: peer.device_id,
                author_enc_pk: &author.enc_pk,
                peer_enc_key_id: peer.enc_key_id,
                label,
                encap: &peer_encap,
            },
        )
        .expect("peer should be able to load decryption key");
    assert!(matches!(peer_psk, UniPsk::RecvOnly(_)));

    assert_eq!(author_psk.identity(), peer_psk.identity());
    assert_eq!(author_psk.raw_secret_bytes(), peer_psk.raw_secret_bytes());
}

/// A basic positive test for creating a unidirectional channel
/// where the author is open only.
pub fn test_create_open_only_uni_channel<T: TestImpl>() {
    let mut author = T::new(); // open only
    let mut peer = T::new(); // seal only

    let label = Label::new(42);
    let parent_cmd_id = Id::random(&mut Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: "CreateUniOnlyChannel",
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AqcUniChannel { peer_encap, key_id } = author
        .ffi
        .create_uni_channel(
            &ctx,
            &mut author.eng,
            parent_cmd_id,
            author.enc_key_id,
            peer.enc_pk.clone(),
            author.device_id,
            peer.device_id,
            label,
        )
        .expect("author should be able to create a uni channel");

    // This is called by the author of the channel after
    // receiving the effect.
    let author_psk = author
        .handler
        .uni_channel_created(
            &mut author.eng,
            &UniChannelCreated {
                psk_length_in_bytes: 32,
                parent_cmd_id,
                author_id: author.device_id,
                send_id: peer.device_id,
                recv_id: author.device_id,
                author_enc_key_id: author.enc_key_id,
                peer_enc_pk: &peer.enc_pk,
                label,
                key_id: key_id.into(),
            },
        )
        .expect("author should be able to load decryption key");
    assert!(matches!(author_psk, UniPsk::RecvOnly(_)));

    // This is called by the channel peer after receiving the
    // effect.
    let peer_psk = peer
        .handler
        .uni_channel_received(
            &mut peer.eng,
            &UniChannelReceived {
                psk_length_in_bytes: 32,
                parent_cmd_id,
                author_id: author.device_id,
                send_id: peer.device_id,
                recv_id: author.device_id,
                author_enc_pk: &author.enc_pk,
                peer_enc_key_id: peer.enc_key_id,
                label,
                encap: &peer_encap,
            },
        )
        .expect("peer should be able to load encryption key");
    assert!(matches!(peer_psk, UniPsk::SendOnly(_)));

    assert_eq!(author_psk.identity(), peer_psk.identity());
    assert_eq!(author_psk.raw_secret_bytes(), peer_psk.raw_secret_bytes());
}
