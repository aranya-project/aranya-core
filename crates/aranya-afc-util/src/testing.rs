//! Utilities for testing [`Handler`] and [`Ffi`].

#![cfg(any(test, feature = "testing"))]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::panic)]

extern crate alloc;

use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    cell::UnsafeCell,
    hash::BuildHasherDefault,
    mem::{self, MaybeUninit},
    ops::Deref,
    result::Result,
};

use aranya_crypto::{
    afc::{
        BidiAuthorSecret, BidiChannel, BidiPeerEncap, UniAuthorSecret, UniChannel, UniPeerEncap,
    },
    engine::WrappedKey,
    keystore::{memstore, Entry, Occupied, Vacant},
    CipherSuite, DeviceId, EncryptionKey, EncryptionKeyId, EncryptionPublicKey, Engine, Id,
    IdentityKey, KeyStore, Rng,
};
use aranya_fast_channels::{self, AfcState, AranyaState, ChannelId, Client, Label, NodeId};
use aranya_policy_vm::{ActionContext, CommandContext};
use indexmap::IndexSet;
use siphasher::sip::SipHasher13;
use spin::Mutex;

use crate::{
    ffi::{AfcBidiChannel, AfcUniChannel, Ffi},
    handler::{
        BidiChannelCreated, BidiChannelReceived, Handler, UniChannelCreated, UniChannelReceived,
        UniKey,
    },
    transform::Transform,
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
    /// The [`AfcState`] to use.
    type Afc: AfcState<CipherSuite = <Self::Engine as Engine>::CS>;
    /// The [`AranyaState`] to use.
    type Aranya: AranyaState<CipherSuite = <Self::Engine as Engine>::CS>;
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
    /// AFC encryption/decryption client.
    afc_client: Client<T::Afc>,
    /// Aranya's view of the shared state.
    afc_state: T::Aranya,
    /// Maps `DeviceId`s to `NodeId`s.
    mapping: IndexSet<DeviceId, BuildHasherDefault<SipHasher13>>,
}

impl<T: TestImpl> Device<T> {
    /// Creates a new [`Device`].
    pub fn new(mut eng: T::Engine, afc: T::Afc, aranya: T::Aranya, mut store: T::Store) -> Self {
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
            .try_insert(enc_key_id.into_id(), wrapped)
            .expect("should be able to insert wrapped `EncryptionKey`");

        Self {
            eng,
            device_id,
            enc_key_id,
            enc_pk,
            ffi: Ffi::new(store.clone()),
            handler: Handler::new(device_id, store),
            afc_client: Client::new(afc),
            afc_state: aranya,
            mapping: Default::default(),
        }
    }

    fn lookup(&mut self, id: DeviceId) -> NodeId {
        let (idx, _) = self.mapping.insert_full(id);
        NodeId::new(u32::try_from(idx).expect("`idx` out of range"))
    }

    /// Tests that `opener` can decrypt what `sealer` encrypts.
    fn test_roundtrip(sealer: &mut Self, opener: &mut Self, label: Label) {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let opener_node_id = sealer.lookup(opener.device_id);
            let id = ChannelId::new(opener_node_id, label);
            let mut dst = vec![0u8; GOLDEN.len() + Client::<T::Afc>::OVERHEAD];
            sealer
                .afc_client
                .seal(id, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({id}, ...): {err}"));
            dst
        };
        let (plaintext, got_label, got_seq) = {
            let sealer_node_id = opener.lookup(sealer.device_id);
            let mut dst = vec![0u8; ciphertext.len() - Client::<T::Afc>::OVERHEAD];
            let (label, seq) = opener
                .afc_client
                .open(sealer_node_id, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("open({sealer_node_id}, ...): {err}"));
            (dst, label, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes());
        assert_eq!(got_label, label);
        assert_eq!(got_seq, 0);
    }

    /// Tests the case where `label` has not been assigned to
    /// `sealer`.
    fn test_bad_label(sealer: &mut Self, opener: &mut Self, label: Label) {
        const GOLDEN: &str = "hello, world!";
        let opener_node_id = sealer.lookup(opener.device_id);
        let id = ChannelId::new(opener_node_id, label);
        let mut dst = vec![0u8; GOLDEN.len() + Client::<T::Afc>::OVERHEAD];
        let err = sealer
            .afc_client
            .seal(id, &mut dst[..], GOLDEN.as_bytes())
            .expect_err("should have failed");
        assert_eq!(err, aranya_fast_channels::Error::NotFound(id));
    }

    /// Tests the case where `label` has not been assigned to
    /// `sealer`.
    fn test_wrong_direction(sealer: &mut Self, opener: &mut Self, label: Label) {
        const GOLDEN: &str = "hello, world!";
        let opener_node_id = sealer.lookup(opener.device_id);
        let id = ChannelId::new(opener_node_id, label);
        let mut dst = vec![0u8; GOLDEN.len() + Client::<T::Afc>::OVERHEAD];
        let err = sealer
            .afc_client
            .seal(id, &mut dst[..], GOLDEN.as_bytes())
            .expect_err("should have failed");
        assert_eq!(err, aranya_fast_channels::Error::NotFound(id));
    }
}

/// Performs all of the tests in this module.
///
/// # Example
///
/// ```rust
///
/// use aranya_fast_channels::memory::State;
/// use aranya_afc_util::testing::{test_all, MemStore, TestImpl, Device};
/// use aranya_crypto::{
///     default::{DefaultCipherSuite, DefaultEngine},
///     Rng,
/// };
///
/// struct DefaultImpl;
///
/// impl TestImpl for DefaultImpl {
///     type Engine = DefaultEngine<Rng, DefaultCipherSuite>;
///     type Afc = State<DefaultCipherSuite>;
///     type Aranya = State<DefaultCipherSuite>;
///     type Store = MemStore;
///
///     fn new() -> Device<Self> {
///         let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
///         let afc = State::new();
///         let aranya = afc.clone();
///         let store = MemStore::new();
///         Device::new(eng, afc, aranya, store)
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
pub fn test_create_bidi_channel<T: TestImpl>()
where
    (
        <<T as TestImpl>::Aranya as AranyaState>::SealKey,
        <<T as TestImpl>::Aranya as AranyaState>::OpenKey,
    ): for<'a> Transform<(
        &'a BidiChannel<'a, <T::Engine as Engine>::CS>,
        BidiAuthorSecret<<T::Engine as Engine>::CS>,
    )>,
    (
        <<T as TestImpl>::Aranya as AranyaState>::SealKey,
        <<T as TestImpl>::Aranya as AranyaState>::OpenKey,
    ): for<'a> Transform<(
        &'a BidiChannel<'a, <T::Engine as Engine>::CS>,
        BidiPeerEncap<<T::Engine as Engine>::CS>,
    )>,
{
    let mut author = T::new();
    let mut peer = T::new();

    let label = Label::new(42);
    let parent_cmd_id = Id::random(&mut Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: "CreateBidiChannel",
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AfcBidiChannel { peer_encap, key_id } = author
        .ffi
        .create_bidi_channel(
            &ctx,
            &mut author.eng,
            parent_cmd_id,
            author.enc_key_id,
            author.device_id,
            peer.enc_pk.clone(),
            peer.device_id,
            label.into(),
        )
        .expect("author should be able to create a bidi channel");

    // This is called by the author of the channel after
    // receiving the effect.
    {
        let keys = author
            .handler
            .bidi_channel_created(
                &mut author.eng,
                &BidiChannelCreated {
                    parent_cmd_id,
                    author_id: author.device_id,
                    author_enc_key_id: author.enc_key_id,
                    peer_id: peer.device_id,
                    peer_enc_pk: &peer.enc_pk,
                    label,
                    key_id: key_id.into(),
                },
            )
            .expect("author should be able to load bidi keys");

        let peer_node_id = author.lookup(peer.device_id);
        let id = ChannelId::new(peer_node_id, label);
        author
            .afc_state
            .add(id, keys.into())
            .expect("author should be able to add channel");
    }

    // This is called by the channel peer after receiving the
    // effect.
    {
        let keys = peer
            .handler
            .bidi_channel_received(
                &mut peer.eng,
                &BidiChannelReceived {
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

        let author_node_id = peer.lookup(author.device_id);
        let id = ChannelId::new(author_node_id, label);
        peer.afc_state
            .add(id, keys.into())
            .expect("peer should be able to add channel");
    }

    Device::test_roundtrip(&mut author, &mut peer, label);
    Device::test_roundtrip(&mut peer, &mut author, label);

    Device::test_bad_label(&mut author, &mut peer, Label::new(123));
    Device::test_bad_label(&mut peer, &mut author, Label::new(123));
}

/// A basic positive test for creating a unidirectional channel
/// where the author is seal-only.
pub fn test_create_seal_only_uni_channel<T: TestImpl>()
where
    <T::Aranya as AranyaState>::SealKey: for<'a> Transform<(
        &'a UniChannel<'a, <T::Engine as Engine>::CS>,
        UniAuthorSecret<<T::Engine as Engine>::CS>,
    )>,
    <T::Aranya as AranyaState>::OpenKey: for<'a> Transform<(
        &'a UniChannel<'a, <T::Engine as Engine>::CS>,
        UniAuthorSecret<<T::Engine as Engine>::CS>,
    )>,
    <T::Aranya as AranyaState>::SealKey: for<'a> Transform<(
        &'a UniChannel<'a, <T::Engine as Engine>::CS>,
        UniPeerEncap<<T::Engine as Engine>::CS>,
    )>,
    <T::Aranya as AranyaState>::OpenKey: for<'a> Transform<(
        &'a UniChannel<'a, <T::Engine as Engine>::CS>,
        UniPeerEncap<<T::Engine as Engine>::CS>,
    )>,
{
    let mut author = T::new();
    let mut peer = T::new();

    let label = Label::new(42);
    let parent_cmd_id = Id::random(&mut Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: "CreateSealOnlyChannel",
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AfcUniChannel { peer_encap, key_id } = author
        .ffi
        .create_uni_channel(
            &ctx,
            &mut author.eng,
            parent_cmd_id,
            author.enc_key_id,
            peer.enc_pk.clone(),
            author.device_id,
            peer.device_id,
            label.into(),
        )
        .expect("author should be able to create a uni channel");

    // This is called by the author of the channel after
    // receiving the effect.
    {
        let keys = author
            .handler
            .uni_channel_created(
                &mut author.eng,
                &UniChannelCreated {
                    parent_cmd_id,
                    author_id: author.device_id,
                    seal_id: author.device_id,
                    open_id: peer.device_id,
                    author_enc_key_id: author.enc_key_id,
                    peer_enc_pk: &peer.enc_pk,
                    label,
                    key_id: key_id.into(),
                },
            )
            .expect("author should be able to load encryption key");
        assert!(matches!(keys, UniKey::SealOnly(_)));

        let peer_node_id = author.lookup(peer.device_id);
        let id = ChannelId::new(peer_node_id, label);
        author
            .afc_state
            .add(id, keys.into())
            .expect("author should be able to add channel");
    }

    // This is called by the channel peer after receiving the
    // effect.
    {
        let keys = peer
            .handler
            .uni_channel_received(
                &mut peer.eng,
                &UniChannelReceived {
                    parent_cmd_id,
                    author_id: author.device_id,
                    seal_id: author.device_id,
                    open_id: peer.device_id,
                    author_enc_pk: &author.enc_pk,
                    peer_enc_key_id: peer.enc_key_id,
                    label,
                    encap: &peer_encap,
                },
            )
            .expect("peer should be able to load decryption key");
        assert!(matches!(keys, UniKey::OpenOnly(_)));

        let author_node_id = peer.lookup(author.device_id);
        let id = ChannelId::new(author_node_id, label);
        peer.afc_state
            .add(id, keys.into())
            .expect("peer should be able to add channel");
    }

    Device::test_roundtrip(&mut author, &mut peer, label);
    Device::test_bad_label(&mut author, &mut peer, Label::new(123));
    Device::test_wrong_direction(&mut peer, &mut author, label);
}

/// A basic positive test for creating a unidirectional channel
/// where the author is open only.
pub fn test_create_open_only_uni_channel<T: TestImpl>()
where
    <T::Aranya as AranyaState>::SealKey: for<'a> Transform<(
        &'a UniChannel<'a, <T::Engine as Engine>::CS>,
        UniAuthorSecret<<T::Engine as Engine>::CS>,
    )>,
    <T::Aranya as AranyaState>::OpenKey: for<'a> Transform<(
        &'a UniChannel<'a, <T::Engine as Engine>::CS>,
        UniAuthorSecret<<T::Engine as Engine>::CS>,
    )>,
    <T::Aranya as AranyaState>::SealKey: for<'a> Transform<(
        &'a UniChannel<'a, <T::Engine as Engine>::CS>,
        UniPeerEncap<<T::Engine as Engine>::CS>,
    )>,
    <T::Aranya as AranyaState>::OpenKey: for<'a> Transform<(
        &'a UniChannel<'a, <T::Engine as Engine>::CS>,
        UniPeerEncap<<T::Engine as Engine>::CS>,
    )>,
{
    let mut author = T::new(); // open only
    let mut peer = T::new(); // seal only

    let label = Label::new(42);
    let parent_cmd_id = Id::random(&mut Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: "CreateUniOnlyChannel",
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AfcUniChannel { peer_encap, key_id } = author
        .ffi
        .create_uni_channel(
            &ctx,
            &mut author.eng,
            parent_cmd_id,
            author.enc_key_id,
            peer.enc_pk.clone(),
            author.device_id,
            peer.device_id,
            label.into(),
        )
        .expect("author should be able to create a uni channel");

    // This is called by the author of the channel after
    // receiving the effect.
    {
        let keys = author
            .handler
            .uni_channel_created(
                &mut author.eng,
                &UniChannelCreated {
                    parent_cmd_id,
                    author_id: author.device_id,
                    seal_id: peer.device_id,
                    open_id: author.device_id,
                    author_enc_key_id: author.enc_key_id,
                    peer_enc_pk: &peer.enc_pk,
                    label,
                    key_id: key_id.into(),
                },
            )
            .expect("author should be able to load decryption key");
        assert!(matches!(keys, UniKey::OpenOnly(_)));

        let peer_node_id = author.lookup(peer.device_id);
        let id = ChannelId::new(peer_node_id, label);
        author
            .afc_state
            .add(id, keys.into())
            .expect("author should be able to add channel");
    }

    // This is called by the channel peer after receiving the
    // effect.
    {
        let keys = peer
            .handler
            .uni_channel_received(
                &mut peer.eng,
                &UniChannelReceived {
                    parent_cmd_id,
                    author_id: author.device_id,
                    seal_id: peer.device_id,
                    open_id: author.device_id,
                    author_enc_pk: &author.enc_pk,
                    peer_enc_key_id: peer.enc_key_id,
                    label,
                    encap: &peer_encap,
                },
            )
            .expect("peer should be able to load encryption key");
        assert!(matches!(keys, UniKey::SealOnly(_)));

        let author_node_id = peer.lookup(author.device_id);
        let id = ChannelId::new(author_node_id, label);
        peer.afc_state
            .add(id, keys.into())
            .expect("peer should be able to add channel");
    }

    Device::test_roundtrip(&mut peer, &mut author, label);
    Device::test_bad_label(&mut peer, &mut author, Label::new(123));
    Device::test_wrong_direction(&mut author, &mut peer, label);
}
