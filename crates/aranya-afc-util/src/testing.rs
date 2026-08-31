//! Utilities for testing [`Handler`] and [`Ffi`].

#![cfg(any(test, feature = "testing"))]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::panic)]

extern crate alloc;

use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    cell::UnsafeCell,
    mem::{self, MaybeUninit},
    ops::Deref,
    result::Result,
};

use aranya_crypto::{
    BaseId, CipherSuite, DeviceId, EncryptionKey, EncryptionKeyId, EncryptionPublicKey, Engine,
    IdentityKey, KeyStore, KeyStoreExt as _, Rng,
    afc::{UniAuthorSecret, UniChannel, UniPeerEncap},
    engine::WrappedKey,
    id::IdExt as _,
    keystore::{Entry, Occupied, Vacant, memstore},
    policy::{CmdId, LabelId},
};
use aranya_fast_channels::{self, AfcState, AranyaState, Client, LocalChannelId};
use aranya_policy_vm::{ActionContext, CommandContext, ident};
use spin::Mutex;

use crate::{
    ffi::{AfcUniChannel, Ffi, FfiError},
    handler::{
        Error as EffectHandlerError, Handler, UniChannelCreated, UniChannelReceived, UniKey,
    },
    replay::{MemStore as ReplayMemStore, ReplayStore, Verdict},
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

    fn entry<T: WrappedKey>(&mut self, id: BaseId) -> Result<Entry<'_, Self, T>, Self::Error> {
        let entry = match self.0.entry(id)? {
            GuardedEntry::Vacant(v) => Entry::Vacant(VacantEntry(v)),
            GuardedEntry::Occupied(v) => Entry::Occupied(OccupiedEntry(v)),
        };
        Ok(entry)
    }

    fn get<T: WrappedKey>(&self, id: BaseId) -> Result<Option<T>, Self::Error> {
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
    fn entry<T: WrappedKey>(&self, id: BaseId) -> Result<GuardedEntry<'_, T>, memstore::Error> {
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
    /// The graph this device participates in.
    graph: BaseId,
    /// Receiver-side replay protection.
    replay: ReplayMemStore,
    /// The device's encryption key (also in `store`).
    #[cfg_attr(not(any(test, feature = "std")), allow(dead_code))]
    enc_sk: EncryptionKey<<T::Engine as Engine>::CS>,
    /// The device's keystore.
    #[cfg_attr(not(any(test, feature = "std")), allow(dead_code))]
    store: T::Store,
}

impl<T: TestImpl> Device<T> {
    /// Creates a new [`Device`].
    pub fn new(eng: T::Engine, afc: T::Afc, aranya: T::Aranya, mut store: T::Store) -> Self {
        let device_id = IdentityKey::<<T::Engine as Engine>::CS>::new(&eng)
            .id()
            .expect("device ID should be valid");

        let enc_sk = EncryptionKey::new(&eng);
        let enc_pk = encode_enc_pk(
            &enc_sk
                .public()
                .expect("encryption public key should be valid"),
        );

        let enc_key_id = store
            .insert_key(&eng, enc_sk.clone())
            .expect("should be able to insert wrapped `EncryptionKey`");

        Self {
            device_id,
            enc_key_id,
            enc_pk,
            ffi: Ffi::new(store.clone()),
            handler: Handler::new(device_id, store.clone()),
            afc_client: Client::new(afc),
            afc_state: aranya,
            graph: BaseId::random(Rng),
            replay: ReplayMemStore::new(),
            enc_sk,
            store,
            eng,
        }
    }

    /// Creates a unidirectional channel from `self` to `peer` via
    /// the FFI, returning the effect data the peer would receive.
    fn create_uni_channel(&self, peer: &Self, label_id: LabelId, epoch: u64) -> CreatedChannel {
        let parent_cmd_id = CmdId::random(Rng);
        let ctx = CommandContext::Action(ActionContext {
            name: ident!("CreateUniChannel"),
            head_id: parent_cmd_id,
        });
        let AfcUniChannel { peer_encap, key_id } = self
            .ffi
            .create_uni_channel(
                &ctx,
                &self.eng,
                parent_cmd_id,
                self.enc_key_id,
                peer.enc_pk.clone(),
                self.device_id,
                peer.device_id,
                label_id,
                i64::try_from(epoch).expect("epoch should fit in i64"),
            )
            .expect("author should be able to create a uni channel");
        CreatedChannel {
            parent_cmd_id,
            label_id,
            epoch,
            cmd_id: CmdId::random(Rng),
            peer_encap,
            key_id,
        }
    }

    /// Handles the `AfcUniChannelCreated` effect for `ch` and
    /// installs the resulting seal key.
    fn install_created(&mut self, peer: &Self, ch: &CreatedChannel) -> LocalChannelId
    where
        <T::Aranya as AranyaState>::SealKey: for<'a> Transform<(
            &'a UniChannel<'a, <T::Engine as Engine>::CS>,
            UniAuthorSecret<<T::Engine as Engine>::CS>,
        )>,
        <T::Aranya as AranyaState>::OpenKey: for<'a> Transform<(
            &'a UniChannel<'a, <T::Engine as Engine>::CS>,
            UniAuthorSecret<<T::Engine as Engine>::CS>,
        )>,
    {
        let keys = self
            .handler
            .uni_channel_created(
                &self.eng,
                &UniChannelCreated {
                    parent_cmd_id: ch.parent_cmd_id,
                    open_id: peer.device_id,
                    author_enc_key_id: self.enc_key_id,
                    peer_enc_pk: &peer.enc_pk,
                    label_id: ch.label_id,
                    key_id: ch.key_id.into(),
                    epoch: ch.epoch,
                },
            )
            .expect("author should be able to load encryption key");
        assert!(matches!(keys, UniKey::SealOnly(_)));
        self.afc_state
            .add(keys.into(), ch.label_id, peer.device_id)
            .expect("author should be able to add channel")
    }

    /// Handles the `AfcUniChannelReceived` effect for `ch` with
    /// `replay`, without installing the key.
    #[allow(clippy::type_complexity)]
    fn receive<R: ReplayStore>(
        &mut self,
        author: &Self,
        ch: &CreatedChannel,
        replay: &mut R,
    ) -> Result<
        UniKey<<T::Aranya as AranyaState>::SealKey, <T::Aranya as AranyaState>::OpenKey>,
        EffectHandlerError,
    >
    where
        <T::Aranya as AranyaState>::SealKey: for<'a> Transform<(
            &'a UniChannel<'a, <T::Engine as Engine>::CS>,
            UniPeerEncap<<T::Engine as Engine>::CS>,
        )>,
        <T::Aranya as AranyaState>::OpenKey: for<'a> Transform<(
            &'a UniChannel<'a, <T::Engine as Engine>::CS>,
            UniPeerEncap<<T::Engine as Engine>::CS>,
        )>,
    {
        let graph = self.graph;
        self.handler.uni_channel_received(
            &self.eng,
            replay,
            graph,
            &UniChannelReceived {
                parent_cmd_id: ch.parent_cmd_id,
                seal_id: author.device_id,
                author_enc_pk: &author.enc_pk,
                peer_enc_key_id: self.enc_key_id,
                label_id: ch.label_id,
                encap: &ch.peer_encap,
                epoch: ch.epoch,
                cmd_id: ch.cmd_id,
            },
        )
    }

    /// Handles the `AfcUniChannelReceived` effect for `ch` with
    /// this device's own replay store and installs the resulting
    /// open key.
    fn install_received(&mut self, author: &Self, ch: &CreatedChannel) -> LocalChannelId
    where
        <T::Aranya as AranyaState>::SealKey: for<'a> Transform<(
            &'a UniChannel<'a, <T::Engine as Engine>::CS>,
            UniPeerEncap<<T::Engine as Engine>::CS>,
        )>,
        <T::Aranya as AranyaState>::OpenKey: for<'a> Transform<(
            &'a UniChannel<'a, <T::Engine as Engine>::CS>,
            UniPeerEncap<<T::Engine as Engine>::CS>,
        )>,
    {
        let mut replay = self.replay.clone();
        let keys = self
            .receive(author, ch, &mut replay)
            .expect("peer should be able to load decryption key");
        assert!(matches!(keys, UniKey::OpenOnly(_)));
        self.afc_state
            .add(keys.into(), ch.label_id, author.device_id)
            .expect("peer should be able to add channel")
    }

    /// Tests that `opener` can decrypt what `sealer` encrypts.
    fn test_roundtrip(sealer: (&mut Self, LocalChannelId), opener: (&mut Self, LocalChannelId)) {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let (sealer, chan_id) = sealer;
            let mut dst = vec![0u8; GOLDEN.len() + Client::<T::Afc>::OVERHEAD];
            let mut ctx = sealer
                .afc_client
                .setup_seal_ctx(chan_id)
                .expect("can set up ctx");
            sealer
                .afc_client
                .seal(&mut ctx, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({chan_id}, ...): {err}"));
            dst
        };
        let (plaintext, got_seq) = {
            let (opener, chan_id) = opener;
            let mut dst = vec![0u8; ciphertext.len() - Client::<T::Afc>::OVERHEAD];
            let mut open_ctx = opener
                .afc_client
                .setup_open_ctx(chan_id)
                .expect("can set up ctx");
            let (_, seq) = opener
                .afc_client
                .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("open({chan_id}, ...): {err}"));
            (dst, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes());
        assert_eq!(got_seq, 0);
    }

    /// Tests the case where `label` has not been assigned to
    /// `sealer`.
    fn test_wrong_direction(sealer: &mut Self, channel_id: LocalChannelId) {
        let err = sealer
            .afc_client
            .setup_seal_ctx(channel_id)
            .map(|_| ())
            .expect_err("should have failed");
        assert_eq!(err, aranya_fast_channels::Error::NotFound(channel_id));
    }
}

/// The result of creating a channel via the FFI, plus the fields
/// the policy would place in the resulting effects.
struct CreatedChannel {
    parent_cmd_id: CmdId,
    label_id: LabelId,
    epoch: u64,
    /// The ID of the (ephemeral) control command.
    cmd_id: CmdId,
    peer_encap: Vec<u8>,
    key_id: BaseId,
}

/// A [`ReplayStore`] that always fails.
struct FailingStore;

#[derive(Debug, thiserror::Error)]
#[error("replay store is unavailable")]
struct FailingStoreError;

impl ReplayStore for FailingStore {
    type Error = FailingStoreError;

    fn accept(
        &mut self,
        _graph: BaseId,
        _sender: DeviceId,
        _epoch: u64,
        _nonce: CmdId,
    ) -> Result<Verdict, Self::Error> {
        Err(FailingStoreError)
    }

    fn raise_floor(
        &mut self,
        _graph: BaseId,
        _sender: DeviceId,
        _epoch: u64,
    ) -> Result<(), Self::Error> {
        Err(FailingStoreError)
    }
}

/// Performs all of the tests in this module.
///
/// # Example
///
/// ```rust
/// use aranya_afc_util::testing::{Device, MemStore, TestImpl, test_all};
/// use aranya_crypto::{
///     Rng,
///     default::{DefaultCipherSuite, DefaultEngine},
/// };
/// use aranya_fast_channels::memory::State;
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

            test!(test_create_seal_only_uni_channel);
            test!(test_create_open_only_uni_channel);
            test!(test_receive_seal_only_uni_channel);
            test!(test_create_uni_channel_negative_epoch);
            test!(test_receive_replayed_uni_channel);
            test!(test_receive_stale_epoch_uni_channel);
            test!(test_rotation_forgets_nonces);
            test!(test_sender_must_rotate);
            test!(test_replay_store_error);
        }
    };
}
pub use test_all;

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

    let label_id = LabelId::random(Rng);
    let parent_cmd_id = CmdId::random(Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: ident!("CreateSealOnlyChannel"),
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AfcUniChannel { peer_encap, key_id } = author
        .ffi
        .create_uni_channel(
            &ctx,
            &author.eng,
            parent_cmd_id,
            author.enc_key_id,
            peer.enc_pk.clone(),
            author.device_id,
            peer.device_id,
            label_id,
            0,
        )
        .expect("author should be able to create a uni channel");

    // This is called by the author of the channel after
    // receiving the effect.
    let author_chan_id = {
        let keys = author
            .handler
            .uni_channel_created(
                &author.eng,
                &UniChannelCreated {
                    parent_cmd_id,
                    open_id: peer.device_id,
                    author_enc_key_id: author.enc_key_id,
                    peer_enc_pk: &peer.enc_pk,
                    label_id,
                    key_id: key_id.into(),
                    epoch: 0,
                },
            )
            .expect("author should be able to load encryption key");
        assert!(matches!(keys, UniKey::SealOnly(_)));

        author
            .afc_state
            .add(keys.into(), label_id, peer.device_id)
            .expect("author should be able to add channel")
    };

    // This is called by the channel peer after receiving the
    // effect.
    let peer_chan_id = {
        let mut replay = peer.replay.clone();
        let graph = peer.graph;
        let keys = peer
            .handler
            .uni_channel_received(
                &peer.eng,
                &mut replay,
                graph,
                &UniChannelReceived {
                    parent_cmd_id,
                    seal_id: author.device_id,
                    author_enc_pk: &author.enc_pk,
                    peer_enc_key_id: peer.enc_key_id,
                    label_id,
                    encap: &peer_encap,
                    epoch: 0,
                    cmd_id: CmdId::random(Rng),
                },
            )
            .expect("peer should be able to load decryption key");
        assert!(matches!(keys, UniKey::OpenOnly(_)));

        peer.afc_state
            .add(keys.into(), label_id, author.device_id)
            .expect("peer should be able to add channel")
    };

    Device::test_roundtrip((&mut author, author_chan_id), (&mut peer, peer_chan_id));
    Device::test_wrong_direction(&mut peer, peer_chan_id);
}

/// A negative test for creating a unidirectional channel
/// where the author is the opener.
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
    let mut author = T::new();
    let peer = T::new();

    let label_id = LabelId::random(Rng);
    let parent_cmd_id = CmdId::random(Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: ident!("CreateOpenOnlyChannel"),
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AfcUniChannel {
        peer_encap: _,
        key_id,
    } = author
        .ffi
        .create_uni_channel(
            &ctx,
            &author.eng,
            parent_cmd_id,
            author.enc_key_id,
            peer.enc_pk.clone(),
            author.device_id,
            peer.device_id,
            label_id,
            0,
        )
        .expect("author should be able to create a uni channel");

    // This is called by the author of the channel after
    // receiving the effect.
    match author
            .handler
            .uni_channel_created::<_,  <T::Aranya as AranyaState>::SealKey, <T::Aranya as AranyaState>::OpenKey>(
                &author.eng,
                &UniChannelCreated {
                    parent_cmd_id,
                    open_id: author.device_id, // this causes an error
                    author_enc_key_id: author.enc_key_id,
                    peer_enc_pk: &peer.enc_pk,
                    label_id,
                    key_id: key_id.into(),
                    epoch: 0,
                },
            ) {
                Ok(_) => panic!("author should not be the opener"),
                Err(err) => assert!(matches!(err, EffectHandlerError::AuthorMustBeSealer)),
            }
}

/// A negative test for creating a unidirectional channel
/// where the recipient is the sealer.
pub fn test_receive_seal_only_uni_channel<T: TestImpl>()
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
    let author = T::new();
    let mut peer = T::new();

    let label_id = LabelId::random(Rng);
    let parent_cmd_id = CmdId::random(Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: ident!("CreateOpenOnlyChannel"),
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AfcUniChannel {
        peer_encap: encap,
        key_id: _,
    } = author
        .ffi
        .create_uni_channel(
            &ctx,
            &author.eng,
            parent_cmd_id,
            author.enc_key_id,
            peer.enc_pk.clone(),
            author.device_id,
            peer.device_id,
            label_id,
            0,
        )
        .expect("author should be able to create a uni channel");

    // This is called by the peer of the channel after
    // receiving the effect.
    let mut replay = peer.replay.clone();
    let graph = peer.graph;
    match peer
            .handler
            .uni_channel_received::<_, _, <T::Aranya as AranyaState>::SealKey, <T::Aranya as AranyaState>::OpenKey>(
                &author.eng,
                &mut replay,
                graph,
                &UniChannelReceived {
                    parent_cmd_id,
                    seal_id: peer.device_id,
                    author_enc_pk: &author.enc_pk,
                    label_id,
                    encap: &encap,
                    peer_enc_key_id: peer.enc_key_id,
                    epoch: 0,
                    cmd_id: CmdId::random(Rng),
                },
            ) {
                Ok(_) => panic!("author should not be the opener"),
                Err(err) => assert!(matches!(err, EffectHandlerError::AuthorMustBeSealer)),
            }
    // A message rejected before the replay check must not
    // consume a nonce slot.
    assert_eq!(replay.nonces(graph, peer.device_id), 0);
}

/// A negative test for the FFI: the epoch must be non-negative.
pub fn test_create_uni_channel_negative_epoch<T: TestImpl>() {
    let author = T::new();
    let peer = T::new();

    let label_id = LabelId::random(Rng);
    let parent_cmd_id = CmdId::random(Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: ident!("CreateUniChannel"),
        head_id: parent_cmd_id,
    });
    let err = author
        .ffi
        .create_uni_channel(
            &ctx,
            &author.eng,
            parent_cmd_id,
            author.enc_key_id,
            peer.enc_pk.clone(),
            author.device_id,
            peer.device_id,
            label_id,
            -1,
        )
        .expect_err("negative epoch should be rejected");
    assert!(matches!(err, FfiError::InvalidEpoch), "{err}");
}

/// Delivering the same control message twice installs exactly
/// one key: the second delivery is rejected as a replay.
pub fn test_receive_replayed_uni_channel<T: TestImpl>()
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
    let label_id = LabelId::random(Rng);

    let ch = author.create_uni_channel(&peer, label_id, 0);
    let author_chan_id = author.install_created(&peer, &ch);
    let peer_chan_id = peer.install_received(&author, &ch);
    Device::test_roundtrip((&mut author, author_chan_id), (&mut peer, peer_chan_id));
    assert_eq!(peer.replay.nonces(peer.graph, author.device_id), 1);

    // Replay the exact same control message.
    let mut replay = peer.replay.clone();
    let err = peer
        .receive(&author, &ch, &mut replay)
        .err()
        .expect("replayed control message should be rejected");
    assert!(
        matches!(err, EffectHandlerError::Replay(Verdict::Replay)),
        "{err}"
    );
    assert_eq!(peer.replay.nonces(peer.graph, author.device_id), 1);

    // A different control message from the same sender at the
    // same epoch is still accepted.
    let ch2 = author.create_uni_channel(&peer, label_id, 0);
    let author_chan_id2 = author.install_created(&peer, &ch2);
    let peer_chan_id2 = peer.install_received(&author, &ch2);
    Device::test_roundtrip((&mut author, author_chan_id2), (&mut peer, peer_chan_id2));
    assert_eq!(peer.replay.nonces(peer.graph, author.device_id), 2);
}

/// A control message from an older epoch than the highest
/// accepted from that sender is rejected.
pub fn test_receive_stale_epoch_uni_channel<T: TestImpl>()
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
    let label_id = LabelId::random(Rng);

    let old = author.create_uni_channel(&peer, label_id, 1);
    let new = author.create_uni_channel(&peer, label_id, 2);

    // Accept the newer epoch first...
    let author_chan_id = author.install_created(&peer, &new);
    let peer_chan_id = peer.install_received(&author, &new);
    Device::test_roundtrip((&mut author, author_chan_id), (&mut peer, peer_chan_id));
    assert_eq!(peer.replay.epoch(peer.graph, author.device_id), 2);

    // ...then the older one is stale.
    let mut replay = peer.replay.clone();
    let err = peer
        .receive(&author, &old, &mut replay)
        .err()
        .expect("stale epoch should be rejected");
    assert!(
        matches!(
            err,
            EffectHandlerError::Replay(Verdict::StaleEpoch { current: 2 })
        ),
        "{err}"
    );
    assert_eq!(peer.replay.nonces(peer.graph, author.device_id), 1);
}

/// Rotating the sender's epoch (as observed via the graph)
/// invalidates outstanding control messages and lets the
/// receiver forget old nonces.
pub fn test_rotation_forgets_nonces<T: TestImpl>()
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
    let label_id = LabelId::random(Rng);
    let graph = peer.graph;

    let ch0 = author.create_uni_channel(&peer, label_id, 0);
    let author_chan_id = author.install_created(&peer, &ch0);
    let peer_chan_id = peer.install_received(&author, &ch0);
    Device::test_roundtrip((&mut author, author_chan_id), (&mut peer, peer_chan_id));
    assert_eq!(peer.replay.epoch(graph, author.device_id), 0);
    assert_eq!(peer.replay.nonces(graph, author.device_id), 1);

    // The sender rotates to epoch 1; the receiver learns about
    // it via the `AfcEpochRotated` effect.
    peer.replay
        .raise_floor(graph, author.device_id, 1)
        .expect("raise_floor should succeed");
    assert_eq!(peer.replay.epoch(graph, author.device_id), 1);
    assert_eq!(peer.replay.nonces(graph, author.device_id), 0);

    // An old control message is now stale.
    let mut replay = peer.replay.clone();
    let err = peer
        .receive(&author, &ch0, &mut replay)
        .err()
        .expect("old epoch should be rejected");
    assert!(
        matches!(
            err,
            EffectHandlerError::Replay(Verdict::StaleEpoch { current: 1 })
        ),
        "{err}"
    );

    // Channels at the new epoch work.
    let ch1 = author.create_uni_channel(&peer, label_id, 1);
    let author_chan_id = author.install_created(&peer, &ch1);
    let peer_chan_id = peer.install_received(&author, &ch1);
    Device::test_roundtrip((&mut author, author_chan_id), (&mut peer, peer_chan_id));
    assert_eq!(peer.replay.nonces(graph, author.device_id), 1);

    // A control message with a newer epoch also ratchets the
    // receiver forward and forgets the old nonces, so a later
    // `AfcEpochRotated` for that epoch is a no-op.
    let ch2 = author.create_uni_channel(&peer, label_id, 2);
    let author_chan_id = author.install_created(&peer, &ch2);
    let peer_chan_id = peer.install_received(&author, &ch2);
    Device::test_roundtrip((&mut author, author_chan_id), (&mut peer, peer_chan_id));
    assert_eq!(peer.replay.epoch(graph, author.device_id), 2);
    assert_eq!(peer.replay.nonces(graph, author.device_id), 1);
    peer.replay
        .raise_floor(graph, author.device_id, 2)
        .expect("raise_floor should succeed");
    assert_eq!(peer.replay.epoch(graph, author.device_id), 2);
    assert_eq!(peer.replay.nonces(graph, author.device_id), 1);

    // Another rotation forgets everything again.
    peer.replay
        .raise_floor(graph, author.device_id, 3)
        .expect("raise_floor should succeed");
    assert_eq!(peer.replay.nonces(graph, author.device_id), 0);
    let mut replay = peer.replay.clone();
    let err = peer
        .receive(&author, &ch2, &mut replay)
        .err()
        .expect("old epoch should be rejected");
    assert!(
        matches!(
            err,
            EffectHandlerError::Replay(Verdict::StaleEpoch { current: 3 })
        ),
        "{err}"
    );
}

/// Once the per-epoch nonce cap is exhausted, the receiver fails
/// closed until the sender rotates.
pub fn test_sender_must_rotate<T: TestImpl>()
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
    let label_id = LabelId::random(Rng);
    peer.replay = ReplayMemStore::with_cap(2);

    let ch1 = author.create_uni_channel(&peer, label_id, 0);
    let ch2 = author.create_uni_channel(&peer, label_id, 0);
    let ch3 = author.create_uni_channel(&peer, label_id, 0);
    peer.install_received(&author, &ch1);
    peer.install_received(&author, &ch2);

    let mut replay = peer.replay.clone();
    let err = peer
        .receive(&author, &ch3, &mut replay)
        .err()
        .expect("third channel should exceed the cap");
    assert!(
        matches!(
            err,
            EffectHandlerError::Replay(Verdict::SenderMustRotate { cap: 2 })
        ),
        "{err}"
    );

    // Rotating clears the cap.
    let ch4 = author.create_uni_channel(&peer, label_id, 1);
    let author_chan_id = author.install_created(&peer, &ch4);
    let peer_chan_id = peer.install_received(&author, &ch4);
    Device::test_roundtrip((&mut author, author_chan_id), (&mut peer, peer_chan_id));
}

/// A failing replay store surfaces as
/// [`Error::ReplayStore`][EffectHandlerError::ReplayStore].
pub fn test_replay_store_error<T: TestImpl>()
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
    let author = T::new();
    let mut peer = T::new();
    let label_id = LabelId::random(Rng);

    let ch = author.create_uni_channel(&peer, label_id, 0);
    let err = peer
        .receive(&author, &ch, &mut FailingStore)
        .err()
        .expect("unavailable replay store should be an error");
    assert!(matches!(err, EffectHandlerError::ReplayStore), "{err}");

    // Once the store is available again the same message is
    // accepted: the failed attempt did not record it.
    let mut replay = peer.replay.clone();
    let keys = peer
        .receive(&author, &ch, &mut replay)
        .expect("peer should be able to load decryption key");
    assert!(matches!(keys, UniKey::OpenOnly(_)));
}

/// Two concurrent deliveries of the same control message yield
/// exactly one key.
///
/// Each thread models an independent daemon worker: it has its
/// own [`Handler`] and keystore (holding the receiver's
/// encryption key) and shares only the [`ReplayStore`].
#[cfg(any(test, feature = "std"))]
pub fn test_concurrent_uni_channel_received<T: TestImpl>()
where
    EncryptionKey<<T::Engine as Engine>::CS>: Send,
    <T::Aranya as AranyaState>::SealKey: Send,
    <T::Aranya as AranyaState>::OpenKey: Send,
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
    const THREADS: usize = 8;
    const ROUNDS: usize = 16;

    let author = T::new();
    let peer = T::new();
    let label_id = LabelId::random(Rng);

    for round in 0..ROUNDS {
        let ch = author.create_uni_channel(&peer, label_id, 0);

        let barrier = std::sync::Barrier::new(THREADS);
        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let mut replay = peer.replay.clone();
                    let peer_enc_sk = peer.enc_sk.clone();
                    let peer_device_id = peer.device_id;
                    let peer_enc_key_id = peer.enc_key_id;
                    let graph = peer.graph;
                    let author_device_id = author.device_id;
                    let author_enc_pk = author.enc_pk.clone();
                    let (parent_cmd_id, epoch, cmd_id, peer_encap) =
                        (ch.parent_cmd_id, ch.epoch, ch.cmd_id, ch.peer_encap.clone());
                    let barrier = &barrier;
                    scope.spawn(move || {
                        // An independent worker with its own
                        // engine and keystore.
                        let worker = T::new();
                        let mut store = worker.store.clone();
                        let key_id = store
                            .insert_key(&worker.eng, peer_enc_sk)
                            .expect("should be able to insert wrapped `EncryptionKey`");
                        assert_eq!(key_id, peer_enc_key_id);
                        let mut handler = Handler::new(peer_device_id, store);

                        let effect = UniChannelReceived {
                            parent_cmd_id,
                            seal_id: author_device_id,
                            author_enc_pk: &author_enc_pk,
                            peer_enc_key_id,
                            label_id,
                            encap: &peer_encap,
                            epoch,
                            cmd_id,
                        };

                        barrier.wait();
                        handler
                            .uni_channel_received::<_, _, <T::Aranya as AranyaState>::SealKey, <T::Aranya as AranyaState>::OpenKey>(
                                &worker.eng, &mut replay, graph, &effect,
                            )
                            .map(|keys| matches!(keys, UniKey::OpenOnly(_)))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("thread should not panic"))
                .collect()
        });

        let fresh = results.iter().filter(|r| matches!(r, Ok(true))).count();
        let replays = results
            .iter()
            .filter(|r| matches!(r, Err(EffectHandlerError::Replay(Verdict::Replay))))
            .count();
        assert_eq!(
            fresh, 1,
            "round {round}: exactly one delivery should succeed"
        );
        assert_eq!(
            replays,
            THREADS - 1,
            "round {round}: the rest should be replays"
        );
        assert_eq!(peer.replay.nonces(peer.graph, author.device_id), round + 1);
    }
}
