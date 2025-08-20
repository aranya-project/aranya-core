//! Utilities for testing [`Handler`] and [`Ffi`].

#![cfg(any(test, feature = "testing"))]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

extern crate alloc;

use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    mem::{self, MaybeUninit},
    ops::Deref,
    result::Result,
};

use aranya_crypto::{
    self, CipherSuite, DeviceId, EncryptionKey, EncryptionKeyId, EncryptionPublicKey, Engine, Id,
    IdentityKey, KeyStore, KeyStoreExt as _, Random, Rng,
    aqc::{BidiPskId, CipherSuiteId, UniPskId},
    engine::WrappedKey,
    keystore::{Entry, Occupied, Vacant, memstore},
};
use aranya_policy_vm::{ActionContext, CommandContext, ident};
use spin::Mutex;

use crate::{
    ffi::{AqcBidiChannel, AqcUniChannel, Ffi},
    handler::{
        BidiChannelCreated, BidiChannelReceived, Handler, UniChannelCreated, UniChannelReceived,
    },
    shared::LabelId,
};

/// Encodes a [`EncryptionPublicKey`].
fn encode_enc_pk<CS: CipherSuite>(pk: &EncryptionPublicKey<CS>) -> Vec<u8> {
    postcard::to_allocvec(pk).expect("should be able to encode an `EncryptionPublicKey`")
}

fn shuffle<T>(data: &mut [T]) {
    shuffle_by(data.len(), |i, j| {
        data.swap(i, j);
    })
}

fn shuffle_by<F>(n: usize, mut swap: F)
where
    F: FnMut(usize, usize),
{
    for i in (0..n).rev() {
        let j = rand_intn(i + 1);
        swap(i, j);
    }
}

#[track_caller]
fn assert_unique<T>(iter: impl IntoIterator<Item = T>)
where
    T: Ord,
{
    let mut uniq = BTreeSet::new();
    for v in iter {
        assert!(uniq.insert(v));
    }
}

/// Returns a random integer in [0, max).
fn rand_intn(max: usize) -> usize {
    debug_assert!(max < usize::MAX);

    // Use Lemire's uniform sampling method to select an index in
    // [0, RANGE). This loop usually runs once, rarely more than
    // twice.
    //
    // See https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
    // See https://lemire.me/blog/2016/06/30/fast-random-shuffling/
    loop {
        let range = max;
        let rand = usize::random(&mut Rng);
        let (hi, lo) = widening_mul(rand, range);
        let thresh = 0usize.wrapping_sub(range) % range;
        if lo >= thresh {
            // Wide multiplying `rand * range` puts the candidate
            // in `hi`.
            debug_assert!(hi < max);
            break hi;
        }
    }
}

/// Returns (hi, lo).
#[inline(always)]
const fn widening_mul(x: usize, y: usize) -> (usize, usize) {
    const SHIFT: u32 = usize::BITS / 2; // high bits
    const MASK: usize = (1 << SHIFT) - 1; // low bits

    let x1 = x >> SHIFT;
    let x0 = x & MASK;
    let y1 = y >> SHIFT;
    let y0 = y & MASK;

    // `x0*y0` cannot overflow because both are at most b/2 bits,
    // and multiplying an m-bit number by an n-bit number uses at
    // most m+n bits.
    let w0 = x0 * y0;
    // `x1*y0` also cannot overflow for the same reasons.
    // However, the addition uses at most one extra bit and might
    // overflow.
    let t = (x1 * y0).wrapping_add(w0 >> SHIFT);
    // `x0*y1` also cannot overflow for the same reasons.
    // However, the addition uses at most one extra bit and might
    // overflow.
    let w1 = (x0 * y1).wrapping_add(t & MASK);
    let w2 = t >> SHIFT;
    // `x1*y1` also cannot overflow for the same reasons.
    // However, each addition uses at most one extra bit and
    // might overflow.
    let hi = (x1 * y1).wrapping_add(w2).wrapping_add(w1 >> SHIFT);
    // Full-width multiplication obviously might overflow.
    let lo = x.wrapping_mul(y);

    (hi, lo)
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
        let enc_pk = encode_enc_pk(
            &enc_sk
                .public()
                .expect("encryption public key should be valid"),
        );

        let enc_key_id = store
            .insert_key(&mut eng, enc_sk)
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
/// use aranya_aqc_util::testing::{Device, MemStore, TestImpl, test_all};
/// use aranya_crypto::{
///     Rng,
///     default::{DefaultCipherSuite, DefaultEngine},
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
            test!(test_create_multi_bidi_channels_same_label);
            test!(test_create_multi_bidi_channels_same_parent_cmd_id);
            test!(test_create_multi_bidi_channels_same_label_multi_peers);
            test!(test_create_send_only_uni_channel);
            test!(test_create_recv_only_uni_channel);
        }
    };
}
pub use test_all;

/// A basic positive test for creating a bidirectional channel.
pub fn test_create_bidi_channel<T: TestImpl>() {
    let mut author = T::new();
    let mut peer = T::new();

    let label_id = LabelId::random(&mut Rng);
    let parent_cmd_id = Id::random(&mut Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: ident!("CreateBidiChannel"),
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AqcBidiChannel {
        peer_encap,
        channel_id,
        author_secrets_id,
        psk_length_in_bytes,
    } = author
        .ffi
        .create_bidi_channel(
            &ctx,
            &mut author.eng,
            parent_cmd_id,
            author.enc_key_id,
            author.device_id,
            peer.enc_pk.clone(),
            peer.device_id,
            label_id,
        )
        .expect("author should be able to create a bidi channel");

    let suite = CipherSuiteId::TlsAes128GcmSha256;

    // This is called by the author of the channel after
    // receiving the effect.
    let author_secret = author
        .handler
        .bidi_channel_created(
            &mut author.eng,
            &BidiChannelCreated {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                author_enc_key_id: author.enc_key_id,
                peer_id: peer.device_id,
                peer_enc_pk: &peer.enc_pk,
                label_id,
                author_secrets_id: author_secrets_id.into(),
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            },
        )
        .expect("author should be able to load secret");
    let author_psk = author_secret
        .generate_psk(suite)
        .expect("author should be able to generate PSK");

    // This is called by the channel peer after receiving the
    // effect.
    let peer_secret = peer
        .handler
        .bidi_channel_received(
            &mut peer.eng,
            &BidiChannelReceived {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                author_enc_pk: &author.enc_pk,
                peer_id: peer.device_id,
                peer_enc_key_id: peer.enc_key_id,
                label_id,
                encap: &peer_encap,
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            },
        )
        .expect("peer should be able to load secret");
    let peer_psk = peer_secret
        .generate_psk(suite)
        .expect("peer should be able to generate PSK");

    assert_eq!(
        &BidiPskId::from((channel_id.into(), suite)),
        author_psk.identity()
    );
    assert_eq!(author_psk.identity(), peer_psk.identity());
    assert_eq!(author_psk.raw_secret_bytes(), peer_psk.raw_secret_bytes());
}

/// A basic positive test for creating a unidirectional channel
/// where the author is send-only.
pub fn test_create_send_only_uni_channel<T: TestImpl>() {
    let mut author = T::new();
    let mut peer = T::new();

    let label_id = LabelId::random(&mut Rng);
    let parent_cmd_id = Id::random(&mut Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: ident!("CreateUniSendOnlyChannel"),
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AqcUniChannel {
        peer_encap,
        channel_id,
        author_secrets_id,
        psk_length_in_bytes,
    } = author
        .ffi
        .create_uni_channel(
            &ctx,
            &mut author.eng,
            parent_cmd_id,
            author.enc_key_id,
            peer.enc_pk.clone(),
            author.device_id,
            peer.device_id,
            label_id,
        )
        .expect("author should be able to create a uni channel");

    let suite = CipherSuiteId::TlsAes128GcmSha256;

    // This is called by the author of the channel after
    // receiving the effect.
    let author_secret = author
        .handler
        .uni_channel_created(
            &mut author.eng,
            &UniChannelCreated {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                send_id: author.device_id,
                recv_id: peer.device_id,
                author_enc_key_id: author.enc_key_id,
                peer_enc_pk: &peer.enc_pk,
                label_id,
                author_secrets_id: author_secrets_id.into(),
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            },
        )
        .expect("author should be able to load secret");
    let author_psk = author_secret
        .generate_send_only_psk(suite)
        .expect("author should be able to generate PSK");

    // This is called by the channel peer after receiving the
    // effect.
    let peer_secret = peer
        .handler
        .uni_channel_received(
            &mut peer.eng,
            &UniChannelReceived {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                send_id: author.device_id,
                recv_id: peer.device_id,
                author_enc_pk: &author.enc_pk,
                peer_enc_key_id: peer.enc_key_id,
                label_id,
                encap: &peer_encap,
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            },
        )
        .expect("peer should be able to load secret");
    let peer_psk = peer_secret
        .generate_recv_only_psk(suite)
        .expect("peer should be able to generate PSK");

    assert_eq!(
        &UniPskId::from((channel_id.into(), suite)),
        author_psk.identity()
    );
    assert_eq!(author_psk.identity(), peer_psk.identity());
    assert_eq!(author_psk.raw_secret_bytes(), peer_psk.raw_secret_bytes());
}

/// A basic positive test for creating a unidirectional channel
/// where the author is recvonly.
pub fn test_create_recv_only_uni_channel<T: TestImpl>() {
    let mut author = T::new(); // recv only
    let mut peer = T::new(); // send only

    let label_id = LabelId::random(&mut Rng);
    let parent_cmd_id = Id::random(&mut Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: ident!("CreateUniRecvOnlyChannel"),
        head_id: parent_cmd_id,
    });

    // This is called via FFI.
    let AqcUniChannel {
        peer_encap,
        channel_id,
        author_secrets_id,
        psk_length_in_bytes,
    } = author
        .ffi
        .create_uni_channel(
            &ctx,
            &mut author.eng,
            parent_cmd_id,
            author.enc_key_id,
            peer.enc_pk.clone(),
            author.device_id,
            peer.device_id,
            label_id,
        )
        .expect("author should be able to create a uni channel");

    let suite = CipherSuiteId::TlsAes128GcmSha256;

    // This is called by the author of the channel after
    // receiving the effect.
    let author_secret = author
        .handler
        .uni_channel_created(
            &mut author.eng,
            &UniChannelCreated {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                send_id: peer.device_id,
                recv_id: author.device_id,
                author_enc_key_id: author.enc_key_id,
                peer_enc_pk: &peer.enc_pk,
                label_id,
                author_secrets_id: author_secrets_id.into(),
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            },
        )
        .expect("author should be able to load secret");
    let author_psk = author_secret
        .generate_recv_only_psk(suite)
        .expect("author should be able to generate PSK");

    // This is called by the channel peer after receiving the
    // effect.
    let peer_secret = peer
        .handler
        .uni_channel_received(
            &mut peer.eng,
            &UniChannelReceived {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                send_id: peer.device_id,
                recv_id: author.device_id,
                author_enc_pk: &author.enc_pk,
                peer_enc_key_id: peer.enc_key_id,
                label_id,
                encap: &peer_encap,
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            },
        )
        .expect("peer should be able to load secret");
    let peer_psk = peer_secret
        .generate_send_only_psk(suite)
        .expect("peer should be able to generate PSK");

    assert_eq!(
        &UniPskId::from((channel_id.into(), suite)),
        author_psk.identity()
    );
    assert_eq!(author_psk.identity(), peer_psk.identity());
    assert_eq!(author_psk.raw_secret_bytes(), peer_psk.raw_secret_bytes());
}

/// A basic positive test for creating multiple bidirectional
/// channels with the same label.
pub fn test_create_multi_bidi_channels_same_label<T: TestImpl>() {
    let mut author = T::new();
    let mut peer = T::new();

    let label_id = LabelId::random(&mut Rng);

    let (mut expect, peer_encaps): (Vec<_>, Vec<_>) = (0..50)
        .map(|_| {
            let parent_cmd_id = Id::random(&mut Rng);
            let ctx = CommandContext::Action(ActionContext {
                name: ident!("CreateBidiChannel"),
                head_id: parent_cmd_id,
            });

            // This is called via FFI.
            let AqcBidiChannel {
                peer_encap,
                channel_id,
                author_secrets_id,
                psk_length_in_bytes,
            } = author
                .ffi
                .create_bidi_channel(
                    &ctx,
                    &mut author.eng,
                    parent_cmd_id,
                    author.enc_key_id,
                    author.device_id,
                    peer.enc_pk.clone(),
                    peer.device_id,
                    label_id,
                )
                .expect("author should be able to create a bidi channel");

            let created = BidiChannelCreated {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                author_enc_key_id: author.enc_key_id,
                peer_id: peer.device_id,
                peer_enc_pk: &peer.enc_pk,
                label_id,
                author_secrets_id: author_secrets_id.into(),
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            };
            let received = BidiChannelReceived {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                author_enc_pk: &author.enc_pk,
                peer_id: peer.device_id,
                peer_enc_key_id: peer.enc_key_id,
                label_id,
                encap: &[],
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            };
            ((created, received), peer_encap)
        })
        .unzip();

    // Set `encap` outside of the loop b/c of lifetime and
    // aliasing issues.
    for ((_, received), encap) in expect.iter_mut().zip(&peer_encaps) {
        received.encap = encap;
    }

    shuffle(&mut expect);

    // There shouldn't be any duplicate channel IDs.
    assert_unique(expect.iter().map(|(created, _)| created.channel_id));

    for (created, received) in &expect {
        // This is called by the author of the channel after
        // receiving the effect.
        let author_secret = author
            .handler
            .bidi_channel_created(&mut author.eng, created)
            .expect("author should be able to load secret");

        // This is called by the channel peer after receiving the
        // effect.
        let peer_secret = peer
            .handler
            .bidi_channel_received(&mut peer.eng, received)
            .expect("peer should be able to load secret");

        for &suite in CipherSuiteId::all() {
            let author_psk = author_secret
                .generate_psk(suite)
                .expect("author should be able to generate PSK");
            let peer_psk = peer_secret
                .generate_psk(suite)
                .expect("peer should be able to generate PSK");

            assert_eq!(author_psk.identity(), peer_psk.identity());
            assert_eq!(author_psk.raw_secret_bytes(), peer_psk.raw_secret_bytes());
        }
    }
}

/// A basic positive test for creating multiple bidirectional
/// channels with the same parent command ID.
pub fn test_create_multi_bidi_channels_same_parent_cmd_id<T: TestImpl>() {
    let mut author = T::new();
    let mut peer = T::new();

    let parent_cmd_id = Id::random(&mut Rng);
    let ctx = CommandContext::Action(ActionContext {
        name: ident!("CreateBidiChannel"),
        head_id: parent_cmd_id,
    });

    let (mut expect, peer_encaps): (Vec<_>, Vec<_>) = (0..50)
        .map(|_| {
            let label_id = LabelId::random(&mut Rng);

            // This is called via FFI.
            let AqcBidiChannel {
                peer_encap,
                channel_id,
                author_secrets_id,
                psk_length_in_bytes,
            } = author
                .ffi
                .create_bidi_channel(
                    &ctx,
                    &mut author.eng,
                    parent_cmd_id,
                    author.enc_key_id,
                    author.device_id,
                    peer.enc_pk.clone(),
                    peer.device_id,
                    label_id,
                )
                .expect("author should be able to create a bidi channel");

            let created = BidiChannelCreated {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                author_enc_key_id: author.enc_key_id,
                peer_id: peer.device_id,
                peer_enc_pk: &peer.enc_pk,
                label_id,
                author_secrets_id: author_secrets_id.into(),
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            };
            let received = BidiChannelReceived {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                author_enc_pk: &author.enc_pk,
                peer_id: peer.device_id,
                peer_enc_key_id: peer.enc_key_id,
                label_id,
                encap: &[],
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            };
            ((created, received), peer_encap)
        })
        .unzip();

    // Set `encap` outside of the loop b/c of lifetime and
    // aliasing issues.
    for ((_, received), encap) in expect.iter_mut().zip(&peer_encaps) {
        received.encap = encap;
    }

    shuffle(&mut expect);

    // There shouldn't be any duplicate channel IDs.
    assert_unique(expect.iter().map(|(created, _)| created.channel_id));

    for (created, received) in &expect {
        // This is called by the author of the channel after
        // receiving the effect.
        let author_secret = author
            .handler
            .bidi_channel_created(&mut author.eng, created)
            .expect("author should be able to load secret");

        // This is called by the channel peer after receiving the
        // effect.
        let peer_secret = peer
            .handler
            .bidi_channel_received(&mut peer.eng, received)
            .expect("peer should be able to load secret");

        for &suite in CipherSuiteId::all() {
            let author_psk = author_secret
                .generate_psk(suite)
                .expect("author should be able to generate PSK");
            let peer_psk = peer_secret
                .generate_psk(suite)
                .expect("peer should be able to generate PSK");

            assert_eq!(&created.channel_id, author_psk.identity().channel_id());
            assert_eq!(author_psk.identity(), peer_psk.identity());
            assert_eq!(author_psk.raw_secret_bytes(), peer_psk.raw_secret_bytes());
        }
    }
}

/// A basic positive test for creating multiple bidirectional
/// channels with the same label with multiple peers.
pub fn test_create_multi_bidi_channels_same_label_multi_peers<T: TestImpl>() {
    let mut author = T::new();
    let mut peers = (0..50).map(|_| T::new()).collect::<Vec<_>>();
    // Just to break the `expect -> peers` aliasing.
    let peer_enc_pks = peers
        .iter()
        .map(|peer| peer.enc_pk.clone())
        .collect::<Vec<_>>();

    let label_id = LabelId::random(&mut Rng);

    let (mut expect, peer_encaps): (Vec<_>, Vec<_>) = peers
        .iter()
        .enumerate()
        .map(|(i, peer)| {
            let parent_cmd_id = Id::random(&mut Rng);
            let ctx = CommandContext::Action(ActionContext {
                name: ident!("CreateBidiChannel"),
                head_id: parent_cmd_id,
            });

            // This is called via FFI.
            let AqcBidiChannel {
                peer_encap,
                channel_id,
                author_secrets_id,
                psk_length_in_bytes,
            } = author
                .ffi
                .create_bidi_channel(
                    &ctx,
                    &mut author.eng,
                    parent_cmd_id,
                    author.enc_key_id,
                    author.device_id,
                    peer.enc_pk.clone(),
                    peer.device_id,
                    label_id,
                )
                .expect("author should be able to create a bidi channel");

            let created = BidiChannelCreated {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                author_enc_key_id: author.enc_key_id,
                peer_id: peer.device_id,
                peer_enc_pk: &peer_enc_pks[i],
                label_id,
                author_secrets_id: author_secrets_id.into(),
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            };
            let received = BidiChannelReceived {
                channel_id: channel_id.into(),
                parent_cmd_id,
                author_id: author.device_id,
                author_enc_pk: &author.enc_pk,
                peer_id: peer.device_id,
                peer_enc_key_id: peer.enc_key_id,
                label_id,
                encap: &[],
                psk_length_in_bytes: psk_length_in_bytes.try_into().unwrap(),
            };
            ((created, received), peer_encap)
        })
        .unzip();

    // Set `encap` outside of the loop b/c of lifetime and
    // aliasing issues.
    for ((_, received), encap) in expect.iter_mut().zip(&peer_encaps) {
        received.encap = encap;
    }

    shuffle_by(expect.len(), |i, j| {
        expect.swap(i, j);
        peers.swap(i, j);
    });

    // There shouldn't be any duplicate channel IDs.
    assert_unique(expect.iter().map(|(created, _)| created.channel_id));

    for ((created, received), mut peer) in expect.iter().zip(peers) {
        // This is called by the author of the channel after
        // receiving the effect.
        let author_secret = author
            .handler
            .bidi_channel_created(&mut author.eng, created)
            .expect("author should be able to load bidi PSK");

        // This is called by the channel peer after receiving the
        // effect.
        let peer_secret = peer
            .handler
            .bidi_channel_received(&mut peer.eng, received)
            .expect("peer should be able to load bidi keys");

        for &suite in CipherSuiteId::all() {
            let author_psk = author_secret
                .generate_psk(suite)
                .expect("author should be able to generate PSK");
            let peer_psk = peer_secret
                .generate_psk(suite)
                .expect("peer should be able to generate PSK");

            assert_eq!(author_psk.identity(), peer_psk.identity());
            assert_eq!(author_psk.raw_secret_bytes(), peer_psk.raw_secret_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use super::*;

    #[test]
    fn test_shuffle() {
        let r = 1;
        let g = 2;
        let b = 3;
        let mut perms = BTreeSet::from_iter([
            [r, g, b],
            [r, b, g],
            [g, r, b],
            [g, b, r],
            [b, r, g],
            [b, g, r],
        ]);
        let mut n = 0;
        let mut data = [r, g, b];
        while !perms.is_empty() {
            shuffle(&mut data);
            perms.remove(&data);
            n += 1;
            // Make sure we don't spin forever when we're buggy.
            //
            // On average, this takes
            //    mean(n) = n*ln(n) + γn + (1/2) + O(1/n)
            // One standard deviation is
            //    stddev(n) = (2^n) / ((pi^2) / n)
            // The 95th percentile is
            //    p95(n) mean(n) + stddev(n) * sqrt(19)
            //
            // mean(6) = ~15 iters
            // stddev(6) = ~39 iters
            // p95(6) = ~184 iters
            //
            // So, choose a number that's very unlikely to be
            // hit.
            if n > 1000 {
                panic!("too many iters");
            }
        }
    }
}
