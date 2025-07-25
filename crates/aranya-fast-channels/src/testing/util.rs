//! Testing utilities.

use std::{
    cell::Cell,
    cmp,
    collections::HashMap,
    iter::{self, IntoIterator},
    marker::PhantomData,
    mem,
    num::NonZeroU16,
};

use aranya_crypto::{
    CipherSuite, EncryptionKey, Engine, Id, IdentityKey,
    afc::{BidiChannel, BidiKeys, BidiSecrets, UniChannel, UniOpenKey, UniSealKey, UniSecrets},
    dangerous::spideroak_crypto::{
        aead::{self, Aead, AeadKey, IndCca2, Lifetime, OpenError, SealError},
        csprng::Csprng,
        default::Rng,
        generic_array::{ArrayLength, GenericArray},
        hash::tuple_hash,
        hpke::{AeadId, HpkeAead},
        oid,
        oid::{Identified, Oid},
        rust::Sha256,
        subtle::ConstantTimeEq,
        typenum::{IsGreaterOrEqual, IsLess, U16, U65536},
    },
    default::{DefaultCipherSuite, DefaultEngine},
    test_util::TestCs,
};

use crate::{
    client::Client,
    header::{DataHeader, Header, MsgType, Version},
    memory,
    state::{AfcState, AranyaState, Channel, ChannelId, Directed, Label, NodeId},
};

#[cfg(feature = "trng")]
static HW_RAND: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(feature = "trng")]
#[unsafe(no_mangle)]
unsafe extern "C" fn OS_hardware_rand() -> u32 {
    HW_RAND.fetch_add(1, core::sync::atomic::Ordering::SeqCst)
}

/// Configuration for a particular test.
pub trait TestImpl {
    /// The [`AfcState`] being used.
    type Afc<CS: CipherSuite>: AfcState<CipherSuite = CS>;
    /// The [`AranyaState`] being used.
    type Aranya<CS: CipherSuite>: AranyaState<CipherSuite = CS>;
    /// The CSRPNG being used.
    type Rng: Csprng;

    /// Creates APS and Aranya states for a particular channel.
    ///
    /// `name` is the name of the test.
    fn new_states<CS: CipherSuite>(
        name: &str,
        id: NodeId,
        max_chans: usize,
    ) -> States<Self::Afc<CS>, Self::Aranya<CS>>;

    /// Converts `keys` into the key types used by
    /// [`AranyaState`].
    #[allow(clippy::type_complexity)]
    fn convert_bidi_keys<CS: CipherSuite>(
        keys: BidiKeys<CS>,
    ) -> (
        <Self::Aranya<CS> as AranyaState>::SealKey,
        <Self::Aranya<CS> as AranyaState>::OpenKey,
    );

    /// Converts `key` into the encryption key type used by
    /// [`AranyaState`].
    fn convert_uni_seal_key<CS: CipherSuite>(
        key: UniSealKey<CS>,
    ) -> <Self::Aranya<CS> as AranyaState>::SealKey;

    /// Converts `key` into the decryption key type used by
    /// [`AranyaState`].
    fn convert_uni_open_key<CS: CipherSuite>(
        key: UniOpenKey<CS>,
    ) -> <Self::Aranya<CS> as AranyaState>::OpenKey;
}

/// APS and Aranya states.
pub struct States<R, W> {
    /// The APS state.
    pub afc: R,
    /// The Aranya state.
    pub aranya: W,
}

/// Channel operations.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ChanOp {
    /// Can only encrypt.
    SealOnly,
    /// Can only decrypt.
    OpenOnly,
    /// Can encrypt and decrypt.
    Any,
}

impl ChanOp {
    /// Attempts to simplify a channel where one side has
    /// bidirectional permissions but the other only has
    /// unidirectional.
    ///
    /// This is an important step. `AfcState` is only required to
    /// record *its own* permissions, which can cause ambiguity.
    /// For instance, given the channel (A,B)=(`Any`,`SealOnly`),
    /// side A (which only knows that it has `Any` permissions),
    /// might think that it can encrypt messages for side B. But
    /// this is false: even though side A has both encryption and
    /// decryption permissions for the label, it is only
    /// permitted to encrypt messages if the intended recipient
    /// is allowed to decrypt them.
    ///
    /// It is Aranya's job to configure APS correctly.
    ///
    /// Invariant: both sides can actually create a channel in
    /// the first place.
    fn disambiguate(lhs: Self, rhs: Self) -> (Self, Self) {
        assert!(lhs.can_create_channel_with(rhs));

        match (lhs, rhs) {
            (Self::Any, Self::SealOnly) => (Self::OpenOnly, rhs),
            (Self::Any, Self::OpenOnly) => (Self::SealOnly, rhs),
            (Self::SealOnly, Self::Any) => (lhs, Self::OpenOnly),
            (Self::OpenOnly, Self::Any) => (lhs, Self::SealOnly),
            _ => (lhs, rhs),
        }
    }

    fn can_create_channel_with(self, other: Self) -> bool {
        self != other || self == Self::Any || other == Self::Any
    }
}

struct Device<T, CS>
where
    T: TestImpl,
    CS: CipherSuite,
{
    ident_sk: IdentityKey<CS>,
    enc_sk: EncryptionKey<CS>,
    state: T::Aranya<CS>,
}

impl<T, CS> Device<T, CS>
where
    T: TestImpl,
    CS: CipherSuite,
{
    fn new<R: Csprng>(rng: &mut R, state: T::Aranya<CS>) -> Self {
        Self {
            ident_sk: IdentityKey::new(rng),
            enc_sk: EncryptionKey::new(rng),
            state,
        }
    }
}

/// A simulated instance of Aranya.
pub struct Aranya<T, E>
where
    T: TestImpl,
    E: Engine,
{
    /// The test name.
    name: String,
    /// All known Aranya devices.
    devices: HashMap<NodeId, Device<T, E::CS>>,
    /// All peers that have `ChanOp` to the label.
    peers: Vec<(NodeId, Label, ChanOp)>,
    /// Selects the next `NodeId` for a client.
    ///
    /// TODO(eric): does this need to be `Cell`?
    next_id: Cell<u32>,
    /// For `T::new_states`.
    max_chans: usize,
    /// The underlying crypto engine.
    eng: E,
}

impl<T, E> Aranya<T, E>
where
    T: TestImpl,
    E: Engine,
{
    /// Creates an instance of Aranya.
    ///
    /// `name` is the name of the test using `Aranya`.
    pub fn new(name: &str, max_chans: usize, eng: E) -> Self {
        #[cfg(feature = "unsafe_debug")]
        crate::util::init_debug_logging();

        Self {
            name: name.to_owned(),
            devices: HashMap::with_capacity(max_chans),
            peers: Vec::with_capacity(max_chans),
            next_id: Cell::new(0),
            max_chans,
            eng,
        }
    }

    /// Create a [`Client`] that has `ChanOp` to a particular
    /// label.
    pub fn new_client<I>(&mut self, labels: I) -> (Client<T::Afc<E::CS>>, NodeId)
    where
        I: IntoIterator<Item = Label>,
    {
        self.new_client_with_type(labels.into_iter().zip(iter::repeat(ChanOp::Any)))
    }

    /// Create a [`Client`] that has `ChanOp` to a particular
    /// label.
    pub fn new_client_with_type<I>(&mut self, labels: I) -> (Client<T::Afc<E::CS>>, NodeId)
    where
        I: IntoIterator<Item = (Label, ChanOp)>,
    {
        let device_id = NodeId::new({
            let old = self.next_id.get();
            let new = old + 1;
            self.next_id.set(new);
            new
        });

        let States { afc, aranya } =
            T::new_states::<E::CS>(self.name.as_str(), device_id, self.max_chans);
        let device = Device::new(&mut self.eng, aranya);
        let client = Client::<T::Afc<E::CS>>::new(afc);

        for (label, device_type) in labels {
            // Find all the peers that we're able to create
            // channels with.
            let peers = self
                .peers
                .iter()
                .filter_map(|(peer_id, peer_label, peer_type)| {
                    if device_id != *peer_id
                        && *peer_label == label
                        && device_type.can_create_channel_with(*peer_type)
                    {
                        Some((peer_id, peer_type))
                    } else {
                        None
                    }
                });
            for (peer_id, peer_type) in peers {
                let peer = self
                    .devices
                    .get(peer_id)
                    .unwrap_or_else(|| panic!("`states.get` does not have {peer_id}"));

                let (our_side, peer_side) = {
                    let author = (&device, device_id, device_type);
                    let peer = (peer, *peer_id, *peer_type);
                    Self::new_channel(&mut self.eng, author, peer, label)
                };

                // Register the peer.
                device
                    .state
                    .add(our_side.id, our_side.keys)
                    .unwrap_or_else(|err| {
                        panic!("{label}: add({peer_id}, ...): unable to register the peer: {err}")
                    });

                // Register with the peer.
                self.devices
                    .get(peer_id)
                    .unwrap_or_else(|| panic!("`devices` does not have {peer_id}"))
                    .state
                    .add(peer_side.id, peer_side.keys)
                    .unwrap_or_else(|err| {
                        panic!(
                            "{label}: add({device_id}, ...): unable to register with peer: {err}"
                        )
                    });
            }
            self.peers.push((device_id, label, device_type));
        }
        self.devices.insert(device_id, device);

        (client, device_id)
    }

    fn new_channel(
        eng: &mut E,
        author: (&Device<T, E::CS>, NodeId, ChanOp),
        peer: (&Device<T, E::CS>, NodeId, ChanOp),
        label: Label,
    ) -> (TestChan<T, E::CS>, TestChan<T, E::CS>) {
        let (author, author_op) = ((author.0, author.1), author.2);
        let (peer, peer_op) = ((peer.0, peer.1), peer.2);
        let (author_op, peer_op) = ChanOp::disambiguate(author_op, peer_op);
        match ChanOp::disambiguate(author_op, peer_op) {
            (ChanOp::Any, ChanOp::Any) => Self::new_bidi_channel(eng, author, peer, label),
            (ChanOp::SealOnly, _) => Self::new_uni_channel(eng, author, peer, label),
            (ChanOp::OpenOnly, _) => {
                let (mut seal, mut open) = Self::new_uni_channel(eng, peer, author, label);
                // We've swapped `author` and `peer`, so swap
                // them back.
                mem::swap(&mut seal, &mut open);
                (seal, open)
            }
            _ => unreachable!(),
        }
    }

    fn new_bidi_channel(
        eng: &mut E,
        author: (&Device<T, E::CS>, NodeId),
        peer: (&Device<T, E::CS>, NodeId),
        label: Label,
    ) -> (TestChan<T, E::CS>, TestChan<T, E::CS>) {
        let (author, author_node_id) = author;
        let (peer, peer_node_id) = peer;

        let (author_keys, peer_keys) = {
            let author_cfg = BidiChannel {
                parent_cmd_id: Id::random(eng),
                our_sk: &author.enc_sk,
                our_id: author.ident_sk.public().unwrap().id().unwrap(),
                their_pk: &peer.enc_sk.public().unwrap(),
                their_id: peer.ident_sk.public().unwrap().id().unwrap(),
                label: label.to_u32(),
            };
            let peer_cfg = BidiChannel {
                parent_cmd_id: author_cfg.parent_cmd_id,
                our_sk: &peer.enc_sk,
                our_id: peer.ident_sk.public().unwrap().id().unwrap(),
                their_pk: &author.enc_sk.public().unwrap(),
                their_id: author.ident_sk.public().unwrap().id().unwrap(),
                label: label.to_u32(),
            };

            let BidiSecrets { author, peer } =
                BidiSecrets::new(eng, &author_cfg).expect("should be able to create `BidiSecrets`");
            let author_keys = BidiKeys::from_author_secret(&author_cfg, author)
                .expect("should be able to decrypt author's `BidiKeys`");
            let peer_keys = BidiKeys::from_peer_encap(&peer_cfg, peer)
                .expect("should be able to decrypt peer's `BidiKeys`");
            (author_keys, peer_keys)
        };

        let author_ch = {
            let (seal, open) = T::convert_bidi_keys(author_keys);
            Channel {
                id: ChannelId::new(peer_node_id, label),
                keys: Directed::Bidirectional { seal, open },
            }
        };
        let peer_ch = {
            let (seal, open) = T::convert_bidi_keys(peer_keys);
            Channel {
                id: ChannelId::new(author_node_id, label),
                keys: Directed::Bidirectional { seal, open },
            }
        };
        (author_ch, peer_ch)
    }

    fn new_uni_channel(
        eng: &mut E,
        seal: (&Device<T, E::CS>, NodeId),
        open: (&Device<T, E::CS>, NodeId),
        label: Label,
    ) -> (TestChan<T, E::CS>, TestChan<T, E::CS>) {
        let (seal, seal_node_id) = seal;
        let (open, open_node_id) = open;

        let (seal_key, open_key) = {
            let seal_cfg = UniChannel {
                parent_cmd_id: Id::random(eng),
                our_sk: &seal.enc_sk,
                their_pk: &open.enc_sk.public().unwrap(),
                seal_id: seal.ident_sk.public().unwrap().id().unwrap(),
                open_id: open.ident_sk.public().unwrap().id().unwrap(),
                label: label.to_u32(),
            };
            let open_cfg = UniChannel {
                parent_cmd_id: seal_cfg.parent_cmd_id,
                our_sk: &open.enc_sk,
                their_pk: &seal.enc_sk.public().unwrap(),
                seal_id: seal.ident_sk.public().unwrap().id().unwrap(),
                open_id: open.ident_sk.public().unwrap().id().unwrap(),
                label: label.to_u32(),
            };

            let UniSecrets { author, peer } =
                UniSecrets::new(eng, &seal_cfg).expect("should be able to create `UniSecrets`");
            let seal_key = UniSealKey::from_author_secret(&seal_cfg, author)
                .expect("should be able to decrypt author's `UniSealKey`");
            let open_key = UniOpenKey::from_peer_encap(&open_cfg, peer)
                .expect("should be able to decrypt peer's `UniOpenKey`");
            (seal_key, open_key)
        };

        let seal_ch = Channel {
            id: ChannelId::new(open_node_id, label),
            keys: Directed::SealOnly {
                seal: T::convert_uni_seal_key(seal_key),
            },
        };
        let open_ch = Channel {
            id: ChannelId::new(seal_node_id, label),
            keys: Directed::OpenOnly {
                open: T::convert_uni_open_key(open_key),
            },
        };
        (seal_ch, open_ch)
    }

    /// Removes a channel for `id`.
    ///
    /// Returns `None` if `id` is not found.
    #[allow(clippy::type_complexity)]
    pub fn remove(
        &mut self,
        id: NodeId,
        ch: ChannelId,
    ) -> Option<Result<(), <T::Aranya<E::CS> as AranyaState>::Error>> {
        let aranya = self.devices.get(&id)?;
        Some(aranya.state.remove(ch))
    }

    /// Removes all channels.
    #[allow(clippy::type_complexity)]
    pub fn remove_all(
        &mut self,
        id: NodeId,
    ) -> Option<Result<(), <T::Aranya<E::CS> as AranyaState>::Error>> {
        let aranya = self.devices.get(&id)?;
        Some(aranya.state.remove_all())
    }

    /// Removes channels where `f(id)` returns true.
    #[allow(clippy::type_complexity)]
    pub fn remove_if(
        &mut self,
        id: NodeId,
        f: impl FnMut(ChannelId) -> bool,
    ) -> Option<Result<(), <T::Aranya<E::CS> as AranyaState>::Error>> {
        let aranya = self.devices.get(&id)?;
        Some(aranya.state.remove_if(f))
    }

    /// Checks if channel exists.
    ///
    /// Returns true if channel exists.
    #[allow(clippy::type_complexity)]
    pub fn exists(
        &mut self,
        id: NodeId,
        ch: ChannelId,
    ) -> Option<Result<bool, <T::Aranya<E::CS> as AranyaState>::Error>> {
        let aranya = self.devices.get(&id)?;
        Some(aranya.state.exists(ch))
    }
}

type TestChan<T, CS> = Channel<
    <<T as TestImpl>::Aranya<CS> as AranyaState>::SealKey,
    <<T as TestImpl>::Aranya<CS> as AranyaState>::OpenKey,
>;

/// A [`TestImpl`] that uses [`memory::State`].
pub struct MockImpl;

impl TestImpl for MockImpl {
    type Afc<CS: CipherSuite> = memory::State<CS>;
    type Aranya<CS: CipherSuite> = memory::State<CS>;
    type Rng = Rng;

    fn new_states<CS: CipherSuite>(
        _name: &str,
        _node_id: NodeId,
        _max_chans: usize,
    ) -> States<Self::Afc<CS>, Self::Aranya<CS>> {
        let afc = memory::State::<CS>::new();
        let aranya = afc.clone();
        States { afc, aranya }
    }

    fn convert_bidi_keys<CS: CipherSuite>(
        keys: BidiKeys<CS>,
    ) -> (
        <Self::Aranya<CS> as AranyaState>::SealKey,
        <Self::Aranya<CS> as AranyaState>::OpenKey,
    ) {
        let (seal, open) = keys
            .into_keys()
            .expect("should be able to create `SealKey` and `OpenKey`");
        (seal, open)
    }

    fn convert_uni_seal_key<CS: CipherSuite>(
        key: UniSealKey<CS>,
    ) -> <Self::Aranya<CS> as AranyaState>::SealKey {
        key.into_key().expect("should be able to create `SealKey`")
    }

    fn convert_uni_open_key<CS: CipherSuite>(
        key: UniOpenKey<CS>,
    ) -> <Self::Aranya<CS> as AranyaState>::OpenKey {
        key.into_key().expect("should be able to create `OpenKey`")
    }
}

/// [`Engine`] parameterized over [`Aead`].
pub type TestEngine<A> = DefaultEngine<
    Rng,
    TestCs<
        A,
        <DefaultCipherSuite as CipherSuite>::Hash,
        <DefaultCipherSuite as CipherSuite>::Kdf,
        <DefaultCipherSuite as CipherSuite>::Kem,
        <DefaultCipherSuite as CipherSuite>::Mac,
        <DefaultCipherSuite as CipherSuite>::Signer,
    >,
>;

/// An [`Aead`] only used for [`Aead::KeySize`].
pub struct DummyAead;

impl Aead for DummyAead {
    const LIFETIME: Lifetime = Lifetime::Messages(u64::MAX);

    type KeySize = U16;

    type NonceSize = U16;

    type Overhead = U16;

    const MAX_PLAINTEXT_SIZE: u64 = u64::MAX;
    const MAX_ADDITIONAL_DATA_SIZE: u64 = u64::MAX;

    type Key = AeadKey<U16>;

    fn new(_key: &Self::Key) -> Self {
        Self
    }

    fn seal_in_place(
        &self,
        _nonce: &[u8],
        _data: &mut [u8],
        _tag: &mut [u8],
        _additional_data: &[u8],
    ) -> Result<(), SealError> {
        unreachable!()
    }

    fn open_in_place(
        &self,
        _nonce: &[u8],
        _data: &mut [u8],
        _tag: &[u8],
        _additional_data: &[u8],
    ) -> Result<(), OpenError> {
        unreachable!()
    }
}
impl IndCca2 for DummyAead {}
impl HpkeAead for DummyAead {
    const ID: AeadId = AeadId::Other(NonZeroU16::new(42).unwrap());
}
impl Identified for DummyAead {
    const OID: &Oid = oid!("1.2.3");
}

/// An [`Aead`] with a small nonce, limiting the maximum number
/// of encryptions we can perform.
pub struct LimitedAead<A, N> {
    aead: A,
    _n: PhantomData<N>,
}

impl<A, N> Aead for LimitedAead<A, N>
where
    A: Aead,
    N: ArrayLength + IsLess<U65536> + 'static,
{
    const LIFETIME: Lifetime = A::LIFETIME;

    type KeySize = A::KeySize;
    const KEY_SIZE: usize = A::KEY_SIZE;

    type NonceSize = N;

    type Overhead = A::Overhead;
    const OVERHEAD: usize = A::OVERHEAD;

    const MAX_PLAINTEXT_SIZE: u64 = A::MAX_PLAINTEXT_SIZE;
    const MAX_ADDITIONAL_DATA_SIZE: u64 = A::MAX_ADDITIONAL_DATA_SIZE;
    const MAX_CIPHERTEXT_SIZE: u64 = A::MAX_CIPHERTEXT_SIZE;

    type Key = A::Key;

    fn new(key: &Self::Key) -> Self {
        Self {
            aead: A::new(key),
            _n: PhantomData,
        }
    }

    fn seal_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), SealError> {
        let mut real_nonce = GenericArray::<u8, A::NonceSize>::default();
        let min = cmp::min(nonce.len(), real_nonce.len());
        let real_len = real_nonce.len();
        real_nonce[real_len - min..].copy_from_slice(&nonce[..min]);

        self.aead
            .seal_in_place(&real_nonce, data, tag, additional_data)
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError> {
        let mut real_nonce = GenericArray::<u8, A::NonceSize>::default();
        let min = cmp::min(nonce.len(), real_nonce.len());
        let real_len = real_nonce.len();
        real_nonce[real_len - min..].copy_from_slice(&nonce[..min]);

        self.aead
            .open_in_place(&real_nonce, data, tag, additional_data)
    }
}

impl<A, N> IndCca2 for LimitedAead<A, N>
where
    A: IndCca2,
    N: ArrayLength + IsLess<U65536> + 'static,
{
}

impl<A, N> Identified for LimitedAead<A, N>
where
    A: Identified,
{
    const OID: &Oid = A::OID;
}

impl<A, N> HpkeAead for LimitedAead<A, N>
where
    A: HpkeAead,
    N: ArrayLength + IsLess<U65536> + 'static,
{
    const ID: AeadId = A::ID;
}

/// A no-op [`Aead`].
///
/// - `K` is the size in octets of its key.
/// - `N` is the size in octets of its nonce.
/// - `T` is the size in octets of its tag.
/// - `L` is the AEAD's lifetime.
pub struct NoopAead<K, N, T, const L: u64>(PhantomData<(K, N, T)>);

impl<K, N, T, const L: u64> Aead for NoopAead<K, N, T, L>
where
    K: ArrayLength + IsGreaterOrEqual<U16> + IsLess<U65536> + 'static,
    N: ArrayLength + IsLess<U65536> + 'static,
    T: ArrayLength + IsGreaterOrEqual<U16>,
{
    const LIFETIME: Lifetime = Lifetime::Messages(L);

    type KeySize = K;
    type NonceSize = N;
    type Overhead = T;

    const MAX_PLAINTEXT_SIZE: u64 = u64::MAX - Self::OVERHEAD as u64;
    const MAX_ADDITIONAL_DATA_SIZE: u64 = u64::MAX;

    type Key = AeadKey<Self::KeySize>;

    fn new(_key: &Self::Key) -> Self {
        Self(PhantomData)
    }

    fn seal_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        overhead: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), SealError> {
        aead::check_seal_in_place_params::<Self>(nonce, data, overhead, additional_data)?;

        let digest = tuple_hash::<Sha256, _>([nonce, data, additional_data]);
        let min = cmp::min(overhead.len(), digest.len());
        overhead[..min].copy_from_slice(&digest[..min]);
        Ok(())
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        overhead: &[u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError> {
        aead::check_open_in_place_params::<Self>(nonce, data, overhead, additional_data)?;

        let got = tuple_hash::<Sha256, _>([nonce, data, additional_data]);
        let min = cmp::min(overhead.len(), got.len());
        if !bool::from(overhead.ct_eq(&got[..min])) {
            Err(OpenError::Authentication)
        } else {
            Ok(())
        }
    }
}

impl<K, N, T, const L: u64> IndCca2 for NoopAead<K, N, T, L>
where
    K: ArrayLength + IsGreaterOrEqual<U16> + IsLess<U65536> + 'static,
    N: ArrayLength + IsLess<U65536> + 'static,
    T: ArrayLength + IsGreaterOrEqual<U16>,
{
}

impl<K, N, T, const L: u64> Identified for NoopAead<K, N, T, L> {
    const OID: &Oid = oid!("1.2.3");
}

impl<K, N, T, const L: u64> HpkeAead for NoopAead<K, N, T, L>
where
    K: ArrayLength + IsGreaterOrEqual<U16> + IsLess<U65536> + 'static,
    N: ArrayLength + IsLess<U65536> + 'static,
    T: ArrayLength + IsGreaterOrEqual<U16>,
{
    const ID: AeadId = AeadId::Other(NonZeroU16::new(42).unwrap());
}

/// Returns a random `u32` in [0, n).
pub fn rand_intn<R: Csprng>(rng: &mut R, n: u32) -> u32 {
    fn rand_u32<R: Csprng>(rng: &mut R) -> u32 {
        let mut b = [0u8; 4];
        rng.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    assert_ne!(n, 0);
    if n.is_power_of_two() {
        return rand_u32(rng) & (n - 1);
    }
    let mut v = rand_u32(rng);
    if v > u32::MAX - n {
        let ceil = u32::MAX - u32::MAX % n;
        while v >= ceil {
            v = rand_u32(rng);
        }
    }
    v % n
}

/// Used to modify [`Header`]s.
#[derive(Default)]
pub struct HeaderBuilder {
    /// The APS protocol version.
    version: Option<u16>,
    /// The type of message.
    msg_type: Option<u16>,
    /// The channel label.
    label: Option<u32>,
    /// The message sequence number.
    seq: Option<u64>,
}

impl HeaderBuilder {
    /// Creates a new `HeaderBuilder`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `version` field.
    pub fn version(mut self, v: u16) -> Self {
        self.version = Some(v);
        self
    }

    /// Sets the `msg_typ` field.
    pub fn msg_type(mut self, typ: u16) -> Self {
        self.msg_type = Some(typ);
        self
    }

    /// Sets the `label` field.
    pub fn label(mut self, label: u32) -> Self {
        self.label = Some(label);
        self
    }

    /// Sets the `seq` field.
    pub fn seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }

    /// Modifies the header at the end of `buf`.
    pub fn encode(self, buf: &mut [u8]) {
        let (_, out) = buf
            .split_last_chunk_mut()
            .expect("`ciphertext` should contain a header");
        let hdr = Header::try_parse(out).unwrap_or(Header {
            version: Version::V1,
            msg_type: MsgType::Data,
            label: Label::new(0),
        });

        // NB: we have to do this manually because `Header` uses
        // enums like `Version`, not raw integers.
        let (version_out, rest) = out
            .split_first_chunk_mut()
            .expect("`out` should be large enough for `Version`");
        *version_out = self.version.unwrap_or(hdr.version.to_u16()).to_le_bytes();

        let (msg_typ_out, rest) = rest
            .split_first_chunk_mut()
            .expect("`out` should be large enough for `MsgType`");
        *msg_typ_out = self.msg_type.unwrap_or(hdr.msg_type.to_u16()).to_le_bytes();

        let (label_out, rest) = rest
            .split_first_chunk_mut()
            .expect("`out` should be large enough for `Label`");
        *label_out = self.label.unwrap_or(hdr.label.to_u32()).to_le_bytes();

        assert!(rest.is_empty(), "`out` should be exactly `Header::SIZE`");
    }
}

/// Used to modify `DataHeader`s.
#[derive(Default)]
pub struct DataHeaderBuilder {
    /// The channel label.
    label: Option<u32>,
    /// The message sequence number.
    seq: Option<u64>,
}

impl DataHeaderBuilder {
    /// Creates a new `HeaderBuilder`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `label` field.
    pub fn label(mut self, label: u32) -> Self {
        self.label = Some(label);
        self
    }

    /// Sets the `seq` field.
    pub fn seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }

    /// Modifies the header at the end of `buf`.
    pub fn encode(self, buf: &mut [u8]) {
        let (_, out) = buf
            .split_last_chunk_mut()
            .expect("`ciphertext` should contain a header");
        let hdr = DataHeader::try_parse(out).expect("should be able to parse `DataHeader`");

        let (label_out, rest) = out
            .split_first_chunk_mut()
            .expect("`out` should be large enough for `Label`");
        *label_out = self.label.unwrap_or(hdr.label.to_u32()).to_le_bytes();

        let (seq_out, rest) = rest
            .split_first_chunk_mut()
            .expect("`out` should be large enough for `Seq`");
        *seq_out = self.seq.unwrap_or(hdr.seq.to_u64()).to_le_bytes();

        assert!(rest.is_empty(), "`out` should be exactly `Header::SIZE`");
    }
}
