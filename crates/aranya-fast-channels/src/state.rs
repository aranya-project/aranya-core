use core::{
    fmt::{self, Debug},
    ops::Deref,
};

use aranya_crypto::{
    afc::{OpenKey, SealKey},
    subtle::ConstantTimeEq,
    CipherSuite,
};
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// AFC's view of the shared state.
pub trait AfcState {
    /// Used to encrypt/decrypt messages.
    type CipherSuite: CipherSuite;

    /// Invokes `f` with the channel's encryption key.
    fn seal<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>) -> Result<T, Error>;

    /// Invokes `f` with the channel's decryption key.
    fn open<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&OpenKey<Self::CipherSuite>) -> Result<T, Error>;

    /// Reports whether the channel exists.
    fn exists(&self, id: ChannelId) -> Result<bool, Error>;
}

/// Aranya's view of the shared state.
pub trait AranyaState {
    /// The error returned by `AranyaState`'s methods.
    type Error: core::error::Error;

    /// Used to encrypt/decrypt messages.
    type CipherSuite: CipherSuite;

    /// The type of key used to encrypt messages.
    type SealKey;

    /// The type of key used to decrypt messages.
    type OpenKey;

    /// Adds or updates a channel.
    fn add(
        &self,
        id: ChannelId,
        keys: Directed<Self::SealKey, Self::OpenKey>,
    ) -> Result<(), Self::Error>;

    /// Removes an existing channel.
    ///
    /// It is not an error if the channel does not exist.
    fn remove(&self, id: ChannelId) -> Result<(), Self::Error> {
        self.remove_if(|v| v == id)
    }

    /// Removes all existing channels.
    ///
    /// It is not an error if the channel does not exist.
    fn remove_all(&self) -> Result<(), Self::Error> {
        self.remove_if(|_| true)
    }

    /// Removes channels where `f(id)` returns true.
    ///
    /// It is not an error if the channel does not exist.
    fn remove_if(&self, f: impl FnMut(ChannelId) -> bool) -> Result<(), Self::Error>;

    /// Reports whether the channel exists.
    fn exists(&self, id: ChannelId) -> Result<bool, Self::Error>;
}

/// Uniquely identifies a channel for a particular [`AfcState`]
/// and [`AranyaState`].
///
/// It has two primary parts: a [`NodeId`] that identifies the
/// team member and a [`Label`] that identifies the set of policy
/// rules that govern the channel.
///
/// A [`Channel`] must be enabled in Aranya before it can be
/// used. Otherwise, methods like
/// [`Client::seal`][crate::Client::seal] will be unable to find
/// it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct ChannelId {
    node_id: NodeId,
    label: Label,
}

impl ChannelId {
    /// Creates a channel.
    pub const fn new(id: NodeId, label: Label) -> Self {
        ChannelId { node_id: id, label }
    }

    /// Returns the team member's ID.
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the channel's label.
    pub const fn label(&self) -> Label {
        self.label
    }

    /// Converts the ID to bytes.
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        self.node_id().put_bytes(&mut b[..4]);
        self.label().put_bytes(&mut b[4..]);
        b
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChannelId(node_id={}, label={})",
            self.node_id, self.label
        )
    }
}

/// A local identifier that associates a [`Channel`] with an
/// Aranya team member.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct NodeId(u32);

impl NodeId {
    /// Creates a [`NodeId`].
    pub const fn new(id: u32) -> Self {
        NodeId(id)
    }

    /// The size in bytes of an ID.
    pub const SIZE: usize = 4;

    /// Creates a [`NodeId`] from its little-endian
    /// representation.
    pub fn from_bytes(b: &[u8]) -> Self {
        Self::new(LittleEndian::read_u32(b))
    }

    /// Converts the [`NodeId`] to its little-endian
    /// representation.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        self.put_bytes(&mut b);
        b
    }

    /// Converts the [`NodeId`] to its little-endian
    /// representation.
    pub fn put_bytes(&self, dst: &mut [u8]) {
        LittleEndian::write_u32(dst, self.0);
    }

    /// Converts the [`NodeId`] to its u32 representation.
    pub const fn to_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for NodeId {
    fn from(id: u32) -> Self {
        Self::new(id)
    }
}

/// Associates a [`Channel`] with Aranya policy rules that govern
/// communication in the channel.
///
/// Labels are defined inside Aranya policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Label(u32);

impl Label {
    /// Creates a [`Label`] from its policy source ID.
    pub const fn new(label: u32) -> Self {
        Self(label)
    }

    /// The size in bytes of a label.
    pub const SIZE: usize = 4;

    /// Creates a label from its little-endian
    /// representation.
    pub fn from_bytes(b: &[u8]) -> Self {
        Label::new(LittleEndian::read_u32(b))
    }

    /// Converts the [`Label`] to its little-endian
    /// representation.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        self.put_bytes(&mut b);
        b
    }

    /// Converts the [`Label`] to its little-endian
    /// representation.
    pub fn put_bytes(&self, dst: &mut [u8]) {
        LittleEndian::write_u32(dst, self.to_u32());
    }

    /// Converts the label to a `u32`.
    pub const fn to_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_u32())
    }
}

impl From<u32> for Label {
    fn from(id: u32) -> Self {
        Self::new(id)
    }
}

/// An AFC channel.
#[derive(Copy, Clone)]
pub struct Channel<S, O> {
    /// Uniquely identifies the channel.
    pub id: ChannelId,
    /// The channel's encryption keys.
    pub keys: Directed<S, O>,
}

impl<S, O> Channel<S, O> {
    /// Converts from `Channel<T>` to `Channel<&T>>`.
    pub const fn as_ref(&self) -> Channel<&S, &O> {
        Channel {
            id: self.id,
            keys: self.keys.as_ref(),
        }
    }
}

impl<S, O> Debug for Channel<S, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("id", &self.id)
            .field("keys", &self.keys)
            .finish()
    }
}

/// A directed channel secret.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum Directed<S, O> {
    /// For the encryption half of a unidirectional channel.
    SealOnly {
        /// Used for encryption.
        seal: S,
    },
    /// For the decryption half of a unidirectional channel.
    OpenOnly {
        /// Used for decryption.
        open: O,
    },
    /// For bidirectional channels.
    Bidirectional {
        /// Used for encryption.
        seal: S,
        /// Used for decryption.
        open: O,
    },
}

impl<S, O> Directed<S, O> {
    /// Returns the secret used for encryption.
    pub fn seal(&self) -> Option<&S> {
        match self {
            Self::SealOnly { seal } | Self::Bidirectional { seal, .. } => Some(seal),
            Self::OpenOnly { .. } => None,
        }
    }

    /// Returns the secret used for encryption.
    pub fn seal_mut(&mut self) -> Option<&mut S> {
        match self {
            Self::SealOnly { seal } | Self::Bidirectional { seal, .. } => Some(seal),
            Self::OpenOnly { .. } => None,
        }
    }

    /// Returns the secret used for decryption.
    pub fn open(&self) -> Option<&O> {
        match self {
            Self::OpenOnly { open } | Self::Bidirectional { open, .. } => Some(open),
            Self::SealOnly { .. } => None,
        }
    }

    /// Returns the secret used for decryption.
    pub fn open_mut(&mut self) -> Option<&mut O> {
        match self {
            Self::OpenOnly { open } | Self::Bidirectional { open, .. } => Some(open),
            Self::SealOnly { .. } => None,
        }
    }
}

impl<S, O> Directed<&S, &O> {
    /// Maps a `Directed<&S, &O>` to `Directed<S, O>`.
    pub fn cloned(self) -> Directed<S, O>
    where
        S: Clone,
        O: Clone,
    {
        match self {
            Self::SealOnly { seal } => Directed::SealOnly { seal: seal.clone() },
            Self::OpenOnly { open } => Directed::OpenOnly { open: open.clone() },
            Self::Bidirectional { seal, open } => Directed::Bidirectional {
                seal: seal.clone(),
                open: open.clone(),
            },
        }
    }
}

impl<S, O> Directed<S, O> {
    /// Converts from `Directed<S, O>` to `Directed<&S, &O>>`.
    pub const fn as_ref(&self) -> Directed<&S, &O> {
        match *self {
            Self::SealOnly { ref seal } => Directed::SealOnly { seal },
            Self::OpenOnly { ref open } => Directed::OpenOnly { open },
            Self::Bidirectional { ref seal, ref open } => Directed::Bidirectional { seal, open },
        }
    }

    /// Converts from `Directed<S, O>` to `Directed<&S::Target,
    /// &O::Target>`.
    pub fn as_deref(&self) -> Directed<&<S as Deref>::Target, &<O as Deref>::Target>
    where
        S: Deref,
        O: Deref,
    {
        match self.as_ref() {
            Directed::SealOnly { seal } => Directed::SealOnly { seal: seal.deref() },
            Directed::OpenOnly { open } => Directed::OpenOnly { open: open.deref() },
            Directed::Bidirectional { seal, open } => Directed::Bidirectional {
                seal: seal.deref(),
                open: open.deref(),
            },
        }
    }
}

impl<S, O> Eq for Directed<S, O>
where
    S: ConstantTimeEq,
    O: ConstantTimeEq,
{
}

// Manually implement `PartialEq` (instead of deriving) so that
// comparisons are in constant time.
impl<S, O> PartialEq for Directed<S, O>
where
    S: ConstantTimeEq,
    O: ConstantTimeEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Directed::SealOnly { seal: lhs }, Directed::SealOnly { seal: rhs }) => {
                bool::from(lhs.ct_eq(rhs))
            }
            (Directed::OpenOnly { open: lhs }, Directed::OpenOnly { open: rhs }) => {
                bool::from(lhs.ct_eq(rhs))
            }
            (
                Directed::Bidirectional {
                    seal: lhs_seal,
                    open: lhs_open,
                },
                Directed::Bidirectional {
                    seal: rhs_seal,
                    open: rhs_open,
                },
            ) => {
                let seal = lhs_seal.ct_eq(rhs_seal);
                let open = lhs_open.ct_eq(rhs_open);
                bool::from(seal & open)
            }
            _ => false,
        }
    }
}

// Manually implement `Debug` so that we don't leak secrets.
impl<S, O> Debug for Directed<S, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SealOnly { .. } => f.write_str("SealOnly { .. }"),
            Self::OpenOnly { .. } => f.write_str("OpenOnly { .. }"),
            Self::Bidirectional { .. } => f.write_str("Bidirectional { .. }"),
        }
    }
}

#[cfg(test)]
mod test {
    use aranya_crypto::{
        afc::{BidiKeys, OpenKey, SealKey, UniOpenKey, UniSealKey},
        CipherSuite, Rng,
    };
    use buggy::Bug;

    use crate::{
        error::Error,
        memory,
        testing::{
            test_impl,
            util::{MockImpl, States, TestImpl},
        },
        AfcState, AranyaState, ChannelId, Directed, NodeId,
    };

    test_impl!(mock, MockImpl);

    /// An implementation of [`AfcState`] and [`AranyaState`]
    /// that defers to default trait methods.
    pub struct DefaultState<CS: CipherSuite> {
        state: memory::State<CS>,
    }

    impl<CS: CipherSuite> Clone for DefaultState<CS> {
        fn clone(&self) -> Self {
            DefaultState {
                state: self.state.clone(),
            }
        }
    }

    impl<CS: CipherSuite> Default for DefaultState<CS> {
        fn default() -> Self {
            Self {
                state: memory::State::default(),
            }
        }
    }

    impl<CS: CipherSuite> DefaultState<CS> {
        /// Creates a new `DefaultState`.
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl<CS> AfcState for DefaultState<CS>
    where
        CS: CipherSuite,
    {
        type CipherSuite = CS;

        fn seal<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, Error>, Error>
        where
            F: FnOnce(&mut SealKey<Self::CipherSuite>) -> Result<T, Error>,
        {
            self.state.seal(id, f)
        }

        fn open<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, Error>, Error>
        where
            F: FnOnce(&OpenKey<Self::CipherSuite>) -> Result<T, Error>,
        {
            self.state.open(id, f)
        }

        fn exists(&self, id: ChannelId) -> Result<bool, Error> {
            AfcState::exists(&self.state, id)
        }
    }

    impl<CS> AranyaState for DefaultState<CS>
    where
        CS: CipherSuite,
    {
        type CipherSuite = CS;

        type SealKey = SealKey<CS>;
        type OpenKey = OpenKey<CS>;
        type Error = Bug;

        fn add(
            &self,
            id: ChannelId,
            keys: Directed<Self::SealKey, Self::OpenKey>,
        ) -> Result<(), Self::Error> {
            self.state.add(id, keys)?;
            Ok(())
        }

        fn remove_if(&self, f: impl FnMut(ChannelId) -> bool) -> Result<(), Self::Error> {
            self.state.remove_if(f)?;
            Ok(())
        }

        fn exists(&self, id: ChannelId) -> Result<bool, Self::Error> {
            AranyaState::exists(&self.state, id)
        }
    }

    /// A [`TestImpl`] that uses [`State`].
    pub struct DefaultImpl;

    impl TestImpl for DefaultImpl {
        type Afc<CS: CipherSuite> = DefaultState<CS>;
        type Aranya<CS: CipherSuite> = DefaultState<CS>;
        type Rng = Rng;

        fn new_states<CS: CipherSuite>(
            _name: &str,
            _node_id: NodeId,
            _max_chans: usize,
        ) -> States<Self::Afc<CS>, Self::Aranya<CS>> {
            let afc = DefaultState::<CS>::new();
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

    test_impl!(default, DefaultImpl);
}
