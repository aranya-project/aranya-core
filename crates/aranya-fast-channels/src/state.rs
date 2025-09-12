use core::{
    fmt::{self, Debug},
    ops::Deref,
};

use aranya_crypto::{
    CipherSuite,
    afc::{OpenKey, SealKey},
    policy::LabelId,
    subtle::ConstantTimeEq,
};
use byteorder::{ByteOrder, LittleEndian};
use derive_where::derive_where;
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// AFC's view of the shared state.
pub trait AfcState {
    /// Used to encrypt/decrypt messages.
    type CipherSuite: CipherSuite;

    /// Invokes `f` with the channel's encryption key.
    ///
    /// # Errors
    ///
    /// Returns an error if `label_id` does not match the label ID associated
    /// with the channel.
    fn seal<F, T>(&self, id: ChannelId, label_id: LabelId, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>) -> Result<T, Error>;

    /// Invokes `f` with the channel's decryption key.
    ///
    /// # Errors
    ///
    /// Returns an error if `label_id` does not match the label ID associated
    /// with the channel.
    fn open<F, T>(&self, id: ChannelId, label_id: LabelId, f: F) -> Result<Result<T, Error>, Error>
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
        label_id: LabelId,
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

/// A unique identifier representing a channel.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct ChannelId(pub(crate) u32);

impl ChannelId {
    /// Creates a [`ChannelId`].
    pub const fn new(id: u32) -> Self {
        ChannelId(id)
    }

    /// The size in bytes of an ID.
    pub const SIZE: usize = 4;

    /// Creates a [`ChannelId`] from its little-endian
    /// representation.
    pub fn from_bytes(b: &[u8]) -> Self {
        Self::new(LittleEndian::read_u32(b))
    }

    /// Converts the [`ChannelId`] to its little-endian
    /// representation.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        self.put_bytes(&mut b);
        b
    }

    /// Converts the [`ChannelId`] to its little-endian
    /// representation.
    pub fn put_bytes(&self, dst: &mut [u8]) {
        LittleEndian::write_u32(dst, self.0);
    }

    /// Converts the [`ChannelId`] to its u32 representation.
    pub const fn to_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for ChannelId {
    fn from(id: u32) -> Self {
        Self::new(id)
    }
}

/// An AFC channel.
#[derive(Copy, Clone)]
#[derive_where(Debug)]
pub struct Channel<S, O> {
    /// Uniquely identifies the channel.
    pub id: ChannelId,
    /// The channel's encryption keys.
    pub keys: Directed<S, O>,
    /// Uniquely identifies the label.
    pub label_id: LabelId,
}

impl<S, O> Channel<S, O> {
    /// Converts from `Channel<T>` to `Channel<&T>>`.
    pub const fn as_ref(&self) -> Channel<&S, &O> {
        Channel {
            id: self.id,
            keys: self.keys.as_ref(),
            label_id: self.label_id,
        }
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
        CipherSuite, Rng,
        afc::{BidiKeys, OpenKey, SealKey, UniOpenKey, UniSealKey},
        policy::LabelId,
    };
    use buggy::Bug;
    use derive_where::derive_where;

    use crate::{
        AfcState, AranyaState, ChannelId, Directed,
        error::Error,
        memory,
        testing::{
            test_impl,
            util::{MockImpl, NodeId, States, TestImpl},
        },
    };

    test_impl!(mock, MockImpl);

    /// An implementation of [`AfcState`] and [`AranyaState`]
    /// that defers to default trait methods.
    #[derive_where(Clone, Default)]
    pub struct DefaultState<CS: CipherSuite> {
        state: memory::State<CS>,
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

        fn seal<F, T>(
            &self,
            id: ChannelId,
            label_id: LabelId,
            f: F,
        ) -> Result<Result<T, Error>, Error>
        where
            F: FnOnce(&mut SealKey<Self::CipherSuite>) -> Result<T, Error>,
        {
            self.state.seal(id, label_id, f)
        }

        fn open<F, T>(
            &self,
            id: ChannelId,
            label_id: LabelId,
            f: F,
        ) -> Result<Result<T, Error>, Error>
        where
            F: FnOnce(&OpenKey<Self::CipherSuite>) -> Result<T, Error>,
        {
            self.state.open(id, label_id, f)
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
            label_id: LabelId,
        ) -> Result<(), Self::Error> {
            self.state.add(id, keys, label_id)?;
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
