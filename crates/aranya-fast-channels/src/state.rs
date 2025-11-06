use core::{
    fmt::{self, Debug},
    ops::Deref,
};

use aranya_crypto::{
    CipherSuite, DeviceId,
    afc::{OpenKey, SealKey},
    policy::LabelId,
    subtle::ConstantTimeEq,
};
use derive_where::derive_where;
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// AFC's view of the shared state.
pub trait AfcState {
    /// Used to encrypt/decrypt messages.
    type CipherSuite: CipherSuite;

    type SealCtx;

    /// Sets up the seal context for a given channel.
    ///
    /// # SAFETY
    /// This must only be called once for any `id`.
    unsafe fn setup_seal_ctx(&self, id: LocalChannelId) -> Result<Self::SealCtx, Error>;

    /// Invokes `f` with the channel's encryption key.
    fn seal<F, T>(&self, ctx: &mut Self::SealCtx, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>, LabelId) -> Result<T, Error>;

    /// Invokes `f` with the channel's decryption key.
    fn open<F, T>(&self, id: LocalChannelId, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&OpenKey<Self::CipherSuite>, LabelId) -> Result<T, Error>;

    /// Reports whether the channel exists.
    fn exists(&self, id: LocalChannelId) -> Result<bool, Error>;
}

/// The set of Params passed to the closure in [AranyaState::remove_if]
pub struct RemoveIfParams {
    /// Channel ID
    pub local_channel_id: LocalChannelId,
    /// Label ID associated with the channel
    pub label_id: LabelId,
    /// The device ID of the peer associated with this channel
    pub peer_id: DeviceId,
    /// Describes the direction that data flows in the channel.
    pub direction: ChannelDirection,
}

impl RemoveIfParams {
    /// Create a new [RemoveIfParams].
    pub fn new(
        local_channel_id: LocalChannelId,
        label_id: LabelId,
        peer_id: DeviceId,
        direction: ChannelDirection,
    ) -> Self {
        Self {
            local_channel_id,
            label_id,
            peer_id,
            direction,
        }
    }
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

    /// Adds a new channel.
    fn add(
        &self,
        keys: Directed<Self::SealKey, Self::OpenKey>,
        label_id: LabelId,
        peer_id: DeviceId,
    ) -> Result<LocalChannelId, Self::Error>;

    /// Removes an existing channel.
    ///
    /// It is not an error if the channel does not exist.
    fn remove(&self, id: LocalChannelId) -> Result<(), Self::Error> {
        self.remove_if(|p| p.local_channel_id == id)
    }

    /// Removes all existing channels.
    ///
    /// It is not an error if the channel does not exist.
    fn remove_all(&self) -> Result<(), Self::Error> {
        self.remove_if(|_| true)
    }

    /// Removes channels where `f(params)` returns true.
    ///
    /// It is not an error if the channel does not exist.
    fn remove_if(&self, f: impl FnMut(RemoveIfParams) -> bool) -> Result<(), Self::Error>;

    /// Reports whether the channel exists.
    fn exists(&self, id: LocalChannelId) -> Result<bool, Self::Error>;
}

/// Uniquely identifies a channel inside the shared state.
///
/// This is strictly a local identifier.
// TODO(eric): Make this 32 bits on 32-bit platforms?
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct LocalChannelId(u64);

impl LocalChannelId {
    /// Creates a [`LocalChannelId`].
    #[cfg(any(test, feature = "sdlib", feature = "posix", feature = "memory"))]
    pub(crate) const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Converts the [`LocalChannelId`] to its `u64` representation.
    #[cfg(any(feature = "sdlib", feature = "posix"))]
    pub(crate) const fn to_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for LocalChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An AFC channel.
#[derive(Copy, Clone)]
#[derive_where(Debug)]
pub struct Channel<S, O> {
    /// Uniquely identifies the channel.
    pub id: LocalChannelId,
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
}

impl<S, O> Directed<S, O> {
    /// Returns the secret used for encryption.
    pub fn seal(&self) -> Option<&S> {
        match self {
            Self::SealOnly { seal } => Some(seal),
            Self::OpenOnly { .. } => None,
        }
    }

    /// Returns the secret used for encryption.
    pub fn seal_mut(&mut self) -> Option<&mut S> {
        match self {
            Self::SealOnly { seal } => Some(seal),
            Self::OpenOnly { .. } => None,
        }
    }

    /// Returns the secret used for decryption.
    pub fn open(&self) -> Option<&O> {
        match self {
            Self::OpenOnly { open } => Some(open),
            Self::SealOnly { .. } => None,
        }
    }

    /// Returns the secret used for decryption.
    pub fn open_mut(&mut self) -> Option<&mut O> {
        match self {
            Self::OpenOnly { open } => Some(open),
            Self::SealOnly { .. } => None,
        }
    }

    /// Returns the corresponding [ChannelDirection].
    pub fn direction(&self) -> ChannelDirection {
        match self {
            Self::SealOnly { .. } => ChannelDirection::Seal,
            Self::OpenOnly { .. } => ChannelDirection::Open,
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
        }
    }
}

impl<S, O> Directed<S, O> {
    /// Converts from `Directed<S, O>` to `Directed<&S, &O>>`.
    pub const fn as_ref(&self) -> Directed<&S, &O> {
        match *self {
            Self::SealOnly { ref seal } => Directed::SealOnly { seal },
            Self::OpenOnly { ref open } => Directed::OpenOnly { open },
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
            (Self::SealOnly { seal: lhs }, Self::SealOnly { seal: rhs }) => {
                bool::from(lhs.ct_eq(rhs))
            }
            (Self::OpenOnly { open: lhs }, Self::OpenOnly { open: rhs }) => {
                bool::from(lhs.ct_eq(rhs))
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
        }
    }
}

/// Describes the flow of data for an AFC channel.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum ChannelDirection {
    /// See [`Directed::SealOnly`].
    Seal,
    /// See [`Directed::OpenOnly`].
    Open,
}

#[cfg(test)]
mod test {
    use aranya_crypto::{
        CipherSuite, DeviceId, Rng,
        afc::{OpenKey, SealKey, UniOpenKey, UniSealKey},
        policy::LabelId,
    };
    use derive_where::derive_where;

    use crate::{
        AfcState, AranyaState, Directed, LocalChannelId, RemoveIfParams,
        error::Error,
        memory,
        testing::{
            test_impl,
            util::{DeviceIdx, MockImpl, States, TestImpl},
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
        type SealCtx = <memory::State<CS> as AfcState>::SealCtx;

        unsafe fn setup_seal_ctx(&self, id: LocalChannelId) -> Result<Self::SealCtx, Error> {
            unsafe { self.state.setup_seal_ctx(id) }
        }

        fn seal<F, T>(&self, ctx: &mut Self::SealCtx, f: F) -> Result<Result<T, Error>, Error>
        where
            F: FnOnce(&mut SealKey<Self::CipherSuite>, LabelId) -> Result<T, Error>,
        {
            self.state.seal(ctx, f)
        }

        fn open<F, T>(&self, id: LocalChannelId, f: F) -> Result<Result<T, Error>, Error>
        where
            F: FnOnce(&OpenKey<Self::CipherSuite>, LabelId) -> Result<T, Error>,
        {
            self.state.open(id, f)
        }

        fn exists(&self, id: LocalChannelId) -> Result<bool, Error> {
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
        type Error = Error;

        fn add(
            &self,
            keys: Directed<Self::SealKey, Self::OpenKey>,
            label_id: LabelId,
            peer_id: DeviceId,
        ) -> Result<LocalChannelId, Self::Error> {
            let id = self.state.add(keys, label_id, peer_id)?;
            Ok(id)
        }

        fn remove_if(&self, f: impl FnMut(RemoveIfParams) -> bool) -> Result<(), Self::Error> {
            self.state.remove_if(f)?;
            Ok(())
        }

        fn exists(&self, id: LocalChannelId) -> Result<bool, Self::Error> {
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
            _device_idx: DeviceIdx,
            _max_chans: usize,
        ) -> States<Self::Afc<CS>, Self::Aranya<CS>> {
            let afc = DefaultState::<CS>::new();
            let aranya = afc.clone();
            States { afc, aranya }
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
