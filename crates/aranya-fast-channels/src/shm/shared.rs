use core::{alloc::Layout, marker::PhantomData};

use aranya_crypto::{
    CipherSuite, Csprng, DeviceId, Random,
    afc::{OpenKey, RawOpenKey, RawSealKey, SealKey, Seq},
    dangerous::spideroak_crypto::{aead::Aead, hash::tuple_hash},
    policy::LabelId,
};
use buggy::Bug;
use cfg_if::cfg_if;
use derive_where::derive_where;

use super::{
    error::{
        Corrupted, Error, LayoutError, bad_chan_direction, bad_chan_magic, bad_state_key_size,
        bad_state_magic, bad_state_size, bad_state_version,
    },
    le::{U32, U64},
    path::{Flag, Mode, Path},
};
#[allow(unused_imports)]
use crate::features::*;
use crate::{
    ChannelDirection, RemoveIfParams,
    arena::Arena,
    errno::Errno,
    state::{Directed, LocalChannelId},
};

cfg_if! {
    if #[cfg(feature = "sdlib")] {
        use super::sdlib::Mapping;
    } else {
        use super::posix::Mapping;
    }
}

/// Causes a compilation error if `$type` is not FFI safe.
macro_rules! assert_ffi_safe {
    ($type:ty) => {
        const _: () = {
            if cfg!(debug_assertions) {
                #[allow(dead_code)]
                #[deny(improper_ctypes, improper_ctypes_definitions)]
                extern "C" fn foo(_: $type) {}
            }
        };
    };
}
pub(crate) use assert_ffi_safe;

pub(super) fn index_from_id(id: LocalChannelId) -> crate::arena::Index {
    unsafe { core::mem::transmute::<u64, crate::arena::Index>(id.to_u64()) }
}

pub(super) fn id_from_index(idx: crate::arena::Index) -> LocalChannelId {
    LocalChannelId::new(unsafe { core::mem::transmute::<crate::arena::Index, u64>(idx) })
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum PageSizeError {
    /// `sysconf` failed.
    #[error("unable to get page size: {0}")]
    Errno(#[from] Errno),
    /// A bug was discovered.
    #[error("unable to get page size: {0}")]
    Bug(#[from] Bug),
}

/// Used by both `ReadState` and `WriteState`.
#[derive(Debug)]
pub(super) struct State<CS: CipherSuite> {
    ptr: Mapping<SharedMem<CS>>,
    /// The maximum number of channels supported by the shared
    /// memory.
    max_chans: u32,
}

impl<CS: CipherSuite> State<CS> {
    /// Creates a new `State`.
    pub(super) fn open<P: AsRef<Path>>(
        path: P,
        flag: Flag,
        mode: Mode,
        max_chans: u32,
    ) -> Result<Self, Error> {
        let layout = SharedMem::<CS>::layout(max_chans)?;
        let ptr = Mapping::open(path.as_ref(), flag, mode, layout)?;
        if flag == Flag::Create {
            SharedMem::init(ptr.as_ptr(), max_chans, layout);
        }
        let state = Self { ptr, max_chans };
        state.validate()?;
        Ok(state)
    }

    /// Performs basic sanity checking on the shared memory.
    ///
    /// Does not check the read/write offsets as they might be
    /// changing (if the daemon is active) and we don't want to
    /// have to do a CAS loop.
    fn validate(&self) -> Result<(), Corrupted> {
        let shm = self.shm();
        if shm.magic != SharedMem::<CS>::MAGIC {
            return Err(bad_state_magic(shm.magic));
        }
        if shm.version != SharedMem::<CS>::VERSION {
            return Err(bad_state_version(shm.version, SharedMem::<CS>::VERSION));
        }
        let layout = SharedMem::<CS>::layout(self.max_chans)?;
        if shm.size != layout.size() as u64 {
            return Err(bad_state_size(shm.size, layout.size() as u64));
        }
        if shm.key_size != SharedMem::<CS>::KEY_SIZE {
            return Err(bad_state_key_size(shm.key_size));
        }
        Ok(())
    }

    /// Returns the inner [`SharedMem`].
    pub(super) fn shm(&self) -> &SharedMem<CS> {
        self.ptr.as_ref()
    }
}

/// Describes one of [`ShmChan`]'s variants.
// NB: see `ShmChan::matches` to understand the
// discriminants.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum ChanDirection {
    /// See [`Directed::SealOnly`].
    SealOnly = 1,
    /// See [`Directed::OpenOnly`].
    OpenOnly = 2,
}

impl ChanDirection {
    /// Converts the `ChanDirection` to its 32-bit integer
    /// representation.
    const fn to_u32(self) -> u32 {
        self as u32
    }

    fn from_directed<S, O>(dir: &Directed<S, O>) -> Self {
        match dir {
            Directed::SealOnly { .. } => Self::SealOnly,
            Directed::OpenOnly { .. } => Self::OpenOnly,
        }
    }

    /// Creates a `ChanDirection` from its integer
    /// representation.
    const fn try_from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::SealOnly),
            2 => Some(Self::OpenOnly),
            _ => None,
        }
    }
}

impl From<ChanDirection> for ChannelDirection {
    fn from(value: ChanDirection) -> Self {
        match value {
            ChanDirection::SealOnly => Self::Seal,
            ChanDirection::OpenOnly => Self::Open,
        }
    }
}

/// The contents of the shared memory.
///
/// It is (at least) aligned to the size of a cache line.
#[cfg_attr(
    any(target_arch = "aarch64", target_arch = "powerpc64"),
    repr(C, align(128))
)]
#[cfg_attr(any(target_arch = "x86_64"), repr(C, align(64)))]
#[cfg_attr(
    any(
        target_arch = "arm",
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "riscv64",
        target_arch = "powerpc",
    ),
    repr(C, align(32))
)]
#[derive_where(Debug)]
pub(super) struct SharedMem<CS: CipherSuite> {
    /// Identifies this memory as a [`SharedMem`].
    ///
    /// Should be [`Self::MAGIC`].
    magic: U32,
    /// shm implementation version
    version: U32,
    max_chans: U32,
    /// The total size of this object, including trailing data.
    size: U64,
    /// The size in bytes of the keys stored in each
    /// [`ChanList`].
    key_size: U64,
    /// The size in bytes of the nonces stored in each
    /// [`ChanList`].
    nonce_size: U64,
    /// Start of the arena.
    arena: PhantomData<Arena<ShmChan<CS>>>,
}
assert_ffi_safe!(SharedMem<aranya_crypto::default::DefaultCipherSuite>);

// SAFETY: `SharedMem` can be safely shared between threads.
unsafe impl<CS: CipherSuite> Sync for SharedMem<CS> {}

impl<CS: CipherSuite> SharedMem<CS> {
    const MAGIC: U32 = U32::new(0xfcee4325);
    const VERSION: U32 = U32::new(0x00000000);
    const KEY_SIZE: U64 = U64::new(<CS::Aead as Aead>::KEY_SIZE as u64);
    const NONCE_SIZE: U64 = U64::new(<CS::Aead as Aead>::NONCE_SIZE as u64);

    /// Initializes the memory at `ptr`.
    pub(super) fn init(ptr: *mut Self, max_chans: u32, layout: Layout) {
        // Zero everything. This simplifies the following
        // code.
        //
        // SAFETY: the pointer is in bounds and will not
        // overflow.
        unsafe { (ptr.cast::<u8>()).write_bytes(0, layout.size()) };

        let shm = Self {
            magic: Self::MAGIC,
            version: Self::VERSION,
            max_chans: max_chans.into(),
            size: U64::from(layout.size() as u64),
            key_size: Self::KEY_SIZE,
            nonce_size: Self::NONCE_SIZE,
            arena: PhantomData,
        };
        // SAFETY: ptr is valid for writes and properly
        // aligned.
        unsafe { ptr.write(shm) };

        // SAFETY: the offsets come directly from memory laid out
        // with `Layout`.
        unsafe {
            Arena::<ShmChan<CS>>::init((&raw mut (*ptr).arena).cast(), max_chans);
        }
    }

    /// Returns its memory layout.
    fn layout(max_chans: u32) -> Result<Layout, LayoutError> {
        Ok(Layout::new::<Self>()
            .extend(Arena::<ShmChan<CS>>::layout(max_chans)?)?
            .0
            .pad_to_align())
    }

    /// Performs basic sanity checking.
    #[track_caller]
    fn check(&self) -> Result<(), Corrupted> {
        // Perform more "expensive" checks in debug mode.
        //
        // We also panic in debug mode so that we get nice stack
        // traces.
        debug_assert_eq!(self.magic, Self::MAGIC);
        debug_assert_eq!(self.version, Self::VERSION);

        let magic = self.magic;
        if unlikely!(magic != Self::MAGIC) {
            Err(bad_state_magic(magic))
        } else {
            Ok(())
        }
    }

    /// Returns the side corresponding with `off`.
    pub(super) fn arena(&self) -> Result<&Arena<ShmChan<CS>>, Corrupted> {
        self.check()?;

        // SAFETY: ptr is non-null, suitably aligned, and won't
        // wrap.
        let arena =
            unsafe { &*Arena::from_parts((&raw const self.arena).cast(), self.max_chans.into()) };
        // TODO: list.check()?;
        Ok(arena)
    }
}

/// The in-memory representation of a channel.
///
/// All integers are little endian.
#[repr(C)]
#[derive_where(Debug)]
pub(super) struct ShmChan<CS: CipherSuite> {
    /// Must be [`ShmChan::MAGIC`].
    magic: U32,
    /// Describes the direction that data flows in the channel.
    direction: U32,
    // /// The channel's ID.
    // pub(super) local_channel_id: U64,
    /// The current encryption sequence counter.
    seq: U64,
    /// The channel's label.
    label_id: LabelId,
    /// The ID of the peer.
    peer_id: DeviceId,
    /// The key/nonce used to encrypt data for the channel peer.
    #[derive_where(skip(Debug))]
    seal_key: RawSealKey<CS>,
    /// The key/nonce used to decrypt data from the channel peer.
    #[derive_where(skip(Debug))]
    open_key: RawOpenKey<CS>,
    /// Uniquely identifies `seal_key` and `open_key`.
    key_id: KeyId,
}
assert_ffi_safe!(ShmChan<aranya_crypto::default::DefaultCipherSuite>);

impl<CS: CipherSuite> ShmChan<CS> {
    /// Identifies the `ShmChan` in memory.
    const MAGIC: U32 = U32::new(0x36bb2c43);

    pub(super) fn new<R: Csprng>(
        label_id: LabelId,
        peer_id: DeviceId,
        keys: &Directed<RawSealKey<CS>, RawOpenKey<CS>>,
        rng: &mut R,
    ) -> Self {
        // As a safety precaution, randomize keys that we don't
        // use. Leaving them unset (usually all zeros) is
        // dangerous.
        //
        // If we were to leave it unset and accidentally use it
        // for encryption, the resulting ciphertext would be
        // encrypted with a non-uniformly random key (e.g., all
        // zeros). By randomizing it, the ciphertext is instead
        // rendered irrecoverable.
        //
        // If we were leave it unset and accidentally use it for
        // decryption, an attacker could create a ciphertext that
        // decrypts and authenticates for the key. Randomizing
        // the key prevents an attacker from crafting such
        // a ciphertext.
        let seal_key = keys.seal().cloned().unwrap_or_else(|| Random::random(rng));
        let open_key = keys.open().cloned().unwrap_or_else(|| Random::random(rng));
        let key_id = KeyId::new(&seal_key, &open_key);
        Self {
            magic: Self::MAGIC,
            direction: ChanDirection::from_directed(keys).to_u32().into(),
            // local_channel_id: id.to_u64().into(),
            // For the same reason that we randomize keys,
            // manually exhaust the sequence number.
            seq: if keys.seal().is_some() {
                U64::new(0)
            } else {
                U64::MAX
            },
            label_id,
            peer_id,
            seal_key,
            open_key,
            key_id,
        }
    }

    pub(super) fn remove_if_params(
        &self,
        idx: crate::arena::Index,
    ) -> Result<RemoveIfParams, Corrupted> {
        Ok(RemoveIfParams {
            local_channel_id: id_from_index(idx),
            label_id: self.label_id()?,
            peer_id: self.peer_id()?,
            direction: self.direction()?.into(),
        })
    }

    #[cfg(test)]
    pub(super) fn keys(&self) -> Result<Directed<&RawSealKey<CS>, &RawOpenKey<CS>>, Corrupted> {
        Ok(match self.direction()? {
            ChanDirection::SealOnly => Directed::SealOnly {
                seal: &self.seal_key,
            },
            ChanDirection::OpenOnly => Directed::OpenOnly {
                open: &self.open_key,
            },
        })
    }

    /// Returns the [label ID][LabelId] associated with this channel.
    #[inline(always)]
    pub(super) fn label_id(&self) -> Result<LabelId, Corrupted> {
        self.check()?;

        Ok(self.label_id)
    }

    /// Returns the [Id of the peer][DeviceId] associated with this channel.
    #[inline(always)]
    fn peer_id(&self) -> Result<DeviceId, Corrupted> {
        self.check()?;

        Ok(self.peer_id)
    }

    fn direction(&self) -> Result<ChanDirection, Corrupted> {
        self.check()?;

        ChanDirection::try_from_u32(self.direction.into()).ok_or(bad_chan_direction(self.direction))
    }

    pub(super) fn seal_key(&self) -> Result<SealKey<CS>, crate::Error> {
        let direction = self.direction()?;
        if direction != ChanDirection::SealOnly {
            // TODO: Better error
            return Err(crate::Error::InvalidArgument("TODO"));
        }
        Ok(SealKey::from_raw(&self.seal_key, self.seq())?)
    }

    pub(super) fn open_key(&self) -> Result<OpenKey<CS>, crate::Error> {
        let direction = self.direction()?;
        if direction != ChanDirection::OpenOnly {
            // TODO: Better error
            return Err(crate::Error::InvalidArgument("TODO"));
        }
        Ok(OpenKey::from_raw(&self.open_key)?)
    }

    /// Returns the encryption sequence number.
    fn seq(&self) -> Seq {
        Seq::new(self.seq.into())
    }

    /// Updates the sequence number.
    pub(super) fn set_seq(&mut self, seq: Seq) {
        debug_assert!(
            seq.to_u64() > self.seq.into(),
            "{} <= {}",
            seq.to_u64(),
            self.seq.into()
        );

        self.seq = seq.to_u64().into();
    }

    /// Performs basic sanity checking.
    #[track_caller]
    pub(super) fn check(&self) -> Result<(), Corrupted> {
        // Perform more "expensive" checks in debug mode.
        //
        // We also panic in debug mode so that we get nice stack
        // traces.
        #[cfg(debug_assertions)]
        {
            assert_eq!(self.magic, Self::MAGIC, "invalid magic");
        }

        let magic = self.magic;
        if unlikely!(magic != Self::MAGIC) {
            Err(bad_chan_magic(magic))
        } else {
            Ok(())
        }
    }
}

/// Uniquely identifies a [`RawSealKey`], [`RawOpenKey`] tuple.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct KeyId([u8; 16]);

impl KeyId {
    fn new<CS: CipherSuite>(seal: &RawSealKey<CS>, open: &RawOpenKey<CS>) -> Self {
        let id = tuple_hash::<CS::Hash, _>([
            seal.key.as_bytes(),
            &seal.base_nonce,
            open.key.as_bytes(),
            &open.base_nonce,
        ])
        .into_array();
        #[allow(
            clippy::unwrap_used,
            clippy::indexing_slicing,
            reason = "The compiler proves that this does not panic."
        )]
        Self(id[..16].try_into().unwrap())
    }
}

// TODO: move into `tests.rs`
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chan_direction() {
        const TYPES: &[ChanDirection] = &[ChanDirection::SealOnly, ChanDirection::OpenOnly];
        for want in TYPES.iter().copied() {
            let got = ChanDirection::try_from_u32(want.to_u32()).expect("should be `Some`");
            assert_eq!(want, got);
        }
    }
}
