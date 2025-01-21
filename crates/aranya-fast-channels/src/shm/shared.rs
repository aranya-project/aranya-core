use core::{
    alloc::Layout,
    fmt,
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
    ptr, slice, str,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

use aranya_buggy::{Bug, BugExt};
use aranya_crypto::{
    aead::Aead,
    afc::{RawOpenKey, RawSealKey, Seq},
    hash::tuple_hash,
    CipherSuite, Csprng, Random,
};
use cfg_if::cfg_if;

use super::{
    align::{is_aligned_to, layout_repeat, CacheAligned},
    error::{
        bad_chan_direction, bad_chan_magic, bad_chanlist_magic, bad_page_alignment,
        bad_state_key_size, bad_state_magic, bad_state_size, bad_state_version, corrupted,
        Corrupted, Error, LayoutError,
    },
    le::{U32, U64},
    path::{Flag, Mode, Path},
};
#[allow(unused_imports)]
use crate::features::*;
use crate::{
    errno::{errno, Errno},
    mutex::Mutex,
    state::{ChannelId, Directed, NodeId},
    util::{const_assert, debug},
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

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum PageSizeError {
    /// `sysconf` failed.
    #[error("unable to get page size: {0}")]
    Errno(#[from] Errno),
    /// A bug was discovered.
    #[error("unable to get page size: {0}")]
    Bug(#[from] Bug),
}

/// Returns the current page size if the `libc` feature is
/// enabled, or `None` otherwise.
fn getpagesize() -> Result<Option<usize>, PageSizeError> {
    #[cfg(feature = "libc")]
    {
        // SAFETY: FFI call, no invariants.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size < 0 {
            Err(PageSizeError::Errno(errno()))
        } else {
            let size = usize::try_from(size).assume("`_SC_PAGESIZE` should fit in `usize`")?;
            Ok(Some(size))
        }
    }
    #[cfg(not(feature = "libc"))]
    {
        Ok(None)
    }
}

/// Used by both `ReadState` and `WriteState`.
pub(super) struct State<CS> {
    ptr: Mapping<SharedMem<CS>>,
    /// The maximum number of channels supported by the shared
    /// memory.
    max_chans: usize,
    /// The known valid offset of side_a.
    ///
    /// Used to validate read_off and write_off.
    side_a: usize,
    /// The known valid offset of side_b.
    ///
    /// Used to validate read_off and write_off.
    side_b: usize,
}

impl<CS: CipherSuite> State<CS> {
    /// Creates a new `State`.
    pub fn open<P: AsRef<Path>>(
        path: P,
        flag: Flag,
        mode: Mode,
        max_chans: usize,
    ) -> Result<Self, Error> {
        let layout = SharedMem::<CS>::layout(max_chans)?;
        let ptr = Mapping::open(path.as_ref(), flag, mode, layout.layout)?;
        if flag == Flag::Create {
            SharedMem::init(ptr.as_ptr(), max_chans, &layout);
        };
        let state = Self {
            ptr,
            max_chans,
            side_a: layout.side_a,
            side_b: layout.side_b,
        };
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
        if shm.size != layout.size64() {
            return Err(bad_state_size(shm.size, layout.size64()));
        }
        if shm.page_aligned != layout.page_aligned {
            return Err(bad_page_alignment(layout.page_aligned));
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

    /// Loads the [`ChanList`] at the current `read_off`.
    pub(super) fn load_read_list(&self) -> Result<&Mutex<ChanListData<CS>>, Corrupted> {
        let shm = self.shm();
        let off = self.read_off(shm)?;
        shm.side(off)
    }

    /// Loads the [`ChanList`] at the current `write_off`.
    pub(super) fn load_write_list(&self) -> Result<&Mutex<ChanListData<CS>>, Corrupted> {
        let shm = self.shm();
        let off = self.write_off(shm)?;
        shm.side(off)
    }

    /// Load the current `read_off` from `shm`.
    fn read_off(&self, shm: &SharedMem<CS>) -> Result<Offset, Corrupted> {
        let off = shm.read_off.load(Ordering::SeqCst);
        if unlikely!(!self.valid_offset(off)) {
            Err(corrupted("invalid read offset"))
        } else {
            Ok(Offset(off))
        }
    }

    /// Load the current `write_off` from `shm`.
    pub(super) fn write_off(&self, shm: &SharedMem<CS>) -> Result<Offset, Corrupted> {
        let off = shm.write_off.load(Ordering::SeqCst);
        if unlikely!(!self.valid_offset(off)) {
            Err(corrupted("invalid write offset"))
        } else {
            Ok(Offset(off))
        }
    }

    /// Swaps `write_off` for `read_off` and returns `read_off`.
    pub(super) fn swap_offsets(
        &self,
        shm: &SharedMem<CS>,
        write_off: Offset,
    ) -> Result<Offset, Corrupted> {
        let off = shm.read_off.swap(write_off.into(), Ordering::SeqCst);
        if unlikely!(!self.valid_offset(off)) {
            Err(corrupted("invalid write offset"))
        } else {
            Ok(Offset(off))
        }
    }

    /// Reports whether `off` is a known valid offset.
    const fn valid_offset(&self, off: usize) -> bool {
        off == self.side_a || off == self.side_b
    }

    #[cfg(test)]
    pub fn find_chan(
        &self,
        ch: ChannelId,
        hint: Option<Index>,
    ) -> Result<Option<(ShmChan<CS>, Index)>, Corrupted> {
        let list = self.load_read_list()?.lock().assume("poisoned")?;
        list.find(ch, hint, Op::Any)
            .map(|res| res.map(|(chan, idx)| ((*chan).clone(), idx)))
    }
}

/// An operation intended with a channel.
// NB: see `ChanDirection::matches` to understand the
// discriminants.
#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub(super) enum Op {
    /// Encryption.
    Seal = 1,
    /// Decryption.
    Open = 2,
    /// Either.
    #[allow(dead_code)]
    Any = 3,
}

impl Op {
    const fn to_u32(self) -> u32 {
        self as u32
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Seal => "seal",
            Self::Open => "open",
            Self::Any => "any",
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The index of a [`ShmChan`] in a [`ChanList`].
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Index(pub(super) usize);

/// A validated offset.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default)]
pub(super) struct Offset(usize);

impl From<Offset> for usize {
    fn from(val: Offset) -> usize {
        val.0
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
    /// See [`Directed::Bidirectional`].
    Bidirectional = 3,
}

impl ChanDirection {
    /// Reports whether this channel type matches `op`.
    const fn matches(self, op: Op) -> bool {
        const_assert!(ChanDirection::SealOnly.matches(Op::Seal));
        const_assert!(!ChanDirection::SealOnly.matches(Op::Open));
        const_assert!(ChanDirection::SealOnly.matches(Op::Any));

        const_assert!(ChanDirection::OpenOnly.matches(Op::Open));
        const_assert!(!ChanDirection::OpenOnly.matches(Op::Seal));
        const_assert!(ChanDirection::OpenOnly.matches(Op::Any));

        const_assert!(ChanDirection::Bidirectional.matches(Op::Seal));
        const_assert!(ChanDirection::Bidirectional.matches(Op::Open));
        const_assert!(ChanDirection::Bidirectional.matches(Op::Any));

        // Ideally, we'd write this using `matches`. But the
        // compiler isn't smart enough to turn it into a bitmask,
        // so we have to do it manually.
        self.to_u32() & op.to_u32() != 0
    }

    /// Converts the `ChanDirection` to its 32-bit integer
    /// representation.
    const fn to_u32(self) -> u32 {
        self as u32
    }

    fn from_directed<S, O>(dir: &Directed<S, O>) -> Self {
        match dir {
            Directed::SealOnly { .. } => Self::SealOnly,
            Directed::OpenOnly { .. } => Self::OpenOnly,
            Directed::Bidirectional { .. } => Self::Bidirectional,
        }
    }

    /// Creates a `ChanDirection` from its integer
    /// representation.
    const fn try_from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::SealOnly),
            2 => Some(Self::OpenOnly),
            3 => Some(Self::Bidirectional),
            _ => None,
        }
    }
}

impl PartialEq<Op> for ChanDirection {
    fn eq(&self, other: &Op) -> bool {
        self.matches(*other)
    }
}

/// The in-memory representation of a channel.
///
/// All integers are little endian.
#[repr(C)]
pub(super) struct ShmChan<CS: CipherSuite> {
    /// Must be [`ShmChan::MAGIC`].
    pub magic: U32,
    /// The peer's node ID.
    pub node_id: U32,
    /// The channel's label.
    pub label: U32,
    /// Describes the direction that data flows in the channel.
    pub direction: U32,

    /// The current encryption sequence counter.
    pub seq: U64,
    /// The key/nonce used to encrypt data for the channel peer.
    pub seal_key: RawSealKey<CS>,
    /// The key/nonce used to decrypt data from the channel peer.
    pub open_key: RawOpenKey<CS>,
    /// Uniquely identifies `seal_key` and `open_key`.
    pub key_id: KeyId,
}
assert_ffi_safe!(ShmChan<aranya_crypto::default::DefaultCipherSuite>);

impl<CS: CipherSuite> ShmChan<CS> {
    /// Identifies the `ShmChan` in memory.
    pub const MAGIC: U32 = U32::new(0x36bb2c43);

    /// Returns the channel's memory layout.
    const fn layout() -> Layout {
        Layout::new::<Self>()
    }

    /// Initializes the memory at `ptr`.
    ///
    /// It uses `rng` to randomize unset fields.
    pub fn init<R: Csprng>(
        ptr: &mut MaybeUninit<Self>,
        id: ChannelId,
        keys: &Directed<RawSealKey<CS>, RawOpenKey<CS>>,
        rng: &mut R,
    ) {
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
        let chan = Self {
            magic: Self::MAGIC,
            node_id: id.node_id().to_u32().into(),
            label: id.label().to_u32().into(),
            direction: ChanDirection::from_directed(keys).to_u32().into(),
            // For the same reason that we randomize keys,
            // manually exhaust the sequence number.
            seq: if keys.seal().is_some() {
                U64::new(0)
            } else {
                U64::MAX
            },
            key_id: KeyId::new(&seal_key, &open_key),
            seal_key,
            open_key,
        };
        ptr.write(chan);
    }

    /// Returns itself as a `MaybeUninit`.
    pub fn as_uninit_mut(&mut self) -> &mut MaybeUninit<Self> {
        // SAFETY: `self` and `MaybeUninit<Self>` have the same
        // memory layout.
        unsafe { &mut *(self as *mut ShmChan<CS>).cast::<MaybeUninit<ShmChan<CS>>>() }
    }

    #[cfg(test)]
    pub(crate) fn keys(&self) -> Result<Directed<&RawSealKey<CS>, &RawOpenKey<CS>>, Corrupted> {
        Ok(match self.direction()? {
            ChanDirection::SealOnly => Directed::SealOnly {
                seal: &self.seal_key,
            },
            ChanDirection::OpenOnly => Directed::OpenOnly {
                open: &self.open_key,
            },
            ChanDirection::Bidirectional => Directed::Bidirectional {
                seal: &self.seal_key,
                open: &self.open_key,
            },
        })
    }

    /// Returns the channel's unique ID.
    #[inline(always)]
    pub fn id(&self) -> Result<ChannelId, Corrupted> {
        self.check()?;

        let node_id = NodeId::new(self.node_id.into());
        let label: u32 = self.label.into();
        Ok(ChannelId::new(node_id, label.into()))
    }

    /// Reports whether this channel matches `op`.
    #[inline(always)]
    pub fn matches(&self, op: Op) -> Result<bool, Corrupted> {
        Ok(self.direction()?.matches(op))
    }

    fn direction(&self) -> Result<ChanDirection, Corrupted> {
        self.check()?;

        ChanDirection::try_from_u32(self.direction.into()).ok_or(bad_chan_direction(self.direction))
    }

    /// Returns the encryption sequence number.
    pub fn seq(&self) -> Seq {
        Seq::new(self.seq.into())
    }

    /// Updates the sequence number.
    pub fn set_seq(&mut self, seq: Seq) {
        debug_assert!(seq.to_u64() > self.seq.into());

        self.seq = seq.to_u64().into();
    }

    /// Performs basic sanity checking.
    #[track_caller]
    fn check(&self) -> Result<(), Corrupted> {
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

impl<CS: CipherSuite> Clone for ShmChan<CS> {
    fn clone(&self) -> Self {
        Self {
            magic: self.magic,
            node_id: self.node_id,
            label: self.label,
            direction: self.direction,
            seq: self.seq,
            seal_key: self.seal_key.clone(),
            open_key: self.open_key.clone(),
            key_id: self.key_id,
        }
    }
}

impl<CS: CipherSuite> fmt::Debug for ShmChan<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShmChan")
            .field("magic", &self.magic)
            .field("node_id", &self.node_id)
            .field("label", &self.label)
            .field("direction", &self.direction)
            .field("seq", &self.seq)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Describes the memory layout of a [`SharedMem`].
pub(super) struct ShmLayout {
    layout: Layout,
    /// Offset of side_a.
    side_a: usize,
    /// Offset of side_b.
    side_b: usize,
    /// Is ~everything page aligned?
    page_aligned: bool,
}

impl ShmLayout {
    /// Shorthand for `self.layout.size()`.
    pub const fn size(&self) -> usize {
        self.layout.size()
    }

    /// Shorthand for `self.layout.size()`.
    pub const fn size64(&self) -> U64 {
        U64::new(self.size() as u64)
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
#[derive(Debug)]
pub(super) struct SharedMem<CS> {
    /// Identifies this memory as a [`SharedMem`].
    ///
    /// Should be [`Self::MAGIC`].
    magic: U32,
    /// shm implementation version
    version: U32,
    /// The total size of this object, including trailing data.
    size: U64,
    /// `true` if this object and its [`ChanList`]s are page
    /// aligned.
    page_aligned: bool,
    /// Padding for `page_aligned`.
    _pad1: [u8; 7],
    /// The size in bytes of the keys stored in each
    /// [`ChanList`].
    key_size: U64,
    /// The size in bytes of the nonces stored in each
    /// [`ChanList`].
    nonce_size: U64,
    /// The offset of either `side_a` or `side_b`.
    ///
    /// `read_off` always refers to the opposite of `write_off`.
    read_off: CacheAligned<AtomicUsize>,
    /// The offset of either `side_a` or `side_b`.
    ///
    /// `write_off` always refers to the opposite of `read_off`.
    pub write_off: CacheAligned<AtomicUsize>,
    /// In memory, this is actually two fields:
    ///
    /// ```ignore
    /// side_a: ChanList,
    /// side_b: ChanList,
    /// ```
    ///
    /// It is a ZST and does not affect the memory layout.
    sides: PhantomData<CS>,
}
assert_ffi_safe!(SharedMem<aranya_crypto::default::DefaultEngine<aranya_crypto::Rng>>);

// SAFETY: `SharedMem` can be safely shared between threads.
unsafe impl<CS: CipherSuite> Sync for SharedMem<CS> {}

impl<CS: CipherSuite> SharedMem<CS> {
    const MAGIC: U32 = U32::new(0xfcee4325);
    const VERSION: U32 = U32::new(0x00000000);
    const KEY_SIZE: U64 = U64::new(<CS::Aead as Aead>::KEY_SIZE as u64);
    const NONCE_SIZE: U64 = U64::new(<CS::Aead as Aead>::NONCE_SIZE as u64);

    /// Initializes the memory at `ptr`.
    pub fn init(ptr: *mut Self, max_chans: usize, layout: &ShmLayout) {
        // Zero everything. This simplifies the following
        // code.
        //
        // SAFETY: the pointer is in bounds and will not
        // overflow.
        unsafe { (ptr.cast::<u8>()).write_bytes(0, layout.size()) };

        let shm = Self {
            magic: Self::MAGIC,
            version: Self::VERSION,
            size: layout.size64(),
            page_aligned: layout.page_aligned,
            _pad1: [0u8; 7],
            key_size: Self::KEY_SIZE,
            nonce_size: Self::NONCE_SIZE,
            read_off: CacheAligned::new(AtomicUsize::new(layout.side_a)),
            write_off: CacheAligned::new(AtomicUsize::new(layout.side_b)),
            sides: PhantomData,
        };
        // SAFETY: ptr is valid for writes and properly
        // aligned.
        unsafe { ptr.write(shm) };

        // SAFETY: the offsets come directly from memory laid out
        // with `Layout`.
        unsafe {
            ptr.byte_add(layout.side_a)
                .cast::<ChanList<CS>>()
                .write(ChanList::<CS>::new(max_chans));
            ptr.byte_add(layout.side_b)
                .cast::<ChanList<CS>>()
                .write(ChanList::<CS>::new(max_chans));
        }

        // We do not need to do anything with the
        // trailing data since we've already set it to
        // all zeros.
    }

    /// Returns its memory layout.
    fn layout(max_chans: usize) -> Result<ShmLayout, LayoutError> {
        let (list, page_aligned) = ChanList::<CS>::layout(max_chans)?;

        let layout = Layout::new::<Self>();
        let (layout, side_a) = layout.extend(list)?;
        let (mut layout, side_b) = layout.extend(list)?;

        if page_aligned {
            if let Some(page_size) = getpagesize()? {
                if layout.size() < page_size {
                    layout = layout.align_to(page_size)?;
                }
            }
        }

        Ok(ShmLayout {
            layout: layout.pad_to_align(),
            side_a,
            side_b,
            page_aligned,
        })
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
    pub fn side(&self, off: Offset) -> Result<&Mutex<ChanListData<CS>>, Corrupted> {
        self.check()?;

        // SAFETY: ptr is non-null, suitably aligned, and won't
        // wrap.
        let list = unsafe {
            let ptr = (self as *const SharedMem<CS>).byte_add(off.into());
            let ptr = ptr.cast::<ChanList<CS>>();
            &*ptr
        };
        list.check()?;
        Ok(&list.data)
    }
}

/// A list of [`ShmChan`]s.
///
/// Unlike (for example) `ShmChan`, this struct is the actual
/// memory layout, with the exception of the trailing `ShmChan`
/// array.
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
#[derive(Debug)]
struct ChanList<CS> {
    /// Identifies this memory as a [`ChanList`].
    ///
    /// Should be [`Self::MAGIC`].
    magic: U32,
    /// Padding for `magic`.
    _pad0: [u8; 4],
    /// The locked list data.
    data: Mutex<ChanListData<CS>>,
}
assert_ffi_safe!(ChanList<aranya_crypto::default::DefaultEngine<aranya_crypto::Rng>>);

impl<CS: CipherSuite> ChanList<CS> {
    const MAGIC: U32 = U32::new(0x1b771244);

    /// Returns its memory layout, including the trailing data.
    ///
    /// It reports whether it is page aligned.
    fn layout(max_chans: usize) -> Result<(Layout, bool), LayoutError> {
        let chans = layout_repeat(ShmChan::<CS>::layout(), max_chans)?;

        // Extend by the size of the trailing data.
        let layout = Layout::new::<Self>();
        let (layout, _) = layout.extend(chans)?;

        // If the cumulative size of the two sides are going to
        // straddle multiple pages, align each to the page size.
        let (page_size, page_aligned) = if cfg!(feature = "page-aligned") {
            let page_size = getpagesize()?.assume("`page-aligned` feature requires `libc`")?;
            let page_aligned =
                (layout.size() * 2 > page_size) && is_aligned_to(page_size, layout.align());
            (page_size, page_aligned)
        } else {
            (0, false)
        };
        if page_aligned {
            Ok((layout.align_to(page_size)?, true))
        } else {
            Ok((layout, false))
        }
    }

    /// Performs basic sanity checking.
    #[track_caller]
    fn check(&self) -> Result<(), Corrupted> {
        // Perform more "expensive" checks in debug mode.
        //
        // We also panic in debug mode so that we get nice stack
        // traces.
        debug_assert_eq!(self.magic, Self::MAGIC);

        let magic = self.magic;
        if unlikely!(magic != Self::MAGIC) {
            Err(bad_chanlist_magic(magic))
        } else {
            Ok(())
        }
    }

    /// Creates a [`ChanList`] with space for at most
    /// `max_chans`.
    fn new(max_chans: usize) -> Self {
        Self {
            magic: ChanList::<CS>::MAGIC,
            _pad0: [0u8; 4],
            data: Mutex::new(ChanListData {
                gen: AtomicU32::new(0),
                _pad0: [0u8; 4],
                len: U64::new(0),
                cap: U64::new(max_chans as u64),
                chans: PhantomData,
            }),
        }
    }
}

/// The "data" portion of a [`ChanList`].
///
/// Broken out separately so it can be placed inside a [`Mutex`].
#[repr(C, align(8))]
#[derive(Debug)]
pub(super) struct ChanListData<CS> {
    /// The current generation.
    ///
    /// It is incremented each time the list is modified.
    ///
    /// It is atomic so that `ReadState` can safely read it even
    /// while this struct is locked.
    ///
    /// Putting it as the first field significantly decreases the
    /// size of the struct.
    pub gen: AtomicU32,
    /// Padding for `gen`.
    _pad0: [u8; 4],
    /// The current number of channels.
    pub len: U64,
    /// The maximum number of channels.
    pub cap: U64,
    /// This is actually `[ShmChan; cap]`.
    ///
    /// It is a ZST and does not affect the memory layout.
    chans: PhantomData<CS>,
}
assert_ffi_safe!(ChanListData<aranya_crypto::default::DefaultEngine<aranya_crypto::Rng>>);

const_assert!(
    // `Mutex` is 8 bytes, so ensure that `Mutex<ChanListData>`
    // is only 8 (cache-aligned) bytes larger.
    size_of::<Mutex<ChanListData<()>>>() == 8 + size_of::<ChanListData<()>>()
);

impl<CS: CipherSuite> ChanListData<CS> {
    /// Performs basic sanity checking.
    #[track_caller]
    fn check(&self) {
        debug_assert!(self.len <= self.cap);
    }

    fn len(&self) -> Result<usize, Corrupted> {
        usize::try_from(self.len).map_err(|_| corrupted("`len` is larger than `usize::MAX`"))
    }

    fn cap(&self) -> Result<usize, Corrupted> {
        usize::try_from(self.cap).map_err(|_| corrupted("`cap` is larger than `usize::MAX`"))
    }

    /// Truncates the list.
    pub fn clear(&mut self) {
        self.len = U64::new(0);
        self.gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Returns a slice of the channels.
    fn chans(&self) -> Result<&[ShmChan<CS>], Corrupted> {
        self.check();

        let ptr = ptr::addr_of!(self.chans).cast::<ShmChan<CS>>();
        // SAFETY: `ptr` is correctly aligned and non-null.
        Ok(unsafe { slice::from_raw_parts(ptr, self.len()?) })
    }

    /// Returns the in-use channels.
    pub fn chans_mut(&mut self) -> Result<&mut [ShmChan<CS>], Corrupted> {
        self.check();

        let ptr = ptr::addr_of_mut!(self.chans).cast::<ShmChan<CS>>();
        // SAFETY: `ptr` is correctly aligned and non-null.
        Ok(unsafe { slice::from_raw_parts_mut(ptr, self.len()?) })
    }

    /// Returns the trailing data.
    fn all_chans_mut(&mut self) -> Result<&mut [MaybeUninit<ShmChan<CS>>], Corrupted> {
        self.check();

        let ptr = ptr::addr_of_mut!(self.chans).cast::<MaybeUninit<ShmChan<CS>>>();
        // SAFETY: `ptr` is correctly aligned and non-null.
        Ok(unsafe { slice::from_raw_parts_mut(ptr, self.cap()?) })
    }

    /// Returns the [`ShmChan`] at index `idx`.
    ///
    /// Unlike [`at`][`Self::at`], this method will return
    /// uninitialized channels. It also returns an error if `idx`
    /// is out of range.
    pub fn raw_at(&mut self, idx: usize) -> Result<&mut MaybeUninit<ShmChan<CS>>, Corrupted> {
        self.check();

        self.all_chans_mut()?
            .get_mut(idx)
            .ok_or(corrupted("`ShmChan` index out of range"))
    }

    /// Returns the [`ShmChan`] at index `idx`.
    ///
    /// Unlike `raw_at`, this method only returns initialized
    /// channels. It is not an error if `idx` is out of range.
    /// Instead, it returns `None`.
    pub fn get(&self, idx: usize) -> Result<Option<&ShmChan<CS>>, Corrupted> {
        self.check();

        Ok(self.chans()?.get(idx))
    }

    /// Returns the [`ShmChan`] at index `idx`.
    ///
    /// Unlike `raw_at`, this method only returns initialized
    /// channels. It is not an error if `idx` is out of range.
    /// Instead, it returns `None`.
    pub fn get_mut(&mut self, idx: usize) -> Result<Option<&mut ShmChan<CS>>, Corrupted> {
        self.check();

        Ok(self.chans_mut()?.get_mut(idx))
    }

    /// Removes all elements where `f` returns true.
    pub(super) fn remove_if<F>(&mut self, f: &mut F) -> Result<(), Corrupted>
    where
        F: FnMut(ChannelId) -> bool,
    {
        self.check();

        let mut updated = false;
        let mut idx = 0;
        while let Some(chan) = self.get(idx)? {
            let id = chan.id()?;
            if !f(id) {
                // Nope, try the next index.
                idx += 1;
                continue;
            }
            debug!("removing chan {id}");

            if !updated {
                // As a precaution, update the generation before
                // we actually delete anything.
                let gen = self.gen.fetch_add(1, Ordering::AcqRel);
                debug!("side gen={}", gen + 1);

                updated = true;
            }
            debug!("removing chan at {idx}");

            // self[i] = self[self.len-1]
            self.swap_remove(idx)?;
            // We just set `self[i] = self[self.len-1]`, so don't
            // increment `idx`. Just try `i` again.
        }
        Ok(())
    }

    /// Checks if channel exists.
    pub(super) fn exists(&self, id: ChannelId, hint: Option<Index>, op: Op) -> Result<bool, Error> {
        self.check();

        Ok(self.find(id, hint, op)?.is_some())
    }

    /// Retrieves the channel and its index for a particular
    /// channel.
    ///
    /// The channel must match the particular `op`.
    pub(super) fn find(
        &self,
        ch: ChannelId,
        hint: Option<Index>,
        op: Op,
    ) -> Result<Option<(&ShmChan<CS>, Index)>, Corrupted> {
        debug!("looking up {ch} with hint {hint:?} for {op}");

        // If the caller provided an index, use that.
        if let Some(hint) = hint {
            if let Some(chan) = self
                .get(hint.0)?
                // Hints are purely additive, so we purposefully
                // ignore errors (e.g., Corrupted) while finding
                // the channel.
                .filter(|chan| {
                    chan.id().is_ok_and(|got| got == ch) && chan.matches(op).is_ok_and(|ok| ok)
                })
            {
                debug!("used hint {hint:?} for {ch}");
                return Ok(Some((chan, hint)));
            }
        }

        // The index (if any) wasn't valid, so fall back to
        // a linear search.
        if let Some((idx, chan)) = self.try_iter()?.enumerate().try_find(|(_, chan)| {
            let ok = chan.id()? == ch && chan.matches(op)?;
            Ok::<bool, Corrupted>(ok)
        })? {
            Ok(Some((chan, Index(idx))))
        } else {
            Ok(None)
        }
    }

    /// Retrieves the channel and its index for a particular
    /// channel.
    ///
    /// The channel must match the particular `op`.
    pub(super) fn find_mut(
        &mut self,
        ch: ChannelId,
        hint: Option<Index>,
        op: Op,
    ) -> Result<Option<(&mut ShmChan<CS>, Index)>, Corrupted> {
        debug!("looking up {ch} with hint {hint:?} for {op}");

        // If the caller provided an index, use that.
        if let Some(hint) = hint {
            if let Some(chan) = self
                .get_mut(hint.0)?
                // Hints are purely additive, so we purposefully
                // ignore errors (e.g., Corrupted) while finding
                // the channel.
                .filter(|chan| {
                    chan.id().is_ok_and(|got| got == ch) && chan.matches(op).is_ok_and(|ok| ok)
                })
                // Use ptr to work around early return borrow
                // checker limitation
                .map(|chan| -> *mut ShmChan<CS> { chan })
            {
                debug!("used hint {hint:?} for {ch}");
                // SAFETY: `chan` is borrowed from self then
                // immediately returned. The lifetime of the
                // returned value is tied to self.
                return Ok(Some((unsafe { &mut *chan }, hint)));
            }
        }

        // The index (if any) wasn't valid, so fall back to
        // a linear search.
        if let Some((idx, chan)) = self.try_iter_mut()?.enumerate().try_find(|(_, chan)| {
            let ok = chan.id()? == ch && chan.matches(op)?;
            Ok::<bool, Corrupted>(ok)
        })? {
            Ok(Some((chan, Index(idx))))
        } else {
            Ok(None)
        }
    }

    /// Removes the [`ShmChan`] at `idx`, replacing it with
    /// the last channel in the list.
    pub fn swap_remove(&mut self, idx: usize) -> Result<(), Corrupted> {
        self.check();

        let len = self.len()?;
        if unlikely!(len == 0) {
            Err(corrupted("`swap_remove` called with len == 0"))
        } else if unlikely!(idx >= len) {
            Err(corrupted("`ShmChan` index out of range"))
        } else {
            // No need to perform a swap if there is only one
            // channel.
            if len > 1 {
                self.chans_mut()?.swap(idx, len - 1);
            }
            self.len -= 1;
            assert!(self.len <= self.cap);
            Ok(())
        }
    }

    /// Returns an iterator over the list's channels.
    pub fn try_iter(&self) -> Result<slice::Iter<'_, ShmChan<CS>>, Corrupted> {
        self.check();

        Ok(self.chans()?.iter())
    }

    /// Returns an iterator over the list's channels.
    pub fn try_iter_mut(&mut self) -> Result<slice::IterMut<'_, ShmChan<CS>>, Corrupted> {
        self.check();

        Ok(self.chans_mut()?.iter_mut())
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
        const TYPES: &[ChanDirection] = &[
            ChanDirection::SealOnly,
            ChanDirection::OpenOnly,
            ChanDirection::Bidirectional,
        ];
        for want in TYPES.iter().copied() {
            let got = ChanDirection::try_from_u32(want.to_u32()).expect("should be `Some`");
            assert_eq!(want, got);
        }
    }
}
