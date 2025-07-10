#![forbid(unsafe_code)]

use core::{any::Any, ffi::CStr, marker::PhantomData, ops::Deref};

use aranya_id::{Id, IdTag};
use buggy::BugExt;
use cfg_if::cfg_if;
use ciborium as cbor;
use ciborium_io::{Read, Write};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self, AtFlags, FlockOperation, Mode, OFlags},
    io::{self, Errno},
    path::Arg,
};
use spideroak_base58::{String32, ToBase58};

use super::error::{Error, RootDeleted, UnexpectedEof};
use crate::{
    BaseId, KeyStore,
    engine::WrappedKey,
    keystore::{Entry, Occupied, Vacant},
};
/// A file system backed [`KeyStore`].
pub struct Store {
    root: OwnedFd,
}

impl Store {
    /// Creates a key store rooted in `dir`.
    const fn new(dir: OwnedFd) -> Self {
        Self { root: dir }
    }

    /// Creates a key store rooted in `path`.
    pub fn open(path: impl Arg) -> Result<Self, Error> {
        let fd = fs::open(
            path,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Self::init_canary(fd.as_fd())?;
        Ok(Self::new(fd))
    }

    /// Clones the `KeyStore`.
    pub fn try_clone(&self) -> Result<Self, Error> {
        let root = match self.root.try_clone() {
            Ok(fd) => fd,
            Err(err) => {
                // Annoyingly, rustix returns either
                // `std::io::Error` or `rustix::io::Errno`
                // depending on whether its `std` feature is
                // enabled, so we have to handle both cases.
                let raw = &err.raw_os_error() as &dyn Any;
                let err = if let Some(raw) = raw.downcast_ref::<i32>() {
                    Some(*raw)
                } else {
                    raw.downcast_ref::<Option<i32>>().copied().flatten()
                }
                .assume("should have a raw OS error")?;
                return Err(Errno::from_raw_os_error(err).into());
            }
        };
        Self::init_canary(root.as_fd())?;
        Ok(Self::new(root))
    }

    fn alias(&self, id: BaseId) -> Alias {
        Alias(id.to_base58())
    }

    /// Initializes the root directory canary. See
    /// [`check_canary`][Self::check_canary].
    fn init_canary(fd: BorrowedFd<'_>) -> Result<(), Error> {
        if !cfg!(debug_assertions) {
            return Ok(());
        }
        fs::openat(
            fd,
            "__canary",
            OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR, // 0o600
        )?;
        Ok(())
    }

    /// Returns [`RootDeleted`] if the directory canary does not
    /// exist.
    ///
    /// The directory canary is an empty file used to determine
    /// whether the root directory was deleted. This usually
    /// occurs during unit tests when `TempDir` is prematurely
    /// dropped. See issue/705 for more information.
    ///
    /// It is not enabled in production as it adds significant
    /// overhead.
    fn check_canary(&self) -> Result<(), Error> {
        if !cfg!(debug_assertions) {
            return Ok(());
        }
        match fs::statat(&self.root, "__canary", AtFlags::empty()) {
            Err(Errno::NOENT) => Err(RootDeleted(()).into()),
            _ => Ok(()),
        }
    }
}

impl KeyStore for Store {
    type Error = Error;
    type Vacant<'a, T: WrappedKey> = VacantEntry<'a, T>;
    type Occupied<'a, T: WrappedKey> = OccupiedEntry<'a, T>;

    fn entry<T: WrappedKey>(
        &mut self,
        id: Id<impl IdTag>,
    ) -> Result<Entry<'_, Self, T>, Self::Error> {
        let id = id.into_id();
        let alias = self.alias(id);
        // The loop is kinda dumb. Normally, we'd just call
        // `open(..., O_CREAT)`. But that doesn't tell us whether
        // or not we created the file. We *could* check the
        // length (0 == created), but then we're unconditionally
        // performing a syscall. We could also just try and read
        // from the file, but that doesn't really work well with
        // `OccupiedEntry::get` because it returns `T` and not
        // `&T`. We could add a header before the CBOR that's set
        // to 1 the first time the file is written to, but that's
        // way more complicated than this dumb loop.
        let entry = loop {
            match Exclusive::openat(&self.root, &*alias) {
                Ok(fd) => {
                    break Entry::Occupied(OccupiedEntry::new(self.root.as_fd(), fd, alias));
                }
                Err(Errno::NOENT) => {
                    // It doesn't exist yet, so create it.
                }
                Err(err) => return Err(err.into()),
            };
            match Exclusive::create_new(&self.root, &*alias) {
                Ok(fd) => {
                    break Entry::Vacant(VacantEntry::new(self.root.as_fd(), fd, alias));
                }
                Err(Errno::NOENT) => {
                    // Guess somebody created the file before we
                    // could. Try to open it again.
                }
                Err(err) => return Err(err.into()),
            }
        };
        Ok(entry)
    }

    fn get<T: WrappedKey>(&self, id: Id<impl IdTag>) -> Result<Option<T>, Self::Error> {
        let id = id.into_id();
        match Shared::openat(&self.root, &*self.alias(id)) {
            Ok(fd) => Ok(cbor::from_reader(fd)?),
            Err(Errno::NOENT) => {
                self.check_canary()?;
                Ok(None)
            }
            Err(err) => Err(err.into()),
        }
    }
}

/// The path to an entry, relative to the root in [`Store`].
// TODO(eric): the resulting string might be cause us to exceed
// PATH_MAX, should we truncate it?
struct Alias(String32);

impl Deref for Alias {
    type Target = CStr;

    fn deref(&self) -> &Self::Target {
        self.0.as_cstr()
    }
}

/// A view into a vacant entry in [`Store`].
pub struct VacantEntry<'a, T> {
    root: BorrowedFd<'a>,
    fd: Exclusive,
    alias: Alias,
    dirty: bool,
    _t: PhantomData<T>,
}

impl<'a, T> VacantEntry<'a, T> {
    const fn new(root: BorrowedFd<'a>, fd: Exclusive, alias: Alias) -> Self {
        Self {
            root,
            fd,
            alias,
            dirty: false,
            _t: PhantomData,
        }
    }
}

impl<T: WrappedKey> Vacant<T> for VacantEntry<'_, T> {
    type Error = Error;

    fn insert(mut self, key: T) -> Result<(), Self::Error> {
        // The file should be empty.
        debug_assert_eq!(self.fd.fstat()?.st_size, 0);

        cbor::into_writer(&key, &self.fd)?;
        self.fd.fsync()?;

        // Only set the dirty flag after a successful write.
        self.dirty = true;

        Ok(())
    }
}

impl<T> Drop for VacantEntry<'_, T> {
    fn drop(&mut self) {
        if !self.dirty {
            // The entry isn't dirty, so the caller must've
            // dropped it before calling `insert`. Don't leave
            // the empty file around.
            let _ = fs::unlinkat(self.root, &*self.alias, AtFlags::empty());
        }
    }
}

/// A view into an occupied entry in [`Store`].
pub struct OccupiedEntry<'a, T> {
    root: BorrowedFd<'a>,
    fd: Exclusive,
    alias: Alias,
    _t: PhantomData<T>,
}

impl<'a, T> OccupiedEntry<'a, T> {
    const fn new(root: BorrowedFd<'a>, fd: Exclusive, alias: Alias) -> Self {
        Self {
            root,
            fd,
            alias,
            _t: PhantomData,
        }
    }
}

impl<T: WrappedKey> Occupied<T> for OccupiedEntry<'_, T> {
    type Error = Error;

    fn get(&self) -> Result<T, Self::Error> {
        Ok(cbor::from_reader(&self.fd)?)
    }

    fn remove(self) -> Result<T, Self::Error> {
        // NB: this won't work on Windows since you (generally)
        // cannot delete files with open handles. This isn't
        // a big deal since the code currently doesn't need to
        // support Windows.
        fs::unlinkat(self.root, &*self.alias, AtFlags::empty())?;
        self.get()
    }
}

/// A file locked with an exclusive lock.
///
/// It can be read from and written to.
struct Exclusive(OwnedFd);

impl Exclusive {
    /// Opens the file at `path`.
    fn openat(dir: impl AsFd, path: impl Arg) -> io::Result<Self> {
        let fd = fs::openat(dir, path, OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())?;
        fs::flock(&fd, FlockOperation::LockExclusive)?;
        Ok(Self(fd))
    }

    /// Creates a new file at `path`.
    ///
    /// The file must not already exist.
    fn create_new(dir: impl AsFd, path: impl Arg) -> io::Result<Self> {
        let fd = fs::openat(
            dir,
            path,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR, // 0o600
        )?;
        fs::flock(&fd, FlockOperation::LockExclusive)?;
        Ok(Self(fd))
    }

    fn fstat(&self) -> io::Result<fs::Stat> {
        fs::fstat(&self.0)
    }

    fn fsync(&self) -> io::Result<()> {
        cfg_if! {
            if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                fs::fcntl_fullfsync(&self.0)?;
            } else {
                fs::fdatasync(&self.0)?;
            }
        }
        Ok(())
    }
}

impl Write for Exclusive {
    type Error = Error;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        (&*self).write_all(buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        (&*self).flush()
    }
}

impl Write for &Exclusive {
    type Error = Error;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        write_all(self.0.as_fd(), buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Read for &Exclusive {
    type Error = Error;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        read_exact(self.0.as_fd(), buf)
    }
}

/// A file locked with a shared lock.
///
/// It can only be read from.
struct Shared(OwnedFd);

impl Shared {
    /// Opens the file at `path`.
    fn openat(dir: impl AsFd, path: impl Arg) -> io::Result<Self> {
        let fd = fs::openat(dir, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
        fs::flock(&fd, FlockOperation::LockShared)?;
        Ok(Self(fd))
    }
}

impl Read for Shared {
    type Error = Error;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        (&*self).read_exact(buf)
    }
}

impl Read for &Shared {
    type Error = Error;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        read_exact(self.0.as_fd(), buf)
    }
}

/// Reads exactly `buf.len()` bytes from `fd` into `buf.
fn read_exact(fd: BorrowedFd<'_>, mut buf: &mut [u8]) -> Result<(), Error> {
    while !buf.is_empty() {
        match io::read(fd, buf) {
            Ok(0) => break,
            Ok(n) => buf = &mut buf[n..],
            Err(Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    if !buf.is_empty() {
        Err(UnexpectedEof.into())
    } else {
        Ok(())
    }
}

/// Writes the entirety of `buf` to `fd`.
fn write_all(fd: BorrowedFd<'_>, mut buf: &[u8]) -> Result<(), Error> {
    while !buf.is_empty() {
        match io::write(fd, buf) {
            Ok(0) => break,
            Ok(n) => buf = &buf[n..],
            Err(Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
