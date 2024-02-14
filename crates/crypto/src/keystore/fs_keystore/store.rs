#![forbid(unsafe_code)]

use core::{marker::PhantomData, ops::Deref};

use base58::{String64, ToBase58};
use ciborium as cbor;
use ciborium_io::{Read, Write};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self, AtFlags, FlockOperation, Mode, OFlags},
    io::{self, Errno},
    path::Arg,
};

use super::error::{Error, UnexpectedEof};
use crate::{
    engine::WrappedKey,
    keystore::{Entry, Occupied, Vacant},
    Id, KeyStore,
};

/// A file system backed [`KeyStore`].
pub struct Store {
    root: OwnedFd,
}

impl Store {
    /// Creates a key store rooted in `dir`.
    pub const fn new(dir: OwnedFd) -> Self {
        Self { root: dir }
    }

    /// Creates a key store rooted in `path`.
    pub fn open(path: impl Arg) -> io::Result<Self> {
        let fd = fs::open(
            path,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self::new(fd))
    }

    fn alias(&self, id: &Id) -> Alias {
        Alias(id.to_base58())
    }
}

impl KeyStore for Store {
    type Error = Error;
    type Vacant<'a, T: WrappedKey> = VacantEntry<T>;
    type Occupied<'a, T: WrappedKey> = OccupiedEntry<'a, T>;

    fn entry<T: WrappedKey>(&mut self, id: Id) -> Result<Entry<'_, Self, T>, Self::Error> {
        let alias = self.alias(&id);
        // The loops is kinda dumb. Normally, we'd just call
        // `open(..., O_CREAT)`. But that doesn't tell us whether
        // or not we created the file. We *could* check the
        // length (0 == created), but then we're unconditionally
        // performing a syscall. We could also just try and read
        // from the file, but that doesn't really work well with
        // `OccupiedEntry::get` because it returns `T` and not
        // `&T`. We could add a header before the CBOR that's set
        // to 1 the first time the file is written to. But that's
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
                Ok(file) => {
                    break Entry::Vacant(VacantEntry::new(file));
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

    fn get<T: WrappedKey>(&self, id: &Id) -> Result<Option<T>, Self::Error> {
        match Shared::openat(&self.root, &*self.alias(id)) {
            Ok(fd) => Ok(cbor::from_reader(fd)?),
            Err(Errno::NOENT) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}

/// The path to an entry, relative to the root in [`Store`].
// TODO(eric): the resulting string might be cause us to exceed
// PATH_MAX, should we truncate it?
struct Alias(String64);

impl Deref for Alias {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A view into a vacant entry in [`Store`].
pub struct VacantEntry<T> {
    fd: Exclusive,
    _t: PhantomData<T>,
}

impl<T> VacantEntry<T> {
    const fn new(fd: Exclusive) -> Self {
        Self {
            fd,
            _t: PhantomData,
        }
    }
}

impl<T: WrappedKey> Vacant<T> for VacantEntry<T> {
    type Error = Error;

    fn insert(self, key: T) -> Result<(), Self::Error> {
        // The file should be empty.
        debug_assert_eq!(self.fd.fstat()?.st_size, 0);

        cbor::into_writer(&key, self.fd)?;
        Ok(())
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

impl<'a, T: WrappedKey> Occupied<T> for OccupiedEntry<'a, T> {
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

    #[cfg(debug_assertions)]
    fn fstat(&self) -> io::Result<fs::Stat> {
        fs::fstat(&self.0)
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
