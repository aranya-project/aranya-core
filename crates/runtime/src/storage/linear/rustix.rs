//! IO provider for linear storage based on libc files.

#![cfg(feature = "rustix")]
#![cfg_attr(docs, doc(cfg(feature = "rustix")))]

use alloc::{string::ToString, sync::Arc};

use buggy::BugExt;
use rustix::{
    fd::OwnedFd,
    fs::{self, Mode, OFlags},
    io::Errno,
};

use crate::{linear, Id, StorageError};

#[derive(Debug)]
pub struct FileManager {
    dir: OwnedFd,
}

impl FileManager {
    pub fn new<P: rustix::path::Arg>(dir: P) -> rustix::io::Result<Self> {
        Ok(Self {
            dir: fs::open(
                dir,
                fs::OFlags::RDONLY | fs::OFlags::DIRECTORY,
                fs::Mode::empty(),
            )?,
        })
    }
}

impl linear::io::FileManager for FileManager {
    type File = File;

    fn create(&mut self, id: Id) -> Result<Self::File, StorageError> {
        let name = id.to_string();
        let fd = fs::openat(
            &self.dir,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP,
        )?;
        fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive)?;
        // TODO(jdygert): fallocate?
        Ok(File::new(fd))
    }

    fn open(&mut self, id: Id) -> Result<Option<Self::File>, StorageError> {
        let name = id.to_string();
        let fd = match fs::openat(&self.dir, name, OFlags::RDWR, Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive)?;
        Ok(Some(File::new(fd)))
    }
}

#[derive(Debug)]
pub struct File {
    fd: Arc<OwnedFd>,
}

impl File {
    fn new(fd: OwnedFd) -> Self {
        Self { fd: Arc::new(fd) }
    }
}

#[derive(Clone, Debug)]
pub struct ReadOnly {
    fd: Arc<OwnedFd>,
}

impl linear::io::Read for ReadOnly {
    fn read_exact(&self, mut offset: u64, mut buf: &mut [u8]) -> Result<(), StorageError> {
        while !buf.is_empty() {
            match rustix::io::pread(&*self.fd, buf, offset) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    offset = offset
                        .checked_add(u64::try_from(n).assume("read within bounds")?)
                        .assume("read within bounds")?;
                }
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !buf.is_empty() {
            // Could not fill buffer
            Err(StorageError::IoError)
        } else {
            Ok(())
        }
    }
}

impl linear::io::Write for File {
    type ReadOnly = ReadOnly;
    fn readonly(&self) -> Self::ReadOnly {
        ReadOnly {
            fd: self.fd.clone(),
        }
    }

    fn write_all(&mut self, mut offset: u64, mut buf: &[u8]) -> Result<(), StorageError> {
        while !buf.is_empty() {
            match rustix::io::pwrite(&*self.fd, buf, offset) {
                Ok(0) => {
                    // Failed to write whole buffer
                    return Err(StorageError::IoError);
                }
                Ok(n) => {
                    buf = &buf[n..];
                    offset = offset
                        .checked_add(u64::try_from(n).assume("write within bounds")?)
                        .assume("write within bounds")?;
                }
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<(), StorageError> {
        fs::fsync(&*self.fd)?;
        Ok(())
    }
}
