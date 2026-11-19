#![cfg(feature = "libc")]

use alloc::vec::Vec;

use rustix::{
    buffer::spare_capacity,
    fd::{AsFd as _, BorrowedFd},
    fs::{self, AtFlags, Mode, OFlags, RenameFlags},
    io::{self, Errno},
};

use crate::policy::PolicyId;

pub struct FileStore {
    dir: rustix::fd::OwnedFd,
}

impl FileStore {
    pub fn new(path: impl rustix::path::Arg) -> Result<Self, Errno> {
        let dir = fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self { dir })
    }
}

impl super::ByteStore for FileStore {
    type Error = Errno;

    fn get(&self, id: PolicyId) -> Result<Option<Vec<u8>>, Errno> {
        let path = IdPath::new(id);
        let fd = match fs::openat(
            &self.dir,
            path.as_cstr(),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e),
        };
        let bytes = read_all(fd.as_fd())?;
        Ok(Some(bytes))
    }

    fn put(&mut self, id: PolicyId, bytes: &[u8]) -> Result<(), Errno> {
        let path = IdPath::new(id);
        let tmp_path = path.tmp();
        {
            let tmpfd = fs::openat(
                &self.dir,
                tmp_path.as_cstr(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::APPEND | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP,
            )?;
            write_all(tmpfd.as_fd(), bytes)?;
            fs::fsync(tmpfd)?;
        }
        fs::renameat_with(
            &self.dir,
            tmp_path.as_cstr(),
            &self.dir,
            path.as_cstr(),
            RenameFlags::NOREPLACE,
        )
        .inspect_err(|_| {
            fs::unlinkat(&self.dir, tmp_path.as_cstr(), AtFlags::empty()).ok();
        })?;
        Ok(())
    }
}

fn read_all(fd: BorrowedFd) -> Result<Vec<u8>, Errno> {
    let len = fs::fstat(fd)?.st_size;
    let len = usize::try_from(len).map_err(|_| Errno::FBIG)?;

    let mut buf = Vec::with_capacity(len);

    while buf.len() < len {
        match io::read(fd, spare_capacity(&mut buf)) {
            Ok(0) => break,
            Ok(_) => {}
            Err(Errno::INTR) => {}
            Err(e) => return Err(e),
        }
    }

    Ok(buf)
}

fn write_all(fd: BorrowedFd, mut bytes: &[u8]) -> Result<(), Errno> {
    while !bytes.is_empty() {
        match io::write(fd, bytes) {
            Ok(0) => break,
            Ok(n) => bytes = &bytes[n..],
            Err(Errno::INTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

use path::IdPath;
mod path {
    //! Null-terminated path handling.

    use core::ffi::CStr;

    use spideroak_base58::{String32, ToBase58 as _};

    use crate::PolicyId;

    /// A path created from a [`PolicyId`].
    #[derive(Copy, Clone)]
    pub struct IdPath(String32);

    impl IdPath {
        pub fn new(id: PolicyId) -> Self {
            Self(id.to_base58())
        }

        pub fn tmp(&self) -> IdPathTmp {
            IdPathTmp::new(self)
        }

        pub fn as_cstr(&self) -> &CStr {
            self.0.as_cstr()
        }
    }

    const TMP_EXT: [u8; 5] = *b".tmp\0";

    /// A path created from a [`PolicyId`].
    #[derive(Copy, Clone)]
    pub struct IdPathTmp([u8; String32::B58_SIZE + size_of_val(&TMP_EXT)]);

    impl IdPathTmp {
        fn new(path: &IdPath) -> Self {
            Self(concat(*path.0.as_bytes(), TMP_EXT))
        }

        pub fn as_cstr(&self) -> &CStr {
            unsafe { CStr::from_bytes_with_nul_unchecked(&self.0) }
        }
    }

    fn concat<const N: usize, const M: usize, const K: usize>(
        left: [u8; N],
        right: [u8; M],
    ) -> [u8; K] {
        const { assert!(N + M == K) };
        let mut out = [0u8; K];
        out[..N].copy_from_slice(&left);
        out[N..].copy_from_slice(&right);
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_idpath() {
            let id = PolicyId::default();

            let got = IdPath::new(id);
            let want = format!("{id}\0");

            assert_eq!(got.as_cstr().to_bytes_with_nul(), want.as_bytes());

            let got = got.tmp();
            let want = format!("{id}.tmp\0");
            assert_eq!(got.as_cstr().to_bytes_with_nul(), want.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::ByteStore as _;

    #[test]
    fn it_works() {
        let temp = TempDir::new().unwrap();
        let mut store = FileStore::new(temp.path()).unwrap();

        let id_1 = PolicyId::from_bytes([1; _]);
        let bytes_1 = b"first value";
        let id_2 = PolicyId::from_bytes([2; _]);
        let bytes_2 = b"second value";

        assert!(
            store.get(id_1).unwrap().is_none(),
            "first value absent before insert"
        );

        store.put(id_1, bytes_1).unwrap();
        assert_eq!(
            store.get(id_1).unwrap().unwrap(),
            bytes_1,
            "can retreive first value"
        );

        assert!(
            store.get(id_2).unwrap().is_none(),
            "second value absent before insert"
        );

        store.put(id_2, bytes_2).unwrap();
        assert_eq!(
            store.get(id_2).unwrap().unwrap(),
            bytes_2,
            "can retrieve second value"
        );

        assert_eq!(
            store.get(id_1).unwrap().unwrap(),
            bytes_1,
            "first value still there"
        );

        store.put(id_1, b"").expect_err("re-insertion should fail");
    }
}
