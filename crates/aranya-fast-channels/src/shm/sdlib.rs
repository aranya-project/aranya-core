#![cfg(feature = "sdlib")]

use core::{
    alloc::Layout,
    ffi::{c_char, c_int, c_uint, c_void},
    ptr,
};

use buggy::BugExt;
use derive_where::derive_where;
use libc::off_t;

use super::{
    align::Aligned,
    error::Error,
    path::{Flag, Mode, Path},
};
use crate::errno::{Errno, errno};

const MMU_ATTR_PROT_SUP_READ: c_uint = 0x00000001;
const MMU_ATTR_PROT_SUP_WRITE: c_uint = 0x00000002;
const MMU_ATTR_PROT_USR_READ: c_uint = 0x00000008;
const MMU_ATTR_PROT_USR_WRITE: c_uint = 0x00000010;
const MMU_ATTR_VALID: c_uint = 0x00000040;
const MMU_ATTR_SUP_RW: c_uint = MMU_ATTR_PROT_SUP_READ | MMU_ATTR_PROT_SUP_WRITE;
const MMU_ATTR_USR_RW: c_uint = MMU_ATTR_PROT_USR_READ | MMU_ATTR_PROT_USR_WRITE;
const MMU_ATTR_SUP_RO: c_uint = MMU_ATTR_PROT_SUP_READ;
const MMU_ATTR_USR_RO: c_uint = MMU_ATTR_PROT_USR_READ;

const SD_ATTR_RW: c_uint = MMU_ATTR_SUP_RW | MMU_ATTR_USR_RW | MMU_ATTR_VALID;
const SD_ATTR_RO: c_uint = MMU_ATTR_SUP_RO | MMU_ATTR_USR_RO | MMU_ATTR_VALID;

const SD_LINGER: c_int = 0x00000001;

const OM_CREATE: c_int = 0x10000000;
const OM_EXCL: c_int = 0x20000000;

// From the VxWorks Application API reference 6.9.
unsafe extern "C" {
    fn sdOpen(
        name: *const c_char,
        options: c_int,
        mode: c_int,
        size: usize,
        phys_addr: off_t,
        attr: c_uint,
        p_virt_addr: *mut *mut c_void,
    ) -> c_int;
    fn sdDelete(id: c_int, options: c_int) -> c_int;
    fn sdUnmap(id: c_int, options: c_int) -> c_int;
}

/// Delete the shared data at `path`.
pub(super) fn unlink<P>(path: P) -> Result<(), Errno>
where
    P: AsRef<Path>,
{
    let mut addr = ptr::null_mut();
    // SAFETY: FFI call, no invariants.
    let id = unsafe {
        sdOpen(
            path.as_ref().as_ptr(),  // name
            0,                       // options
            0,                       // mode
            1,                       // size
            0,                       // physAddress
            0,                       // attr
            ptr::addr_of_mut!(addr), // pVirtAddress
        )
    };
    if id == 0 {
        // The mapping does not exist.
        return Ok(());
    }
    if id < 0 {
        return Err(errno());
    }
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { sdDelete(id, 0) };
    if ret < 0 { Err(errno()) } else { Ok(()) }
}

fn unmap(id: c_int) -> Result<(), Errno> {
    // SAFETY: FFI call, no invariants.
    let ret = unsafe { sdUnmap(id, 0) };
    if ret < 0 { Err(errno()) } else { Ok(()) }
}

/// Shared data mapping.
#[derive_where(Debug)]
pub(super) struct Mapping<T> {
    /// The usable section of the mapping.
    ptr: Aligned<T>,
    /// The base of the mapping.
    id: c_int,
}

// SAFETY: `Mapping` is !Send by default because it contains raw
// pointers.  But since it does not have any thread affinity, we
// can safely make it Send.
unsafe impl<T: Send> Send for Mapping<T> {}

impl<T> Drop for Mapping<T> {
    fn drop(&mut self) {
        let _ = unmap(self.id);
    }
}

impl<T: Sync> AsRef<T> for Mapping<T> {
    fn as_ref(&self) -> &T {
        // SAFETY: the pointer is aligned, the pointer is
        // dereferenceable, the data is initialized, we do not
        // violate aliasing rules.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> Mapping<T> {
    /// Acquires the underlying `*mut` pointer.
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Creates a shared data mapping at `path`.
    pub fn open<P>(path: P, flag: Flag, mode: Mode, layout: Layout) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        // TODO(eric): cache coherency mode
        let attr = match mode {
            #[allow(deprecated)]
            Mode::ReadOnly => SD_ATTR_RO,
            Mode::ReadWrite => SD_ATTR_RW,
        };
        let mode = match flag {
            Flag::OpenOnly => 0,
            Flag::Create => OM_CREATE | OM_EXCL,
        };
        let mut addr = ptr::null_mut();
        // SAFETY: FFI call, no invariants.
        let id = unsafe {
            sdOpen(
                path.as_ref().as_ptr(),  // name
                SD_LINGER,               // options
                mode,                    // mode
                layout.size(),           // size
                0,                       // physAddress
                attr,                    // attr
                ptr::addr_of_mut!(addr), // pVirtAddress
            )
        };
        if id == 0 {
            Err(Error::Errno(errno()))
        } else {
            let ptr = Aligned::new(addr.cast::<T>(), layout).assume("unable to align pointer")?;
            Ok(Mapping { ptr, id })
        }
    }
}
