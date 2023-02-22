#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(allocator_api)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

use {alloc::ffi::CString, core::ffi::c_char};

#[cfg(not(feature = "std"))]
mod mmap;

#[cfg(not(feature = "std"))]
mod no_std;

#[no_mangle]
pub extern "C" fn version() -> *const c_char {
    CString::new("42").unwrap().into_raw()
}
