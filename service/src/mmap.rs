#![cfg(not(feature = "std"))]

extern crate alloc;
extern crate libc;

use {
    cfg_if::cfg_if,
    core::{
        alloc::{GlobalAlloc, Layout},
        ptr,
    },
    libc::{c_int, c_void, size_t},
};

/// A `mmap(2)`-based allocator.
#[derive(Debug, Clone, Copy)]
pub struct MmapAllocator;

unsafe impl GlobalAlloc for MmapAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        const ADDR: *mut c_void = ptr::null_mut::<c_void>();
        const PROT: c_int = libc::PROT_READ | libc::PROT_WRITE;
        const FLAGS: c_int = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let size = layout.size() as size_t;
        match libc::mmap(ADDR, size, PROT, FLAGS, -1, 0) {
            libc::MAP_FAILED => ptr::null_mut::<u8>(),
            ptr => {
                assert_eq!(0, (ptr as usize) % layout.align());
                ptr as *mut u8
            }
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let addr = ptr as *mut c_void;
        libc::munmap(addr, layout.size() as size_t);
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.alloc(layout)
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        cfg_if! {
            if #[cfg(feature = "mremap")] {
                let old_addr = ptr as *mut c_void;
                let old_size = layout.size() as size_t;
                const FLAGS: c_int = libc::MREMAP_MAYMOVE;
                match libc::mremap(old_addr, old_size, new_size, FLAGS) {
                    libc::MAP_FAILED => ptr::null_mut::<u8>(),
                    ptr => {
                        assert_eq!(0, (ptr as usize) % layout.align());
                        ptr as *mut u8
                    }
                }
            } else {
                let new_layout = Layout::from_size_align(
                    new_size, layout.align()).unwrap();
                let new_ptr = self.alloc(new_layout);
                if new_ptr.is_null() {
                    return ptr::null_mut::<u8>();
                }
                ptr::copy(ptr, new_ptr, layout.size());
                self.dealloc(ptr, layout);
                new_ptr
            }
        }
    }
}
