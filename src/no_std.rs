#![cfg(all(not(feature = "std"), not(test)))]

extern crate alloc;
extern crate libc;

use {
    cfg_if::cfg_if,
    core::{alloc::Layout, panic::PanicInfo},
};

cfg_if! {
    if #[cfg(any(target_os = "vxworks", feature = "mmap-allocator"))] {
        use crate::mmap;

        #[global_allocator]
        static ALLOCATOR: mmap::MmapAllocator = mmap::MmapAllocator;
    } else {
        #[global_allocator]
        static ALLOCATOR: libc_alloc::LibcAlloc = libc_alloc::LibcAlloc;
    }
}

cfg_if! {
    if #[cfg(debug_assertions)] {
        use libc::abort;

        #[panic_handler]
        fn panic(_info: &PanicInfo) -> ! {
            unsafe { abort(); }
        }
    } else {
        use core::sync::{atomic, atomic::{Ordering}};

        #[inline(never)]
        #[panic_handler]
        fn panic(_info: &PanicInfo) -> ! {
            loop {
                atomic::compiler_fence(Ordering::SeqCst);
            }
        }
    }
}

#[alloc_error_handler]
fn oom(_layout: Layout) -> ! {
    panic!("out of memory");
}

#[lang = "eh_personality"]
extern "C" fn eh_personality() {}
