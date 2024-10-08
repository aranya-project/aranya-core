#![cfg(not(any(test, doctest)))]
#![no_std]
#![no_main]

extern crate aranya_buggy;
extern crate aranya_crypto;
extern crate base58;
extern crate crypto_ffi;
extern crate device_ffi;
extern crate envelope_ffi;
extern crate idam_ffi;
extern crate perspective_ffi;
extern crate policy_ast;
extern crate policy_module;
extern crate policy_vm;
extern crate runtime;
extern crate trouble;

#[cfg(target_os = "none")] // hack to please rust-analyzer
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

struct BadAllocator;
unsafe impl core::alloc::GlobalAlloc for BadAllocator {
    unsafe fn alloc(&self, _: core::alloc::Layout) -> *mut u8 {
        unimplemented!()
    }
    unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {
        unimplemented!()
    }
}

#[global_allocator]
static ALLOCATOR: BadAllocator = BadAllocator;
