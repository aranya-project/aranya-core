#![cfg(not(any(test, doctest)))]
#![no_std]
#![no_main]

extern crate aranya_base58;
extern crate aranya_crypto;
extern crate aranya_crypto_core;
extern crate aranya_crypto_ffi;
extern crate aranya_device_ffi;
extern crate aranya_envelope_ffi;
extern crate aranya_idam_ffi;
extern crate aranya_perspective_ffi;
extern crate aranya_policy_ast;
extern crate aranya_policy_module;
extern crate aranya_policy_vm;
extern crate aranya_runtime;

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
