#![cfg(not(any(test, doctest)))]
#![no_std]
#![no_main]

extern crate base58;
extern crate buggy;
extern crate crypto;
extern crate trouble;

#[cfg(target_os = "none")] // hack to please rust-analyzer
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[allow(unused)]
fn main() {}
