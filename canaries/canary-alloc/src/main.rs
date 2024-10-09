#![cfg(not(any(test, doctest)))]
#![no_std]
#![no_main]

extern crate aranya_base58;
extern crate aranya_buggy;
extern crate aranya_crypto;
extern crate aranya_trouble;

#[cfg(target_os = "none")] // hack to please rust-analyzer
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[allow(unused)]
fn main() {}
