#![cfg(not(any(test, doctest, feature = "std")))]
#![no_std]
#![no_main]

extern crate base58;
extern crate buggy;
extern crate crypto;
extern crate trouble;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
