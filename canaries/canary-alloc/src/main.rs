#![no_std]
#![no_main]

extern crate base58;
extern crate crypto;
// extern crate idam;
// extern crate policy_ast;
// extern crate policy_lang;
// extern crate policy_vm;
// extern crate runtime;
// extern crate service;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
