#![allow(unused)]
#![forbid(unsafe_code)]

use core::cmp;

/// Returns `min(x, usize::MAX)`.
pub const fn saturate(x: u64) -> usize {
    if x > (usize::MAX as u64) {
        usize::MAX
    } else {
        x as usize
    }
}

/// Copy from `src` to `dst`.
pub fn copy<T: Copy>(dst: &mut [T], src: &[T]) -> usize {
    let n = cmp::min(src.len(), dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

/// Like [`assert!`], but forces a compile-time error.
macro_rules! const_assert {
    ($($tt:tt)*) => {
        const _: () = assert!($($tt)*);
    }
}

/// Invokes `$name` at some indeterminate time before `fn main`.
macro_rules! ctor {
    ($name:expr) => {
        const _: () = {
            extern "C" fn init() {
                $name()
            }

            #[used]
            // mach-o uses __mod_init_func
            // - https://stackoverflow.com/a/30703178
            // - https://opensource.apple.com/source/dyld/dyld-239.3/src/dyldInitialization.cpp
            #[cfg_attr(
                any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos",
                    target_os = "watchos"
                ),
                link_section = "__DATA,__mod_init_func"
            )]
            // ELF uses .init_array
            // - https://refspecs.linuxfoundation.org/LSB_1.1.0/gLSB/specialsections.html
            #[cfg_attr(
                all(
                    unix,
                    not(any(target_os = "macos", target_os = "ios", target_os = "tvos"))
                ),
                link_section = ".init_array"
            )]
            // The only LLVM toolchain that uses .ctors is mingw.
            #[cfg_attr(
                all(target_os = "windows", target_env = "gnu"),
                link_section = ".ctors"
            )]
            // Windows (outside of mingw) uses .CRT$XCU.
            #[cfg_attr(all(windows, not(target_env = "gnu")), link_section = ".CRT$XCU")]
            static __CTOR: extern "C" fn() = init;

            // AIX uses -wl,-binitfini:$name
            // I don't think VxWorks has any support for this,
            // even though it uses ELF.
            #[cfg(any(target_os = "aix", target_os = "vxworks",))]
            compile_error("VxWorks and AIX are currently unsupported");
        };
    };
}
