//! A set of proc macros for requirements tracking.
//!
//! It integrates with the following tools:
//!
//! * Inflectra SpiraTest ([`spira`][mod@spira])

#![allow(unstable_name_collisions)]
#![cfg_attr(docs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod spira;

#[cfg(feature = "spira")]
pub use rtrack_derive::*;

#[cfg(feature = "debug")]
mod debug {
    use log::Log;

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

    /// Initializes logging to stderr.
    fn init_logging() {
        struct PrintLogger;
        impl Log for PrintLogger {
            fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
                true
            }

            fn log(&self, record: &log::Record<'_>) {
                let file = record
                    .file()
                    .unwrap_or_else(|| record.file_static().unwrap_or("???"));
                let line = record.line().unwrap_or(0);
                eprintln!(
                    "# {}:{}: {}: {}",
                    file,
                    line,
                    record.target(),
                    record.args()
                );
            }

            fn flush(&self) {}
        }
        if log::set_logger(&PrintLogger).is_ok() {
            log::set_max_level(log::LevelFilter::Debug);
        }
    }
    ctor!(init_logging);
}
