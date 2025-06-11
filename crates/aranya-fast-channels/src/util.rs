// Just depends on features
#![allow(unused_macros)]

macro_rules! const_assert {
    ($($tt:tt)*) => {
		#[allow(clippy::arithmetic_side_effects, reason = "compile time arithmetic")]
        const _: () = { ::const_format::assertcp!($($tt)*); };
    }
}
#[allow(unused_imports)]
pub(crate) use const_assert;

macro_rules! const_assert_eq {
    ($left:expr, $right:expr $(,)?) => {
		#[allow(clippy::arithmetic_side_effects, reason = "compile time arithmetic")]
        const _: () = { ::const_format::assertcp_eq!($left, $right, "{} != {}", $left, $right); };
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
		#[allow(clippy::arithmetic_side_effects, reason = "compile time arithmetic")]
        const _: () = { ::const_format::assertcp_eq!($left, $right, $(arg)+); };
    };
}
#[allow(unused_imports)]
pub(crate) use const_assert_eq;

#[allow(unused)]
#[cfg(all(feature = "libc", not(feature = "std")))]
pub(crate) struct Stderr;

#[cfg(all(feature = "libc", not(feature = "std")))]
impl core::fmt::Write for Stderr {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        // SAFETY: FFI call, no invariants.
        unsafe {
            libc::write(
                libc::STDERR_FILENO,
                s.as_ptr().cast::<core::ffi::c_void>(),
                s.len(),
            );
        };
        Ok(())
    }
}

#[cfg(all(feature = "libc", not(feature = "std")))]
macro_rules! eprintln {
    () => {
        $crate::util::Stderr.write_str("\n")
            .expect("`write_str` should not fail");
    };
    ($($arg:tt)*) => {{
        use ::core::fmt::Write;
        ::core::writeln!(&mut $crate::util::Stderr, $($arg)*)
            .expect("`writeln` should not fail");
    }};
}

/// Configures the debugging logger.
#[cfg_attr(docsrs, doc(cfg(feature = "unsafe_debug")))]
#[cfg(feature = "unsafe_debug")]
pub fn init_debug_logging() {
    struct PrintLogger;
    impl log::Log for PrintLogger {
        fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            let file = record
                .file()
                .unwrap_or_else(|| record.file_static().unwrap_or("???"));
            let line = record.line().unwrap_or(0);
            eprintln!("# APS DEBUG: {}:{}: {}", file, line, record.args());
        }

        fn flush(&self) {}
    }
    if log::set_logger(&PrintLogger).is_ok() {
        log::set_max_level(log::LevelFilter::Debug);
    }
}

/// Similar to [`log::debug`], but only prints when the
/// `unsafe_debug` feature is enabled.
macro_rules! debug {
    (target: $target:expr, $($arg:tt)+) => (
		cfg_if::cfg_if! {
			if #[cfg(feature = "unsafe_debug")] {
				log::debug!(target: $target, $($arg)+)
			} else {
				if false {
					let _: &str = $target;
					::core::format_args!($($arg)+);
				}
			}
		}
    );
	($($arg:tt)+) => (
		cfg_if::cfg_if! {
			if #[cfg(feature = "unsafe_debug")] {
				log::debug!($($arg)+)
			} else {
				if false {
					::core::format_args!($($arg)+);
				}
			}
		}
    );
}
pub(crate) use debug;
