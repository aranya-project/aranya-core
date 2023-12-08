#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(error_in_core, feature(error_in_core))]

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        pub use std::error::Error;
    } else if #[cfg(error_in_core)] {
        pub use core::error::Error;
    } else {
        /// See [`std::error::Error`].
        pub trait Error: core::fmt::Debug + core::fmt::Display {
            /// See [`std::error::Error::source`].
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                None
            }
        }
    }
}
