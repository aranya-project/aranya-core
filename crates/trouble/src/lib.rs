//! This crate re-exports or redefines [`std::error::Error`] or
//! [`core::error::Error`], based on `std` and nightly availability.
//!
//! If [`error_in_core`] is stabilized, this will no longer be needed.
//!
//! [`error_in_core`]: https://github.com/rust-lang/rust/issues/103765

#![no_std]
#![cfg_attr(error_in_core, feature(error_in_core))]
#![warn(clippy::arithmetic_side_effects, missing_docs)]

cfg_if::cfg_if! {
    if #[cfg(any(doc, feature = "std"))] {
        extern crate std;

        #[doc(no_inline)]
        pub use std::error::Error;
    } else if #[cfg(error_in_core)] {
        pub use core::error::Error;
    } else {
        use core::any::TypeId;

        mod private {
            #[derive(Debug)]
            pub struct Internal;
        }

        /// See [`std::error::Error`].
        pub trait Error: core::fmt::Debug + core::fmt::Display {
            /// See [`std::error::Error::source`].
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                None
            }

            // See [`std::error::Error::type_id`].
            #[doc(hidden)]
            fn type_id(&self, _: private::Internal) -> TypeId
            where
                Self: 'static,
            {
                TypeId::of::<Self>()
            }
        }

        impl dyn Error + 'static {
            /// See [`std::error::Error::is`].
            #[inline]
            pub fn is<T: Error + 'static>(&self) -> bool {
                let t = TypeId::of::<T>();

                let concrete = self.type_id(private::Internal);

                t == concrete
            }

            /// See [`std::error::Error::downcast_ref`].
            #[inline]
            pub fn downcast_ref<T: Error + 'static>(&self) -> Option<&T> {
                if self.is::<T>() {
                    // SAFETY: `is` ensures this type cast is
                    // correct
                    unsafe { Some(&*(self as *const dyn Error as *const T)) }
                } else {
                    None
                }
            }
        }

        impl dyn Error + 'static + Send {
            /// Forwards the call to the method defined on `dyn
            /// Error`.
            #[inline]
            pub fn is<T: Error + 'static>(&self) -> bool {
                <dyn Error + 'static>::is::<T>(self)
            }

            /// Forwards the call to the method defined on `dyn
            /// Error`.
            #[inline]
            pub fn downcast_ref<T: Error + 'static>(&self) -> Option<&T> {
                <dyn Error + 'static>::downcast_ref::<T>(self)
            }
        }

        impl dyn Error + 'static + Send + Sync {
            /// Forwards the call to the method defined on `dyn
            /// Error`.
            #[inline]
            pub fn is<T: Error + 'static>(&self) -> bool {
                <dyn Error + 'static>::is::<T>(self)
            }

            /// Forwards the call to the method defined on `dyn
            /// Error`.
            #[inline]
            pub fn downcast_ref<T: Error + 'static>(&self) -> Option<&T> {
                <dyn Error + 'static>::downcast_ref::<T>(self)
            }
        }

        impl Error for core::alloc::LayoutError {}
        impl Error for core::convert::Infallible {}

        #[cfg(feature = "third-party")]
        impl Error for postcard::Error {}
    }
}
