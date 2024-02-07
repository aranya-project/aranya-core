#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(error_in_core, feature(error_in_core))]

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
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
    }
}
