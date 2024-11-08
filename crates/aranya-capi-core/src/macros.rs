/// Generates a "build" constructor for the named type.
///
/// # Example
///
/// For example, the following usage
///
/// ```rust,ignore
/// use aranya_capi_core::builds;
///
/// #[builds(Foo)]
/// struct FooBuilder { ... }
///
/// struct Foo { ... }
/// ```
///
/// generates the following code (boilerplate elided):
///
/// ```rust,ignore
/// use core::mem::MaybeUninit;
///
/// use aranya_capi_core::safe::OwnedPtr;
///
/// extern "C" foo_builder_build(
///     ptr: OwnedPtr<FooBuilder>,
///     out: &mut MaybeUninit<Foo>,
/// ) { ... }
/// ```
pub use aranya_capi_macro::builds;
/// Generates a constructors and/or destructors for the type.
///
/// # Example
///
/// ```rust,ignore
/// #[aranya_capi_core::derive(Init, Cleanup)]
/// struct Foo { ... };
/// ```
pub use aranya_capi_macro::derive;
/// Instructs `cbindgen` to ignore the Rust struct's fields and
/// instead generate a C struct with a specific size and
/// alignment.
///
/// # Usage
///
/// `#[opaque(size = S, align = A)]`
///
/// - `size` is the size in bytes of the struct. It must be an
///   integer literal that fits in `usize`. It must be at least
///   as large as the corresponding Rust type's size.
/// - `align` is the alignment in bytes of the struct. It must be
///   an integer literal that fits in `usize`. It must be at
///   least as large as the corresponding Rust type's alignment.
///
/// # Example
///
/// For example, given the following Rust code
///
/// ```rust,ignore
/// #[opaque(size = 32, align = 8)]
/// struct Rust {
///     // 32 or fewer bytes worth of fields
/// }
/// ```
///
/// `cbindgen` will generate the following C code
///
/// ```text
/// typedef struct __attribute__((aligned(8))) Rust {
///     uint8_t __for_size_only[32];
/// } Rust;
/// ```
pub use aranya_capi_macro::opaque;
/// Derives an implementation of [`ErrorCode`][crate::ErrorCode].
///
/// # Usage
///
/// - Must be applied to a unit-only `enum`.
/// - The `enum` must be `#[repr(u*)]` (e.g., `#[repr(u32)]`).
/// - The `enum` must implement [`Copy`], [`Clone`],
///   [`Debug`][core::fmt::Debug], [`Eq`], and [`PartialEq`].
/// - The `enum` must implement
///   [`From<&InvalidArg<'static>>`][crate::InvalidArg].
/// - `#[capi(msg = "...")]` can be used to define static string
///   messages for each variant.
/// - One variant must be marked with `#[capi(success)]`.
///
/// # Example
///
/// ```rust
/// use core::fmt::Debug;
///
/// use aranya_capi_core::{ErrorCode, InvalidArg};
///
/// #[derive(Copy, Clone, Debug, Eq, PartialEq, ErrorCode)]
/// #[repr(u32)]
/// enum Error {
///     #[capi(msg = "success")]
///     #[capi(success)]
///     Success,
///     #[capi(msg = "out of memory")]
///     OutOfMemory,
///     #[capi(msg = "does not exist")]
///     DoesNotExist,
///     #[capi(msg = "invalid argument")]
///     InvalidArgument,
/// }
///
/// impl From<&InvalidArg<'static>> for Error {
///     fn from(_err: &InvalidArg<'static>) -> Self {
///         Self::InvalidArgument
///     }
/// }
///
/// assert_eq!(Error::Success, Error::SUCCESS);
/// assert_eq!(c"invalid argument", Error::InvalidArgument.to_cstr());
/// ```
pub use aranya_capi_macro::ErrorCode;
#[doc(hidden)]
pub use aranya_capi_macro::{generated, no_ext_error};
