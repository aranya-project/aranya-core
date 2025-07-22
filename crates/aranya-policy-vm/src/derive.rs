//! Utilities for deriving `FfiModule` implementations.

#![cfg(feature = "derive")]
#![cfg_attr(docsrs, doc(cfg(feature = "derive")))]

/// When applied to an `impl` block, [`macro@ffi`] generates an
/// implementation of  [`FfiModule`][crate::ffi::FfiModule].
///
/// It accepts the following arguments:
///
/// - `name`: the name of the FFI module (e.g., everything before
///   the `::` in `aranya_crypto::encrypt_data`).
///
/// Methods and associated functions in the `impl` block with the
/// `#[ffi_export]` attribute are included in the FFI module's
/// function table. Methods and associated functions without the
/// attribute are ignored.
///
/// The `#[ffi_export]` attribute has the following required
/// arguments:
///
/// - `def`: the definition of the function in policy DSL.
///
/// # Arguments and Results
///
/// Each method or associated function must take the generic
/// parameter `E: Engine` (see
/// [`Engine`][aranya_crypto::Engine]):
///
/// ```ignore
/// fn foo<E: Engine>(...)
/// ```
///
/// Receivers must not be projected. For example:
///
/// ```ignore
/// // WRONG!
/// fn foo<E: Engine>(self: &Pin<Self>, ...)
/// // WRONG!
/// fn bar<E: Engine>(self: Box<Self>, ...)
/// ```
///
/// The parameter following the receiver, if any, must be
/// `&CommandContext`:
///
/// ```ignore
/// fn foo<E: Engine>(&self, ctx: &CommandContext, ...)
/// fn bar<E: Engine>(ctx: &CommandContext, ...)
/// ```
///
/// Parameters (other than the receiver and
/// [`CommandContext`][crate::CommandContext]) must implement
/// [`TryFrom<Value, Error = MachineErrorType>`][TryFrom].
///
/// The result must be either [`()`][unit] or [`Result<T, E>`]
/// where `T` is either [`()`][unit] or [`Into<Value>`] (see
/// [`Value`][crate::Value]) and `E` is [`Into<MachineError>`].
///
/// # Example
///
/// ```
/// extern crate alloc;
///
/// use alloc::vec::Vec;
/// use core::{convert::Infallible, marker::PhantomData};
///
/// use aranya_crypto::Engine;
/// use aranya_policy_vm::{
///     CommandContext,
///     ffi::ffi,
///     MachineError,
///     MachineErrorType,
/// };
///
/// #[derive(Copy, Clone, Debug)]
/// struct Overflow;
///
/// impl From<Overflow> for MachineError {
///     fn from(_err: Overflow) -> Self {
///         MachineError::new(MachineErrorType::IntegerOverflow)
///     }
/// }
///
/// #[derive(Copy, Clone, Debug)]
/// struct DivideByZero;
///
/// impl From<DivideByZero> for MachineError {
///     fn from(_err: DivideByZero) -> Self {
///         MachineError::new(MachineErrorType::Unknown("divide by zero".to_string()))
///     }
/// }
///
/// struct Crypto<T>(PhantomData<T>);
///
/// #[ffi(
///     module = "crypto",
///     def = r#"
/// struct S0 {
///     a int,
///     b bytes,
///     c string,
/// }
/// struct S1 {
///     x struct S0,
/// }
/// "#
/// )]
/// impl<T> Crypto<T> {
///     /// By default, the function's name is the same as it
///     /// exists in Rust. This will be `calc::add` in the
///     /// `FfiModule`'s schema.
///     #[ffi_export(def = "function add(x int, y int) int")]
///     fn add<E: Engine>(
///         _ctx: &CommandContext,
///         _eng: &mut E,
///         x: i64,
///         y: i64,
///     ) -> Result<i64, Overflow> {
///         x.checked_add(y).ok_or(Overflow)
///     }
///
///     /// `name` can be used to rename functions. This will be
///     /// `calc::divide` in the `FfiModule`'s schema.
///     #[ffi_export(def = "function quo(x int, y int) int")]
///     fn quo<E: Engine>(
///         _ctx: &CommandContext,
///         _eng: &mut E,
///         x: i64,
///         y: i64,
///     ) -> Result<i64, DivideByZero> {
///         x.checked_div(y).ok_or(DivideByZero)
///     }
///
///     #[ffi_export(def = "function custom_def(a int, b bytes) bool")]
///     fn custom_def<E: Engine>(
///         _ctx: &CommandContext,
///         _eng: &mut E,
///         _a: i64,
///         _b: Vec<u8>,
///     ) -> Result<bool, Infallible> {
///         Ok(true)
///     }
///
///     #[ffi_export(def = "function struct_fn(x struct S0) struct S1")]
///     fn struct_fn<E: Engine>(
///         _ctx: &CommandContext,
///         _eng: &mut E,
///         x: S0,
///     ) -> Result<S1, Infallible> {
///         Ok(S1 { x })
///     }
///
///     /// Functions without the `#[ffi_export]` macro are
///     /// ignored.
///     fn ignored() {}
/// }
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "derive")))]
pub use aranya_policy_derive::ffi;
