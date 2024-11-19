extern crate aranya_capi_core as __capi;
use __capi::Builder;
use __capi::internal::tracing;
mod __imports {
    pub(super) use aranya_capi_core::{
        prelude::*, safe::{TypeId, Typed},
        InvalidArg,
    };
}
#[derive(::core::marker::Copy)]
#[derive(::core::clone::Clone)]
#[derive(::core::default::Default)]
#[derive(::core::fmt::Debug)]
#[repr(u8)]
#[cfg(cbindgen)]
#[must_use]
pub enum PrefixEnum {
    #[default]
    A,
    B,
}
#[derive(::core::marker::Copy)]
#[derive(::core::clone::Clone)]
#[derive(::core::fmt::Debug)]
#[derive(::core::default::Default)]
#[repr(C)]
#[cfg(cbindgen)]
pub struct PrefixStruct {
    pub a: ::core::primitive::u32,
}
#[cfg(not(cbindgen))]
pub type PrefixStruct = self::__hidden::PrefixStruct;
#[repr(transparent)]
#[cfg(cbindgen)]
pub struct PrefixSafeStruct(crate::defs::SafeStruct);
#[cfg(not(cbindgen))]
pub type PrefixSafeStruct = self::__hidden::PrefixSafeStruct;
/// Extended error information.
#[aranya_capi_core::opaque(size = 72, align = 8)]
pub type PrefixExtError = self::__hidden::PrefixExtError;
#[derive(::core::marker::Copy)]
#[derive(::core::clone::Clone)]
#[derive(::core::fmt::Debug)]
#[derive(::core::cmp::Eq)]
#[derive(::core::cmp::PartialEq)]
#[derive(::aranya_capi_core::ErrorCode)]
#[repr(u32)]
#[must_use]
pub enum PrefixError {
    #[capi(success)]
    #[capi(msg = "success")]
    Success,
    #[capi(msg = "invalid argument")]
    InvalidArg,
}
#[no_mangle]
#[::tracing::instrument(level = "trace")]
pub extern "C" fn prefix_test_unit_unit0() {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { __tramp_prefix_test_unit_unit0() } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_unit_unit0() -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_unit_unit0() } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace")]
pub extern "C" fn prefix_test_unit_unit1() -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { __tramp_prefix_test_unit_unit1() } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_unit_unit1() -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_unit_unit1() } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace")]
pub extern "C" fn prefix_test_unit_result_unit_error() -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { __tramp_prefix_test_unit_result_unit_error() } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(()) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(__ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err))
)]
pub extern "C" fn prefix_test_unit_result_unit_error_ext(
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { __tramp_prefix_test_unit_result_unit_error() } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(()) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_unit_result_unit_error() -> ::core::result::Result<
    (),
    crate::Error,
> {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_unit_result_unit_error() } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_u8_unit(_a: ::core::primitive::u8) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u8_unit(__capi::internal::util::check_valid_input_ty_val(_a))
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u8_unit(_a: ::core::primitive::u8) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u8_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_u16_unit(_a: ::core::primitive::u16) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u16_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u16_unit(_a: ::core::primitive::u16) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u16_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_u32_unit(_a: ::core::primitive::u32) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u32_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u32_unit(_a: ::core::primitive::u32) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u32_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_u64_unit(_a: ::core::primitive::u64) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u64_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u64_unit(_a: ::core::primitive::u64) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u64_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_usize_unit(_a: ::core::primitive::usize) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_usize_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_usize_unit(_a: ::core::primitive::usize) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_usize_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_i8_unit(_a: ::core::primitive::i8) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i8_unit(__capi::internal::util::check_valid_input_ty_val(_a))
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i8_unit(_a: ::core::primitive::i8) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i8_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_i16_unit(_a: ::core::primitive::i16) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i16_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i16_unit(_a: ::core::primitive::i16) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i16_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_i32_unit(_a: ::core::primitive::i32) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i32_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i32_unit(_a: ::core::primitive::i32) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i32_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_i64_unit(_a: ::core::primitive::i64) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i64_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i64_unit(_a: ::core::primitive::i64) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i64_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_isize_unit(_a: ::core::primitive::isize) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_isize_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_isize_unit(_a: ::core::primitive::isize) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_isize_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_u8_u8(_a: ::core::primitive::u8) -> ::core::primitive::u8 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u8_u8(__capi::internal::util::check_valid_input_ty_val(_a))
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u8_u8(_a: ::core::primitive::u8) -> ::core::primitive::u8 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u8_u8(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_u16_u16(
    _a: ::core::primitive::u16,
) -> ::core::primitive::u16 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u16_u16(__capi::internal::util::check_valid_input_ty_val(_a))
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u16_u16(_a: ::core::primitive::u16) -> ::core::primitive::u16 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u16_u16(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_u32_u32(
    _a: ::core::primitive::u32,
) -> ::core::primitive::u32 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u32_u32(__capi::internal::util::check_valid_input_ty_val(_a))
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u32_u32(_a: ::core::primitive::u32) -> ::core::primitive::u32 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u32_u32(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_u64_u64(
    _a: ::core::primitive::u64,
) -> ::core::primitive::u64 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u64_u64(__capi::internal::util::check_valid_input_ty_val(_a))
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u64_u64(_a: ::core::primitive::u64) -> ::core::primitive::u64 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u64_u64(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_usize_usize(
    _a: ::core::primitive::usize,
) -> ::core::primitive::usize {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_usize_usize(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_usize_usize(
    _a: ::core::primitive::usize,
) -> ::core::primitive::usize {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_usize_usize(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_i8_i8(_a: ::core::primitive::i8) -> ::core::primitive::i8 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i8_i8(__capi::internal::util::check_valid_input_ty_val(_a))
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i8_i8(_a: ::core::primitive::i8) -> ::core::primitive::i8 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i8_i8(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_i16_i16(
    _a: ::core::primitive::i16,
) -> ::core::primitive::i16 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i16_i16(__capi::internal::util::check_valid_input_ty_val(_a))
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i16_i16(_a: ::core::primitive::i16) -> ::core::primitive::i16 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i16_i16(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_i32_i32(
    _a: ::core::primitive::i32,
) -> ::core::primitive::i32 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i32_i32(__capi::internal::util::check_valid_input_ty_val(_a))
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i32_i32(_a: ::core::primitive::i32) -> ::core::primitive::i32 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i32_i32(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_i64_i64(
    _a: ::core::primitive::i64,
) -> ::core::primitive::i64 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i64_i64(__capi::internal::util::check_valid_input_ty_val(_a))
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i64_i64(_a: ::core::primitive::i64) -> ::core::primitive::i64 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i64_i64(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a))]
pub extern "C" fn prefix_test_isize_isize(
    _a: ::core::primitive::isize,
) -> ::core::primitive::isize {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_isize_isize(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_isize_isize(
    _a: ::core::primitive::isize,
) -> ::core::primitive::isize {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_isize_isize(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a, _b = _b))]
pub extern "C" fn prefix_test_u8_u8_u8(
    _a: ::core::primitive::u8,
    _b: ::core::primitive::u8,
) -> ::core::primitive::u8 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u8_u8_u8(
            __capi::internal::util::check_valid_input_ty_val(_a),
            __capi::internal::util::check_valid_input_ty_val(_b),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u8_u8_u8(
    _a: ::core::primitive::u8,
    _b: ::core::primitive::u8,
) -> ::core::primitive::u8 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u8_u8_u8(_a, _b) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a, _b = _b))]
pub extern "C" fn prefix_test_u16_u16_u16(
    _a: ::core::primitive::u16,
    _b: ::core::primitive::u16,
) -> ::core::primitive::u16 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u16_u16_u16(
            __capi::internal::util::check_valid_input_ty_val(_a),
            __capi::internal::util::check_valid_input_ty_val(_b),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u16_u16_u16(
    _a: ::core::primitive::u16,
    _b: ::core::primitive::u16,
) -> ::core::primitive::u16 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u16_u16_u16(_a, _b) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a, _b = _b))]
pub extern "C" fn prefix_test_u32_u32_u32(
    _a: ::core::primitive::u32,
    _b: ::core::primitive::u32,
) -> ::core::primitive::u32 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u32_u32_u32(
            __capi::internal::util::check_valid_input_ty_val(_a),
            __capi::internal::util::check_valid_input_ty_val(_b),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u32_u32_u32(
    _a: ::core::primitive::u32,
    _b: ::core::primitive::u32,
) -> ::core::primitive::u32 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u32_u32_u32(_a, _b) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a, _b = _b))]
pub extern "C" fn prefix_test_u64_u64_u64(
    _a: ::core::primitive::u64,
    _b: ::core::primitive::u64,
) -> ::core::primitive::u64 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_u64_u64_u64(
            __capi::internal::util::check_valid_input_ty_val(_a),
            __capi::internal::util::check_valid_input_ty_val(_b),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_u64_u64_u64(
    _a: ::core::primitive::u64,
    _b: ::core::primitive::u64,
) -> ::core::primitive::u64 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_u64_u64_u64(_a, _b) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a, _b = _b))]
pub extern "C" fn prefix_test_usize_usize_usize(
    _a: ::core::primitive::usize,
    _b: ::core::primitive::usize,
) -> ::core::primitive::usize {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_usize_usize_usize(
            __capi::internal::util::check_valid_input_ty_val(_a),
            __capi::internal::util::check_valid_input_ty_val(_b),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_usize_usize_usize(
    _a: ::core::primitive::usize,
    _b: ::core::primitive::usize,
) -> ::core::primitive::usize {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_usize_usize_usize(_a, _b) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a, _b = _b))]
pub extern "C" fn prefix_test_i8_i8_i8(
    _a: ::core::primitive::i8,
    _b: ::core::primitive::i8,
) -> ::core::primitive::i8 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i8_i8_i8(
            __capi::internal::util::check_valid_input_ty_val(_a),
            __capi::internal::util::check_valid_input_ty_val(_b),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i8_i8_i8(
    _a: ::core::primitive::i8,
    _b: ::core::primitive::i8,
) -> ::core::primitive::i8 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i8_i8_i8(_a, _b) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a, _b = _b))]
pub extern "C" fn prefix_test_i16_i16_i16(
    _a: ::core::primitive::i16,
    _b: ::core::primitive::i16,
) -> ::core::primitive::i16 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i16_i16_i16(
            __capi::internal::util::check_valid_input_ty_val(_a),
            __capi::internal::util::check_valid_input_ty_val(_b),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i16_i16_i16(
    _a: ::core::primitive::i16,
    _b: ::core::primitive::i16,
) -> ::core::primitive::i16 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i16_i16_i16(_a, _b) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a, _b = _b))]
pub extern "C" fn prefix_test_i32_i32_i32(
    _a: ::core::primitive::i32,
    _b: ::core::primitive::i32,
) -> ::core::primitive::i32 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i32_i32_i32(
            __capi::internal::util::check_valid_input_ty_val(_a),
            __capi::internal::util::check_valid_input_ty_val(_b),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i32_i32_i32(
    _a: ::core::primitive::i32,
    _b: ::core::primitive::i32,
) -> ::core::primitive::i32 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i32_i32_i32(_a, _b) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a, _b = _b))]
pub extern "C" fn prefix_test_i64_i64_i64(
    _a: ::core::primitive::i64,
    _b: ::core::primitive::i64,
) -> ::core::primitive::i64 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_i64_i64_i64(
            __capi::internal::util::check_valid_input_ty_val(_a),
            __capi::internal::util::check_valid_input_ty_val(_b),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_i64_i64_i64(
    _a: ::core::primitive::i64,
    _b: ::core::primitive::i64,
) -> ::core::primitive::i64 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_i64_i64_i64(_a, _b) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = _a, _b = _b))]
pub extern "C" fn prefix_test_isize_isize_isize(
    _a: ::core::primitive::isize,
    _b: ::core::primitive::isize,
) -> ::core::primitive::isize {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_isize_isize_isize(
            __capi::internal::util::check_valid_input_ty_val(_a),
            __capi::internal::util::check_valid_input_ty_val(_b),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_isize_isize_isize(
    _a: ::core::primitive::isize,
    _b: ::core::primitive::isize,
) -> ::core::primitive::isize {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_isize_isize_isize(_a, _b) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = ::tracing::field::Empty))]
pub extern "C" fn prefix_test_enum_unit(_a: PrefixEnum) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_enum_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        _a = ::tracing::field::Empty,
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_test_enum_unit_ext(
    _a: PrefixEnum,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_enum_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_enum_unit(
    _a: PrefixEnum,
) -> ::core::result::Result<(), __capi::InvalidArg<'static>> {
    #[allow(clippy::let_with_type_underscore)]
    let _a: _ = {
        let _a = __capi::try_as_enum!(crate ::defs::Enum, _a);
        __capi::to_inner!(_a)
    };
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_enum_unit(_a) } {
        __pattern => ::core::result::Result::Ok(__pattern),
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(_a = ::tracing::field::Empty))]
pub extern "C" fn prefix_test_struct_unit(_a: PrefixStruct) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_struct_unit(
            __capi::internal::util::check_valid_input_ty_val(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_struct_unit(_a: PrefixStruct) -> () {
    #[allow(clippy::let_with_type_underscore)]
    let _a: _ = __capi::to_inner!(_a);
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_struct_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace")]
pub extern "C" fn prefix_test_unit_struct() -> PrefixStruct {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { __tramp_prefix_test_unit_struct() } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_unit_struct() -> PrefixStruct {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_unit_struct() } {
        __pattern => {
            type __Result = PrefixStruct;
            __capi::from_inner!(__pattern => __Result)
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(_a = %__capi::internal::util::Addr::from_ptr(_a))
)]
pub extern "C" fn prefix_test_ref_struct_unit(_a: *const PrefixStruct) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ref_struct_unit(
            __capi::internal::util::check_valid_input_ty_const_ptr(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        _a = %__capi::internal::util::Addr::from_ptr(_a),
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_test_ref_struct_unit_ext(
    _a: *const PrefixStruct,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ref_struct_unit(
            __capi::internal::util::check_valid_input_ty_const_ptr(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_ref_struct_unit(
    _a: *const PrefixStruct,
) -> ::core::result::Result<(), __capi::InvalidArg<'static>> {
    #[allow(clippy::let_with_type_underscore)]
    let _a: &_ = {
        let _a = __capi::try_as_ref!(_a);
        __capi::to_inner_ref!(_a)
    };
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_ref_struct_unit(_a) } {
        __pattern => ::core::result::Result::Ok(__pattern),
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(_a = %__capi::internal::util::Addr::from_ptr(_a))
)]
pub extern "C" fn prefix_test_ptr_struct_unit(_a: *const PrefixStruct) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ptr_struct_unit(
            __capi::internal::util::check_valid_input_ty_const_ptr(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_ptr_struct_unit(_a: *const PrefixStruct) -> () {
    #[allow(clippy::let_with_type_underscore)]
    let _a: *const _ = __capi::to_inner_ptr!(_a);
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_ptr_struct_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(level = "trace", fields(a = ::tracing::field::Empty))]
pub extern "C" fn prefix_test_struct_struct(a: PrefixStruct) -> PrefixStruct {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_struct_struct(
            __capi::internal::util::check_valid_input_ty_val(a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_struct_struct(a: PrefixStruct) -> PrefixStruct {
    #[allow(clippy::let_with_type_underscore)]
    let a: _ = __capi::to_inner!(a);
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_struct_struct(a) } {
        __pattern => {
            type __Result = PrefixStruct;
            __capi::from_inner!(__pattern => __Result)
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(__output = %__capi::internal::util::Addr::from_ptr(__output))
)]
pub extern "C" fn prefix_test_unit_result_struct_error(
    __output: *mut ::core::mem::MaybeUninit<PrefixStruct>,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_unit_result_struct_error(
            __capi::internal::util::check_valid_input_ty_mut_ptr(__output),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    match __pattern {
                        ::core::result::Result::Ok(()) => {
                            <PrefixError as __capi::ErrorCode>::SUCCESS
                        }
                        ::core::result::Result::Err(ref err) => {
                            __capi::internal::error::convert_err(err)
                        }
                    }
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        __output = %__capi::internal::util::Addr::from_ptr(__output),
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_test_unit_result_struct_error_ext(
    __output: *mut ::core::mem::MaybeUninit<PrefixStruct>,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_unit_result_struct_error(
            __capi::internal::util::check_valid_input_ty_mut_ptr(__output),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    match __pattern {
                        ::core::result::Result::Ok(()) => {
                            <PrefixError as __capi::ErrorCode>::SUCCESS
                        }
                        ::core::result::Result::Err(err) => {
                            type __ExtErrTy = PrefixExtError;
                            __capi::internal::error::handle_ext_error(
                                err,
                                __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                            )
                        }
                    }
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_unit_result_struct_error(
    __output: *mut ::core::mem::MaybeUninit<PrefixStruct>,
) -> ::core::result::Result<
    ::core::result::Result<(), crate::Error>,
    __capi::InvalidArg<'static>,
> {
    #[allow(clippy::let_with_type_underscore)]
    let __output: &mut ::core::mem::MaybeUninit<_> = {
        let __output = __capi::try_as_uninit_mut!(__output);
        __capi::to_inner_mut!(__output)
    };
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_unit_result_struct_error() } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    ::core::mem::MaybeUninit::write(__output, __pattern);
                    ::core::result::Result::Ok(::core::result::Result::Ok(()))
                }
                ::core::result::Result::Err(err) => {
                    ::core::result::Result::Ok(::core::result::Result::Err(err))
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(_a = %__capi::internal::util::Addr::from_ptr(_a))
)]
pub extern "C" fn prefix_test_ref_safestruct_unit(
    _a: *const PrefixSafeStruct,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ref_safestruct_unit(
            __capi::internal::util::check_valid_input_ty_const_ptr(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        _a = %__capi::internal::util::Addr::from_ptr(_a),
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_test_ref_safestruct_unit_ext(
    _a: *const PrefixSafeStruct,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ref_safestruct_unit(
            __capi::internal::util::check_valid_input_ty_const_ptr(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_ref_safestruct_unit(
    _a: *const PrefixSafeStruct,
) -> ::core::result::Result<(), __capi::InvalidArg<'static>> {
    #[allow(clippy::let_with_type_underscore)]
    let _a: &_ = {
        let _a = __capi::try_as_ref!(_a);
        __capi::to_inner_ref!(_a)
    };
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_ref_safestruct_unit(_a) } {
        __pattern => ::core::result::Result::Ok(__pattern),
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(_a = %__capi::internal::util::Addr::from_ptr(_a))
)]
pub extern "C" fn prefix_test_ptr_safestruct_unit(_a: *const PrefixSafeStruct) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ptr_safestruct_unit(
            __capi::internal::util::check_valid_input_ty_const_ptr(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_ptr_safestruct_unit(_a: *const PrefixSafeStruct) -> () {
    #[allow(clippy::let_with_type_underscore)]
    let _a: *const _ = __capi::to_inner_ptr!(_a);
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_ptr_safestruct_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(__output = %__capi::internal::util::Addr::from_ptr(__output))
)]
pub extern "C" fn prefix_test_unit_result_safestruct_error(
    __output: *mut ::core::mem::MaybeUninit<PrefixSafeStruct>,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_unit_result_safestruct_error(
            __capi::internal::util::check_valid_input_ty_mut_ptr(__output),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    match __pattern {
                        ::core::result::Result::Ok(()) => {
                            <PrefixError as __capi::ErrorCode>::SUCCESS
                        }
                        ::core::result::Result::Err(ref err) => {
                            __capi::internal::error::convert_err(err)
                        }
                    }
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        __output = %__capi::internal::util::Addr::from_ptr(__output),
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_test_unit_result_safestruct_error_ext(
    __output: *mut ::core::mem::MaybeUninit<PrefixSafeStruct>,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_unit_result_safestruct_error(
            __capi::internal::util::check_valid_input_ty_mut_ptr(__output),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    match __pattern {
                        ::core::result::Result::Ok(()) => {
                            <PrefixError as __capi::ErrorCode>::SUCCESS
                        }
                        ::core::result::Result::Err(err) => {
                            type __ExtErrTy = PrefixExtError;
                            __capi::internal::error::handle_ext_error(
                                err,
                                __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                            )
                        }
                    }
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_unit_result_safestruct_error(
    __output: *mut ::core::mem::MaybeUninit<PrefixSafeStruct>,
) -> ::core::result::Result<
    ::core::result::Result<(), crate::Error>,
    __capi::InvalidArg<'static>,
> {
    #[allow(clippy::let_with_type_underscore)]
    let __output: &mut ::core::mem::MaybeUninit<_> = {
        let __output = __capi::try_as_uninit_mut!(__output);
        __capi::to_inner_mut!(__output)
    };
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_unit_result_safestruct_error() } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    ::core::mem::MaybeUninit::write(__output, __pattern);
                    ::core::result::Result::Ok(::core::result::Result::Ok(()))
                }
                ::core::result::Result::Err(err) => {
                    ::core::result::Result::Ok(::core::result::Result::Err(err))
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(_a = %__capi::internal::util::Addr::from_ptr(_a))
)]
pub extern "C" fn prefix_test_ownedptr_u32_unit(
    _a: *mut ::core::primitive::u32,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ownedptr_u32_unit(
            __capi::internal::util::check_valid_input_ty_mut_ptr(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        _a = %__capi::internal::util::Addr::from_ptr(_a),
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_test_ownedptr_u32_unit_ext(
    _a: *mut ::core::primitive::u32,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ownedptr_u32_unit(
            __capi::internal::util::check_valid_input_ty_mut_ptr(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_ownedptr_u32_unit(
    _a: *mut ::core::primitive::u32,
) -> ::core::result::Result<(), __capi::InvalidArg<'static>> {
    #[allow(clippy::let_with_type_underscore)]
    let _a: __capi::safe::OwnedPtr<::core::primitive::u32> = {
        let _a = __capi::try_consume!(_a);
        __capi::to_inner!(_a)
    };
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_ownedptr_u32_unit(_a) } {
        __pattern => ::core::result::Result::Ok(__pattern),
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(_a = %__capi::internal::util::Addr::from_ptr(_a))
)]
pub extern "C" fn prefix_test_ownedptr_struct_unit(
    _a: *mut PrefixStruct,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ownedptr_struct_unit(
            __capi::internal::util::check_valid_input_ty_mut_ptr(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        _a = %__capi::internal::util::Addr::from_ptr(_a),
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_test_ownedptr_struct_unit_ext(
    _a: *mut PrefixStruct,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ownedptr_struct_unit(
            __capi::internal::util::check_valid_input_ty_mut_ptr(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_ownedptr_struct_unit(
    _a: *mut PrefixStruct,
) -> ::core::result::Result<(), __capi::InvalidArg<'static>> {
    #[allow(clippy::let_with_type_underscore)]
    let _a: __capi::safe::OwnedPtr<_> = {
        let _a = __capi::try_consume!(_a);
        __capi::to_inner!(_a)
    };
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_ownedptr_struct_unit(_a) } {
        __pattern => ::core::result::Result::Ok(__pattern),
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(_a = %__capi::internal::util::Addr::from_ptr(_a))
)]
pub extern "C" fn prefix_test_ownedptr_safestruct_unit(
    _a: *mut PrefixSafeStruct,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ownedptr_safestruct_unit(
            __capi::internal::util::check_valid_input_ty_mut_ptr(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        _a = %__capi::internal::util::Addr::from_ptr(_a),
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_test_ownedptr_safestruct_unit_ext(
    _a: *mut PrefixSafeStruct,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ownedptr_safestruct_unit(
            __capi::internal::util::check_valid_input_ty_mut_ptr(_a),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_ownedptr_safestruct_unit(
    _a: *mut PrefixSafeStruct,
) -> ::core::result::Result<(), __capi::InvalidArg<'static>> {
    #[allow(clippy::let_with_type_underscore)]
    let _a: __capi::safe::OwnedPtr<_> = {
        let _a = __capi::try_consume!(_a);
        __capi::to_inner!(_a)
    };
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_ownedptr_safestruct_unit(_a) } {
        __pattern => ::core::result::Result::Ok(__pattern),
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(_a = %__capi::internal::util::Addr::from_ptr(_a))
)]
pub extern "C" fn prefix_test_ptr_ptr_ptr_ptr_u32_unit(
    _a: *const *const *const *const ::core::primitive::u32,
) {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ptr_ptr_ptr_ptr_u32_unit(
            __capi::internal::util::check_valid_input_ty_const_ptr(_a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_ptr_ptr_ptr_ptr_u32_unit(
    _a: *const *const *const *const ::core::primitive::u32,
) -> () {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_ptr_ptr_ptr_ptr_u32_unit(_a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(a = %__capi::internal::util::Addr::from_ptr(a))
)]
pub extern "C" fn prefix_test_ptr_ptr_ptr_ptr_u32_ptr_ptr_ptr_ptr_u32(
    a: *const *const *const *const ::core::primitive::u32,
) -> *const *const *const *const ::core::primitive::u32 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_ptr_ptr_ptr_ptr_u32_ptr_ptr_ptr_ptr_u32(
            __capi::internal::util::check_valid_input_ty_const_ptr(a),
        )
    } {
        __pattern => __pattern,
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_ptr_ptr_ptr_ptr_u32_ptr_ptr_ptr_ptr_u32(
    a: *const *const *const *const ::core::primitive::u32,
) -> *const *const *const *const ::core::primitive::u32 {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_ptr_ptr_ptr_ptr_u32_ptr_ptr_ptr_ptr_u32(a) } {
        __pattern => __pattern,
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(_a = %__capi::internal::util::Addr::from_ptr(_a), _a_len = _a_len)
)]
pub extern "C" fn prefix_test_slice_u8_unit(
    _a: *const ::core::primitive::u8,
    _a_len: ::core::primitive::usize,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_slice_u8_unit(
            __capi::internal::util::check_valid_input_ty_const_ptr(_a),
            __capi::internal::util::check_valid_input_ty_val(_a_len),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        _a = %__capi::internal::util::Addr::from_ptr(_a),
        _a_len = _a_len,
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_test_slice_u8_unit_ext(
    _a: *const ::core::primitive::u8,
    _a_len: ::core::primitive::usize,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_test_slice_u8_unit(
            __capi::internal::util::check_valid_input_ty_const_ptr(_a),
            __capi::internal::util::check_valid_input_ty_val(_a_len),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    <PrefixError as __capi::ErrorCode>::SUCCESS
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_test_slice_u8_unit(
    _a: *const ::core::primitive::u8,
    _a_len: ::core::primitive::usize,
) -> ::core::result::Result<(), __capi::InvalidArg<'static>> {
    #[allow(clippy::let_with_type_underscore)]
    let _a: &[::core::primitive::u8] = {
        let _a = __capi::try_as_slice!(_a, _a_len);
        __capi::to_inner_slice!(_a)
    };
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { crate::defs::test_slice_u8_unit(_a) } {
        __pattern => ::core::result::Result::Ok(__pattern),
    }
}
/// Initializes `PrefixExtError`.
///
/// When no longer needed, `out`'s resources must be released
/// with its cleanup routine.
///
/// @relates PrefixExtError
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(out = %__capi::internal::util::Addr::from_ptr(out))
)]
pub extern "C" fn prefix_ext_error_init(
    out: *mut ::core::mem::MaybeUninit<PrefixExtError>,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_ext_error_init(
            __capi::internal::util::check_valid_input_ty_mut_ptr(out),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    match __pattern {
                        ::core::result::Result::Ok(()) => {
                            <PrefixError as __capi::ErrorCode>::SUCCESS
                        }
                        ::core::result::Result::Err(ref err) => {
                            __capi::internal::error::convert_err(err)
                        }
                    }
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
/// Initializes `PrefixExtError`.
///
/// When no longer needed, `out`'s resources must be released
/// with its cleanup routine.
///
/// @relates PrefixExtError
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        out = %__capi::internal::util::Addr::from_ptr(out),
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_ext_error_init_ext(
    out: *mut ::core::mem::MaybeUninit<PrefixExtError>,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_ext_error_init(
            __capi::internal::util::check_valid_input_ty_mut_ptr(out),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    match __pattern {
                        ::core::result::Result::Ok(()) => {
                            <PrefixError as __capi::ErrorCode>::SUCCESS
                        }
                        ::core::result::Result::Err(err) => {
                            type __ExtErrTy = PrefixExtError;
                            __capi::internal::error::handle_ext_error(
                                err,
                                __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                            )
                        }
                    }
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_ext_error_init(
    out: *mut ::core::mem::MaybeUninit<PrefixExtError>,
) -> ::core::result::Result<
    ::core::result::Result<(), __capi::InvalidArg<'static>>,
    __capi::InvalidArg<'static>,
> {
    let out: &mut ::core::mem::MaybeUninit<PrefixExtError> = __capi::try_as_uninit_mut!(
        out
    );
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { self::ext_error_init(out) } {
        __pattern => ::core::result::Result::Ok(__pattern),
    }
}
#[::tracing::instrument(fields(out = %__capi::internal::util::Addr::from_mut(out)))]
fn ext_error_init(
    out: &mut ::core::mem::MaybeUninit<PrefixExtError>,
) -> ::core::result::Result<(), __capi::InvalidArg<'static>> {
    <PrefixExtError as __capi::InitDefault>::init_default(out);
    ::core::result::Result::Ok(())
}
/// Releases any resources associated with `ptr`.
///
/// `ptr` must either be null or initialized by `::prefix_ext_error_init`.
///
/// @relates PrefixExtError
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(ptr = %__capi::internal::util::Addr::from_ptr(ptr))
)]
pub extern "C" fn prefix_ext_error_cleanup(ptr: *mut PrefixExtError) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_ext_error_cleanup(
            __capi::internal::util::check_valid_input_ty_mut_ptr(ptr),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    match __pattern {
                        ::core::result::Result::Ok(()) => {
                            <PrefixError as __capi::ErrorCode>::SUCCESS
                        }
                        ::core::result::Result::Err(ref err) => {
                            __capi::internal::error::convert_err(err)
                        }
                    }
                }
                ::core::result::Result::Err(ref err) => {
                    __capi::internal::error::convert_err(err)
                }
            }
        }
    }
}
/// Releases any resources associated with `ptr`.
///
/// `ptr` must either be null or initialized by `::prefix_ext_error_init`.
///
/// @relates PrefixExtError
#[no_mangle]
#[::tracing::instrument(
    level = "trace",
    fields(
        ptr = %__capi::internal::util::Addr::from_ptr(ptr),
        __ext_err = %__capi::internal::util::Addr::from_ptr(__ext_err)
    )
)]
pub extern "C" fn prefix_ext_error_cleanup_ext(
    ptr: *mut PrefixExtError,
    __ext_err: *mut PrefixExtError,
) -> PrefixError {
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match {
        __tramp_prefix_ext_error_cleanup(
            __capi::internal::util::check_valid_input_ty_mut_ptr(ptr),
        )
    } {
        __pattern => {
            match __pattern {
                ::core::result::Result::Ok(__pattern) => {
                    match __pattern {
                        ::core::result::Result::Ok(()) => {
                            <PrefixError as __capi::ErrorCode>::SUCCESS
                        }
                        ::core::result::Result::Err(err) => {
                            type __ExtErrTy = PrefixExtError;
                            __capi::internal::error::handle_ext_error(
                                err,
                                __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                            )
                        }
                    }
                }
                ::core::result::Result::Err(err) => {
                    type __ExtErrTy = PrefixExtError;
                    __capi::internal::error::handle_ext_error(
                        err,
                        __capi::from_inner_mut_ptr!(__ext_err => __ExtErrTy),
                    )
                }
            }
        }
    }
}
#[allow(clippy::unused_unit)]
fn __tramp_prefix_ext_error_cleanup(
    ptr: *mut PrefixExtError,
) -> ::core::result::Result<
    ::core::result::Result<(), __capi::InvalidArg<'static>>,
    __capi::InvalidArg<'static>,
> {
    let ptr: ::core::option::Option<__capi::safe::OwnedPtr<PrefixExtError>> = __capi::try_consume_opt!(
        ptr
    );
    #[allow(clippy::blocks_in_conditions)] #[allow(clippy::match_single_binding)]
    #[allow(unused_braces)]
    match { self::ext_error_cleanup(ptr) } {
        __pattern => ::core::result::Result::Ok(__pattern),
    }
}
#[__capi::internal::tracing::instrument(
    fields(ptr = %__capi::internal::util::Addr::from_opt_owned_ptr(&ptr)),
)]
fn ext_error_cleanup(
    ptr: ::core::option::Option<__capi::safe::OwnedPtr<PrefixExtError>>,
) -> ::core::result::Result<(), __capi::InvalidArg<'static>> {
    if let ::core::option::Option::Some(ptr) = ptr {
        unsafe {
            ptr.drop_in_place();
        }
    }
    ::core::result::Result::Ok(())
}
#[cfg(not(cbindgen))]
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrefixEnum(::core::primitive::u8);
mod __hidden {
    #[allow(clippy::wildcard_imports)]
    use super::*;
    #[doc = ::core::concat!(
        "Hidden impls, etc. for [`", ::core::stringify!(PrefixEnum), "`]."
    )]
    const _: () = {
        impl PrefixEnum {
            #[cfg(not(cbindgen))]
            const A: Self = Self(crate::defs::Enum::A as _);
            #[cfg(not(cbindgen))]
            const B: Self = Self(crate::defs::Enum::B as _);
        }
        impl PrefixEnum {
            const __ENUM_A: <Self as __capi::types::Enum>::Repr = crate::defs::Enum::A
                as <Self as __capi::types::Enum>::Repr;
            const __ENUM_B: <Self as __capi::types::Enum>::Repr = crate::defs::Enum::B
                as <Self as __capi::types::Enum>::Repr;
        }
        #[automatically_derived]
        impl __capi::types::Enum for PrefixEnum {
            type Repr = ::core::primitive::u8;
            fn try_from_repr(repr: Self::Repr) -> ::core::option::Option<Self> {
                let v = match repr {
                    Self::__ENUM_A => Self::A,
                    Self::__ENUM_B => Self::B,
                    _ => return ::core::option::Option::None,
                };
                ::core::option::Option::Some(v)
            }
        }
        impl PrefixEnum {
            /// Converts the underlying type to
            /// `Self`.
            const fn from_underlying(other: crate::defs::Enum) -> Self {
                match other {
                    crate::defs::Enum::A => Self::A,
                    crate::defs::Enum::B => Self::B,
                }
            }
        }
        /// SAFETY: The type is a unit-only enumeration
        /// with a `#[repr(...)]`, and we check for
        /// invalid representations, so it is FFI safe.
        #[automatically_derived]
        unsafe impl __capi::types::Input for PrefixEnum {}
        /// SAFETY: The type is a unit-only enumeration
        /// with a `#[repr(...)]`, and we check for
        /// invalid representations, so it is FFI safe.
        #[automatically_derived]
        unsafe impl __capi::types::ByValue for PrefixEnum {}
        #[automatically_derived]
        impl<T> ::core::convert::From<T> for PrefixEnum
        where
            crate::defs::Enum: ::core::convert::From<T>,
        {
            fn from(v: T) -> Self {
                let other: crate::defs::Enum = <crate::defs::Enum as ::core::convert::From<
                    T,
                >>::from(v);
                Self::from_underlying(other)
            }
        }
        #[automatically_derived]
        impl __capi::types::Enum for crate::defs::Enum {
            type Repr = PrefixEnum;
            fn try_from_repr(repr: PrefixEnum) -> Option<Self> {
                match repr {
                    PrefixEnum::A => ::core::option::Option::Some(Self::A),
                    PrefixEnum::B => ::core::option::Option::Some(Self::B),
                    _ => ::core::option::Option::None,
                }
            }
        }
    };
    pub type PrefixStruct = __PrefixStructFfiWrapper<
        crate::defs::Struct,
        ::core::primitive::u32,
    >;
    #[repr(transparent)]
    #[derive(Debug)]
    pub struct __PrefixStructFfiWrapper<Inner, _0> {
        pub inner: Inner,
        _0: ::core::marker::PhantomData<_0>,
    }
    #[automatically_derived]
    impl<Inner, _0> __capi::InitDefault for __PrefixStructFfiWrapper<Inner, _0>
    where
        Inner: __capi::InitDefault,
    {
        fn init_default(out: &mut ::core::mem::MaybeUninit<Self>) {
            <Inner as __capi::InitDefault>::init_default(unsafe {
                ::core::mem::transmute::<
                    &mut ::core::mem::MaybeUninit<Self>,
                    &mut ::core::mem::MaybeUninit<Inner>,
                >(out)
            })
        }
    }
    #[automatically_derived]
    impl<Inner, _0> ::core::marker::Copy for __PrefixStructFfiWrapper<Inner, _0>
    where
        Inner: ::core::marker::Copy,
    {}
    #[automatically_derived]
    impl<Inner, _0> ::core::clone::Clone for __PrefixStructFfiWrapper<Inner, _0>
    where
        Inner: ::core::clone::Clone,
    {
        fn clone(&self) -> Self {
            Self {
                inner: ::core::clone::Clone::clone(&self.inner),
                _0: ::core::marker::PhantomData,
            }
        }
    }
    #[automatically_derived]
    impl<Inner, _0> ::core::ops::Deref for __PrefixStructFfiWrapper<Inner, _0> {
        type Target = Inner;
        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }
    #[automatically_derived]
    impl<Inner, _0> ::core::ops::DerefMut for __PrefixStructFfiWrapper<Inner, _0> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }
    #[automatically_derived]
    impl<Inner, _0> __capi::Builder for __PrefixStructFfiWrapper<Inner, _0>
    where
        Inner: __capi::Builder,
    {
        type Output = <Inner as __capi::Builder>::Output;
        type Error = <Inner as __capi::Builder>::Error;
        unsafe fn build(
            self,
            out: &mut ::core::mem::MaybeUninit<Self::Output>,
        ) -> ::core::result::Result<(), Self::Error> {
            unsafe { __capi::Builder::build(self.inner, out) }
        }
    }
    #[automatically_derived]
    unsafe impl<_0> __capi::internal::conv::newtype::NewType
    for __PrefixStructFfiWrapper<crate::defs::Struct, _0> {
        type Inner = crate::defs::Struct;
    }
    #[automatically_derived]
    impl<Inner, _0> __capi::types::Opaque for __PrefixStructFfiWrapper<Inner, _0>
    where
        Inner: __capi::types::Opaque,
    {}
    #[automatically_derived]
    unsafe impl<Inner, _0> __capi::types::Input for __PrefixStructFfiWrapper<Inner, _0>
    where
        _0: __capi::types::Input,
    {}
    #[automatically_derived]
    unsafe impl<Inner, _0> __capi::types::ByValue for __PrefixStructFfiWrapper<Inner, _0>
    where
        Inner: ::core::marker::Copy,
        _0: __capi::types::ByValue,
    {}
    #[automatically_derived]
    unsafe impl<Inner, _0> __capi::types::ByConstPtr
    for __PrefixStructFfiWrapper<Inner, _0>
    where
        _0: __capi::types::ByConstPtr,
    {}
    #[automatically_derived]
    unsafe impl<Inner, _0> __capi::types::ByMutPtr
    for __PrefixStructFfiWrapper<Inner, _0>
    where
        _0: __capi::types::ByMutPtr,
    {}
    const _: () = {
        const GOT: usize = ::core::mem::size_of::<PrefixStruct>();
        const WANT: usize = ::core::mem::size_of::<crate::defs::Struct>();
        const MSG: &str = __capi::internal::const_format::formatcp!(
            "BUG: invalid size: {GOT} != {WANT}"
        );
        ::core::assert!(GOT == WANT, "{}", MSG);
    };
    const _: () = {
        const GOT: usize = ::core::mem::align_of::<PrefixStruct>();
        const WANT: usize = ::core::mem::align_of::<crate::defs::Struct>();
        const MSG: &str = __capi::internal::const_format::formatcp!(
            "BUG: invalid alignment: {GOT} != {WANT}"
        );
        ::core::assert!(GOT == WANT, "{}", MSG);
    };
    const _: () = {
        const GOT: bool = ::core::mem::needs_drop::<PrefixStruct>();
        const WANT: bool = ::core::mem::needs_drop::<crate::defs::Struct>();
        const MSG: &str = __capi::internal::const_format::formatcp!(
            "BUG: invalid `Drop` impl: {GOT} != {WANT}"
        );
        ::core::assert!(GOT == WANT, "{}", MSG);
    };
    pub type PrefixSafeStruct = __PrefixSafeStructFfiWrapper<crate::defs::SafeStruct>;
    #[repr(transparent)]
    #[derive(Debug)]
    pub struct __PrefixSafeStructFfiWrapper<Inner> {
        pub inner: Inner,
    }
    #[automatically_derived]
    impl<Inner> __capi::InitDefault for __PrefixSafeStructFfiWrapper<Inner>
    where
        Inner: __capi::InitDefault,
    {
        fn init_default(out: &mut ::core::mem::MaybeUninit<Self>) {
            <Inner as __capi::InitDefault>::init_default(unsafe {
                ::core::mem::transmute::<
                    &mut ::core::mem::MaybeUninit<Self>,
                    &mut ::core::mem::MaybeUninit<Inner>,
                >(out)
            })
        }
    }
    #[automatically_derived]
    impl<Inner> ::core::marker::Copy for __PrefixSafeStructFfiWrapper<Inner>
    where
        Inner: ::core::marker::Copy,
    {}
    #[automatically_derived]
    impl<Inner> ::core::clone::Clone for __PrefixSafeStructFfiWrapper<Inner>
    where
        Inner: ::core::clone::Clone,
    {
        fn clone(&self) -> Self {
            Self {
                inner: ::core::clone::Clone::clone(&self.inner),
            }
        }
    }
    #[automatically_derived]
    impl<Inner> ::core::ops::Deref for __PrefixSafeStructFfiWrapper<Inner> {
        type Target = Inner;
        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }
    #[automatically_derived]
    impl<Inner> ::core::ops::DerefMut for __PrefixSafeStructFfiWrapper<Inner> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }
    #[automatically_derived]
    impl<Inner> __capi::Builder for __PrefixSafeStructFfiWrapper<Inner>
    where
        Inner: __capi::Builder,
    {
        type Output = <Inner as __capi::Builder>::Output;
        type Error = <Inner as __capi::Builder>::Error;
        unsafe fn build(
            self,
            out: &mut ::core::mem::MaybeUninit<Self::Output>,
        ) -> ::core::result::Result<(), Self::Error> {
            unsafe { __capi::Builder::build(self.inner, out) }
        }
    }
    #[automatically_derived]
    unsafe impl __capi::internal::conv::newtype::NewType
    for __PrefixSafeStructFfiWrapper<crate::defs::SafeStruct> {
        type Inner = crate::defs::SafeStruct;
    }
    #[automatically_derived]
    impl<Inner> __capi::types::Opaque for __PrefixSafeStructFfiWrapper<Inner>
    where
        Inner: __capi::types::Opaque,
    {}
    #[automatically_derived]
    unsafe impl<Inner> __capi::types::Input for __PrefixSafeStructFfiWrapper<Inner> {}
    #[automatically_derived]
    unsafe impl<Inner> __capi::types::ByValue for __PrefixSafeStructFfiWrapper<Inner>
    where
        Inner: ::core::marker::Copy,
    {}
    #[automatically_derived]
    unsafe impl<Inner> __capi::types::ByConstPtr
    for __PrefixSafeStructFfiWrapper<Inner> {}
    #[automatically_derived]
    unsafe impl<Inner> __capi::types::ByMutPtr for __PrefixSafeStructFfiWrapper<Inner> {}
    const _: () = {
        const GOT: usize = ::core::mem::size_of::<PrefixSafeStruct>();
        const WANT: usize = ::core::mem::size_of::<crate::defs::SafeStruct>();
        const MSG: &str = __capi::internal::const_format::formatcp!(
            "BUG: invalid size: {GOT} != {WANT}"
        );
        ::core::assert!(GOT == WANT, "{}", MSG);
    };
    const _: () = {
        const GOT: usize = ::core::mem::align_of::<PrefixSafeStruct>();
        const WANT: usize = ::core::mem::align_of::<crate::defs::SafeStruct>();
        const MSG: &str = __capi::internal::const_format::formatcp!(
            "BUG: invalid alignment: {GOT} != {WANT}"
        );
        ::core::assert!(GOT == WANT, "{}", MSG);
    };
    const _: () = {
        const GOT: bool = ::core::mem::needs_drop::<PrefixSafeStruct>();
        const WANT: bool = ::core::mem::needs_drop::<crate::defs::SafeStruct>();
        const MSG: &str = __capi::internal::const_format::formatcp!(
            "BUG: invalid `Drop` impl: {GOT} != {WANT}"
        );
        ::core::assert!(GOT == WANT, "{}", MSG);
    };
    pub type PrefixExtError = __PrefixExtErrorFfiWrapper<crate::defs::ExtError>;
    #[repr(transparent)]
    #[derive(Debug)]
    pub struct __PrefixExtErrorFfiWrapper<Inner> {
        pub inner: Inner,
    }
    #[automatically_derived]
    impl<Inner> __capi::InitDefault for __PrefixExtErrorFfiWrapper<Inner>
    where
        Inner: __capi::InitDefault,
    {
        fn init_default(out: &mut ::core::mem::MaybeUninit<Self>) {
            <Inner as __capi::InitDefault>::init_default(unsafe {
                ::core::mem::transmute::<
                    &mut ::core::mem::MaybeUninit<Self>,
                    &mut ::core::mem::MaybeUninit<Inner>,
                >(out)
            })
        }
    }
    #[automatically_derived]
    impl<Inner> ::core::marker::Copy for __PrefixExtErrorFfiWrapper<Inner>
    where
        Inner: ::core::marker::Copy,
    {}
    #[automatically_derived]
    impl<Inner> ::core::clone::Clone for __PrefixExtErrorFfiWrapper<Inner>
    where
        Inner: ::core::clone::Clone,
    {
        fn clone(&self) -> Self {
            Self {
                inner: ::core::clone::Clone::clone(&self.inner),
            }
        }
    }
    #[automatically_derived]
    impl<Inner> ::core::ops::Deref for __PrefixExtErrorFfiWrapper<Inner> {
        type Target = Inner;
        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }
    #[automatically_derived]
    impl<Inner> ::core::ops::DerefMut for __PrefixExtErrorFfiWrapper<Inner> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }
    #[automatically_derived]
    impl<Inner> __capi::Builder for __PrefixExtErrorFfiWrapper<Inner>
    where
        Inner: __capi::Builder,
    {
        type Output = <Inner as __capi::Builder>::Output;
        type Error = <Inner as __capi::Builder>::Error;
        unsafe fn build(
            self,
            out: &mut ::core::mem::MaybeUninit<Self::Output>,
        ) -> ::core::result::Result<(), Self::Error> {
            unsafe { __capi::Builder::build(self.inner, out) }
        }
    }
    #[automatically_derived]
    unsafe impl __capi::internal::conv::newtype::NewType
    for __PrefixExtErrorFfiWrapper<crate::defs::ExtError> {
        type Inner = crate::defs::ExtError;
    }
    #[automatically_derived]
    impl<Inner> __capi::types::Opaque for __PrefixExtErrorFfiWrapper<Inner>
    where
        Inner: __capi::types::Opaque,
    {}
    #[automatically_derived]
    unsafe impl<Inner> __capi::types::Input for __PrefixExtErrorFfiWrapper<Inner> {}
    #[automatically_derived]
    unsafe impl<Inner> __capi::types::ByValue for __PrefixExtErrorFfiWrapper<Inner>
    where
        Inner: ::core::marker::Copy,
    {}
    #[automatically_derived]
    unsafe impl<Inner> __capi::types::ByConstPtr for __PrefixExtErrorFfiWrapper<Inner> {}
    #[automatically_derived]
    unsafe impl<Inner> __capi::types::ByMutPtr for __PrefixExtErrorFfiWrapper<Inner> {}
    const _: () = {
        const GOT: usize = ::core::mem::size_of::<PrefixExtError>();
        const WANT: usize = ::core::mem::size_of::<crate::defs::ExtError>();
        const MSG: &str = __capi::internal::const_format::formatcp!(
            "BUG: invalid size: {GOT} != {WANT}"
        );
        ::core::assert!(GOT == WANT, "{}", MSG);
    };
    const _: () = {
        const GOT: usize = ::core::mem::align_of::<PrefixExtError>();
        const WANT: usize = ::core::mem::align_of::<crate::defs::ExtError>();
        const MSG: &str = __capi::internal::const_format::formatcp!(
            "BUG: invalid alignment: {GOT} != {WANT}"
        );
        ::core::assert!(GOT == WANT, "{}", MSG);
    };
    const _: () = {
        const GOT: bool = ::core::mem::needs_drop::<PrefixExtError>();
        const WANT: bool = ::core::mem::needs_drop::<crate::defs::ExtError>();
        const MSG: &str = __capi::internal::const_format::formatcp!(
            "BUG: invalid `Drop` impl: {GOT} != {WANT}"
        );
        ::core::assert!(GOT == WANT, "{}", MSG);
    };
    #[doc = ::core::concat!(
        "Hidden impls, etc. for [`", ::core::stringify!(PrefixError), "`]."
    )]
    const _: () = {
        impl PrefixError {
            const __ENUM_SUCCESS: <Self as __capi::types::Enum>::Repr = crate::defs::Error::Success
                as <Self as __capi::types::Enum>::Repr;
            const __ENUM_INVALID_ARG: <Self as __capi::types::Enum>::Repr = crate::defs::Error::InvalidArg
                as <Self as __capi::types::Enum>::Repr;
        }
        #[automatically_derived]
        impl __capi::types::Enum for PrefixError {
            type Repr = ::core::primitive::u32;
            fn try_from_repr(repr: Self::Repr) -> ::core::option::Option<Self> {
                let v = match repr {
                    Self::__ENUM_SUCCESS => Self::Success,
                    Self::__ENUM_INVALID_ARG => Self::InvalidArg,
                    _ => return ::core::option::Option::None,
                };
                ::core::option::Option::Some(v)
            }
        }
        impl PrefixError {
            /// Converts the underlying type to
            /// `Self`.
            const fn from_underlying(other: crate::defs::Error) -> Self {
                match other {
                    crate::defs::Error::Success => Self::Success,
                    crate::defs::Error::InvalidArg => Self::InvalidArg,
                }
            }
        }
        /// SAFETY: The type is a unit-only enumeration
        /// with a `#[repr(...)]`, and we check for
        /// invalid representations, so it is FFI safe.
        #[automatically_derived]
        unsafe impl __capi::types::Input for PrefixError {}
        /// SAFETY: The type is a unit-only enumeration
        /// with a `#[repr(...)]`, and we check for
        /// invalid representations, so it is FFI safe.
        #[automatically_derived]
        unsafe impl __capi::types::ByValue for PrefixError {}
        #[automatically_derived]
        impl<T> ::core::convert::From<T> for PrefixError
        where
            crate::defs::Error: ::core::convert::From<T>,
        {
            fn from(v: T) -> Self {
                let other: crate::defs::Error = <crate::defs::Error as ::core::convert::From<
                    T,
                >>::from(v);
                Self::from_underlying(other)
            }
        }
    };
}