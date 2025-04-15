use aranya_capi_core::{
    prelude::*,
    safe::{TypeId, Typed},
    InvalidArg,
};

pub fn test_unit_unit0() {}
#[allow(clippy::unused_unit)]
pub fn test_unit_unit1() -> () {}
pub fn test_unit_result_unit_error() -> Result<(), crate::Error> {
    Ok(())
}

pub fn test_u8_unit(_a: u8) {}
pub fn test_u16_unit(_a: u16) {}
pub fn test_u32_unit(_a: u32) {}
pub fn test_u64_unit(_a: u64) {}
pub fn test_usize_unit(_a: usize) {}

pub fn test_i8_unit(_a: i8) {}
pub fn test_i16_unit(_a: i16) {}
pub fn test_i32_unit(_a: i32) {}
pub fn test_i64_unit(_a: i64) {}
pub fn test_isize_unit(_a: isize) {}

pub fn test_u8_u8(_a: u8) -> u8 {
    0
}
pub fn test_u16_u16(_a: u16) -> u16 {
    0
}
pub fn test_u32_u32(_a: u32) -> u32 {
    0
}
pub fn test_u64_u64(_a: u64) -> u64 {
    0
}
pub fn test_usize_usize(_a: usize) -> usize {
    0
}

pub fn test_i8_i8(_a: i8) -> i8 {
    0
}
pub fn test_i16_i16(_a: i16) -> i16 {
    0
}
pub fn test_i32_i32(_a: i32) -> i32 {
    0
}
pub fn test_i64_i64(_a: i64) -> i64 {
    0
}
pub fn test_isize_isize(_a: isize) -> isize {
    0
}

pub fn test_u8_u8_u8(_a: u8, _b: u8) -> u8 {
    0
}
pub fn test_u16_u16_u16(_a: u16, _b: u16) -> u16 {
    0
}
pub fn test_u32_u32_u32(_a: u32, _b: u32) -> u32 {
    0
}
pub fn test_u64_u64_u64(_a: u64, _b: u64) -> u64 {
    0
}
pub fn test_usize_usize_usize(_a: usize, _b: usize) -> usize {
    0
}

pub fn test_i8_i8_i8(_a: i8, _b: i8) -> i8 {
    0
}
pub fn test_i16_i16_i16(_a: i16, _b: i16) -> i16 {
    0
}
pub fn test_i32_i32_i32(_a: i32, _b: i32) -> i32 {
    0
}
pub fn test_i64_i64_i64(_a: i64, _b: i64) -> i64 {
    0
}
pub fn test_isize_isize_isize(_a: isize, _b: isize) -> isize {
    0
}

#[repr(u8)]
#[derive(Copy, Clone, Default, Debug)]
pub enum Enum {
    #[default]
    A,
    B,
}

pub fn test_enum_unit(_a: Enum) {}
pub fn test_unit_enum() -> Enum {
    Enum::A
}
pub fn test_enum_enum(a: Enum) -> Enum {
    a
}
pub fn test_enum_result_enum_error(a: Enum) -> Result<Enum, crate::Error> {
    Ok(a)
}
// pub fn test_mut_ref_enum_enum(a: &mut Enum) -> Enum {
//     a.clone()
// }

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct Struct {
    pub a: u32,
    // pub b: Enum,
}

impl Typed for Struct {
    const TYPE_ID: TypeId = TypeId::new(1234);
}

pub fn test_struct_unit(_a: Struct) {}
pub fn test_unit_struct() -> Struct {
    Struct {
        a: 42,
        // b: Enum::A,
    }
}
pub fn test_ref_struct_unit(_a: &Struct) {}
// pub fn test_ref_ref_struct_unit(_a: &&Struct) {}
pub fn test_ptr_struct_unit(_a: *const Struct) {}
pub fn test_struct_struct(a: Struct) -> Struct {
    a
}
pub fn test_unit_result_struct_error() -> Result<Struct, crate::Error> {
    Err(crate::Error::BufferTooSmall)
}

pub fn test_optional_ref_struct(_a: Option<&Struct>) {}
pub fn test_optional_mut_ref_struct(_a: Option<&mut Struct>) {}
// pub fn test_nested_optional_ref_struct(_a: Option<&Option<&Struct>>) {}

pub type SafeStruct = Safe<Struct>;

// TODO(eric): Should we allow this?
// pub fn test_safestruct_unit(_a: SafeStruct) {}
// TODO(eric): Should we allow this?
// pub fn test_unit_safestruct() -> SafeStruct {
//     unimplemented!()
// }
pub fn test_ref_safestruct_unit(_a: &SafeStruct) {}
pub fn test_ptr_safestruct_unit(_a: *const SafeStruct) {}
// TODO(eric): Should we allow this?
// pub fn test_safestruct_safestruct(a: SafeStruct) -> SafeStruct {
//     a
// }
pub fn test_unit_result_safestruct_error() -> Result<SafeStruct, crate::Error> {
    Err(crate::Error::BufferTooSmall)
}

// pub fn test_cstr_unit(_a: &'static CStr) {}
// pub fn test_unit_cstr() -> &'static CStr {
//     c"hello, world!"
// }
// pub fn test_cstr_cstr<'a>(a: &'a CStr) -> &'a CStr {
//     a
// }
// pub fn test_cstr_result_cstr_error<'a>(a: &'a CStr) -> Result<&'a CStr, crate::Error> {
//     Ok(a)
// }

// pub fn test_option_cstr_unit(_a: Option<&CStr>) {}
// pub fn test_unit_option_cstr<'a>() -> Option<&'a CStr> {
//     None
// }

pub fn test_ownedptr_u32_unit(_a: OwnedPtr<u32>) {}
pub fn test_ownedptr_struct_unit(_a: OwnedPtr<Struct>) {}
// TODO(eric): Should we allow this?
// pub fn test_ownedptr_ownedptr_u32_unit(_a: OwnedPtr<OwnedPtr<u32>>) {}
// pub fn test_ownedptr_ownedptr_struct_unit(_a: OwnedPtr<OwnedPtr<Struct>>) {}

pub fn test_ownedptr_safestruct_unit(_a: OwnedPtr<SafeStruct>) {}
// TODO(eric): Should we allow this?
// pub fn test_ownedptr_ownedptr_safestruct_unit(_a: OwnedPtr<OwnedPtr<SafeStruct>>) {}

pub fn test_ptr_ptr_ptr_ptr_u32_unit(_a: *const *const *const *const u32) {}
pub fn test_ptr_ptr_ptr_ptr_u32_ptr_ptr_ptr_ptr_u32(
    a: *const *const *const *const u32,
) -> *const *const *const *const u32 {
    a
}

pub fn test_slice_u8_unit(_a: &[u8]) {}

pub fn test_ref_arr_u8_unit(_a: &[u8; 64]) {}
pub fn test_ref_arr_u8_ret(a: &[u8; 64]) -> [u8; 64] {
    *a
}
pub fn test_mut_ref_arr_u8_unit(_a: &mut [u8; 64]) {}

/// Extended error information.
#[aranya_capi_core::derive(Init, Cleanup)]
#[aranya_capi_core::opaque(size = 72, align = 8)]
pub type ExtError = Safe<crate::ExtError>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ErrorCode)]
#[repr(u32)]
pub enum Error {
    #[capi(success)]
    #[capi(msg = "success")]
    Success,
    #[capi(msg = "invalid argument")]
    InvalidArg,
}

impl From<&InvalidArg<'static>> for Error {
    fn from(_err: &InvalidArg<'static>) -> Self {
        Self::InvalidArg
    }
}

impl From<&crate::Error> for Error {
    fn from(_err: &crate::Error) -> Self {
        unimplemented!()
    }
}

#[cfg(feature = "test_cfg")]
#[repr(transparent)]
pub struct TestConfigInheritance(u8);

#[cfg(feature = "test_cfg")]
pub fn test_cfg_inheritance() {}

#[cfg(not(feature = "test_cfg"))]
#[repr(transparent)]
pub struct TestConfigInheritance2(u8);

#[cfg(not(feature = "test_cfg"))]
pub fn test_cfg_inheritance2() {}
