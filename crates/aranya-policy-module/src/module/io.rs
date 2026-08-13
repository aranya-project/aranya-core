use bytes::{Buf as _, BufMut as _};
use sha2::{Digest as _, Sha256};

use crate::{Module, ModuleData, Version};

const MODULE_MAGIC: [u8; 8] = [0x50, 0x4d, 0x4f, 0x44, 0xcb, 0xb3, 0xcc, 0xbe];

/// Errors that can be produced by reading or writing a module
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ModuleIoError {
    /// Invalid version in header
    #[error("invalid version")]
    InvalidVersion,
    /// Postcard deserialization produced an error
    #[error("postcard")]
    Postcard(#[from] postcard::Error),
    /// zstd compression
    #[error("compression")]
    Compression,
    /// zstd decompression
    #[error("decompression")]
    Decompression,
    /// The source or destination slice is too small to fit the data
    #[error("insufficient space in target slice")]
    SliceTooSmall,
    /// The checksum didn't match when loading a module
    #[error("checksum mismatch")]
    ChecksumMismatch,
    /// The header magic did not match when loading a module
    #[error("bad header magic")]
    BadMagic,
}

// details for these errors are elided as zrip's errors don't implement `core::error::Error`,
// and I don't expect they'd be useful anyway.
impl From<zrip::CompressError> for ModuleIoError {
    fn from(_: zrip::CompressError) -> Self {
        Self::Compression
    }
}

impl From<zrip::DecompressError> for ModuleIoError {
    fn from(_: zrip::DecompressError) -> Self {
        Self::Decompression
    }
}

// This does not use regular postcard serialization because we want all fields to be fixed-width
#[derive(Debug)]
struct Header {
    magic: [u8; 8],
    version: u32,
    size: u32,
    uncompressed_size: u32,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            magic: MODULE_MAGIC,
            version: 0,
            size: 0,
            uncompressed_size: 0,
        }
    }
}

impl Header {
    const LEN: usize = size_of::<Self>();

    fn write_to_slice(&self, s: &mut [u8]) -> Result<(), ModuleIoError> {
        if s.len() < Self::LEN {
            return Err(ModuleIoError::SliceTooSmall);
        }
        let mut b = &mut s[..];
        b.put_slice(&self.magic);
        b.put_u32(self.version);
        b.put_u32(self.size);
        b.put_u32(self.uncompressed_size);
        Ok(())
    }

    fn read_from_slice(s: &[u8]) -> Result<Self, ModuleIoError> {
        if s.len() < Self::LEN {
            return Err(ModuleIoError::SliceTooSmall);
        }

        let mut h = Self::default();
        // create a new mutable ref so it can move via `BufMut`
        let mut b = s;
        b.copy_to_slice(&mut h.magic);
        h.version = b.get_u32();
        h.size = b.get_u32();
        h.uncompressed_size = b.get_u32();
        Ok(h)
    }
}

impl Module {
    /// Write a module to a mutable slice.
    ///
    /// The slice need to be large enough to contain the serialized module, or it will
    /// return [`ModuleIoError::SliceTooSmall`]. But since this process involves serialization and
    /// compression, it is not generally possible to know that size ahead of time.
    pub fn write_to_slice(&self, s: &mut [u8]) -> Result<usize, ModuleIoError> {
        if s.len() < Header::LEN {
            return Err(ModuleIoError::SliceTooSmall);
        }
        let after_header = &mut s[Header::LEN..];
        let module_data = match &self.data {
            ModuleData::V0(m) => postcard::to_allocvec(&m)?,
            ModuleData::V1(m) => postcard::to_allocvec(&m)?,
        };
        let compressed_size = zrip::compress_into(&module_data, after_header, 4)?;
        let header_data_len = compressed_size.saturating_add(Header::LEN);
        let header_data_checksum_len = header_data_len.saturating_add(32);
        if s.len() < header_data_checksum_len {
            return Err(ModuleIoError::SliceTooSmall);
        }

        let h = Header {
            version: self.version().to_u32(),
            size: header_data_checksum_len as u32,
            uncompressed_size: module_data.len() as u32,
            ..Default::default()
        };
        h.write_to_slice(s)?;

        let hash: [u8; 32] = Sha256::digest(&s[..header_data_len]).into();
        s[header_data_len..header_data_checksum_len].copy_from_slice(&hash);

        Ok(header_data_checksum_len)
    }

    /// Read a module from a slice.
    ///
    /// The slice does not have to be exactly sized; the module header will read only the bytes
    /// necessary. If there are not enough bytes in the slice according to the header, this will
    /// return [`ModuleIoError::SliceTooSmall`].
    pub fn read_from_slice(s: &[u8]) -> Result<Self, ModuleIoError> {
        let h = Header::read_from_slice(s)?;
        if h.magic != MODULE_MAGIC {
            return Err(ModuleIoError::BadMagic);
        }
        let header_data_checksum_len = h.size as usize;
        if header_data_checksum_len > s.len() {
            return Err(ModuleIoError::SliceTooSmall);
        }
        let header_data_len = header_data_checksum_len.saturating_sub(32);
        let checksum = &s[header_data_len..header_data_checksum_len];
        let computed_checksum: [u8; 32] = Sha256::digest(&s[..header_data_len]).into();
        if checksum != computed_checksum {
            return Err(ModuleIoError::ChecksumMismatch);
        }
        let compressed_data = &s[Header::LEN..header_data_len];
        let data = zrip::decompress_with_limit(compressed_data, h.uncompressed_size as usize)?;
        let module_data = match Version::try_from_u32(h.version) {
            Some(Version::V0) => ModuleData::V0(postcard::from_bytes(&data)?),
            Some(Version::V1) => ModuleData::V1(postcard::from_bytes(&data)?),
            None => return Err(ModuleIoError::InvalidVersion),
        };
        Ok(Self { data: module_data })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

    use sha2::{Digest as _, Sha256};

    use crate::{Module, ModuleData, ModuleIoError, ModuleV1, module::io::Header, v1};

    fn dummy_module() -> Module {
        Module {
            data: ModuleData::V1(ModuleV1 {
                program: v1::Program {
                    progmem: Box::new([]),
                    labels: BTreeMap::new(),
                    globals: BTreeMap::new(),
                    codemap: None,
                },
                contract: v1::Contract {
                    signature: [0u8; 32],
                    actions: Vec::new(),
                    commands: Vec::new(),
                    facts: Vec::new(),
                    structs: Vec::new(),
                    enums: Vec::new(),
                    ffis: Vec::new(),
                },
            }),
        }
    }

    /// Evil procedure which recomputes the hash of the module data for testing corrupted data
    /// normally protected by the checksum.
    fn recompute_checksum(s: &mut [u8]) {
        let hash_boundary = s.len().saturating_sub(32);
        let new_checksum: [u8; 32] = Sha256::digest(&s[..hash_boundary]).into();
        s[hash_boundary..].copy_from_slice(&new_checksum);
    }

    #[test]
    fn test_round_trip() {
        let m = dummy_module();

        let mut buf = [0u8; 256];
        let n = m
            .write_to_slice(&mut buf)
            .expect("cannot write module to slice");
        println!("wrote {n} bytes");
        let m2 = Module::read_from_slice(&buf).expect("could not read module from slice");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_short_read() {
        let buf = [0u8; 4];
        let e = Module::read_from_slice(&buf).expect_err("read_from_slice erroneously succeeded");
        assert_eq!(e, ModuleIoError::SliceTooSmall);
    }

    #[test]
    fn test_short_write() {
        let m = dummy_module();
        let e = m
            .write_to_slice(&mut [])
            .expect_err("write_to_slice erroneously succeeded");
        assert_eq!(e, ModuleIoError::SliceTooSmall);
    }

    #[test]
    fn test_slightly_less_short_write() {
        let m = dummy_module();
        let mut buf = [0u8; Header::LEN];
        let e = m
            .write_to_slice(&mut buf)
            .expect_err("write_to_slice erroneously succeeded");
        // This produces a compression error because `write_to_slice` compresses directly into the
        // output buffer. If there is insufficient space, zrip errors.
        assert_eq!(e, ModuleIoError::Compression);
    }

    #[test]
    fn test_not_enough_space_for_checksum() {
        let m = dummy_module();
        let mut buf = [0u8; 40]; // magic 40 here calculated by hand and depends on serialization and compression
        let e = m
            .write_to_slice(&mut buf)
            .expect_err("write_to_slice erroneously succeeded");
        // Here compression has enough space to succeed, but there is not enough space to write the
        // checksum afterwards.
        assert_eq!(e, ModuleIoError::SliceTooSmall);
    }

    #[test]
    fn bad_checksum() {
        let m = dummy_module();
        let mut buf = [0u8; 256];
        let n = m.write_to_slice(&mut buf).expect("write_to_slice failed");

        let before_checksum = n.saturating_sub(32);
        buf[before_checksum..n].fill(0);

        let e = Module::read_from_slice(&buf).expect_err("read_from_slice erroneously succeeded");
        assert_eq!(e, ModuleIoError::ChecksumMismatch);
    }

    #[test]
    fn bad_magic() {
        let m = dummy_module();
        let mut buf = [0u8; 256];
        m.write_to_slice(&mut buf).expect("write_to_slice failed");

        buf[0..8].fill(0);

        let e = Module::read_from_slice(&buf).expect_err("read_from_slice erroneously succeeded");
        assert_eq!(e, ModuleIoError::BadMagic);
    }

    #[test]
    fn bad_decompression() {
        let m = dummy_module();
        let mut buf = [0u8; 256];
        let n = m.write_to_slice(&mut buf).expect("write_to_slice failed");

        buf[Header::LEN] = 0; // destroy the beginning of compressed data
        recompute_checksum(&mut buf[..n]);

        let e = Module::read_from_slice(&buf).expect_err("read_from_slice erroneously succeeded");
        assert_eq!(e, ModuleIoError::Decompression);
    }

    #[test]
    fn bad_version() {
        let m = dummy_module();
        let mut buf = [0u8; 256];
        let n = m.write_to_slice(&mut buf).expect("write_to_slice failed");

        buf[8..12].fill(0xFF); // corrupt the version field
        recompute_checksum(&mut buf[..n]);

        let e = Module::read_from_slice(&buf).expect_err("read_from_slice erroneously succeeded");
        assert_eq!(e, ModuleIoError::InvalidVersion);
    }

    #[test]
    fn bad_postcard() {
        let mut buf = [0u8; 256];

        let data_area = &mut buf[Header::LEN..];
        // just some data that doesn't fit the thing we expect to deserialize
        let bad_data = postcard::to_allocvec(&[1, 2, 3]).expect("could not serialize slice");
        let compressed_bad_data = zrip::compress(&bad_data, 4).expect("could not compress");
        data_area[..compressed_bad_data.len()].copy_from_slice(&compressed_bad_data);
        let new_total_size = Header::LEN
            .saturating_add(compressed_bad_data.len())
            .saturating_add(32);
        let new_header = Header {
            version: 1,
            size: new_total_size as u32,
            uncompressed_size: bad_data.len() as u32,
            ..Default::default()
        };
        new_header
            .write_to_slice(&mut buf)
            .expect("Could not write new header");
        recompute_checksum(&mut buf[..new_total_size]);

        let e = Module::read_from_slice(&buf).expect_err("read_from_slice erroneously succeeded");
        assert!(
            matches!(e, ModuleIoError::Postcard(_)),
            "got {e:?}, expected ModuleIoError::Postcard(_)"
        );
    }
}
