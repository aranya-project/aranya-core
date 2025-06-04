use aranya_crypto::afc::Seq;
use buggy::{Bug, BugExt, bug};
use serde::{Deserialize, Serialize};

use crate::state::Label;

macro_rules! packed {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident $($tokens:tt)*
    ) => {
        $(#[$meta])*
        $vis struct $name $($tokens)*
        impl $name {
            /// The size in bytes of the packed struct.
            $vis const PACKED_SIZE: usize = {
                #[repr(C, packed)]
                #[allow(dead_code)]
                $vis struct $name $($tokens)*
                ::core::mem::size_of::<$name>()
            };
        }
    };
}

packed! {
    /// The per-message header.
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct Header {
        /// The APS protocol version.
        pub version: Version,
        /// The type of message.
        pub msg_type: MsgType,
        /// The channel label.
        pub label: Label,
    }
}

impl Header {
    /// Parses the header from its byte representation.
    pub fn try_parse(buf: &[u8; Self::PACKED_SIZE]) -> Result<Self, HeaderError> {
        let (version, rest) = buf
            .split_first_chunk()
            .assume("`buf` should be large enough for `Version`")?;
        let (msg_typ, rest) = rest
            .split_first_chunk()
            .assume("`buf` should be large enough for `MsgType`")?;
        let (label, rest) = rest
            .split_first_chunk()
            .assume("`buf` should be large enough for `Label`")?;

        if !rest.is_empty() {
            bug!("`rest` has trailing data");
        }

        Ok(Self {
            version: Version::try_from_u16(u16::from_le_bytes(*version))
                .ok_or(HeaderError::UnknownVersion)?,
            msg_type: MsgType::try_from_u16(u16::from_le_bytes(*msg_typ))
                .ok_or(HeaderError::InvalidMsgType)?,
            label: u32::from_le_bytes(*label).into(),
        })
    }

    /// Writes its byte representation to `out`.
    pub fn encode(&self, out: &mut [u8; Header::PACKED_SIZE]) -> Result<(), HeaderError> {
        let (version_out, rest) = out
            .split_first_chunk_mut()
            .assume("`out` should be large enough for `Version`")?;
        *version_out = self.version.to_u16().to_le_bytes();

        let (msg_typ_out, rest) = rest
            .split_first_chunk_mut()
            .assume("`out` should be large enough for `MsgType`")?;
        *msg_typ_out = self.msg_type.to_u16().to_le_bytes();

        let (label_out, rest) = rest
            .split_first_chunk_mut()
            .assume("`out` should be large enough for `Label`")?;
        *label_out = self.label.to_u32().to_le_bytes();

        if !rest.is_empty() {
            bug!("`out` should be exactly `Header::PACKED_SIZE`");
        }

        Ok(())
    }
}

packed! {
    /// The "header" appended to data messages.
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub(crate) struct DataHeader {
        /// The channel label.
        pub label: Label,
        /// The ciphertext's sequence number.
        pub seq: Seq,
    }
}

impl DataHeader {
    /// Parses the header from its byte representation.
    pub fn try_parse(buf: &[u8; Self::PACKED_SIZE]) -> Result<Self, HeaderError> {
        let (label, rest) = buf
            .split_first_chunk()
            .assume("`buf` should be large enough for `Label`")?;
        let (seq, rest) = rest
            .split_first_chunk()
            .assume("`buf` should be large enough for `Seq`")?;

        if !rest.is_empty() {
            bug!("`rest` has trailing data");
        }

        Ok(Self {
            label: u32::from_le_bytes(*label).into(),
            seq: Seq::new(u64::from_le_bytes(*seq)),
        })
    }

    /// Writes the header to `out`.
    pub fn encode(&self, out: &mut [u8; DataHeader::PACKED_SIZE]) -> Result<(), HeaderError> {
        let (label_out, rest) = out
            .split_first_chunk_mut()
            .assume("`out` should be large enough for `Label`")?;
        *label_out = self.label.to_u32().to_le_bytes();

        let (seq_out, rest) = rest
            .split_first_chunk_mut()
            .assume("`out` should be large enough for a sequence number")?;
        *seq_out = self.seq.to_u64().to_le_bytes();

        if !rest.is_empty() {
            bug!("`out` should be exactly `DataHeader::PACKED_SIZE`");
        }

        Ok(())
    }
}

/// The header was invalid.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HeaderError {
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
    /// The size of the header is invalid.
    #[error("invalid header size")]
    InvalidSize,
    /// Unknown AFC protocol version.
    #[error("unknown AFC protocol version")]
    UnknownVersion,
    /// The `MsgType` is invalid.
    #[error("invalid `MsgType`")]
    InvalidMsgType,
}

/// The APS protocol version.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[repr(u16)]
pub enum Version {
    /// Version 1.
    V1 = 0x6f54,
}

impl Version {
    pub(crate) const fn current() -> Self {
        Self::V1
    }

    const fn try_from_u16(v: u16) -> Option<Self> {
        const V1: u16 = Version::V1.to_u16();
        match v {
            V1 => Some(Self::V1),
            _ => None,
        }
    }

    pub(crate) const fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Describes the type of message.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u16)]
pub enum MsgType {
    /// Some ciphertext.
    Data = 1,
    /// A control message that must be passed to Aranya.
    Control = 2,
}

impl MsgType {
    const fn try_from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Data),
            2 => Some(Self::Control),
            _ => None,
        }
    }

    pub(crate) const fn to_u16(self) -> u16 {
        self as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::util::HeaderBuilder;

    #[test]
    fn test_header_basic() {
        for label in [Label::new(0), Label::new(1), Label::new(u32::MAX)] {
            for msg_typ in [MsgType::Data, MsgType::Control] {
                let want = Header {
                    version: Version::V1,
                    msg_type: msg_typ,
                    label,
                };
                let got = {
                    let mut buf = [0u8; Header::PACKED_SIZE];
                    want.encode(&mut buf)
                        .expect("`Header::encode` should not fail");
                    Header::try_parse(&buf).expect("`Header::try_parse` should not fail")
                };
                assert_eq!(want, got);
            }
        }
    }

    #[test]
    fn test_header_invalid_version() {
        for v in 0..u16::MAX {
            if Version::try_from_u16(v).is_some() {
                continue;
            }
            let mut buf = [0u8; Header::PACKED_SIZE];
            HeaderBuilder::new().version(v).encode(&mut buf);
            let err = Header::try_parse(&buf).expect_err("`Header::try_parse` should fail");
            assert_eq!(err, HeaderError::UnknownVersion);
        }
    }

    #[test]
    fn test_header_invalid_msg_type() {
        for t in 0..u16::MAX {
            if MsgType::try_from_u16(t).is_some() {
                continue;
            }
            let mut buf = [0u8; Header::PACKED_SIZE];
            HeaderBuilder::new().msg_type(42).encode(&mut buf);
            let err = Header::try_parse(&buf).expect_err("`Header::try_parse` should fail");
            assert_eq!(err, HeaderError::InvalidMsgType);
        }
    }

    #[test]
    fn test_data_header_basic() {
        for label in [Label::new(0), Label::new(1), Label::new(u32::MAX)] {
            for seq in [0, 1, u64::MAX].map(Into::<Seq>::into) {
                let want = DataHeader { label, seq };
                let got = {
                    let mut buf = [0u8; DataHeader::PACKED_SIZE];
                    want.encode(&mut buf)
                        .expect("`DataHeader::encode` should not fail");
                    DataHeader::try_parse(&buf).expect("`DataHeader::try_parse` should not fail")
                };
                assert_eq!(want, got);
            }
        }
    }
}
