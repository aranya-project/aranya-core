//! CHAKE per [SP 800-185].
//!
//! [SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

use core::{fmt, num::NonZeroU16};

use sha3::{
    digest::{
        core_api::{Block, CoreProxy, UpdateCore},
        crypto_common::{AlgorithmName, BlockSizeUser},
        ExtendableOutput, Update,
    },
    Keccak256, Keccak512,
};
use sha3_utils::{bytepad_blocks, encode_string, right_encode, right_encode_bytes};
use typenum::Unsigned;

use crate::xof::{Xof, XofId, XofReader};

macro_rules! impl_cshake {
    ($name:ident, $id:literal, $reader:ident, $keccak:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Debug)]
        pub struct $name {
            keccak: sha3::$keccak,
        }

        impl $name {
            /// Creates a CSHAKE instance with the customization
            /// string `s`.
            #[inline]
            pub fn new(s: &[u8]) -> Self {
                Self::new_with_function_name(&[], s)
            }

            /// Creates a CSHAKE instance with the function name
            /// `n` and customization string `s`.
            #[inline]
            pub fn new_with_function_name(n: &[u8], s: &[u8]) -> Self {
                let core = <$keccak as CoreProxy>::Core::new(s);

                // NB: This is the same thing as
                //     const RATE: usize = <$cshake as BlockSizeUser>::BlockSize::USIZE;
                //     for s in &bytepad::<RATE>(encode_string(k)) {
                //         cshake.update(s);
                //     }
                // but avoids a panicking branch.
                const BLOCK_SIZE: usize = <$keccak as BlockSizeUser>::BlockSize::USIZE;
                let (head, mid, tail) = bytepad_blocks::<BLOCK_SIZE>(encode_string(n));
                core.update_blocks(&[*Block::<$keccak>::from_slice(&head)]);
                if !mid.is_empty() {
                    core.update_blocks(
                        // SAFETY: `[u8; BLOCK_SIZE]` and
                        // `Block<$cshake>` has the same layout in
                        // memory.
                        unsafe { &*(mid as *const [[u8; BLOCK_SIZE]] as *const [Block<$keccak>]) },
                    );
                }
                if let Some(tail) = tail {
                    core.update_blocks(&[*Block::<$keccak>::from_slice(&tail)]);
                }

                let mut keccak = sha3::$keccak::from_core(core);
                Self { keccak }
            }
        }

        impl Xof for $name {
            const ID: XofId = XofId::Other(
                // SAFETY: `$id` is clearly non-zero.
                unsafe { NonZeroU16::new_unchecked($id) },
            );

            type Reader = $reader;

            #[inline]
            fn update(&mut self, data: &[u8]) {
                use sha3::digest::Update;

                self.keccak.update(data);
            }

            #[inline]
            fn finalize_xof(self) -> Self::Reader {
                use sha3::digest::ExtendableOutput;

                $reader {
                    reader: self.keccak.finalize_xof(),
                }
            }
        }

        #[doc = "An [`XofReader`] for"]
        #[doc = concat!("[`", stringify!($name), "`].")]
        #[derive(Clone)]
        pub struct $reader {
            reader: <sha3::$name as sha3::digest::ExtendableOutput>::Reader,
        }

        impl XofReader for $reader {
            #[inline]
            fn read(&mut self, out: &mut [u8]) {
                use sha3::digest::XofReader;

                self.reader.read(out);
            }
        }

        impl fmt::Debug for $reader {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($reader)).finish_non_exhaustive()
            }
        }
    };
}
impl_cshake!(CShake128, 0xfffc, CShake128Reader, Keccak256, "CSHAKE128");
impl_cshake!(CShake256, 0xfffb, CShake256Reader, Keccak512, "CSHAKE256");
