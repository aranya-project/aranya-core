//! SHAKE per [FIPS 202].
//!
//! [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final

use core::{fmt, num::NonZeroU16};

use crate::xof::{Xof, XofId, XofReader};

macro_rules! impl_shake {
    ($name:ident, $id:literal, $reader:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Default, Debug)]
        pub struct $name {
            shake: sha3::$name,
        }

        impl $name {
            /// Creates a new SHAKE instance.
            #[inline]
            pub fn new() -> Self {
                let shake = sha3::$name::default();
                Self { shake }
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

                self.shake.update(data);
            }

            #[inline]
            fn finalize_xof(self) -> Self::Reader {
                use sha3::digest::ExtendableOutput;

                $reader {
                    reader: self.shake.finalize_xof(),
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
                f.debug_struct("ShakeReader").finish_non_exhaustive()
            }
        }
    };
}
impl_shake!(Shake128, 0xfffe, Shake128Reader, "SHAKE128");
impl_shake!(Shake256, 0xfffd, Shake256Reader, "SHAKE256");
