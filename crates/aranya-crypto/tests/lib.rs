#![cfg(feature = "test_util")]

use aranya_crypto::{default::DefaultCipherSuite, test_ciphersuite};

#[cfg(feature = "trng")]
#[unsafe(no_mangle)]
extern "C" fn OS_hardware_rand() -> u32 {
    42
}

test_ciphersuite!(default_ciphersuite, DefaultCipherSuite);

mod unwrapped_tests {
    use core::marker::PhantomData;

    use aranya_crypto::{id::IdError, unwrapped, Id, Identified};

    #[test]
    fn test_unwrapped() {
        struct Seed<CS> {
            seed: [u8; 64],
            _marker: PhantomData<CS>,
        }
        impl<CS> Identified for Seed<CS> {
            type Id = Id;
            fn id(&self) -> Result<Self::Id, IdError> {
                Ok(Id::default())
            }
        }
        unwrapped! {
            name: Seed;
            type: Seed;
            into: |seed: Self| { seed.seed };
            from: |seed: [u8; 64]| { Seed { seed, _marker: PhantomData } };
        }
    }
}
