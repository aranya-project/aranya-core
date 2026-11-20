pub mod libc;

use alloc::vec::Vec;

use aranya_crypto::PolicyId;

pub trait ByteStore {
    type Error: core::fmt::Display + Send + Sync + 'static;
    fn get(&self, id: PolicyId) -> Result<Option<Vec<u8>>, Self::Error>;
    fn put(&mut self, id: PolicyId, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[cfg(feature = "testing")]
pub mod testing {
    use alloc::vec::Vec;

    use aranya_crypto::PolicyId;

    /// A byte store which does not actually store anything.
    ///
    /// Most tests do not need to persist the policy.
    #[derive(Debug, Default)]
    pub struct NullStore;

    impl NullStore {
        pub fn new() -> Self {
            Self
        }
    }

    impl super::ByteStore for NullStore {
        type Error = core::convert::Infallible;

        fn get(&self, _id: PolicyId) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(None)
        }

        fn put(&mut self, _id: PolicyId, _bytes: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
