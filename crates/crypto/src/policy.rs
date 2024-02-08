use core::borrow::Borrow;

use crate::{
    aranya::{Signature, SigningKeyId},
    ciphersuite::SuiteIds,
    engine::Engine,
    hash::{tuple_hash, Digest, Hash},
    id::{custom_id, Id},
};

custom_id!(CmdId, "The ID of a policy command.");

/// Computes the command's unique ID.
pub(crate) fn cmd_id<E: Engine + ?Sized>(
    cmd: &Digest<<E::Hash as Hash>::DigestSize>,
    sig: &Signature<E>,
) -> CmdId {
    // id = H(
    //     "PolicyCommandId-v1",
    //     command,
    //     signature,
    // )
    tuple_hash::<E::Hash, _>([
        "PolicyCommandId-v1".as_bytes(),
        cmd.as_bytes(),
        sig.raw_sig().borrow(),
    ])
    .into_array()
    .into()
}

/// A policy command.
#[derive(Copy, Clone, Debug)]
pub struct Cmd<'a> {
    /// The command encoded in its canonical format.
    pub data: &'a [u8],
    /// The name of the command.
    ///
    /// E.g., `AddUser`.
    pub name: &'a str,
    /// The parent command in the graph.
    pub parent_id: &'a Id,
}

impl<'a> Cmd<'a> {
    /// Returns the digest of the command and its contextual
    /// binding.
    pub(crate) fn digest<E: Engine + ?Sized>(
        &self,
        author: &SigningKeyId,
    ) -> Digest<<E::Hash as Hash>::DigestSize> {
        // digest = H(
        //     "SignPolicyCommand-v1",
        //     suites,
        //     pk,
        //     name,
        //     parent_id,
        //     msg,
        // )
        tuple_hash::<E::Hash, _>([
            // Domain separation.
            "SignPolicyCommand-v1".as_bytes(),
            // Bind the signature to the current cipher suite,
            &SuiteIds::from_suite::<E>().into_bytes(),
            // and to the author's public key,
            author.as_bytes(),
            // and to the type of command being signed,
            self.name.as_bytes(),
            // and to the parent command,
            self.parent_id.as_bytes(),
            // and finally the command data itself.
            self.data,
        ])
    }
}
