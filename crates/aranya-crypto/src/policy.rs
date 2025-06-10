use core::borrow::Borrow;

use spideroak_crypto::hash::{Digest, Hash};
use zerocopy::{Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    aranya::{Signature, SigningKeyId},
    ciphersuite::{CipherSuite, CipherSuiteExt},
    id::{custom_id, Id, PolicyId},
};

custom_id! {
    /// Uniquely identifies a policy.
    #[derive(Immutable, IntoBytes, KnownLayout, Unaligned)]
    pub struct PolicyId;
}

custom_id! {
    /// The ID of a policy command.
    pub struct CmdId;
}

/// Computes the command's unique ID.
pub(crate) fn cmd_id<CS: CipherSuite>(
    cmd: &Digest<<CS::Hash as Hash>::DigestSize>,
    sig: &Signature<CS>,
) -> CmdId {
    // id = H(
    //     "PolicyCommandId-v1",
    //     command,
    //     signature,
    // )
    CS::tuple_hash(
        b"PolicyCommandId-v1",
        [cmd.as_bytes(), sig.raw_sig().borrow()],
    )
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
    /// E.g., `AddDevice`.
    pub name: &'a str,
    /// The parent command in the graph.
    pub parent_id: &'a Id,
    /// The policy under which this command is executed.
    pub policy_id: &'a PolicyId,
}

impl Cmd<'_> {
    /// Returns the digest of the command and its contextual
    /// binding.
    pub(crate) fn digest<CS: CipherSuite>(
        &self,
        author: SigningKeyId,
    ) -> Digest<<CS::Hash as Hash>::DigestSize> {
        // digest = H(
        //     "SignPolicyCommand-v1",
        //     suites,
        //     pk,
        //     name,
        //     parent_id,
        //     policy_id,
        //     msg,
        // )
        //
        // Bind the signature to the current cipher suite,
        CS::tuple_hash(
            b"SignPolicyCommand-v1",
            [
                // and to the author's public key,
                author.as_bytes(),
                // and to the type of command being signed,
                self.name.as_bytes(),
                // and to the parent command,
                self.parent_id.as_bytes(),
                // and to the policy,
                self.policy_id.as_bytes(),
                // and finally the command data itself.
                self.data,
            ],
        )
    }
}
