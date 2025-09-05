//! Aranya policy related routines.

use core::borrow::Borrow;

use spideroak_crypto::hash::{Digest, Hash};
use zerocopy::{Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    aranya::{Signature, SigningKeyId},
    ciphersuite::{CipherSuite, CipherSuiteExt},
    id::{IdExt as _, custom_id},
};

custom_id! {
    /// Uniquely identifies a group.
    #[derive(Immutable, IntoBytes, KnownLayout, Unaligned)]
    pub struct GroupId;
}

custom_id! {
    /// Uniquely identifies a policy.
    #[derive(Immutable, IntoBytes, KnownLayout, Unaligned)]
    pub struct PolicyId;
}

custom_id! {
    /// The ID of a policy command.
    #[derive(Immutable, IntoBytes, KnownLayout, Unaligned)]
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
    CmdId::new::<CS>(
        b"PolicyCommandId-v1",
        [cmd.as_bytes(), sig.raw_sig().borrow()],
    )
}

/// Computes a merge command's ID.
pub fn merge_cmd_id<CS: CipherSuite>(left: CmdId, right: CmdId) -> CmdId {
    // id = H(
    //     "MergeCommandId-v1",
    //     left_id,
    //     right_id,
    // )
    CmdId::new::<CS>(b"MergeCommandId-v1", [left.as_bytes(), right.as_bytes()])
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
    pub parent_id: &'a CmdId,
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
                // and finally the command data itself.
                self.data,
            ],
        )
    }
}

custom_id! {
    /// Uniquely identifies a role.
    #[derive(Immutable, IntoBytes, KnownLayout, Unaligned)]
    pub struct RoleId;
}

/// Computes the ID of a policy role.
///
/// `cmd` must be the command that created (or is creating) the
/// role. `name` is the name of the role, e.g., `admin`.
pub fn role_id<CS: CipherSuite>(cmd_id: CmdId, name: &str, policy_id: PolicyId) -> RoleId {
    // id = H(
    //     "RoleId-v1",
    //     cmd_id,
    //     name,
    //     policy_id,
    // )
    RoleId::new::<CS>(
        b"RoleId-v1",
        [cmd_id.as_bytes(), name.as_bytes(), policy_id.as_bytes()],
    )
}

custom_id! {
    /// Uniquely identifies an AQC label.
    ///
    /// A label associates an AQC channel with Aranya policy
    /// rules that govern communication in the channel.
    #[derive(Immutable, IntoBytes, KnownLayout, Unaligned)]
    pub struct LabelId;
}

/// Computes the ID of a label.
///
/// `cmd` must be the command that created (or is creating) the
/// label. `name` is the name of the label, e.g., `telemetry`.
pub fn label_id<CS: CipherSuite>(cmd_id: CmdId, name: &str, policy_id: PolicyId) -> LabelId {
    // id = H(
    //     "LabelId-v1",
    //     cmd_id,
    //     name,
    //     policy_id,
    // )
    LabelId::new::<CS>(
        b"LabelId-v1",
        [cmd_id.as_bytes(), name.as_bytes(), policy_id.as_bytes()],
    )
}

#[cfg(test)]
mod tests {
    use spideroak_crypto::{ed25519::Ed25519, rust};

    use super::*;
    use crate::{default::DhKemP256HkdfSha256, test_util::TestCs};

    type CS = TestCs<
        rust::Aes256Gcm,
        rust::Sha256,
        rust::HkdfSha512,
        DhKemP256HkdfSha256,
        rust::HmacSha512,
        Ed25519,
    >;

    /// Golden test for [`label_id`].
    #[test]
    fn test_label_id() {
        let tests = [
            (
                CmdId::default(),
                "foo",
                PolicyId::default(),
                "C1PupQYTjr2ouZ3DohnRFEaHR4yoTnMkarbBK4TGhJoi",
            ),
            (
                CmdId::default(),
                "bar",
                PolicyId::default(),
                "Eq71P2UhRVMt7R1s1ZB6m1kSuuzwBZwAd21BEv3gmtBC",
            ),
            (
                CmdId::from_bytes([b'A'; 32]),
                "bar",
                PolicyId::default(),
                "B4XqE83yLS1i8AiyMxGKo2wtrwvqrhUers5ou3eRfH8z",
            ),
            (
                CmdId::from_bytes([b'A'; 32]),
                "baz",
                PolicyId::from_bytes([b'B'; 32]),
                "ACnKJXFwd9e2tSnakXgP8SMiYHBSQLUetWgRjHjyQo8y",
            ),
        ];
        for (i, (cmd_id, name, policy_id, want)) in tests.iter().enumerate() {
            let got = label_id::<CS>(*cmd_id, name, *policy_id);
            let want = LabelId::decode(*want).unwrap();
            assert_eq!(got, want, "#{i}");
        }
    }

    /// Golden test for [`role_id`].
    #[test]
    fn test_role_id() {
        let tests = [
            (
                CmdId::default(),
                "foo",
                PolicyId::default(),
                "BoukxZv6twB39TdXkzMafUxsT1uvpmMJbr6nsKLBg7VT",
            ),
            (
                CmdId::default(),
                "bar",
                PolicyId::default(),
                "CEEjmy5R6Q7RXBqFtt1nrh597Ytr7bCc2aEWJfixEp9K",
            ),
            (
                CmdId::from_bytes([b'A'; 32]),
                "bar",
                PolicyId::default(),
                "9NEW3iaJim8iipkeBCJPJ3v75pEH92iLtrqo8sddkqER",
            ),
            (
                CmdId::from_bytes([b'A'; 32]),
                "baz",
                PolicyId::from_bytes([b'B'; 32]),
                "4sVA51vurQexYL8NFxGYnhj7RTf51udZg7Qd1dhsgBnx",
            ),
        ];
        for (i, (cmd_id, name, policy_id, want)) in tests.iter().enumerate() {
            let got = role_id::<CS>(*cmd_id, name, *policy_id);
            let want = RoleId::decode(*want).unwrap();
            assert_eq!(got, want, "#{i}");
        }
    }
}
