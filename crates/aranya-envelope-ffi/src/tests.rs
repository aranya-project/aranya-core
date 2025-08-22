#![cfg(test)]
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;
use alloc::vec::Vec;
use core::iter;

use aranya_crypto::{Csprng, DeviceId, Id, Random, Rng, default::DefaultEngine, policy::CmdId};
use aranya_policy_vm::{CommandContext, OpenContext, PolicyContext, SealContext, ident};

use crate::{Envelope, Ffi};

type E = DefaultEngine<Rng>;

/// Returns a random number in [0, max).
fn intn<R: Csprng>(rng: &mut R, max: usize) -> usize {
    if max.is_power_of_two() {
        return usize::random(rng) & (max - 1);
    }
    loop {
        let v = usize::random(rng);
        if v <= max {
            return v;
        }
    }
}
fn rand_vec<R: Csprng>(rng: &mut R, max: usize) -> Vec<u8> {
    let n = intn(rng, max);
    let mut data = vec![0u8; n];
    rng.fill_bytes(&mut data);
    data
}

impl Random for Envelope {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self {
            parent_id: Id::random(rng),
            command_id: Id::random(rng),
            author_id: Id::random(rng),
            payload: rand_vec(rng, 4096),
            signature: rand_vec(rng, 4096),
        }
    }
}

const SEAL_CTX: &CommandContext = &CommandContext::Seal(SealContext {
    name: ident!("dummy"),
    head_id: CmdId::default(),
});

const OPEN_CTX: &CommandContext = &CommandContext::Open(OpenContext {
    name: ident!("dummy"),
});

const POLICY_CTX: &CommandContext = &CommandContext::Policy(PolicyContext {
    name: ident!("dummy"),
    id: CmdId::default(),
    author: DeviceId::default(),
    version: Id::default(),
});

const RECALL_CTX: &CommandContext = &CommandContext::Recall(PolicyContext {
    name: ident!("dummy"),
    id: CmdId::default(),
    author: DeviceId::default(),
    version: Id::default(),
});

#[test]
fn test_author_id() {
    let (mut eng, _) = E::from_entropy(Rng);
    let env = Envelope::random(&mut Rng);
    let got = [
        Ffi.author_id(OPEN_CTX, &mut eng, env.clone())
            .expect("should not fail"),
        Ffi.author_id(POLICY_CTX, &mut eng, env.clone())
            .expect("should not fail"),
        Ffi.author_id(RECALL_CTX, &mut eng, env.clone())
            .expect("should not fail"),
    ];
    for (got, want) in got.into_iter().zip(iter::repeat(env.author_id)) {
        assert_eq!(got, want);
    }
}

#[test]
fn test_command_id() {
    let (mut eng, _) = E::from_entropy(Rng);
    let env = Envelope::random(&mut Rng);
    let got = [
        Ffi.command_id(OPEN_CTX, &mut eng, env.clone())
            .expect("should not fail"),
        Ffi.command_id(POLICY_CTX, &mut eng, env.clone())
            .expect("should not fail"),
        Ffi.command_id(RECALL_CTX, &mut eng, env.clone())
            .expect("should not fail"),
    ];
    for (got, want) in got.into_iter().zip(iter::repeat(env.command_id)) {
        assert_eq!(got, want);
    }
}

#[test]
fn test_signature() {
    let (mut eng, _) = E::from_entropy(Rng);
    let env = Envelope::random(&mut Rng);
    let got = [
        Ffi.signature(OPEN_CTX, &mut eng, env.clone())
            .expect("should not fail"),
        Ffi.signature(POLICY_CTX, &mut eng, env.clone())
            .expect("should not fail"),
        Ffi.signature(RECALL_CTX, &mut eng, env.clone())
            .expect("should not fail"),
    ];
    for (got, want) in got.into_iter().zip(iter::repeat(env.signature)) {
        assert_eq!(got, want);
    }
}

#[test]
fn test_payload() {
    let (mut eng, _) = E::from_entropy(Rng);
    let env = Envelope::random(&mut Rng);
    let got = [
        Ffi.payload(OPEN_CTX, &mut eng, env.clone())
            .expect("should not fail"),
        Ffi.payload(POLICY_CTX, &mut eng, env.clone())
            .expect("should not fail"),
        Ffi.payload(RECALL_CTX, &mut eng, env.clone())
            .expect("should not fail"),
    ];
    for (got, want) in got.into_iter().zip(iter::repeat(env.payload)) {
        assert_eq!(got, want);
    }
}

#[test]
fn test_new_envelope() {
    let (mut eng, _) = E::from_entropy(Rng);
    let env = Envelope::random(&mut Rng);
    let got = Ffi
        .new_envelope(
            SEAL_CTX,
            &mut eng,
            env.parent_id.into(),
            env.author_id.into(),
            env.command_id.into(),
            env.signature.clone(),
            env.payload.clone(),
        )
        .expect("should not fail");
    assert_eq!(got, env);
}
