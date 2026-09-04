//! Utilities for testing [`AfcState`] and
//! [`AranyaState`][crate::AranyaState] implementations.
//!
//! If you implement any traits in this crate it is **very
//! highly** recommended that you use these tests.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]
#![cfg(any(test, feature = "testing"))]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#![cfg_attr(not(feature = "trng"), forbid(unsafe_code))]

pub mod util;

use std::collections::HashMap;

use aranya_crypto::{
    Aead, CipherSuite, Engine, Rng,
    id::IdExt as _,
    policy::LabelId,
    typenum::{U1, Unsigned as _},
};

use crate::{
    AfcState, LocalChannelId,
    buf::FixedBuf,
    client::{Client, OpenCtx, Seq},
    error::Error,
    header::DataHeader,
    replay::{DEFAULT_REPLAY_WINDOW, MAX_REPLAY_WINDOW},
    testing::util::{
        Aranya, ChanOp, DataHeaderBuilder, Device, DeviceIdx, GlobalChannelId, LimitedAead,
        TestEngine, TestImpl,
    },
};

/// The [`OpenCtx`] for a [`TestImpl`]'s [`AfcState`].
type TestOpenCtx<T, CS> = OpenCtx<<<T as TestImpl>::Afc<CS> as AfcState>::OpenCtx>;

/// Open contexts keyed by sender and channel.
type OpenCtxs<T, CS> = HashMap<(DeviceIdx, GlobalChannelId), TestOpenCtx<T, CS>>;

/// The cipher suite for [`TestEngine<A>`].
type TestCs<A> = <TestEngine<A> as Engine>::CS;

/// Performs all of the tests in the [`testing`][crate::testing]
/// module.
///
/// # Example
/// ```
/// use aranya_fast_channels::{test_impl, testing::util::MockImpl};
///
/// test_impl!(mock, MockImpl);
/// ```
#[macro_export]
macro_rules! test_impl {
	($(#[$meta:meta]),* $(,)? $name:ident, $type:ident) => {
        mod $name {
			#[allow(unused_imports)]
			use super::*;

            // Test regular AEADs.
            $crate::testing::__test_impl!($(#[$meta]),* aes256gcm,
                $type, $crate::crypto::Aes256Gcm);

            // Test an AEAD with funky key, nonce, etc. sizes.
            $crate::testing::__test_impl!($(#[$meta]),* funky_sizes,
                $type, $crate::testing::util::NoopAead<
                    ::aranya_crypto::typenum::U37,
                    ::aranya_crypto::typenum::U17,
                    ::aranya_crypto::typenum::U23,
                    3,
                >);
        }
	};
}
pub use test_impl;

#[macro_export]
#[doc(hidden)]
macro_rules! __test_impl {
	($(#[$meta:meta]),* $(,)? $name:ident, $($type:tt)+) => {
		macro_rules! test {
			($test:ident) => {
				#[test]
                $(#[$meta])*
				fn $test() {
					$crate::testing::$test::<$($type)*>()
				}
			};
		}

		mod $name {
			#[allow(unused_imports)]
			use super::*;

			test!(test_seal_open_basic);
			test!(test_seal_open_in_place_basic);
			test!(test_multi_client);
			test!(test_remove);
			test!(test_remove_all);
			test!(test_remove_if);
			test!(test_remove_no_channels);
			test!(test_channels_exist);
			test!(test_channels_not_exist);
			test!(test_issue112);
			test!(test_client_send);
            test!(test_key_expiry);
			test!(test_monotonic_seq_by_one);

            // Unidirectional tests.
			test!(test_unidirectional_basic);
			test!(test_unidirectional_exhaustive);

            // Negative tests.
			test!(test_open_truncated_tag);
			test!(test_open_modified_tag);
			test!(test_open_different_seq);
			test!(test_seal_unknown_channel_label);

			// Replay protection.
			test!(test_replay_in_order);
			test!(test_replay_duplicate);
			test!(test_replay_duplicate_in_place);
			test!(test_replay_reorder_within_window);
			test!(test_replay_gap_and_late_fill);
			test!(test_replay_far_ahead_advance);
			test!(test_replay_first_frame_high_seq);
			test!(test_replay_forged_high_seq);
			test!(test_replay_window_size_one);
			test!(test_replay_window_size_max);
			test!(test_replay_window_bounds);
			test!(test_replay_fresh_ctx_resets_window);
		}
	};
}
pub use __test_impl;

// TODO(jdygert): Update tests to use overhead directly?
// Would need to specify the type or refactor somehow.
const fn overhead<S: AfcState>(_: &Client<S>) -> usize {
    <Client<S>>::OVERHEAD
}

/// Basic positive test for [`Client::seal`] and
/// [`Client::open`].
pub fn test_seal_open_basic<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_seal_open_basic", label_ids.len() * 2, eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

    for (global_id, label_id) in d1.common_channels(d2) {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id1} should have channel for global_id {global_id:?}")
            });

            let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");

            c1.seal(&mut ctx, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({id2}, ...): {err}"));
            dst
        };
        let (plaintext, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
            let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id2} should have channel for global_id {global_id:?}")
            });

            let mut ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
            let (_, seq) = c2
                .open(&mut ctx, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
            (dst, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label_id}");
        assert_eq!(got_seq, 0, "{label_id}");
    }
}

/// Basic positive test for [`Client::seal_in_place`] and
/// [`Client::open_in_place`].
pub fn test_seal_open_in_place_basic<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_seal_open_in_place_basic", label_ids.len() * 2, eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

    for (global_id, label_id) in d1.common_channels(d2) {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
            data.extend_from_slice(GOLDEN.as_bytes());
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id1} should have channel for global_id {global_id:?}")
            });
            let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
            c1.seal_in_place(&mut ctx, &mut data)
                .unwrap_or_else(|err| panic!("seal_in_place({id2}, ...): {err}"));
            data
        };
        let (plaintext, got_seq) = {
            let mut data = ciphertext.clone();
            let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id2} should have channel for global_id {global_id:?}")
            });

            let mut ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
            let (_, seq) = c2
                .open_in_place(&mut ctx, &mut data)
                .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
            (data, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label_id}");
        assert_eq!(got_seq, 0, "{label_id}");
    }
}

/// Similar to [`test_seal_open_basic`], but with multiple
/// clients.
pub fn test_multi_client<T: TestImpl, A: Aead>() {
    let max_nodes = if cfg!(any(
        target_arch = "aarch64",
        target_arch = "x86",
        target_arch = "x86_64",
    )) {
        10
    } else {
        3
    };

    eprintln!("# testing with {max_nodes} nodes");

    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_multi_client", max_nodes * label_ids.len() * 2, eng);

    let mut device_idxs = Vec::new();
    let mut clients = Vec::new();
    for _ in 0..max_nodes {
        let (c, device_idx) = d.new_client(label_ids);
        device_idxs.push(device_idx);
        clients.insert(device_idx, c);
    }

    const GOLDEN: &str = "hello, world!";

    #[allow(clippy::too_many_arguments)]
    fn test<T: TestImpl, CS: CipherSuite>(
        clients: &mut [Client<T::Afc<CS>>],
        devices: &[Device<T, CS>],
        send: DeviceIdx,
        recv: DeviceIdx,
        label_id: LabelId,
        seqs: &mut HashMap<(DeviceIdx, DeviceIdx, LabelId), u64>,
        seal_ctxs: &mut HashMap<(DeviceIdx, GlobalChannelId), <T::Afc<CS> as AfcState>::SealCtx>,
        open_ctxs: &mut OpenCtxs<T, CS>,
    ) {
        let (global_id, label_id) = {
            let send_device = devices.get(send).expect("device to exist");
            let recv_device = devices.get(recv).expect("device to exist");

            send_device
                .common_channels(recv_device)
                .find(|(_, lab)| *lab == label_id)
                .expect("channel to exist")
        };

        let want_seq = *seqs
            .entry((send, recv, label_id))
            .and_modify(|seq| {
                *seq += 1;
            })
            .or_insert(0);

        let ciphertext = {
            let u0 = clients
                .get_mut(send)
                .unwrap_or_else(|| panic!("unable to find send client {send}"));
            let mut dst = vec![0u8; GOLDEN.len() + overhead(u0)];
            let send_channel_id = devices
                .get(send)
                .expect("device to exist")
                .get_local_channel_id(global_id)
                .unwrap_or_else(|| {
                    panic!("send device should have channel for global_id {global_id:?}")
                });
            let ctx = seal_ctxs
                .entry((send, global_id))
                .or_insert_with(|| u0.setup_seal_ctx(send_channel_id).expect("can set up ctx"));
            u0.seal(ctx, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("{label_id}: seal({recv}, ...): {err}"));
            dst
        };

        let (plaintext, got_seq) = {
            let u1 = clients
                .get(recv)
                .unwrap_or_else(|| panic!("unable to find recv client: {recv}"));
            let mut dst = vec![0u8; ciphertext.len() - overhead(u1)];
            let recv_channel_id = devices
                .get(recv)
                .expect("device to exist")
                .get_local_channel_id(global_id)
                .unwrap_or_else(|| {
                    panic!("recv device should have channel for global_id {global_id:?}")
                });

            let ctx = open_ctxs
                .entry((send, global_id))
                .or_insert_with(|| u1.setup_open_ctx(recv_channel_id).expect("can set up ctx"));
            let (_, seq) = u1
                .open(ctx, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("{label_id}: open({send}, ...): {err}"));
            (dst, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{send},{recv}");
        assert_eq!(got_seq, want_seq, "{send},{recv}");
    }

    let mut seqs = HashMap::new();
    let mut seal_ctxs = HashMap::new();
    let mut open_ctxs = HashMap::new();

    for label_id in label_ids {
        for a in &device_idxs {
            for b in &device_idxs {
                if a == b {
                    continue;
                }

                test(
                    &mut clients,
                    &d.devices,
                    *a,
                    *b,
                    label_id,
                    &mut seqs,
                    &mut seal_ctxs,
                    &mut open_ctxs,
                );
                test(
                    &mut clients,
                    &d.devices,
                    *b,
                    *a,
                    label_id,
                    &mut seqs,
                    &mut seal_ctxs,
                    &mut open_ctxs,
                );
            }
        }
    }
}

/// Basic positive test for removing a channel.
pub fn test_remove<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_remove", 2 * 3 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);
    let (c3, id3) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");
    let d3 = d.devices.get(id3).expect("device to exist");

    const GOLDEN: &str = "hello, world!";
    for (c, id, device) in [(&c2, id2, d2), (&c3, id3, d3)] {
        for (global_id, _label_id) in d1.common_channels(device) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });
            let device_channel_id = device.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });

            let mut seal_ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");

            let ciphertext = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(&mut seal_ctx, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let mut open_ctx = c.setup_open_ctx(device_channel_id).expect("can set up ctx");
                let (_, seq) = c
                    .open_in_place(&mut open_ctx, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes());
            assert_eq!(got_seq, 0);

            // Now that we know it works, delete the channel and try
            // again. It should fail.
            d.remove(d1_channel_id, id1)
                .unwrap_or_else(|| panic!("remove({d1_channel_id}, {id}): not found"))
                .unwrap_or_else(|err| panic!("remove({id}): {err}"));

            let err = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(&mut seal_ctx, &mut data)
                    .err()
                    .unwrap_or_else(|| panic!("seal_in_place({id}) should panic"))
            };
            assert_eq!(err, Error::NotFound(d1_channel_id));
        }
    }
}

/// Basic positive test for removing all channels.
pub fn test_remove_all<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_remove_all", 2 * 3 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);
    let (c3, id3) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");
    let d3 = d.devices.get(id3).expect("device to exist");

    let mut ctxs = HashMap::new();

    const GOLDEN: &str = "hello, world!";
    for (c, id, device) in [(&c2, id2, d2), (&c3, id3, d3)] {
        for (global_id, label_id) in d1.common_channels(device) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });
            let device_channel_id = device.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });
            let ciphertext = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                let ctx = ctxs
                    .entry((id1, global_id))
                    .or_insert_with(|| c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx"));
                c1.seal_in_place(ctx, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();

                let mut open_ctx = c.setup_open_ctx(device_channel_id).expect("can set up ctx");
                let (_, seq) = c
                    .open_in_place(&mut open_ctx, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label_id},{id}");
            assert_eq!(got_seq, 0);
        }
    }

    // Now that we know it works, delete all the channels and try
    // again. It should fail.
    d.remove_all(id1)
        .unwrap_or_else(|| panic!("remove_all({id1}): not found"))
        .unwrap_or_else(|err| panic!("remove_all({id1}): {err}"));

    for device in [d2, d3] {
        for (global_id, label_id) in d1.common_channels(device) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });
            let err = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                let ctx = ctxs
                    .get_mut(&(id1, global_id))
                    .expect("to have called `seal` before");
                c1.seal_in_place(ctx, &mut data).err().unwrap_or_else(|| {
                    panic!("seal_in_place({d1_channel_id} {label_id} should panic")
                })
            };
            assert_eq!(err, Error::NotFound(d1_channel_id));
        }
    }
}

/// Basic positive test for removing channels matching condition.
pub fn test_remove_if<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_remove_if", 2 * 3 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);
    let (c3, id3) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");
    let d3 = d.devices.get(id3).expect("device to exist");

    let mut ctxs = HashMap::new();

    const GOLDEN: &str = "hello, world!";
    for (c, id, device) in [(&c2, id2, d2), (&c3, id3, d3)] {
        for (global_id, label_id) in d1.common_channels(device) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });
            let device_channel_id = device.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });
            let ciphertext = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                let ctx = ctxs
                    .entry((id1, global_id))
                    .or_insert_with(|| c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx"));
                c1.seal_in_place(ctx, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let mut open_ctx = c.setup_open_ctx(device_channel_id).expect("can set up ctx");
                let (_, seq) = c
                    .open_in_place(&mut open_ctx, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label_id},{id}");
            assert_eq!(got_seq, 0, "{label_id},{id}");
        }
    }

    for (id, device) in [(id2, d2), (id3, d3)] {
        for (global_id, label_id) in d1.common_channels(device) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });
            // Now that we know it works, delete the channel and try
            // again. It should fail.
            d.remove_if(id1, |p| p.label_id == label_id && p.peer_id == device.id)
                .unwrap_or_else(|| panic!("remove_if({id1}, {id}): not found"))
                .unwrap_or_else(|err| panic!("remove_if({id}): {err}"));
            let err = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                let ctx = ctxs
                    .get_mut(&(id1, global_id))
                    .expect("to have called `seal` before");
                c1.seal_in_place(ctx, &mut data)
                    .err()
                    .unwrap_or_else(|| panic!("seal_in_place({id}) should panic"))
            };
            assert_eq!(err, Error::NotFound(d1_channel_id));

            // Test that other channel still works
            if id == id2 {
                for (global_id, _label_id) in d1.common_channels(d3) {
                    let mut data: Vec<u8> = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                    data.extend_from_slice(GOLDEN.as_bytes());
                    let ctx = ctxs
                        .get_mut(&(id1, global_id))
                        .expect("to have called `seal` before");
                    c1.seal_in_place(ctx, &mut data)
                        .unwrap_or_else(|err| panic!("seal_in_place({id3}, ...): {err}"));
                }
            }
        }
    }
}

/// Test removing channels when there are no channels to remove.
pub fn test_remove_no_channels<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_remove_no_channels", 2 * 3 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);
    let (c3, id3) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");
    let d3 = d.devices.get(id3).expect("device to exist");

    let mut ctxs = HashMap::new();

    const GOLDEN: &str = "hello, world!";
    for (c, id, device) in [(&c2, id2, d2), (&c3, id3, d3)] {
        for (global_id, label_id) in d1.common_channels(device) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });
            let device_channel_id = device.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });
            let ciphertext = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                let ctx = ctxs
                    .entry((id1, global_id))
                    .or_insert_with(|| c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx"));
                c1.seal_in_place(ctx, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let mut open_ctx = c.setup_open_ctx(device_channel_id).expect("can set up ctx");
                let (_, seq) = c
                    .open_in_place(&mut open_ctx, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label_id},{id}");
            assert_eq!(got_seq, 0, "{label_id},{id}");
        }
    }

    // Test that removing channels works when there are no channels
    // to remove.
    d.remove_all(id1)
        .unwrap_or_else(|| panic!("remove_all({id1}): not found"))
        .unwrap_or_else(|err| panic!("remove_all({id1}): {err}"));
    d.remove_if(id1, |_| true)
        .unwrap_or_else(|| panic!("remove_if({id1}): not found"))
        .unwrap_or_else(|err| panic!("remove_if({id1}): {err}"));
    d.remove_all(id1)
        .unwrap_or_else(|| panic!("remove_all({id1}): not found"))
        .unwrap_or_else(|err| panic!("remove_all({id1}): {err}"));

    for (global_id, label_id) in d1.common_channels(d2).chain(d1.common_channels(d3)) {
        let d1_channel_id = d1
            .get_local_channel_id(global_id)
            .unwrap_or_else(|| panic!("device should have channel for global_id {global_id:?}"));
        let err = {
            let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
            data.extend_from_slice(GOLDEN.as_bytes());
            let ctx = ctxs
                .get_mut(&(id1, global_id))
                .expect("to have called `seal` before");
            c1.seal_in_place(ctx, &mut data)
                .err()
                .unwrap_or_else(|| panic!("seal_in_place({d1_channel_id},{label_id}) should panic"))
        };
        assert_eq!(err, Error::NotFound(d1_channel_id));
    }
}

/// Basic positive test for checking if expected channels exist.
pub fn test_channels_exist<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_channels_exist", 2 * 3 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);
    let (c3, id3) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");
    let d3 = d.devices.get(id3).expect("device to exist");

    const GOLDEN: &str = "hello, world!";

    for (c, id, device) in [(&c2, id2, d2), (&c3, id3, d3)] {
        for (global_id, label_id) in d1.common_channels(device) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id1} should have channel for global_id {global_id:?}")
            });
            let device_channel_id = device.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id} should have channel for global_id {global_id:?}")
            });
            let ciphertext = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
                c1.seal_in_place(&mut ctx, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let mut open_ctx = c.setup_open_ctx(device_channel_id).expect("can set up ctx");
                let (_, seq) = c
                    .open_in_place(&mut open_ctx, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label_id},{id}");
            assert_eq!(got_seq, 0, "{label_id},{id}");
        }
    }

    let ids = [id1, id2, id3];
    let devices = [d1, d2, d3];
    for i in 0..ids.len() {
        for j in 0..ids.len() {
            if i == j {
                continue;
            }
            let _ida = ids[i];
            let idb = ids[j];

            let common_channels = devices[i].common_channels(devices[j]);
            // Verify that expected labels exist.

            for (global_id, label_id) in common_channels {
                let device_channel_id =
                    devices[j]
                        .get_local_channel_id(global_id)
                        .unwrap_or_else(|| {
                            panic!("device {idb} should have channel for global_id {global_id:?}")
                        });
                let result = d
                    .exists(device_channel_id, idb)
                    .unwrap_or_else(|| panic!("exists({device_channel_id}, {label_id}): not found"))
                    .unwrap_or_else(|err| panic!("exists({label_id}): {err}"));
                assert!(result);
            }
        }
    }
}

/// Basic negative test for checking that channels that were not
/// created do not exist.
// TODO: Remove this test?
pub fn test_channels_not_exist<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let unused_labels = [
        LabelId::random(&eng),
        LabelId::random(&eng),
        LabelId::random(&eng),
    ];

    let mut d = Aranya::<T, _>::new("test_channels_not_exist", 2 * 3 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);
    let (c3, id3) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");
    let d3 = d.devices.get(id3).expect("device to exist");

    const GOLDEN: &str = "hello, world!";
    for (c, id, device) in [(&c2, id2, d2), (&c3, id3, d3)] {
        for (global_id, label_id) in d1.common_channels(device) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id1} should have channel for global_id {global_id:?}")
            });
            let device_channel_id = device.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id} should have channel for global_id {global_id:?}")
            });
            let ciphertext = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
                c1.seal_in_place(&mut ctx, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let mut open_ctx = c.setup_open_ctx(device_channel_id).expect("can set up ctx");
                let (_, seq) = c
                    .open_in_place(&mut open_ctx, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label_id},{id}");
            assert_eq!(got_seq, 0, "{label_id},{id}");
        }
    }

    let ids = [id1, id2, id3];
    for label_id in unused_labels {
        for i in 0..ids.len() {
            for j in 0..ids.len() {
                if i == j {
                    continue;
                }
                let _ida = ids[i];
                let idb = ids[j];
                let result = d
                    .exists(LocalChannelId::new(9999), idb)
                    .unwrap_or_else(|| panic!("exists({idb}, {label_id}): not found"))
                    .unwrap_or_else(|err| panic!("exists({label_id}): {err}"));
                assert!(!result);
            }
        }
    }
}

/// A test for issue #112, where [`Client`] would fail if the
/// output buffer was not exactly the right size.
pub fn test_issue112<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_id = LabelId::random(&eng);
    let mut d = Aranya::<T, TestEngine<A>>::new("test_issue_112", 2, eng);
    let (c1, id1) = d.new_client([label_id]);
    let (c2, id2) = d.new_client([label_id]);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

    const GOLDEN: &str = "hello";

    for (global_id, label_id) in d1.common_channels(d2) {
        let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id1} should have channel for global_id {global_id:?}")
        });
        let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id2} should have channel for global_id {global_id:?}")
        });
        let ciphertext = {
            let len = GOLDEN.len() + overhead(&c1) + 100;
            let mut dst = vec![0u8; len];
            let mut buf = FixedBuf::from_slice_mut(&mut dst, len).expect("dst should be <= len");
            let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
            c1.seal(&mut ctx, &mut buf, GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({id2}, ...): {err}"));
            dst.truncate(GOLDEN.len() + overhead(&c1));
            dst
        };
        let (plaintext, got_label, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(&c1)];
            let mut open_ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
            let (_, seq) = c2
                .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
            dst.truncate(ciphertext.len() - overhead(&c2));
            (dst, label_id, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes());
        assert_eq!(got_label, label_id);
        assert_eq!(got_seq, 0);
    }
}

/// Tests that `Client` is `Send`.
pub fn test_client_send<T, A>()
where
    T: TestImpl,
    A: Aead,
    <T as TestImpl>::Afc<<TestEngine<A> as Engine>::CS>: Send,
    <T as TestImpl>::Aranya<<TestEngine<A> as Engine>::CS>: Send,
    <T as TestImpl>::Rng: Send,
{
    fn is_send<T: Send>(_v: T) {}

    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label = LabelId::random(&eng);
    let mut d = Aranya::<T, _>::new("test_client_send", 1, eng);
    let (c, _) = d.new_client([label]);
    is_send(c);
}

/// A basic positive test for unidirectional channels.
pub fn test_unidirectional_basic<T: TestImpl, A: Aead>() {
    fn test<S: AfcState, T: TestImpl, CS: CipherSuite>(
        c1: &mut (Client<S>, DeviceIdx),
        c2: &(Client<S>, DeviceIdx),
        d1: &Device<T, CS>,
        d2: &Device<T, CS>,
        label_id: LabelId,
    ) {
        let (c1, id1) = c1;
        let (c2, id2) = c2;

        let (global_id, label_id) = d1
            .common_channels(d2)
            .find(|(_, lab)| *lab == label_id)
            .unwrap_or_else(|| panic!("channel does not exist - {id1}-{id2} label: {label_id}"));

        const GOLDEN: &str = "hello, world!";
        let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id1} should have channel for global_id {global_id:?}")
        });
        let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id2} should have channel for global_id {global_id:?}")
        });
        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + overhead(c1)];
            let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
            c1.seal( &mut ctx, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("({id1}->{id2}) seal(channel_id: {d1_channel_id}, label_id: {label_id} ...): {err}"));
            dst
        };
        let (plaintext, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(c2)];
            let mut open_ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
            let (_, seq) = c2
                .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
            (dst, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{id1},{id2},{label_id}");
        assert_eq!(got_seq, 0, "{id1},{id2},{label_id}");
    }

    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label1 = LabelId::random(&eng);
    let label2 = LabelId::random(&eng);
    let label3 = LabelId::random(&eng);

    let mut d = Aranya::<T, _>::new("test_unidirectional_pos", 18, eng);

    let mut c1 = d.new_client_with_type([
        (label1, ChanOp::SealOnly),
        (label2, ChanOp::OpenOnly),
        (label3, ChanOp::Any),
    ]);
    let mut c2 = d.new_client_with_type([
        (label1, ChanOp::OpenOnly),
        (label2, ChanOp::SealOnly),
        (label3, ChanOp::Any),
    ]);
    let mut c3 = d.new_client_with_type([
        (label1, ChanOp::Any),
        (label2, ChanOp::Any),
        (label3, ChanOp::OpenOnly),
    ]);

    let d1 = d.devices.get(c1.1).expect("device to exist");
    let d2 = d.devices.get(c2.1).expect("device to exist");
    let d3 = d.devices.get(c3.1).expect("device to exist");

    test(&mut c1, &c2, d1, d2, label1);
    test(&mut c1, &c3, d1, d3, label1);
    test(&mut c1, &c3, d1, d3, label3);

    test(&mut c2, &c1, d2, d1, label2);
    test(&mut c2, &c3, d2, d3, label2);
    test(&mut c2, &c3, d2, d3, label3);

    test(&mut c3, &c1, d3, d1, label2);
    test(&mut c3, &c2, d3, d2, label1);
}

/// A positive and negative test for unidirectional channels.
pub fn test_unidirectional_exhaustive<T: TestImpl, A: Aead>() {
    fn fail<S: AfcState, T: TestImpl, CS: CipherSuite>(
        c1: &mut (Client<S>, DeviceIdx),
        c2: &(Client<S>, DeviceIdx),
        d1: &Device<T, CS>,
        d2: &Device<T, CS>,
        label_id: LabelId,
    ) {
        let (c1, id1) = c1;
        let (_c2, id2) = c2;

        let maybe_channel = d1
            .common_channels(d2)
            .find(|(_, lab_id)| *lab_id == label_id);

        if let Some((global_id, _label_id)) = maybe_channel {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id1} should have channel for global_id {global_id:?}")
            });
            let mut dst = vec![0u8; overhead(c1)];
            let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
            let err = c1
                .seal(&mut ctx, &mut dst[..], &[])
                .err()
                .unwrap_or_else(|| panic!("{id1}::seal({id2}, ...): expected an error"));
            assert_eq!(err, Error::NotFound(d1_channel_id));
        }
    }

    fn pass<S: AfcState, T: TestImpl, CS: CipherSuite>(
        c1: &mut (Client<S>, DeviceIdx),
        c2: &(Client<S>, DeviceIdx),
        d1: &Device<T, CS>,
        d2: &Device<T, CS>,
        label_id: LabelId,
    ) {
        let (c1, id1) = c1;
        let (c2, id2) = c2;

        let (global_id, label_id) = d1
            .common_channels(d2)
            .find(|(_, lab)| *lab == label_id)
            .unwrap_or_else(|| panic!("channel does not exist: {id1}->{id2} label: {label_id}"));

        const GOLDEN: &str = "hello, world!";
        let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id1} should have channel for global_id {global_id:?}")
        });
        let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id2} should have channel for global_id {global_id:?}")
        });
        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + overhead(c1)];
            let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
            c1.seal(&mut ctx, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("{id1}::seal({id2}, ...): {err}"));
            dst
        };
        let (plaintext, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(c2)];
            let mut open_ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
            let (_, seq) = c2
                .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("{id2}::open({id1}, ...): {err}"));
            (dst, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{id1},{id2},{label_id}");
        assert_eq!(got_seq, 0, "{id1},{id2},{label_id}");
    }

    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label1 = LabelId::random(&eng);
    let label2 = LabelId::random(&eng);
    let label3 = LabelId::random(&eng);
    let label4 = LabelId::random(&eng);

    let labels = [label1, label2, label3, label4];

    let mut d = Aranya::<T, _>::new("test_unidirectional_exhaustive", 2 * 5 * labels.len(), eng);

    let mut c1 = d.new_client_with_type([
        (label1, ChanOp::OpenOnly),
        (label2, ChanOp::Any),
        (label3, ChanOp::OpenOnly),
    ]);
    let mut c2 = d.new_client_with_type([
        (label1, ChanOp::SealOnly),
        (label2, ChanOp::SealOnly),
        (label3, ChanOp::Any),
    ]);
    let mut c3 = d.new_client_with_type([
        (label1, ChanOp::OpenOnly),
        (label2, ChanOp::SealOnly),
        (label3, ChanOp::OpenOnly),
    ]);
    let mut c4 = d.new_client_with_type([(label4, ChanOp::Any)]);
    let mut c5 = d.new_client_with_type([]);

    let d1 = d.devices.get(c1.1).expect("device to exist");
    let d2 = d.devices.get(c2.1).expect("device to exist");
    let d3 = d.devices.get(c3.1).expect("device to exist");
    let d4 = d.devices.get(c4.1).expect("device to exist");
    let d5 = d.devices.get(c5.1).expect("device to exist");

    fail(&mut c1, &c2, d1, d2, label1); // open -> seal
    fail(&mut c1, &c2, d1, d2, label2); // bidi -> seal
    fail(&mut c1, &c2, d1, d2, label3); // open -> bidi
    fail(&mut c1, &c2, d1, d2, label4); // no chans
    fail(&mut c1, &c3, d1, d3, label1); // open -> open
    fail(&mut c1, &c3, d1, d3, label2); // bidi -> seal
    fail(&mut c1, &c3, d1, d3, label3); // open -> open
    fail(&mut c1, &c3, d1, d3, label4); // no chans
    fail(&mut c1, &c4, d1, d4, label1); // no chans
    fail(&mut c1, &c4, d1, d4, label2); // no chans
    fail(&mut c1, &c4, d1, d4, label3); // no chans
    fail(&mut c1, &c4, d1, d4, label4); // no chans
    fail(&mut c1, &c5, d1, d5, label1); // no chans
    fail(&mut c1, &c5, d1, d5, label2); // no chans
    fail(&mut c1, &c5, d1, d5, label3); // no chans
    fail(&mut c1, &c5, d1, d5, label4); // no chans

    pass(&mut c2, &c1, d2, d1, label1); // seal -> open
    pass(&mut c2, &c1, d2, d1, label2); // seal -> bidi
    pass(&mut c2, &c1, d2, d1, label3); // bidi -> open
    fail(&mut c2, &c1, d2, d1, label4); // no chans

    pass(&mut c2, &c3, d2, d3, label1); // seal -> open
    fail(&mut c2, &c3, d2, d3, label2); // seal -> seal
    pass(&mut c2, &c3, d2, d3, label3); // bidi -> open
    fail(&mut c2, &c3, d2, d3, label4); // no chans

    fail(&mut c2, &c4, d2, d4, label1); // no chans
    fail(&mut c2, &c4, d2, d4, label2); // no chans
    fail(&mut c2, &c4, d2, d4, label3); // no chans
    fail(&mut c2, &c4, d2, d4, label4); // no chans

    fail(&mut c2, &c5, d2, d5, label1); // no chans
    fail(&mut c2, &c5, d2, d5, label2); // no chans
    fail(&mut c2, &c5, d2, d5, label3); // no chans
    fail(&mut c2, &c5, d2, d5, label4); // no chans

    fail(&mut c3, &c1, d3, d1, label1); // open -> open
    pass(&mut c3, &c1, d3, d1, label2); // seal -> bidi
    fail(&mut c3, &c1, d3, d1, label3); // open -> open
    fail(&mut c3, &c1, d3, d1, label4); // no chans

    fail(&mut c3, &c2, d3, d2, label1); // open -> seal
    fail(&mut c3, &c2, d3, d2, label2); // seal -> seal
    fail(&mut c3, &c2, d3, d2, label3); // open -> bidi
    fail(&mut c3, &c2, d3, d2, label4); // no chans

    fail(&mut c3, &c4, d3, d4, label1); // no chans
    fail(&mut c3, &c4, d3, d4, label2); // no chans
    fail(&mut c3, &c4, d3, d4, label3); // no chans
    fail(&mut c3, &c4, d3, d4, label4); // no chans

    fail(&mut c3, &c5, d3, d5, label1); // no chans
    fail(&mut c3, &c5, d3, d5, label2); // no chans
    fail(&mut c3, &c5, d3, d5, label3); // no chans
    fail(&mut c3, &c5, d3, d5, label4); // no chans

    fail(&mut c4, &c1, d4, d1, label1); // no chans
    fail(&mut c4, &c1, d4, d1, label2); // no chans
    fail(&mut c4, &c1, d4, d1, label3); // no chans
    fail(&mut c4, &c1, d4, d1, label4); // no chans

    fail(&mut c4, &c2, d4, d2, label1); // no chans
    fail(&mut c4, &c2, d4, d2, label2); // no chans
    fail(&mut c4, &c2, d4, d2, label3); // no chans
    fail(&mut c4, &c2, d4, d2, label4); // no chans

    fail(&mut c4, &c3, d4, d3, label1); // no chans
    fail(&mut c4, &c3, d4, d3, label2); // no chans
    fail(&mut c4, &c3, d4, d3, label3); // no chans
    fail(&mut c4, &c3, d4, d3, label4); // no chans

    fail(&mut c4, &c5, d4, d5, label1); // no chans
    fail(&mut c4, &c5, d4, d5, label2); // no chans
    fail(&mut c4, &c5, d4, d5, label3); // no chans
    fail(&mut c4, &c5, d4, d5, label4); // no chans

    fail(&mut c5, &c1, d5, d1, label1); // no chans
    fail(&mut c5, &c1, d5, d1, label2); // no chans
    fail(&mut c5, &c1, d5, d1, label3); // no chans
    fail(&mut c5, &c1, d5, d1, label4); // no chans

    fail(&mut c5, &c2, d5, d2, label1); // no chans
    fail(&mut c5, &c2, d5, d2, label2); // no chans
    fail(&mut c5, &c2, d5, d2, label3); // no chans
    fail(&mut c5, &c2, d5, d2, label4); // no chans

    fail(&mut c5, &c3, d5, d3, label1); // no chans
    fail(&mut c5, &c3, d5, d3, label2); // no chans
    fail(&mut c5, &c3, d5, d3, label3); // no chans
    fail(&mut c5, &c3, d5, d3, label4); // no chans

    fail(&mut c5, &c4, d5, d4, label1); // no chans
    fail(&mut c5, &c4, d5, d4, label2); // no chans
    fail(&mut c5, &c4, d5, d4, label3); // no chans
    fail(&mut c5, &c4, d5, d4, label4); // no chans
}

/// A positive test for when keys expire.
pub fn test_key_expiry<T: TestImpl, A: Aead>() {
    type N = U1;
    let (eng, _) = TestEngine::<LimitedAead<A, N>>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng)];

    let mut d = Aranya::<T, _>::new("test_key_expiry", 2 * 2 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

    let mut ctxs = HashMap::new();

    const GOLDEN: &str = "hello, world!";

    // From HPKE: 2^n - 1 where n = nonce length in bytes.
    let seq_max = (1 << (8 * N::USIZE)) - 1;
    assert!(seq_max > 0);

    for seq in 0..=seq_max {
        for (global_id, _label_id) in d1.common_channels(d2) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id1} should have channel for global_id {global_id:?}")
            });
            let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id2} should have channel for global_id {global_id:?}")
            });
            let ciphertext = {
                let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];

                let ctx = ctxs
                    .entry((id1, global_id))
                    .or_insert_with(|| c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx"));
                let res = c1.seal(ctx, &mut dst[..], GOLDEN.as_bytes());
                if seq < seq_max {
                    res.unwrap_or_else(|err| panic!("{seq}: seal({d1_channel_id}, ...): {err}"));
                    dst
                } else {
                    let err = res.err().unwrap_or_else(|| {
                        panic!("{seq}: seal({d1_channel_id}, ...): should have failed")
                    });
                    assert_eq!(err, Error::KeyExpired);
                    continue;
                }
            };

            let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
            let mut open_ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
            if seq < seq_max {
                let (plaintext, got_seq) = {
                    let (_, seq) = c2
                        .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
                        .unwrap_or_else(|err| panic!("{seq}: open({id1}, ...): {err}"));
                    (dst, seq)
                };
                assert_eq!(&plaintext[..], GOLDEN.as_bytes());
                assert_eq!(got_seq, seq);
            } else {
                let err = c2
                    .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
                    .err()
                    .unwrap_or_else(|| panic!("{seq}: open({id1}, ...): should have failed"));
                assert_eq!(err, Error::KeyExpired);
            }
        }
    }
}

/// Basic negative test for [`Client::open`] when the tag is
/// truncated.
pub fn test_open_truncated_tag<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_open_truncated_tag", 2 * 2 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

    for (global_id, _label_id) in d1.common_channels(d2) {
        const GOLDEN: &str = "hello, world!";
        let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id1} should have channel for global_id {global_id:?}")
        });
        let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id2} should have channel for global_id {global_id:?}")
        });
        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
            let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
            c1.seal(&mut ctx, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({d1_channel_id}, ...): {err}"));
            // Remove the first byte in the tag.
            dst.remove(GOLDEN.len());
            dst
        };
        let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];

        let mut open_ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
        let err = c2
            .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
            .err()
            .unwrap_or_else(|| panic!("open({id1}, ...): should have failed"));
        assert_eq!(err, Error::Authentication,);
    }
}

/// Basic negative test for [`Client::open`] when the tag has
/// been modified.
pub fn test_open_modified_tag<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_open_modified_tag", 2 * 2 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

    for (global_id, _label_id) in d1.common_channels(d2) {
        const GOLDEN: &str = "hello, world!";
        let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id1} should have channel for global_id {global_id:?}")
        });
        let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id2} should have channel for global_id {global_id:?}")
        });
        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
            let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
            c1.seal(&mut ctx, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({id2}, ...): {err}"));
            dst[GOLDEN.len()] = dst[GOLDEN.len()].wrapping_add(1);
            dst
        };
        let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
        let mut open_ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
        let err = c2
            .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
            .err()
            .unwrap_or_else(|| panic!("open({id1}, ...): should have failed"));
        assert_eq!(err, Error::Authentication,);
    }
}

/// Basic negative test for [`Client::open`] when the sequence
/// number differs.
pub fn test_open_different_seq<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng), LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_open_different_seq", 2 * 2 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

    for (global_id, _label_id) in d1.common_channels(d2) {
        const GOLDEN: &str = "hello, world!";
        let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id1} should have channel for global_id {global_id:?}")
        });
        let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id2} should have channel for global_id {global_id:?}")
        });
        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
            let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
            c1.seal(&mut ctx, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({id2}, ...): {err}"));

            // Rewrite the header to use a different sequence
            // number.
            let hdr = DataHeader::try_parse(dst.first_chunk().expect("`dst` should have a header"))
                .expect("should be able to parse header");
            DataHeaderBuilder::new()
                .seq(hdr.seq.to_u64().wrapping_add(1))
                .encode(&mut dst);

            dst
        };
        let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
        let mut open_ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
        let err = c2
            .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
            .err()
            .unwrap_or_else(|| panic!("open({id1}, ...): should have failed"));
        assert_eq!(err, Error::Authentication);
    }
}

/// Basic negative test for [`Client::seal`] when the channel
/// does not exist because the label is incorrect.
pub fn test_seal_unknown_channel_label<T: TestImpl, A: Aead>() {
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [
        LabelId::random(&eng),
        LabelId::random(&eng),
        LabelId::random(&eng),
        LabelId::random(&eng),
        LabelId::random(&eng),
    ];
    // Take every other label.
    let open_labels = [label_ids[0], label_ids[2], label_ids[4]];

    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new(
        "test_open_unknown_channel_label",
        2 * 2 * label_ids.len(),
        eng,
    );
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(open_labels);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

    for (global_id, label_id) in d1.common_channels(d2) {
        const GOLDEN: &str = "hello, world!";
        let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id1} should have channel for global_id {global_id:?}")
        });
        let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
            panic!("device {id2} should have channel for global_id {global_id:?}")
        });
        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
            let mut ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");

            let res = c1.seal(&mut ctx, &mut dst[..], GOLDEN.as_bytes());
            if open_labels.contains(&label_id) {
                res.unwrap_or_else(|err| panic!("seal({d1_channel_id}, ...): {err}"));
                dst
            } else {
                let err = res
                    .err()
                    .unwrap_or_else(|| panic!("seal({d1_channel_id}, ...): should have failed"));
                assert_eq!(err, Error::NotFound(d1_channel_id));
                continue;
            }
        };

        let (plaintext, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
            let mut open_ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
            let (_, seq) = c2
                .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
            (dst, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes());
        assert_eq!(got_seq, 0);
    }
}

/// Tests that the sequence number increases by one each time.
// NB: This is essentially the same thing as `test_key_expiry`,
// but explicit.
pub fn test_monotonic_seq_by_one<T: TestImpl, A: Aead>() {
    type N = U1;
    let (eng, _) = TestEngine::<LimitedAead<A, N>>::from_entropy(Rng);
    let label_ids = [LabelId::random(&eng)];
    let mut d = Aranya::<T, _>::new("test_monotonic_seq_by_one", 2 * 2 * label_ids.len(), eng);
    let (c1, id1) = d.new_client(label_ids);
    let (c2, id2) = d.new_client(label_ids);

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

    let mut ctxs = HashMap::new();

    const GOLDEN: &str = "hello, world!";

    // From HPKE: 2^n - 1 where n = nonce length in bytes.
    let seq_max = (1 << (8 * N::USIZE)) - 1;
    assert!(seq_max > 0);

    for want_seq in 0..seq_max {
        for (global_id, label_id) in d1.common_channels(d2) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id1} should have channel for global_id {global_id:?}")
            });
            let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id2} should have channel for global_id {global_id:?}")
            });
            let ciphertext = {
                let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
                let ctx = ctxs
                    .entry((id1, global_id))
                    .or_insert_with(|| c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx"));
                c1.seal(ctx, &mut dst[..], GOLDEN.as_bytes())
                    .unwrap_or_else(|err| panic!("seal({d1_channel_id}, ...): {err}"));
                dst
            };
            let (plaintext, got_seq) = {
                let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
                let mut open_ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");
                let (_, seq) = c2
                    .open(&mut open_ctx, &mut dst[..], &ciphertext[..])
                    .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
                (dst, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{want_seq},{label_id}");
            assert_eq!(got_seq, want_seq, "{want_seq},{label_id}");
        }
    }
}

/// A pair of clients with one seal-only channel from `c1` to
/// `c2`, plus the sealed frames `0..n` in order.
///
/// Returned as `(c1, c2, d1_channel_id, d2_channel_id)` along
/// with the [`Aranya`] instance that owns the devices.
struct ReplayFixture<T: TestImpl, A: Aead> {
    c1: Client<T::Afc<TestCs<A>>>,
    c2: Client<T::Afc<TestCs<A>>>,
    seal_ctx: <T::Afc<TestCs<A>> as AfcState>::SealCtx,
    /// `None` only transiently, while the context is being
    /// recreated.
    open_ctx: Option<TestOpenCtx<T, TestCs<A>>>,
    d2_channel_id: LocalChannelId,
    /// `frames[i]` has `seq == i`.
    frames: Vec<Vec<u8>>,
}

impl<T: TestImpl, A: Aead> ReplayFixture<T, A> {
    const GOLDEN: &'static [u8] = b"hello, world!";

    /// Creates the fixture with `n` sealed frames. `window` is
    /// the receiver's replay window size, or `None` for the
    /// default.
    fn new(name: &str, n: usize, window: Option<u16>) -> Self {
        let (eng, _) = TestEngine::<A>::from_entropy(Rng);
        let label_id = LabelId::random(&eng);
        let mut d = Aranya::<T, _>::new(name, 4, eng);
        let (c1, id1) = d.new_client_with_type([(label_id, ChanOp::SealOnly)]);
        let (c2, id2) = match window {
            Some(w) => d.new_client_with_window([label_id], w),
            None => d.new_client([label_id]),
        };
        let d1 = d.devices.get(id1).expect("device to exist");
        let d2 = d.devices.get(id2).expect("device to exist");

        let (global_id, _) = d1.common_channels(d2).next().expect("channel should exist");
        let d1_channel_id = d1
            .get_local_channel_id(global_id)
            .expect("device 1 should have channel");
        let d2_channel_id = d2
            .get_local_channel_id(global_id)
            .expect("device 2 should have channel");

        let mut seal_ctx = c1.setup_seal_ctx(d1_channel_id).expect("can set up ctx");
        let open_ctx = c2.setup_open_ctx(d2_channel_id).expect("can set up ctx");

        let frames = (0..n)
            .map(|i| {
                let mut dst = vec![0u8; Self::GOLDEN.len() + overhead(&c1)];
                c1.seal(&mut seal_ctx, &mut dst[..], Self::GOLDEN)
                    .unwrap_or_else(|err| panic!("seal #{i}: {err}"));
                let hdr = DataHeader::try_parse(dst.last_chunk().expect("should have header"))
                    .expect("should parse header");
                assert_eq!(hdr.seq, i as u64);
                dst
            })
            .collect();

        Self {
            c1,
            c2,
            seal_ctx,
            open_ctx: Some(open_ctx),
            d2_channel_id,
            frames,
        }
    }

    /// Returns the open context.
    fn open_ctx(&mut self) -> &mut TestOpenCtx<T, TestCs<A>> {
        self.open_ctx.as_mut().expect("open context should exist")
    }

    /// Drops the open context and creates a fresh one.
    fn reset_open_ctx(&mut self) {
        // Some backends only allow one live context per channel,
        // so drop the old one first.
        self.open_ctx = None;
        self.open_ctx = Some(
            self.c2
                .setup_open_ctx(self.d2_channel_id)
                .expect("can set up ctx"),
        );
    }

    /// Opens `frames[seq]` with the fixture's open context.
    fn open(&mut self, seq: u64) -> Result<Seq, Error> {
        let frame = self
            .frames
            .get(usize::try_from(seq).expect("seq fits"))
            .unwrap_or_else(|| panic!("no frame for seq {seq}"));
        let mut dst = vec![0u8; frame.len() - overhead(&self.c2)];
        let ctx = self.open_ctx.as_mut().expect("open context should exist");
        let (_, got) = self.c2.open(ctx, &mut dst[..], frame)?;
        assert_eq!(&dst[..], Self::GOLDEN, "seq {seq}");
        assert_eq!(got, seq);
        Ok(got)
    }

    /// Opens `frames[seq]` in place with the fixture's open
    /// context.
    fn open_in_place(&mut self, seq: u64) -> Result<Seq, Error> {
        let frame = self
            .frames
            .get(usize::try_from(seq).expect("seq fits"))
            .unwrap_or_else(|| panic!("no frame for seq {seq}"));
        let mut data = frame.clone();
        let ctx = self.open_ctx.as_mut().expect("open context should exist");
        let (_, got) = self.c2.open_in_place(ctx, &mut data)?;
        assert_eq!(&data[..], Self::GOLDEN, "seq {seq}");
        assert_eq!(got, seq);
        Ok(got)
    }

    /// Asserts that `frames[seq]` is accepted.
    fn accept(&mut self, seq: u64) {
        self.open(seq)
            .unwrap_or_else(|err| panic!("seq {seq} should be accepted: {err}"));
    }

    /// Asserts that `frames[seq]` is rejected as a replay.
    fn reject(&mut self, seq: u64) {
        let err = self
            .open(seq)
            .err()
            .unwrap_or_else(|| panic!("seq {seq} should be rejected"));
        assert_eq!(err, Error::ReplayedSeq { seq: Seq::new(seq) }, "seq {seq}");
    }

    /// Seals one more frame and appends it to `frames`.
    fn seal_more(&mut self) {
        let mut dst = vec![0u8; Self::GOLDEN.len() + overhead(&self.c1)];
        self.c1
            .seal(&mut self.seal_ctx, &mut dst[..], Self::GOLDEN)
            .expect("should seal");
        self.frames.push(dst);
    }
}

/// Frames delivered in order are all accepted.
pub fn test_replay_in_order<T: TestImpl, A: Aead>() {
    let n = 3 * usize::from(DEFAULT_REPLAY_WINDOW);
    let mut f = ReplayFixture::<T, A>::new("test_replay_in_order", n, None);
    for seq in 0..n as u64 {
        f.accept(seq);
        assert_eq!(f.open_ctx().window().high(), Some(Seq::new(seq)));
    }
}

/// A duplicate frame is rejected before the AEAD runs.
pub fn test_replay_duplicate<T: TestImpl, A: Aead>() {
    let mut f = ReplayFixture::<T, A>::new("test_replay_duplicate", 3, None);
    f.accept(0);
    f.reject(0);
    f.accept(1);
    f.reject(1);
    f.reject(0);

    // The replay check runs before authentication: a replayed
    // frame with a corrupted tag is reported as a replay, not
    // as an authentication failure.
    let mut frame = f.frames[1].clone();
    frame[0] = frame[0].wrapping_add(1);
    let mut dst = vec![0u8; frame.len() - overhead(&f.c2)];
    let err =
        f.c2.open(
            f.open_ctx.as_mut().expect("open context should exist"),
            &mut dst[..],
            &frame,
        )
        .expect_err("should be rejected");
    assert_eq!(err, Error::ReplayedSeq { seq: Seq::new(1) });

    // The same corrupted frame with a fresh `seq` fails
    // authentication instead.
    let mut frame = f.frames[2].clone();
    frame[0] = frame[0].wrapping_add(1);
    let err =
        f.c2.open(
            f.open_ctx.as_mut().expect("open context should exist"),
            &mut dst[..],
            &frame,
        )
        .expect_err("should be rejected");
    assert_eq!(err, Error::Authentication);
    // ...and does not consume the sequence number.
    f.accept(2);
}

/// Like [`test_replay_duplicate`], but for
/// [`Client::open_in_place`].
pub fn test_replay_duplicate_in_place<T: TestImpl, A: Aead>() {
    let mut f = ReplayFixture::<T, A>::new("test_replay_duplicate_in_place", 3, None);
    f.open_in_place(0).expect("seq 0 should be accepted");
    assert_eq!(
        f.open_in_place(0).err(),
        Some(Error::ReplayedSeq { seq: Seq::new(0) })
    );
    f.open_in_place(2).expect("seq 2 should be accepted");
    f.open_in_place(1).expect("seq 1 should be accepted");
    assert_eq!(
        f.open_in_place(1).err(),
        Some(Error::ReplayedSeq { seq: Seq::new(1) })
    );
    // Mixing `open` and `open_in_place` shares the window.
    f.reject(2);
    f.reject(0);
}

/// Frames reordered within the window are accepted exactly
/// once.
pub fn test_replay_reorder_within_window<T: TestImpl, A: Aead>() {
    let mut f = ReplayFixture::<T, A>::new("test_replay_reorder_within_window", 3, None);
    f.accept(0);
    f.accept(2);
    f.accept(1);
    f.reject(1);
    f.reject(2);
    f.reject(0);
    assert_eq!(f.open_ctx().window().high(), Some(Seq::new(2)));
}

/// After a gap, late frames inside the window are accepted and
/// frames just outside it are rejected.
pub fn test_replay_gap_and_late_fill<T: TestImpl, A: Aead>() {
    let w = u64::from(DEFAULT_REPLAY_WINDOW);
    let n = usize::try_from(w + 6).expect("fits");
    let mut f = ReplayFixture::<T, A>::new("test_replay_gap_and_late_fill", n, None);
    f.accept(0);
    f.accept(w + 5);
    // The window is now `(5, W + 5]`.
    f.accept(6);
    f.reject(5);
    f.reject(4);
    f.reject(0);
    for seq in 7..w + 5 {
        f.accept(seq);
    }
    for seq in 6..=w + 5 {
        f.reject(seq);
    }
}

/// Advancing far ahead forgets everything below the new window.
pub fn test_replay_far_ahead_advance<T: TestImpl, A: Aead>() {
    let w = u64::from(DEFAULT_REPLAY_WINDOW);
    let high = 10 + 2 * w;
    let n = usize::try_from(high + 1).expect("fits");
    let mut f = ReplayFixture::<T, A>::new("test_replay_far_ahead_advance", n, None);
    for seq in 0..=10 {
        f.accept(seq);
    }
    f.accept(high);
    for seq in 0..=10 {
        f.reject(seq);
    }
    f.reject(high);
    // The bitmap holds only the new `high`.
    for seq in (high - w + 1)..high {
        f.accept(seq);
    }
    f.reject(high - w);
}

/// The first frame establishes the window wherever it lands.
pub fn test_replay_first_frame_high_seq<T: TestImpl, A: Aead>() {
    let w = u64::from(DEFAULT_REPLAY_WINDOW);
    let mut f = ReplayFixture::<T, A>::new("test_replay_first_frame_high_seq", 1001, None);
    f.accept(1000);
    f.accept(999);
    f.reject(1000 - w);
    f.accept(1000 - w + 1);
    f.reject(999);
}

/// A forged frame with a high `seq` fails authentication and
/// does not move the window.
pub fn test_replay_forged_high_seq<T: TestImpl, A: Aead>() {
    let mut f = ReplayFixture::<T, A>::new("test_replay_forged_high_seq", 3, None);
    f.accept(0);

    // Rewrite frame 1's header to claim a very high `seq`.
    let mut forged = f.frames[1].clone();
    DataHeaderBuilder::new().seq(1 << 40).encode(&mut forged);
    let mut dst = vec![0u8; forged.len() - overhead(&f.c2)];
    let err =
        f.c2.open(
            f.open_ctx.as_mut().expect("open context should exist"),
            &mut dst[..],
            &forged,
        )
        .expect_err("forged frame should be rejected");
    assert_eq!(err, Error::Authentication);
    assert_eq!(f.open_ctx().window().high(), Some(Seq::new(0)));

    // Legitimate traffic is unaffected.
    f.accept(1);
    f.accept(2);
    f.reject(0);
}

/// `W = 1` accepts only strictly increasing sequence numbers.
pub fn test_replay_window_size_one<T: TestImpl, A: Aead>() {
    let mut f = ReplayFixture::<T, A>::new("test_replay_window_size_one", 4, Some(1));
    assert_eq!(f.c2.replay_window(), 1);
    f.accept(0);
    f.accept(1);
    f.reject(0);
    f.reject(1);
    f.accept(3);
    f.reject(2);
    f.reject(3);
}

/// `W = MAX_REPLAY_WINDOW` boundary behavior.
pub fn test_replay_window_size_max<T: TestImpl, A: Aead>() {
    let w = u64::from(MAX_REPLAY_WINDOW);
    let n = usize::try_from(w + 2).expect("fits");
    let mut f =
        ReplayFixture::<T, A>::new("test_replay_window_size_max", n, Some(MAX_REPLAY_WINDOW));
    assert_eq!(f.c2.replay_window(), MAX_REPLAY_WINDOW);
    f.accept(w);
    // `(0, W]` is inside the window.
    f.accept(1);
    f.reject(0);
    f.accept(w - 1);
    f.accept(w + 1);
    // Now the window is `(1, W + 1]`.
    f.reject(1);
    f.accept(2);
}

/// `with_replay_window(0)` and `> MAX_REPLAY_WINDOW` are
/// construction errors.
pub fn test_replay_window_bounds<T: TestImpl, A: Aead>() {
    for (i, size) in [0u16, MAX_REPLAY_WINDOW + 1, u16::MAX]
        .into_iter()
        .enumerate()
    {
        let states = T::new_states::<TestCs<A>>("test_replay_window_bounds", i, 1);
        let err = Client::<T::Afc<TestCs<A>>>::with_replay_window(states.afc, size)
            .err()
            .unwrap_or_else(|| panic!("size {size} should be rejected"));
        assert!(matches!(err, Error::InvalidArgument(_)), "{err}");
    }
    for (i, size) in [1u16, DEFAULT_REPLAY_WINDOW, MAX_REPLAY_WINDOW]
        .into_iter()
        .enumerate()
    {
        let states = T::new_states::<TestCs<A>>("test_replay_window_bounds", i + 3, 1);
        let client = Client::<T::Afc<TestCs<A>>>::with_replay_window(states.afc, size)
            .unwrap_or_else(|err| panic!("size {size} should be accepted: {err}"));
        assert_eq!(client.replay_window(), size);
    }
}

/// A freshly created [`OpenCtx`] has no history.
pub fn test_replay_fresh_ctx_resets_window<T: TestImpl, A: Aead>() {
    let mut f = ReplayFixture::<T, A>::new("test_replay_fresh_ctx_resets_window", 3, None);
    f.accept(0);
    f.accept(1);
    f.reject(0);

    f.reset_open_ctx();
    assert_eq!(f.open_ctx().window().high(), None);
    f.accept(0);
    f.accept(1);
    f.reject(1);

    // Frames sealed after the reset behave normally.
    f.seal_more();
    f.accept(3);
    f.accept(2);
    f.reject(2);
}
