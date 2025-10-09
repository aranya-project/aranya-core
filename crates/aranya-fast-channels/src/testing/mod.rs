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
    policy::LabelId,
    typenum::{U1, Unsigned as _},
};

use crate::{
    AfcState, ChannelId,
    buf::FixedBuf,
    client::Client,
    error::Error,
    header::DataHeader,
    testing::util::{
        Aranya, ChanOp, DataHeaderBuilder, Device, DeviceIdx, LimitedAead, TestEngine, TestImpl,
    },
};

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
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_seal_open_basic", label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

    for (global_id, label_id) in d1.common_channels(d2) {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id1} should have channel for global_id {global_id:?}")
            });
            c1.seal(d1_channel_id, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({id2}, ...): {err}"));
            dst
        };
        let (plaintext, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
            let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id2} should have channel for global_id {global_id:?}")
            });
            let (_, seq) = c2
                .open(d2_channel_id, &mut dst[..], &ciphertext[..])
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
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_seal_open_in_place_basic", label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

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
            c1.seal_in_place(d1_channel_id, &mut data)
                .unwrap_or_else(|err| panic!("seal_in_place({id2}, ...): {err}"));
            data
        };
        let (plaintext, got_seq) = {
            let mut data = ciphertext.clone();
            let d2_channel_id = d2.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device {id2} should have channel for global_id {global_id:?}")
            });
            let (_, seq) = c2
                .open_in_place(d2_channel_id, &mut data)
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

    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_multi_client", max_nodes * label_ids.len(), eng);

    let mut device_idxs = Vec::new();
    let mut clients = Vec::new();
    for idx in 0..max_nodes {
        let op = if idx < (max_nodes / 2) {
            ChanOp::SealOnly
        } else {
            ChanOp::OpenOnly
        };

        let (c, device_idx) = d.new_client_with_type(label_ids.iter().map(|id| (*id, op)));
        device_idxs.push((device_idx, op));
        clients.insert(device_idx, c);
    }

    const GOLDEN: &str = "hello, world!";

    fn test<T: TestImpl, S: AfcState, CS: CipherSuite>(
        clients: &mut [Client<S>],
        devices: &[Device<T, CS>],
        send: DeviceIdx,
        recv: DeviceIdx,
        label_id: LabelId,
        seqs: &mut HashMap<(DeviceIdx, DeviceIdx, LabelId), u64>,
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
            u0.seal(send_channel_id, &mut dst[..], GOLDEN.as_bytes())
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
            let (_, seq) = u1
                .open(recv_channel_id, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("{label_id}: open({send}, ...): {err}"));
            (dst, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{send},{recv}");
        assert_eq!(got_seq, want_seq, "{send},{recv}");
    }

    let mut seqs = HashMap::new();

    for label_id in label_ids {
        for (a, a_op) in &device_idxs {
            for (b, b_op) in &device_idxs {
                if *a_op == ChanOp::SealOnly && *b_op == ChanOp::OpenOnly {
                    test(&mut clients, &d.devices, *a, *b, label_id, &mut seqs);
                }
            }
        }
    }
}

/// Basic positive test for removing a channel.
pub fn test_remove<T: TestImpl, A: Aead>() {
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_remove", 2 * label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));
    let (c3, id3) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

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
            let ciphertext = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(d1_channel_id, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let (_, seq) = c
                    .open_in_place(device_channel_id, &mut data)
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
                c1.seal_in_place(d1_channel_id, &mut data)
                    .err()
                    .unwrap_or_else(|| panic!("seal_in_place({id}) should panic"))
            };
            assert_eq!(err, Error::NotFound(d1_channel_id));
        }
    }
}

/// Basic positive test for removing all channels.
pub fn test_remove_all<T: TestImpl, A: Aead>() {
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_remove_all", 2 * label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));
    let (c3, id3) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");
    let d3 = d.devices.get(id3).expect("device to exist");

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
                c1.seal_in_place(d1_channel_id, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let (_, seq) = c
                    .open_in_place(device_channel_id, &mut data)
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
                c1.seal_in_place(d1_channel_id, &mut data)
                    .err()
                    .unwrap_or_else(|| {
                        panic!("seal_in_place({d1_channel_id} {label_id} should panic")
                    })
            };
            assert_eq!(err, Error::NotFound(d1_channel_id));
        }
    }
}

/// Basic positive test for removing channels matching condition.
pub fn test_remove_if<T: TestImpl, A: Aead>() {
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_remove_if", 2 * label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));
    let (c3, id3) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");
    let d3 = d.devices.get(id3).expect("device to exist");

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
                c1.seal_in_place(d1_channel_id, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let (_, seq) = c
                    .open_in_place(device_channel_id, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label_id},{id}");
            assert_eq!(got_seq, 0, "{label_id},{id}");
        }
    }

    for (id, device) in [(id2, d2), (id3, d3)] {
        for (global_id, _label_id) in d1.common_channels(device) {
            let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                panic!("device should have channel for global_id {global_id:?}")
            });
            // Now that we know it works, delete the channel and try
            // again. It should fail.
            d.remove_if(id1, |v, _| v == d1_channel_id)
                .unwrap_or_else(|| panic!("remove_if({id1}, {id}): not found"))
                .unwrap_or_else(|err| panic!("remove_if({id}): {err}"));
            let err = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(d1_channel_id, &mut data)
                    .err()
                    .unwrap_or_else(|| panic!("seal_in_place({id}) should panic"))
            };
            assert_eq!(err, Error::NotFound(d1_channel_id));

            // Test that other channel still works
            if id == id2 {
                for (global_id, _label_id) in d1.common_channels(d3) {
                    let d1_channel_id = d1.get_local_channel_id(global_id).unwrap_or_else(|| {
                        panic!("device should have channel for global_id {global_id:?}")
                    });
                    let mut data: Vec<u8> = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                    data.extend_from_slice(GOLDEN.as_bytes());
                    c1.seal_in_place(d1_channel_id, &mut data)
                        .unwrap_or_else(|err| panic!("seal_in_place({id3}, ...): {err}"));
                }
            }
        }
    }
}

/// Test removing channels when there are no channels to remove.
pub fn test_remove_no_channels<T: TestImpl, A: Aead>() {
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_remove_no_channels", 2 * label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));
    let (c3, id3) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");
    let d3 = d.devices.get(id3).expect("device to exist");

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
                c1.seal_in_place(d1_channel_id, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let (_, seq) = c
                    .open_in_place(device_channel_id, &mut data)
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
    d.remove_if(id1, |_, _| true)
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
            c1.seal_in_place(d1_channel_id, &mut data)
                .err()
                .unwrap_or_else(|| panic!("seal_in_place({d1_channel_id},{label_id}) should panic"))
        };
        assert_eq!(err, Error::NotFound(d1_channel_id));
    }
}

/// Basic positive test for checking if expected channels exist.
pub fn test_channels_exist<T: TestImpl, A: Aead>() {
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_channels_exist", 2 * label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));
    let (c3, id3) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

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
                c1.seal_in_place(d1_channel_id, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let (_, seq) = c
                    .open_in_place(device_channel_id, &mut data)
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
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let unused_labels = [
        LabelId::random(&mut eng),
        LabelId::random(&mut eng),
        LabelId::random(&mut eng),
    ];

    let mut d = Aranya::<T, _>::new("test_channels_not_exist", 2 * label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));
    let (c3, id3) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

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
                c1.seal_in_place(d1_channel_id, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({id}, ...): {err}"));
                data
            };
            let (plaintext, got_seq) = {
                let mut data = ciphertext.clone();
                let (_, seq) = c
                    .open_in_place(device_channel_id, &mut data)
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
                    .exists(ChannelId::new(9999), idb)
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
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_id = LabelId::random(&mut eng);
    let mut d = Aranya::<T, TestEngine<A>>::new("test_issue_112", 1, eng);
    let (mut c1, id1) = d.new_client_with_type([(label_id, ChanOp::SealOnly)]);
    let (c2, id2) = d.new_client_with_type([(label_id, ChanOp::OpenOnly)]);

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
            c1.seal(d1_channel_id, &mut buf, GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({id2}, ...): {err}"));
            dst.truncate(GOLDEN.len() + overhead(&c1));
            dst
        };
        let (plaintext, got_label, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(&c1)];
            let (_, seq) = c2
                .open(d2_channel_id, &mut dst[..], &ciphertext[..])
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

    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label = LabelId::random(&mut eng);
    let mut d = Aranya::<T, _>::new("test_client_send", 1, eng);
    let (c, _) = d.new_client_with_type([(label, ChanOp::SealOnly)]);
    is_send(c);

    let (c, _) = d.new_client_with_type([(label, ChanOp::OpenOnly)]);
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
            c1.seal(d1_channel_id, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("({id1}->{id2}) seal(channel_id: {d1_channel_id}, label_id: {label_id} ...): {err}"));
            dst
        };
        let (plaintext, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(c2)];
            let (_, seq) = c2
                .open(d2_channel_id, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
            (dst, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{id1},{id2},{label_id}");
        assert_eq!(got_seq, 0, "{id1},{id2},{label_id}");
    }

    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label1 = LabelId::random(&mut eng);
    let label2 = LabelId::random(&mut eng);

    let mut d = Aranya::<T, _>::new("test_unidirectional_pos", 6, eng);

    let mut c1 = d.new_client_with_type([(label1, ChanOp::SealOnly), (label2, ChanOp::OpenOnly)]);
    let mut c2 = d.new_client_with_type([(label1, ChanOp::OpenOnly), (label2, ChanOp::SealOnly)]);

    let d1 = d.devices.get(c1.1).expect("device to exist");
    let d2 = d.devices.get(c2.1).expect("device to exist");

    test(&mut c1, &c2, d1, d2, label1);
    test(&mut c2, &c1, d2, d1, label2);
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
            let err = c1
                .seal(d1_channel_id, &mut dst[..], &[])
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
            c1.seal(d1_channel_id, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("{id1}::seal({id2}, ...): {err}"));
            dst
        };
        let (plaintext, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(c2)];
            let (_, seq) = c2
                .open(d2_channel_id, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("{id2}::open({id1}, ...): {err}"));
            (dst, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{id1},{id2},{label_id}");
        assert_eq!(got_seq, 0, "{id1},{id2},{label_id}");
    }

    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label1 = LabelId::random(&mut eng);
    let label2 = LabelId::random(&mut eng);
    let label3 = LabelId::random(&mut eng);
    let label4 = LabelId::random(&mut eng);

    let mut d = Aranya::<T, _>::new("test_unidirectional_exhaustive", 6, eng);

    let mut c1 = d.new_client_with_type([
        (label1, ChanOp::OpenOnly),
        (label2, ChanOp::OpenOnly),
        (label3, ChanOp::OpenOnly),
    ]);
    let mut c2 = d.new_client_with_type([
        (label1, ChanOp::SealOnly),
        (label2, ChanOp::SealOnly),
        (label3, ChanOp::SealOnly),
    ]);
    let mut c3 = d.new_client_with_type([
        (label1, ChanOp::OpenOnly),
        (label2, ChanOp::SealOnly),
        (label3, ChanOp::OpenOnly),
    ]);
    let mut c4 = d.new_client_with_type([]);

    let d1 = d.devices.get(c1.1).expect("device to exist");
    let d2 = d.devices.get(c2.1).expect("device to exist");
    let d3 = d.devices.get(c3.1).expect("device to exist");
    let d4 = d.devices.get(c4.1).expect("device to exist");

    // c1 -> c2 tests
    fail(&mut c1, &c2, d1, d2, label1); // open -> seal
    fail(&mut c1, &c2, d1, d2, label2); // open -> seal
    fail(&mut c1, &c2, d1, d2, label3); // open -> seal
    fail(&mut c1, &c2, d1, d2, label4); // no chans

    // c1 -> c3 tests
    fail(&mut c1, &c3, d1, d3, label1); // open -> open
    fail(&mut c1, &c3, d1, d3, label2); // open -> seal
    fail(&mut c1, &c3, d1, d3, label3); // open -> open
    fail(&mut c1, &c3, d1, d3, label4); // no chans

    // c1 -> c4 tests
    fail(&mut c1, &c4, d1, d4, label1); // no chans
    fail(&mut c1, &c4, d1, d4, label2); // no chans
    fail(&mut c1, &c4, d1, d4, label3); // no chans
    fail(&mut c1, &c4, d1, d4, label4); // no chans

    // c2 -> c1 tests
    pass(&mut c2, &c1, d2, d1, label1); // seal -> open
    pass(&mut c2, &c1, d2, d1, label2); // seal -> open
    pass(&mut c2, &c1, d2, d1, label3); // seal -> open
    fail(&mut c2, &c1, d2, d1, label4); // no chans

    // c2 -> c3 tests
    pass(&mut c2, &c3, d2, d3, label1); // seal -> open
    fail(&mut c2, &c3, d2, d3, label2); // seal -> seal
    pass(&mut c2, &c3, d2, d3, label3); // seal -> open
    fail(&mut c2, &c3, d2, d3, label4); // no chans

    // c2 -> c4 tests
    fail(&mut c2, &c4, d2, d4, label1); // no chans
    fail(&mut c2, &c4, d2, d4, label2); // no chans
    fail(&mut c2, &c4, d2, d4, label3); // no chans
    fail(&mut c2, &c4, d2, d4, label4); // no chans

    // c3 -> c1 tests
    fail(&mut c3, &c1, d3, d1, label1); // open -> open
    pass(&mut c3, &c1, d3, d1, label2); // seal -> open
    fail(&mut c3, &c1, d3, d1, label3); // open -> open
    fail(&mut c3, &c1, d3, d1, label4); // no chans

    // c3 -> c2 tests
    fail(&mut c3, &c2, d3, d2, label1); // open -> seal
    fail(&mut c3, &c2, d3, d2, label2); // seal -> seal
    fail(&mut c3, &c2, d3, d2, label3); // open -> seal
    fail(&mut c3, &c2, d3, d2, label4); // no chans

    // c3 -> c4 tests
    fail(&mut c3, &c4, d3, d4, label1); // no chans
    fail(&mut c3, &c4, d3, d4, label2); // no chans
    fail(&mut c3, &c4, d3, d4, label3); // no chans
    fail(&mut c3, &c4, d3, d4, label4); // no chans

    // c4 -> c1 tests
    fail(&mut c4, &c1, d4, d1, label1); // no chans
    fail(&mut c4, &c1, d4, d1, label2); // no chans
    fail(&mut c4, &c1, d4, d1, label3); // no chans
    fail(&mut c4, &c1, d4, d1, label4); // no chans

    // c4 -> c2 tests
    fail(&mut c4, &c2, d4, d2, label1); // no chans
    fail(&mut c4, &c2, d4, d2, label2); // no chans
    fail(&mut c4, &c2, d4, d2, label3); // no chans
    fail(&mut c4, &c2, d4, d2, label4); // no chans

    // c4 -> c3 tests
    fail(&mut c4, &c3, d4, d3, label1); // no chans
    fail(&mut c4, &c3, d4, d3, label2); // no chans
    fail(&mut c4, &c3, d4, d3, label3); // no chans
    fail(&mut c4, &c3, d4, d3, label4); // no chans
}

/// A positive test for when keys expire.
pub fn test_key_expiry<T: TestImpl, A: Aead>() {
    type N = U1;
    let (mut eng, _) = TestEngine::<LimitedAead<A, N>>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng)];

    let mut d = Aranya::<T, _>::new("test_key_expiry", label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

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

                let res = c1.seal(d1_channel_id, &mut dst[..], GOLDEN.as_bytes());
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
            if seq < seq_max {
                let (plaintext, got_seq) = {
                    let (_, seq) = c2
                        .open(d2_channel_id, &mut dst[..], &ciphertext[..])
                        .unwrap_or_else(|err| panic!("{seq}: open({id1}, ...): {err}"));
                    (dst, seq)
                };
                assert_eq!(&plaintext[..], GOLDEN.as_bytes());
                assert_eq!(got_seq, seq);
            } else {
                let err = c2
                    .open(d2_channel_id, &mut dst[..], &ciphertext[..])
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
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_open_truncated_tag", label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

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
            c1.seal(d1_channel_id, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({d1_channel_id}, ...): {err}"));
            // Remove the first byte in the tag.
            dst.remove(GOLDEN.len());
            dst
        };
        let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
        let err = c2
            .open(d2_channel_id, &mut dst[..], &ciphertext[..])
            .err()
            .unwrap_or_else(|| panic!("open({id1}, ...): should have failed"));
        assert_eq!(err, Error::Authentication,);
    }
}

/// Basic negative test for [`Client::open`] when the tag has
/// been modified.
pub fn test_open_modified_tag<T: TestImpl, A: Aead>() {
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_open_modified_tag", label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

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
            c1.seal(d1_channel_id, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({id2}, ...): {err}"));
            dst[GOLDEN.len()] = dst[GOLDEN.len()].wrapping_add(1);
            dst
        };
        let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
        let err = c2
            .open(d2_channel_id, &mut dst[..], &ciphertext[..])
            .err()
            .unwrap_or_else(|| panic!("open({id1}, ...): should have failed"));
        assert_eq!(err, Error::Authentication,);
    }
}

/// Basic negative test for [`Client::open`] when the sequence
/// number differs.
pub fn test_open_different_seq<T: TestImpl, A: Aead>() {
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng), LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_open_different_seq", label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

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
            c1.seal(d1_channel_id, &mut dst[..], GOLDEN.as_bytes())
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
        let err = c2
            .open(d2_channel_id, &mut dst[..], &ciphertext[..])
            .err()
            .unwrap_or_else(|| panic!("open({id1}, ...): should have failed"));
        assert_eq!(err, Error::Authentication);
    }
}

/// Basic negative test for [`Client::seal`] when the channel
/// does not exist because the label is incorrect.
pub fn test_seal_unknown_channel_label<T: TestImpl, A: Aead>() {
    let (mut eng, _) = TestEngine::<A>::from_entropy(Rng);
    let label_ids = [
        LabelId::random(&mut eng),
        LabelId::random(&mut eng),
        LabelId::random(&mut eng),
        LabelId::random(&mut eng),
        LabelId::random(&mut eng),
    ];
    // Take every other label.
    let open_labels = [label_ids[0], label_ids[2], label_ids[4]];

    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_open_unknown_channel_label", label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(open_labels.iter().map(|id| (*id, ChanOp::OpenOnly)));

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

            let res = c1.seal(d1_channel_id, &mut dst[..], GOLDEN.as_bytes());
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
            let (_, seq) = c2
                .open(d2_channel_id, &mut dst[..], &ciphertext[..])
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
    let (mut eng, _) = TestEngine::<LimitedAead<A, N>>::from_entropy(Rng);
    let label_ids = [LabelId::random(&mut eng)];
    let mut d = Aranya::<T, _>::new("test_monotonic_seq_by_one", label_ids.len(), eng);
    let (mut c1, id1) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::SealOnly)));
    let (c2, id2) = d.new_client_with_type(label_ids.iter().map(|id| (*id, ChanOp::OpenOnly)));

    let d1 = d.devices.get(id1).expect("device to exist");
    let d2 = d.devices.get(id2).expect("device to exist");

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
                c1.seal(d1_channel_id, &mut dst[..], GOLDEN.as_bytes())
                    .unwrap_or_else(|err| panic!("seal({d1_channel_id}, ...): {err}"));
                dst
            };
            let (plaintext, got_seq) = {
                let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
                let (_, seq) = c2
                    .open(d2_channel_id, &mut dst[..], &ciphertext[..])
                    .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
                (dst, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{want_seq},{label_id}");
            assert_eq!(got_seq, want_seq, "{want_seq},{label_id}");
        }
    }
}
