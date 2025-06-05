//! Utilities for testing [`AfcState`] and
//! [`AranyaState`][crate::AranyaState] implementations.
//!
//! If you implement any traits in this crate it is **very
//! highly** recommended that you use these tests.

#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]
#![cfg(any(test, feature = "testing"))]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#![cfg_attr(not(feature = "trng"), forbid(unsafe_code))]

pub mod util;

use std::{collections::HashMap, str};

use aranya_crypto::{
    typenum::{Unsigned, U1},
    Aead, Engine, Rng,
};

use crate::{
    buf::FixedBuf,
    client::Client,
    error::Error,
    header::DataHeader,
    state::{ChannelId, Label, NodeId},
    testing::util::{Aranya, ChanOp, DataHeaderBuilder, LimitedAead, TestEngine, TestImpl},
    AfcState,
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
			test!(test_open_different_label);
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
    let labels = [Label::new(0), Label::new(42)];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_seal_open_basic", labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);

    for label in labels {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let ch2 = ChannelId::new(id2, label);
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
            c1.seal(ch2, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({ch2}, ...): {err}"));
            dst
        };
        let (plaintext, got_label, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
            let (label, seq) = c2
                .open(id1, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
            (dst, label, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label}");
        assert_eq!(got_label, label, "{label}");
        assert_eq!(got_seq, 0, "{label}");
    }
}

/// Basic positive test for [`Client::seal_in_place`] and
/// [`Client::open_in_place`].
pub fn test_seal_open_in_place_basic<T: TestImpl, A: Aead>() {
    let labels = [Label::new(0), Label::new(42)];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_seal_open_in_place_basic", labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);

    for label in labels {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let ch2 = ChannelId::new(id2, label);
            let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
            data.extend_from_slice(GOLDEN.as_bytes());
            c1.seal_in_place(ch2, &mut data)
                .unwrap_or_else(|err| panic!("seal_in_place({ch2}, ...): {err}"));
            data
        };
        let (plaintext, got_label, got_seq) = {
            let mut data = ciphertext.clone();
            let (label, seq) = c2
                .open_in_place(id1, &mut data)
                .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
            (data, label, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label}");
        assert_eq!(got_label, label, "{label}");
        assert_eq!(got_seq, 0, "{label}");
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

    let labels = [Label::new(0), Label::new(42)];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_multi_client", max_nodes * labels.len(), eng);

    let mut ids = Vec::new();
    let mut clients = HashMap::new();
    for _ in 0..max_nodes {
        let (c, id) = d.new_client(labels);
        ids.push(id);
        clients.insert(id, c);
    }

    const GOLDEN: &str = "hello, world!";

    fn test<S: AfcState>(
        clients: &mut HashMap<NodeId, Client<S>>,
        send: NodeId,
        recv: NodeId,
        label: Label,
        seqs: &mut HashMap<(NodeId, NodeId, Label), u64>,
    ) {
        let want_seq = *seqs
            .entry((send, recv, label))
            .and_modify(|seq| {
                *seq += 1;
            })
            .or_insert(0);

        let ciphertext = {
            let u0 = clients
                .get_mut(&send)
                .unwrap_or_else(|| panic!("unable to find send client {send}"));
            let ch = ChannelId::new(recv, label);
            let mut dst = vec![0u8; GOLDEN.len() + overhead(u0)];
            u0.seal(ch, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("{label}: seal({ch}, ...): {err}"));
            dst
        };

        let (plaintext, got_label, got_seq) = {
            let u1 = clients
                .get(&recv)
                .unwrap_or_else(|| panic!("unable to find recv client: {recv}"));
            let mut dst = vec![0u8; ciphertext.len() - overhead(u1)];
            let (label, seq) = u1
                .open(send, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("{label}: open({send}, ...): {err}"));
            (dst, label, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{send},{recv}");
        assert_eq!(got_label, label, "{send},{recv}");
        assert_eq!(got_seq, want_seq, "{send},{recv}");
    }

    let mut seqs = HashMap::new();
    for label in labels {
        for a in &ids {
            for b in &ids {
                if a == b {
                    continue;
                }
                test(&mut clients, *a, *b, label, &mut seqs);
                test(&mut clients, *b, *a, label, &mut seqs);
            }
        }
    }
}

/// Basic positive test for removing a channel.
pub fn test_remove<T: TestImpl, A: Aead>() {
    let labels = [Label::new(0), Label::new(42)];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_remove", 2 * labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);
    let (c3, id3) = d.new_client(labels);

    for label in labels {
        const GOLDEN: &str = "hello, world!";
        for (c, id) in [(&c2, id2), (&c3, id3)] {
            let ch = ChannelId::new(id, label);
            let ciphertext = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({ch}, ...): {err}"));
                data
            };
            let (plaintext, got_label, got_seq) = {
                let mut data = ciphertext.clone();
                let (label, seq) = c
                    .open_in_place(id1, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, label, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes());
            assert_eq!(got_label, label);
            assert_eq!(got_seq, 0);

            // Now that we know it works, delete the channel and try
            // again. It should fail.
            d.remove(id1, ch)
                .unwrap_or_else(|| panic!("remove({id1}, {ch}): not found"))
                .unwrap_or_else(|err| panic!("remove({ch}): {err}"));

            let err = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch, &mut data)
                    .err()
                    .unwrap_or_else(|| panic!("seal_in_place({ch}) should panic"))
            };
            assert_eq!(err, Error::NotFound(ch));
        }
    }
}

/// Basic positive test for removing all channels.
pub fn test_remove_all<T: TestImpl, A: Aead>() {
    let labels = [Label::new(0), Label::new(42)];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_remove_all", 2 * labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);
    let (c3, id3) = d.new_client(labels);

    const GOLDEN: &str = "hello, world!";
    for label in labels {
        for (c, id) in [(&c2, id2), (&c3, id3)] {
            let ciphertext = {
                let ch = ChannelId::new(id, label);
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({ch}, ...): {err}"));
                data
            };
            let (plaintext, got_label, got_seq) = {
                let mut data = ciphertext.clone();
                let (label, seq) = c
                    .open_in_place(id1, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, label, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label},{id}");
            assert_eq!(got_label, label, "{label},{id}");
            assert_eq!(got_seq, 0, "{label},{id}");
        }
    }

    // Now that we know it works, delete all the channels and try
    // again. It should fail.
    d.remove_all(id1)
        .unwrap_or_else(|| panic!("remove_all({id1}): not found"))
        .unwrap_or_else(|err| panic!("remove_all({id1}): {err}"));

    for label in labels {
        for id in [id2, id3] {
            let ch = ChannelId::new(id, label);
            let err = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch, &mut data)
                    .err()
                    .unwrap_or_else(|| panic!("seal_in_place({ch}) should panic"))
            };
            assert_eq!(err, Error::NotFound(ch));
        }
    }
}

/// Basic positive test for removing channels matching condition.
pub fn test_remove_if<T: TestImpl, A: Aead>() {
    let labels = [Label::new(0), Label::new(42)];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_remove_if", 2 * labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);
    let (c3, id3) = d.new_client(labels);

    const GOLDEN: &str = "hello, world!";
    for label in labels {
        for (c, id) in [(&c2, id2), (&c3, id3)] {
            let ciphertext = {
                let ch = ChannelId::new(id, label);
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({ch}, ...): {err}"));
                data
            };
            let (plaintext, got_label, got_seq) = {
                let mut data = ciphertext.clone();
                let (label, seq) = c
                    .open_in_place(id1, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, label, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label},{id}");
            assert_eq!(got_label, label, "{label},{id}");
            assert_eq!(got_seq, 0, "{label},{id}");
        }
    }

    for label in labels {
        for id in [id2, id3] {
            let ch = ChannelId::new(id, label);
            // Now that we know it works, delete the channel and try
            // again. It should fail.
            d.remove_if(id1, |v| v == ch)
                .unwrap_or_else(|| panic!("remove_if({id1}, {ch}): not found"))
                .unwrap_or_else(|err| panic!("remove_if({ch}): {err}"));
            let err = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch, &mut data)
                    .err()
                    .unwrap_or_else(|| panic!("seal_in_place({ch}) should panic"))
            };
            assert_eq!(err, Error::NotFound(ch));

            // Test that other channel still works
            if id == id2 {
                let ch3 = ChannelId::new(id3, label);
                let mut data: Vec<u8> = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch3, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({ch3}, ...): {err}"));
            }
        }
    }
}

/// Test removing channels when there are no channels to remove.
pub fn test_remove_no_channels<T: TestImpl, A: Aead>() {
    let labels = [Label::new(0), Label::new(42)];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_remove_no_channels", 2 * labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);
    let (c3, id3) = d.new_client(labels);

    const GOLDEN: &str = "hello, world!";
    for label in labels {
        for (c, id) in [(&c2, id2), (&c3, id3)] {
            let ciphertext = {
                let ch = ChannelId::new(id, label);
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({ch}, ...): {err}"));
                data
            };
            let (plaintext, got_label, got_seq) = {
                let mut data = ciphertext.clone();
                let (label, seq) = c
                    .open_in_place(id1, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, label, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label},{id}");
            assert_eq!(got_label, label, "{label},{id}");
            assert_eq!(got_seq, 0, "{label},{id}");
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

    for label in labels {
        for id in [id2, id3] {
            let ch = ChannelId::new(id, label);
            let err = {
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch, &mut data)
                    .err()
                    .unwrap_or_else(|| panic!("seal_in_place({ch}) should panic"))
            };
            assert_eq!(err, Error::NotFound(ch));
        }
    }
}

/// Basic positive test for checking if expected channels exist.
pub fn test_channels_exist<T: TestImpl, A: Aead>() {
    let labels = [Label::new(0), Label::new(42)];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_channels_exist", 2 * labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);
    let (c3, id3) = d.new_client(labels);

    const GOLDEN: &str = "hello, world!";
    for label in labels {
        for (c, id) in [(&c2, id2), (&c3, id3)] {
            let ciphertext = {
                let ch = ChannelId::new(id, label);
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({ch}, ...): {err}"));
                data
            };
            let (plaintext, got_label, got_seq) = {
                let mut data = ciphertext.clone();
                let (label, seq) = c
                    .open_in_place(id1, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, label, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label},{id}");
            assert_eq!(got_label, label, "{label},{id}");
            assert_eq!(got_seq, 0, "{label},{id}");
        }
    }

    let ids = [id1, id2, id3];
    for label in labels {
        for i in 0..ids.len() {
            for j in 0..ids.len() {
                if i == j {
                    continue;
                }
                let ida = ids[i];
                let idb = ids[j];
                // Verify that expected labels exist.
                let ch: ChannelId = ChannelId::new(idb, label);
                let result = d
                    .exists(ida, ch)
                    .unwrap_or_else(|| panic!("exists({idb}, {label}): not found"))
                    .unwrap_or_else(|err| panic!("exists({label}): {err}"));
                assert!(result);
            }
        }
    }
}

/// Basic negative test for checking that channels that were not
/// created do not exist.
pub fn test_channels_not_exist<T: TestImpl, A: Aead>() {
    let labels = [Label::new(0), Label::new(42)];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_channels_not_exist", 2 * labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);
    let (c3, id3) = d.new_client(labels);

    const GOLDEN: &str = "hello, world!";
    for label in labels {
        for (c, id) in [(&c2, id2), (&c3, id3)] {
            let ciphertext = {
                let ch = ChannelId::new(id, label);
                let mut data = Vec::with_capacity(GOLDEN.len() + overhead(&c1));
                data.extend_from_slice(GOLDEN.as_bytes());
                c1.seal_in_place(ch, &mut data)
                    .unwrap_or_else(|err| panic!("seal_in_place({ch}, ...): {err}"));
                data
            };
            let (plaintext, got_label, got_seq) = {
                let mut data = ciphertext.clone();
                let (label, seq) = c
                    .open_in_place(id1, &mut data)
                    .unwrap_or_else(|err| panic!("open_in_place({id1}, ...): {err}"));
                (data, label, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{label},{id}");
            assert_eq!(got_label, label, "{label},{id}");
            assert_eq!(got_seq, 0, "{label},{id}");
        }
    }

    let ids = [id1, id2, id3];
    let unused_labels = [Label::new(1020), Label::new(2010), Label::new(30)];
    for label in unused_labels {
        for i in 0..ids.len() {
            for j in 0..ids.len() {
                if i == j {
                    continue;
                }
                let ida = ids[i];
                let idb = ids[j];
                let ch = ChannelId::new(idb, label);
                let result = d
                    .exists(ida, ch)
                    .unwrap_or_else(|| panic!("exists({idb}, {label}): not found"))
                    .unwrap_or_else(|err| panic!("exists({label}): {err}"));
                assert!(!result);
            }
        }
    }
}

/// A test for issue #112, where [`Client`] would fail if the
/// output buffer was not exactly the right size.
pub fn test_issue112<T: TestImpl, A: Aead>() {
    const LABEL: Label = Label::new(0);
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, TestEngine<A>>::new("test_issue_112", 1, eng);
    let (mut c1, id1) = d.new_client([LABEL]);
    let (c2, id2) = d.new_client([LABEL]);

    const GOLDEN: &str = "hello";
    let ciphertext = {
        let ch2 = ChannelId::new(id2, LABEL);
        let len = GOLDEN.len() + overhead(&c1) + 100;
        let mut dst = vec![0u8; len];
        let mut buf = FixedBuf::from_slice_mut(&mut dst, len).expect("dst should be <= len");
        c1.seal(ch2, &mut buf, GOLDEN.as_bytes())
            .unwrap_or_else(|err| panic!("seal({ch2}, ...): {err}"));
        dst.truncate(GOLDEN.len() + overhead(&c1));
        dst
    };
    let (plaintext, got_label, got_seq) = {
        let mut dst = vec![0u8; ciphertext.len() - overhead(&c1)];
        let (label, seq) = c2
            .open(id1, &mut dst[..], &ciphertext[..])
            .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
        dst.truncate(ciphertext.len() - overhead(&c2));
        (dst, label, seq)
    };
    assert_eq!(&plaintext[..], GOLDEN.as_bytes());
    assert_eq!(got_label, LABEL);
    assert_eq!(got_seq, 0);
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
    let mut d = Aranya::<T, _>::new("test_client_send", 1, eng);
    let (c, _) = d.new_client([Label::new(0)]);
    is_send(c);
}

/// A basic positive test for unidirectional channels.
pub fn test_unidirectional_basic<T: TestImpl, A: Aead>() {
    fn test<S: AfcState>(c1: &mut (Client<S>, NodeId), c2: &(Client<S>, NodeId), label: Label) {
        let (c1, id1) = c1;
        let (c2, id2) = c2;

        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let ch2 = ChannelId::new(*id2, label);
            let mut dst = vec![0u8; GOLDEN.len() + overhead(c1)];
            c1.seal(ch2, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({ch2}, ...): {err}"));
            dst
        };
        let (plaintext, got_label, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(c2)];
            let (label, seq) = c2
                .open(*id1, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
            (dst, label, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{id1},{id2},{label}");
        assert_eq!(got_label, label, "{id1},{id2},{label}");
        assert_eq!(got_seq, 0, "{id1},{id2},{label}");
    }

    const LABEL1: Label = Label::new(1);
    const LABEL2: Label = Label::new(2);
    const LABEL3: Label = Label::new(3);

    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_unidirectional_pos", 6, eng);

    let mut c1 = d.new_client_with_type([
        (LABEL1, ChanOp::SealOnly),
        (LABEL2, ChanOp::OpenOnly),
        (LABEL3, ChanOp::Any),
    ]);
    let mut c2 = d.new_client_with_type([
        (LABEL1, ChanOp::OpenOnly),
        (LABEL2, ChanOp::SealOnly),
        (LABEL3, ChanOp::Any),
    ]);
    let mut c3 = d.new_client_with_type([
        (LABEL1, ChanOp::Any),
        (LABEL2, ChanOp::Any),
        (LABEL3, ChanOp::OpenOnly),
    ]);

    test(&mut c1, &c2, LABEL1);
    test(&mut c1, &c3, LABEL1);
    test(&mut c1, &c3, LABEL3);

    test(&mut c2, &c1, LABEL2);
    test(&mut c2, &c3, LABEL2);
    test(&mut c2, &c3, LABEL3);

    test(&mut c3, &c1, LABEL2);
    test(&mut c3, &c2, LABEL1);
}

/// A positive and negative test for unidirectional channels.
pub fn test_unidirectional_exhaustive<T: TestImpl, A: Aead>() {
    fn fail<S: AfcState>(c1: &mut (Client<S>, NodeId), c2: &(Client<S>, NodeId), label: Label) {
        let (c1, id1) = c1;
        let (_, id2) = c2;

        let ch = ChannelId::new(*id2, label);
        let mut dst = vec![0u8; overhead(c1)];
        let err = c1
            .seal(ch, &mut dst[..], &[])
            .err()
            .unwrap_or_else(|| panic!("{id1}::seal({ch}, ...): expected an error"));
        assert_eq!(err, Error::NotFound(ch));
    }

    fn pass<S: AfcState>(c1: &mut (Client<S>, NodeId), c2: &(Client<S>, NodeId), label: Label) {
        let (c1, id1) = c1;
        let (c2, id2) = c2;

        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let ch2 = ChannelId::new(*id2, label);
            let mut dst = vec![0u8; GOLDEN.len() + overhead(c1)];
            c1.seal(ch2, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("{id1}::seal({ch2}, ...): {err}"));
            dst
        };
        let (plaintext, got_label, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(c2)];
            let (label, seq) = c2
                .open(*id1, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("{id2}::open({id1}, ...): {err}"));
            (dst, label, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{id1},{id2},{label}");
        assert_eq!(got_label, label, "{id1},{id2},{label}");
        assert_eq!(got_seq, 0, "{id1},{id2},{label}");
    }

    const LABEL1: Label = Label::new(1);
    const LABEL2: Label = Label::new(2);
    const LABEL3: Label = Label::new(3);
    const LABEL4: Label = Label::new(4);

    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_unidirectional_exhaustive", 6, eng);

    let mut c1 = d.new_client_with_type([
        (LABEL1, ChanOp::OpenOnly),
        (LABEL2, ChanOp::Any),
        (LABEL3, ChanOp::OpenOnly),
    ]);
    let mut c2 = d.new_client_with_type([
        (LABEL1, ChanOp::SealOnly),
        (LABEL2, ChanOp::SealOnly),
        (LABEL3, ChanOp::Any),
    ]);
    let mut c3 = d.new_client_with_type([
        (LABEL1, ChanOp::OpenOnly),
        (LABEL2, ChanOp::SealOnly),
        (LABEL3, ChanOp::OpenOnly),
    ]);
    let mut c4 = d.new_client_with_type([(LABEL4, ChanOp::Any)]);
    let mut c5 = d.new_client_with_type([]);

    fail(&mut c1, &c2, LABEL1); // open -> seal
    fail(&mut c1, &c2, LABEL2); // bidi -> seal
    fail(&mut c1, &c2, LABEL3); // open -> bidi
    fail(&mut c1, &c2, LABEL4); // no chans
    fail(&mut c1, &c3, LABEL1); // open -> open
    fail(&mut c1, &c3, LABEL2); // bidi -> seal
    fail(&mut c1, &c3, LABEL3); // open -> open
    fail(&mut c1, &c3, LABEL4); // no chans
    fail(&mut c1, &c4, LABEL1); // no chans
    fail(&mut c1, &c4, LABEL2); // no chans
    fail(&mut c1, &c4, LABEL3); // no chans
    fail(&mut c1, &c4, LABEL4); // no chans
    fail(&mut c1, &c5, LABEL1); // no chans
    fail(&mut c1, &c5, LABEL2); // no chans
    fail(&mut c1, &c5, LABEL3); // no chans
    fail(&mut c1, &c5, LABEL4); // no chans

    pass(&mut c2, &c1, LABEL1); // seal -> open
    pass(&mut c2, &c1, LABEL2); // seal -> bidi
    pass(&mut c2, &c1, LABEL3); // bidi -> open
    fail(&mut c2, &c1, LABEL4); // no chans
    pass(&mut c2, &c3, LABEL1); // seal -> open
    fail(&mut c2, &c3, LABEL2); // seal -> seal
    pass(&mut c2, &c3, LABEL3); // bidi -> open
    fail(&mut c2, &c3, LABEL4); // no chans
    fail(&mut c2, &c4, LABEL1); // no chans
    fail(&mut c2, &c4, LABEL2); // no chans
    fail(&mut c2, &c4, LABEL3); // no chans
    fail(&mut c2, &c4, LABEL4); // no chans
    fail(&mut c2, &c5, LABEL1); // no chans
    fail(&mut c2, &c5, LABEL2); // no chans
    fail(&mut c2, &c5, LABEL3); // no chans
    fail(&mut c2, &c5, LABEL4); // no chans

    fail(&mut c3, &c1, LABEL1); // open -> open
    pass(&mut c3, &c1, LABEL2); // seal -> bidi
    fail(&mut c3, &c1, LABEL3); // open -> open
    fail(&mut c3, &c1, LABEL4); // no chans
    fail(&mut c3, &c2, LABEL1); // open -> seal
    fail(&mut c3, &c2, LABEL2); // seal -> seal
    fail(&mut c3, &c2, LABEL3); // open -> bidi
    fail(&mut c3, &c2, LABEL4); // no chans
    fail(&mut c3, &c4, LABEL1); // no chans
    fail(&mut c3, &c4, LABEL2); // no chans
    fail(&mut c3, &c4, LABEL3); // no chans
    fail(&mut c3, &c4, LABEL4); // no chans
    fail(&mut c3, &c5, LABEL1); // no chans
    fail(&mut c3, &c5, LABEL2); // no chans
    fail(&mut c3, &c5, LABEL3); // no chans
    fail(&mut c3, &c5, LABEL4); // no chans

    fail(&mut c4, &c1, LABEL1); // no chans
    fail(&mut c4, &c1, LABEL2); // no chans
    fail(&mut c4, &c1, LABEL3); // no chans
    fail(&mut c4, &c1, LABEL4); // no chans
    fail(&mut c4, &c2, LABEL1); // no chans
    fail(&mut c4, &c2, LABEL2); // no chans
    fail(&mut c4, &c2, LABEL3); // no chans
    fail(&mut c4, &c2, LABEL4); // no chans
    fail(&mut c4, &c3, LABEL1); // no chans
    fail(&mut c4, &c3, LABEL2); // no chans
    fail(&mut c4, &c3, LABEL3); // no chans
    fail(&mut c4, &c3, LABEL4); // no chans
    fail(&mut c4, &c5, LABEL1); // no chans
    fail(&mut c4, &c5, LABEL2); // no chans
    fail(&mut c4, &c5, LABEL3); // no chans
    fail(&mut c4, &c5, LABEL4); // no chans

    fail(&mut c5, &c1, LABEL1); // no chans
    fail(&mut c5, &c1, LABEL2); // no chans
    fail(&mut c5, &c1, LABEL3); // no chans
    fail(&mut c5, &c1, LABEL4); // no chans
    fail(&mut c5, &c2, LABEL1); // no chans
    fail(&mut c5, &c2, LABEL2); // no chans
    fail(&mut c5, &c2, LABEL3); // no chans
    fail(&mut c5, &c2, LABEL4); // no chans
    fail(&mut c5, &c3, LABEL1); // no chans
    fail(&mut c5, &c3, LABEL2); // no chans
    fail(&mut c5, &c3, LABEL3); // no chans
    fail(&mut c5, &c3, LABEL4); // no chans
    fail(&mut c5, &c4, LABEL1); // no chans
    fail(&mut c5, &c4, LABEL2); // no chans
    fail(&mut c5, &c4, LABEL3); // no chans
    fail(&mut c5, &c4, LABEL4); // no chans
}

/// A positive test for when keys expire.
pub fn test_key_expiry<T: TestImpl, A: Aead>() {
    type N = U1;
    let labels = [Label::new(0)];
    let (eng, _) = TestEngine::<LimitedAead<A, N>>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_key_expiry", labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);

    const GOLDEN: &str = "hello, world!";

    // From HPKE: 2^n - 1 where n = nonce length in bytes.
    let seq_max = (1 << (8 * N::USIZE)) - 1;
    assert!(seq_max > 0);

    for seq in 0..=seq_max {
        for label in labels {
            let ciphertext = {
                let ch2 = ChannelId::new(id2, label);
                let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];

                let res = c1.seal(ch2, &mut dst[..], GOLDEN.as_bytes());
                if seq < seq_max {
                    res.unwrap_or_else(|err| panic!("{seq}: seal({ch2}, ...): {err}"));
                    dst
                } else {
                    let err = res
                        .err()
                        .unwrap_or_else(|| panic!("{seq}: seal({ch2}, ...): should have failed"));
                    assert_eq!(err, Error::KeyExpired);
                    continue;
                }
            };

            let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
            if seq < seq_max {
                let (plaintext, got_label, got_seq) = {
                    let (label, seq) = c2
                        .open(id1, &mut dst[..], &ciphertext[..])
                        .unwrap_or_else(|err| panic!("{seq}: open({id1}, ...): {err}"));
                    (dst, label, seq)
                };
                assert_eq!(&plaintext[..], GOLDEN.as_bytes());
                assert_eq!(got_label, label);
                assert_eq!(got_seq, seq);
            } else {
                let err = c2
                    .open(id1, &mut dst[..], &ciphertext[..])
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
    let labels = [1u32.into(), 2u32.into()];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_open_truncated_tag", labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);

    for label in labels {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let ch2 = ChannelId::new(id2, label);
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
            c1.seal(ch2, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({ch2}, ...): {err}"));
            // Remove the first byte in the tag.
            dst.remove(GOLDEN.len());
            dst
        };
        let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
        let err = c2
            .open(id1, &mut dst[..], &ciphertext[..])
            .err()
            .unwrap_or_else(|| panic!("open({id1}, ...): should have failed"));
        assert_eq!(err, Error::Authentication,);
    }
}

/// Basic negative test for [`Client::open`] when the tag has
/// been modified.
pub fn test_open_modified_tag<T: TestImpl, A: Aead>() {
    let labels = [1u32.into(), 2u32.into()];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_open_modified_tag", labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);

    for label in labels {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let ch2 = ChannelId::new(id2, label);
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
            c1.seal(ch2, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({ch2}, ...): {err}"));
            dst[GOLDEN.len()] = dst[GOLDEN.len()].wrapping_add(1);
            dst
        };
        let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
        let err = c2
            .open(id1, &mut dst[..], &ciphertext[..])
            .err()
            .unwrap_or_else(|| panic!("open({id1}, ...): should have failed"));
        assert_eq!(err, Error::Authentication,);
    }
}

/// Basic negative test for [`Client::open`] when the label
/// differs.
pub fn test_open_different_label<T: TestImpl, A: Aead>() {
    let labels = [1u32.into(), 2u32.into()];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_open_different_label", labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);

    const GOLDEN: &str = "hello, world!";
    let ciphertext = {
        let ch2 = ChannelId::new(id2, labels[0]);
        let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
        c1.seal(ch2, &mut dst[..], GOLDEN.as_bytes())
            .unwrap_or_else(|err| panic!("seal({ch2}, ...): {err}"));

        // Rewrite the header to use a different label.
        DataHeaderBuilder::new()
            .label(labels[1].to_u32())
            .encode(&mut dst);

        dst
    };
    let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
    let err = c2
        .open(id1, &mut dst[..], &ciphertext[..])
        .err()
        .unwrap_or_else(|| panic!("open({id1}, ...): should have failed"));
    assert_eq!(err, Error::Authentication,);
}

/// Basic negative test for [`Client::open`] when the sequence
/// number differs.
pub fn test_open_different_seq<T: TestImpl, A: Aead>() {
    let labels = [1u32.into(), 2u32.into()];
    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_open_different_seq", labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);

    for label in labels {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let ch2 = ChannelId::new(id2, label);
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
            c1.seal(ch2, &mut dst[..], GOLDEN.as_bytes())
                .unwrap_or_else(|err| panic!("seal({ch2}, ...): {err}"));

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
            .open(id1, &mut dst[..], &ciphertext[..])
            .err()
            .unwrap_or_else(|| panic!("open({id1}, ...): should have failed"));
        assert_eq!(err, Error::Authentication);
    }
}

/// Basic negative test for [`Client::seal`] when the channel
/// does not exist because the label is incorrect.
pub fn test_seal_unknown_channel_label<T: TestImpl, A: Aead>() {
    let labels = [
        Label::new(1),
        Label::new(2),
        Label::new(3),
        Label::new(4),
        Label::new(5),
    ];
    // Take every other label.
    let open_labels = labels
        .iter()
        .take_while(|label| label.to_u32() % 2 == 0)
        .copied()
        .collect::<Vec<_>>();

    let (eng, _) = TestEngine::<A>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_open_unknown_channel_label", labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(open_labels.clone());

    for label in labels {
        const GOLDEN: &str = "hello, world!";
        let ciphertext = {
            let ch2 = ChannelId::new(id2, label);
            let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];

            let res = c1.seal(ch2, &mut dst[..], GOLDEN.as_bytes());
            if open_labels.contains(&label) {
                res.unwrap_or_else(|err| panic!("seal({ch2}, ...): {err}"));
                dst
            } else {
                let err = res
                    .err()
                    .unwrap_or_else(|| panic!("seal({ch2}, ...): should have failed"));
                assert_eq!(err, Error::NotFound(ch2));
                continue;
            }
        };

        let (plaintext, got_label, got_seq) = {
            let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
            let (label, seq) = c2
                .open(id1, &mut dst[..], &ciphertext[..])
                .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
            (dst, label, seq)
        };
        assert_eq!(&plaintext[..], GOLDEN.as_bytes());
        assert_eq!(got_label, label);
        assert_eq!(got_seq, 0);
    }
}

/// Tests that the sequence number increases by one each time.
// NB: This is essentially the same thing as `test_key_expiry`,
// but explicit.
pub fn test_monotonic_seq_by_one<T: TestImpl, A: Aead>() {
    type N = U1;
    let labels = [Label::new(0)];
    let (eng, _) = TestEngine::<LimitedAead<A, N>>::from_entropy(Rng);
    let mut d = Aranya::<T, _>::new("test_monotonic_seq_by_one", labels.len(), eng);
    let (mut c1, id1) = d.new_client(labels);
    let (c2, id2) = d.new_client(labels);

    const GOLDEN: &str = "hello, world!";

    // From HPKE: 2^n - 1 where n = nonce length in bytes.
    let seq_max = (1 << (8 * N::USIZE)) - 1;
    assert!(seq_max > 0);

    for want_seq in 0..seq_max {
        for label in labels {
            let ciphertext = {
                let ch2 = ChannelId::new(id2, label);
                let mut dst = vec![0u8; GOLDEN.len() + overhead(&c1)];
                c1.seal(ch2, &mut dst[..], GOLDEN.as_bytes())
                    .unwrap_or_else(|err| panic!("seal({ch2}, ...): {err}"));
                dst
            };
            let (plaintext, got_label, got_seq) = {
                let mut dst = vec![0u8; ciphertext.len() - overhead(&c2)];
                let (label, seq) = c2
                    .open(id1, &mut dst[..], &ciphertext[..])
                    .unwrap_or_else(|err| panic!("open({id1}, ...): {err}"));
                (dst, label, seq)
            };
            assert_eq!(&plaintext[..], GOLDEN.as_bytes(), "{want_seq},{label}");
            assert_eq!(got_label, label, "{want_seq},{label}");
            assert_eq!(got_seq, want_seq, "{want_seq},{label}");
        }
    }
}
