#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::unwrap_used)]

use std::{array, hint::black_box, num::NonZeroU16, time::Duration};

use aranya_crypto::{
    CipherSuite, Csprng as _, DeviceId, OpenError, Random as _, Rng, SealError,
    afc::{RawOpenKey, RawSealKey},
    dangerous::spideroak_crypto::{
        aead::{Aead, AeadKey, IndCca2, Lifetime},
        hpke::{AeadId, HpkeAead},
        oid,
        oid::{Identified, Oid},
        rust::HkdfSha256,
    },
    default::DefaultCipherSuite,
    id::IdExt as _,
    policy::LabelId,
    test_util::TestCs,
    typenum::U16,
};
use aranya_fast_channels::{
    AranyaState as _, Client, Directed, LocalChannelId,
    crypto::Aes256Gcm,
    shm::{self, Flag, Mode, Path},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_main};

pub struct NoopAead;

impl Aead for NoopAead {
    const LIFETIME: Lifetime = Lifetime::Messages(u64::MAX);

    type KeySize = U16;
    type NonceSize = U16;
    type Overhead = U16;

    const MAX_PLAINTEXT_SIZE: u64 = u64::MAX - Self::OVERHEAD as u64;
    const MAX_ADDITIONAL_DATA_SIZE: u64 = u64::MAX;

    type Key = AeadKey<U16>;

    #[inline(always)]
    fn new(_key: &Self::Key) -> Self {
        Self
    }

    #[inline(always)]
    fn seal_in_place(
        &self,
        _nonce: &[u8],
        _data: &mut [u8],
        _overhead: &mut [u8],
        _additional_data: &[u8],
    ) -> Result<(), SealError> {
        Ok(())
    }

    #[inline(always)]
    fn open_in_place(
        &self,
        _nonce: &[u8],
        _data: &mut [u8],
        _overhead: &[u8],
        _additional_data: &[u8],
    ) -> Result<(), OpenError> {
        Ok(())
    }
}

impl IndCca2 for NoopAead {}

impl Identified for NoopAead {
    const OID: &Oid = oid!("1.2.3");
}

impl HpkeAead for NoopAead {
    const ID: AeadId = AeadId::Other(NonZeroU16::new(42).unwrap());
}

const SIZES: &[usize] = &[
    // A small message.
    64,
    // A UDP packet.
    576,
    // A TCP packet.
    1448,
    // Demonstrates APS' overhead vs the AEAD's.
    4 * 1024,
    16 * 1024,
    64 * 1024,
];

pub(crate) type CS<A, K> = TestCs<
    A,
    <DefaultCipherSuite as CipherSuite>::Hash,
    K,
    <DefaultCipherSuite as CipherSuite>::Kem,
    <DefaultCipherSuite as CipherSuite>::Mac,
    <DefaultCipherSuite as CipherSuite>::Signer,
>;

macro_rules! bench_impl {
	($name:ident, $aead:ty, $kdf:ty) => {
		fn $name(c: &mut Criterion) {
			// Make sure that `USED_CHANS` is a power of two.
			const MAX_CHANS: usize = 1024;
			const USED_CHANS: usize = MAX_CHANS / 2;

			let path = Path::from_bytes(b"/bench_afc\x00").expect("should not fail");
			let _ = shm::unlink(path);
			let aranya = shm::WriteState::<CS<$aead, $kdf>, Rng>::open(
				path,
				Flag::Create,
				Mode::ReadWrite,
				MAX_CHANS,
				Rng,
			)
			.expect("should not fail");
			let afc = shm::ReadState::open(path, Flag::OpenOnly, Mode::ReadWrite, MAX_CHANS)
				.expect("should not fail");

			let chans: [(LocalChannelId, LocalChannelId); USED_CHANS] = array::from_fn(|_| {
				let label = LabelId::random(&mut Rng);

				// Use the same key to simplify the decryption
				// benchmarks.
				let seal = RawSealKey::random(&mut Rng);
				let open = RawOpenKey {
					key: seal.key.clone(),
					base_nonce: seal.base_nonce,
				};

				let seal_key = Directed::SealOnly {
                    seal,
                };

				let open_key = Directed::OpenOnly {
					open
				};

				(aranya.add(seal_key, label, DeviceId::random(&mut Rng)).unwrap(), aranya.add(open_key, label, DeviceId::random(&mut Rng)).unwrap())
			});
			let mut client = Client::<shm::ReadState<CS<$aead, $kdf>>>::new(afc);

			for size in SIZES {
				let mut g = c.benchmark_group(stringify!($aead));
				g.throughput(Throughput::Bytes(*size as u64));

				let mut input = vec![0u8; *size];
				Rng.fill_bytes(&mut input);

				let mut plaintext = vec![0u8; input.len()];
				let mut ciphertext = vec![0u8; input.len() + <Client::<shm::ReadState<CS<$aead, $kdf>>>>::OVERHEAD ];

				// The best case scenario: the peer's info is
				// always cached.
				let (seal_channel_id, _) = *chans.last().unwrap();
				g.bench_function(BenchmarkId::new("seal_hit", *size), |b| {
					b.iter(|| {
						black_box(client.seal(
							black_box(seal_channel_id),
							black_box(&mut ciphertext),
							black_box(&input),
						))
						.expect("seal_hit: unable to decrypt");
					})
				});

				// The worst case scenario: the peer's info is
				// never cached.
				let mut iter = chans.iter().cycle().copied();
				g.bench_function(BenchmarkId::new("seal_miss", *size), |b| {
					let (seal_channel_id, _) = iter.next().expect("should repeat");
					b.iter(|| {
						black_box(client.seal(
							black_box(seal_channel_id),
							black_box(&mut ciphertext),
							black_box(&input),
						))
						.expect("seal_miss: unable to encrypt");
					})
				});

				// The best case scenario: the peer's info is
				// always cached.
				let (seal_channel_id, open_channel_id) = *chans.last().unwrap();
				client
					.seal(seal_channel_id, &mut ciphertext, &input)
					.expect("open_hit: unable to encrypt");
				g.bench_function(BenchmarkId::new("open_hit", *size), |b| {
					b.iter(|| {
						let _ = black_box(client.open(
							black_box(open_channel_id),
							black_box(&mut plaintext),
							black_box(&ciphertext),
						))
						.expect("open_hit: unable to decrypt");
					})
				});

				// The worst case scenario: the peer's info is
				// never cached.
				let mut iter = chans.iter().cycle();
				g.bench_function(BenchmarkId::new("open_miss", *size), |b| {
					b.iter(|| {
						// Ignore failures instead of creating
						// N ciphertexts.
						let (_seal_channel_id, open_channel_id) = iter.next().expect("should repeat");
						let _ = client.open(
							black_box(*open_channel_id),
							black_box(&mut plaintext),
							black_box(&ciphertext),
						);
					});
				});

				g.finish()
			}
		}
	};
}

bench_impl!(bench_noop, NoopAead, HkdfSha256);

bench_impl!(bench_aes256gcm_hkdfsha256, Aes256Gcm, HkdfSha256);

fn benches() {
    let mut c = Criterion::default().warm_up_time(Duration::from_secs(1));

    bench_noop(&mut c);

    bench_aes256gcm_hkdfsha256(&mut c);
}

criterion_main!(benches);
