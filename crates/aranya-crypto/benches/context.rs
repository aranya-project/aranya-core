//! Quick and dirty benchmarking of different methods of
//! generating contextual binding for KDFs.

use std::{hint::black_box, marker::PhantomData, time::Duration};

use aranya_crypto::dangerous::spideroak_crypto::{
    hash::Hash,
    kdf::{Kdf, KdfError, Prk},
    rust::{HkdfSha256, Sha256},
};
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_main, measurement::Measurement,
};

trait Spec<K: Kdf> {
    #[inline]
    fn extract(salt: &[u8], ikm: &[u8]) -> Prk<K::PrkSize> {
        K::extract(salt, ikm)
    }
    fn expand(out: &mut [u8], prk: &Prk<K::PrkSize>, info: &[u8]) -> Result<(), KdfError>;
}

/// Raw expansion without any additional processing.
struct Raw<K>(PhantomData<K>);
impl<K: Kdf> Spec<K> for Raw<K> {
    #[inline]
    fn expand(out: &mut [u8], prk: &Prk<K::PrkSize>, info: &[u8]) -> Result<(), KdfError> {
        K::expand(out, prk, info)
    }
}

/// Hash the info before expanding.
struct Hashed<K, H>(PhantomData<(K, H)>);
impl<K, H> Spec<K> for Hashed<K, H>
where
    H: Hash,
    K: Kdf,
{
    #[inline]
    fn expand(out: &mut [u8], prk: &Prk<K::PrkSize>, info: &[u8]) -> Result<(), KdfError> {
        let info = H::hash(info);
        K::expand(out, prk, info.as_bytes())
    }
}

// NB: This benchmark is written so that you see output like
//
// HKDF-SHA256/raw/32/0
// HKDF-SHA256/hashed/32/0
// HKDF-SHA256/raw/32/16
// HKDF-SHA256/hashed/32/16
//
// instead of
//
// HKDF-SHA256/raw/32/0
// HKDF-SHA256/raw/32/16
// HKDF-SHA256/hashed/32/0
// HKDF-SHA256/hashed/32/16
fn bench_expand<K: Kdf>(c: &mut Criterion, name: &str) {
    fn bench<S, K, M>(g: &mut BenchmarkGroup<'_, M>, name: &str, out: &mut [u8], info: &[u8])
    where
        S: Spec<K>,
        K: Kdf,
        M: Measurement,
    {
        g.bench_with_input(
            BenchmarkId::new(name, format!("{}/{}", out.len(), info.len())),
            info,
            |b, info| {
                let prk = S::extract(&[0; 32], &[]);
                b.iter(|| {
                    let _ = black_box(S::expand(black_box(out), black_box(&prk), black_box(info)));
                });
            },
        );
    }

    let out_sizes = [32, 64, 128, 256];
    let info_sizes = [0, 16, 32, 64, 128, 256];

    let mut g = c.benchmark_group(name);
    for out_size in out_sizes {
        g.throughput(Throughput::Bytes(out_size as u64));

        let mut out = vec![0; out_size];
        for info_size in info_sizes {
            let info = vec![0; info_size];
            bench::<Raw<K>, _, _>(&mut g, "raw", &mut out, &info);
            bench::<Hashed<K, Sha256>, _, _>(&mut g, "sha256", &mut out, &info);
        }
    }

    g.finish();
}

fn benches() {
    let mut c = Criterion::default().warm_up_time(Duration::from_secs(1));

    bench_expand::<HkdfSha256>(&mut c, "HKDF-SHA256");
}

criterion_main!(benches);
