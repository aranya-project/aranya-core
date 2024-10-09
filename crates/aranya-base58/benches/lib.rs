use std::{env, time::Duration};

use aranya_base58::{String16, String32, String64};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn get_rng() -> StdRng {
    let s = match env::var("BASE58_SEED") {
        Ok(s) => s,
        Err(_) => return StdRng::from_entropy(),
    };
    if let Ok(x) = s.parse() {
        StdRng::seed_from_u64(x)
    } else {
        StdRng::from_entropy()
    }
}

macro_rules! bench_impl {
    ($name:ident, $type:ident, $size:expr) => {
        fn $name(c: &mut Criterion) {
            let mut data = [0u8; $size];
            let mut rng = get_rng();
            rng.fill_bytes(&mut data);

            let mut g = c.benchmark_group(stringify!($type));
            g.throughput(Throughput::Bytes(data.len() as u64));

            g.bench_with_input(BenchmarkId::new("encode", "rand"), &data, |b, data| {
                b.iter(|| {
                    black_box($type::encode(black_box(data)));
                })
            });

            let data = $type::encode(&data);
            g.bench_with_input(BenchmarkId::new("decode", "rand"), &data, |b, data| {
                b.iter(|| {
                    black_box($type::decode(black_box(data))).unwrap();
                })
            });

            g.finish()
        }
    };
}
bench_impl!(bench_string16, String16, 16);
bench_impl!(bench_string32, String32, 32);
bench_impl!(bench_string64, String64, 64);

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1));
    targets = bench_string16, bench_string32, bench_string64
}
criterion_main!(benches);
