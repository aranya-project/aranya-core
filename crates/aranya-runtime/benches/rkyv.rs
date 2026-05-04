#![allow(clippy::unwrap_used)]

use std::hint::black_box;

use aranya_crypto::{Rng, id::IdExt as _};
use aranya_runtime::{
    Address, CmdId, Command, Location, MaxCut, Perspective as _, PolicyId, Prior, Priority,
    QueryMut as _, Segment as _, Storage as _, StorageProvider, storage::linear,
};
use criterion::{Criterion, criterion_group, criterion_main};

struct Cmd {
    id: CmdId,
    priority: Priority,
    parent: Prior<Address>,
    policy: Option<Box<[u8]>>,
    bytes: Box<[u8]>,
}

impl Command for Cmd {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> CmdId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        self.parent
    }

    fn policy(&self) -> Option<&[u8]> {
        self.policy.as_deref()
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn init<SP: StorageProvider>(sp: &mut SP) -> &mut SP::Storage {
    let mut p = sp.new_perspective(PolicyId::new(0));

    let mut parent = CmdId::random(Rng);
    p.add_command(&Cmd {
        id: parent,
        priority: Priority::Init,
        parent: Prior::None,
        policy: Some(vec![0; 512].into_boxed_slice()),
        bytes: vec![0; 512].into_boxed_slice(),
    })
    .unwrap();

    for i in 0..100 {
        let id = CmdId::random(Rng);
        p.add_command(&Cmd {
            id,
            priority: Priority::Basic(42),
            parent: Prior::Single(Address {
                id: parent,
                max_cut: MaxCut(i),
            }),
            policy: None,
            bytes: vec![0; 512].into_boxed_slice(),
        })
        .unwrap();
        p.insert(
            "fact".into(),
            [i.to_string().into_bytes().into_boxed_slice()]
                .into_iter()
                .collect(),
            vec![0u8; 100].into_boxed_slice(),
        )
        .unwrap();
        parent = id;
    }

    sp.new_storage(p).unwrap().1
}

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        let mut group = c.benchmark_group("in-memory");

        group.bench_function("new_storage", |b| {
            b.iter(|| {
                let mut sp = linear::testing::MemStorageProvider::default();
                black_box(init(black_box(&mut sp)));
            });
        });

        let mut sp = linear::testing::MemStorageProvider::default();
        let store = init(&mut sp);
        let loc = Location::new(store.get_head().unwrap().segment, MaxCut(42));

        group.bench_function("get_command_id", |b| {
            b.iter(|| {
                black_box(&store)
                    .get_segment(black_box(loc))
                    .unwrap()
                    .get_command(black_box(loc))
                    .unwrap()
                    .id()
            });
        });
    }

    {
        let mut group = c.benchmark_group("file-based");

        group.bench_function("new_storage", |b| {
            b.iter(|| {
                let tmp = tempfile::tempdir().unwrap();
                let mut sp = linear::LinearStorageProvider::new(
                    linear::libc::FileManager::new(tmp.path()).unwrap(),
                );
                black_box(init(black_box(&mut sp)));
            });
        });

        let tmp = tempfile::tempdir().unwrap();
        let mut sp =
            linear::LinearStorageProvider::new(linear::libc::FileManager::new(tmp.path()).unwrap());
        let store = init(&mut sp);
        let loc = Location::new(store.get_head().unwrap().segment, MaxCut(42));

        group.bench_function("get_command_id", |b| {
            b.iter(|| {
                black_box(&store)
                    .get_segment(black_box(loc))
                    .unwrap()
                    .get_command(black_box(loc))
                    .unwrap()
                    .id()
            });
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
