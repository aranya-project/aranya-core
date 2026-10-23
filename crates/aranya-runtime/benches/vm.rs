use std::sync::Arc;

use aranya_crypto::{DeviceId, Rng, SigningKey, default::DefaultEngine};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{Text, bench_measurements};
use aranya_runtime::{
    ClientState, RuntimeBuffers, mem_spill,
    storage::linear::testing::MemStorageProvider,
    testing::vm::{TEST_POLICY_1, TestPolicyStore, TestSink},
    vm_action, vm_effect,
    vm_policy::{FLAVORS, FfiSet, SealCtx},
};

/// Create a `TestPolicyStore`.
fn new_policy_store() -> TestPolicyStore {
    let seal_ctx = generate_seal_context();
    let (eng, _) = DefaultEngine::from_entropy(Rng);
    TestPolicyStore::new(Arc::new(eng), FfiSet::new(), seal_ctx)
}

/// Compile and serialize the policy.
fn compile_policy(src: &str) -> Vec<u8> {
    let ast = parse_policy_document(src).expect("can parse");
    let module = Compiler::new(&ast)
        .flavors(&FLAVORS)
        .compile()
        .expect("can compile");
    module.write_to_vec().expect("can serialize test module")
}

/// Generate a random seal context.
fn generate_seal_context() -> SealCtx<Arc<DefaultEngine>> {
    use aranya_crypto::id::IdExt as _;
    SealCtx {
        author: DeviceId::random(Rng),
        key: SigningKey::new(Rng),
    }
}

fn benchmark_1() {
    let policy = compile_policy(TEST_POLICY_1);
    let policy_store = new_policy_store();
    let key = policy_store.verifying_key();
    let provider = MemStorageProvider::default();
    let mut cs = ClientState::new(policy_store, provider);
    let mut buffers = RuntimeBuffers::new();

    let mut sink = TestSink::new();
    let graph_id = cs
        .new_graph(&policy, vm_action!(init(0, key)), &mut sink)
        .expect("could not create graph");

    sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 3 }));

    cs.action(
        graph_id,
        &mut sink,
        vm_action!(create_action(3)),
        &mut buffers,
        mem_spill,
    )
    .expect("could not call action");

    sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 4 }));

    cs.action(
        graph_id,
        &mut sink,
        vm_action!(increment()),
        &mut buffers,
        mem_spill,
    )
    .expect("should call increment");

    bench_measurements().print_stats();
}

fn benchmark_map() {
    let test = r#"---
policy-version: 2
---
```policy
        base[init] BaseInit {
            fields { key: bytes }
            get_key { return Some(this.key) }
        }

        fact Key[]=>{key: bytes}

        base[basic] Base {
            get_key {
                return match query Key[] {
                    Some(f) => Some(f.key)
                    None => None
                }
            }
        }

        fact F[i: int]=>{ value: string }

        command Init with BaseInit {
            policy {
                finish {
                    create Key[]=>{key: this.key}
                }
            }
        }

        action[init] init(key: bytes) {
            publish Init { key: key }
        }

        action[basic] insert(i: int, value: string) {
            publish Insert { i:i, value: value }
        }

        command Insert with Base {
            attributes {
                priority: 10,
            }
            fields {
                i: int,
                value: string
            }
            policy {
                finish {
                    create F[i: this.i]=>{value: this.value}
                }
            }
        }

        action[basic] run() {
            map F[i:?] as f {
                publish DoSomething { i: f.i }
            }
        }

        command DoSomething with Base {
            attributes {
                priority: 5,
            }
            fields { i: int }
            policy {
                finish {
                    update F[i:this.i]=>{ value:? } to { value:"updated" }
                }
            }
        }
```
    "#;

    let policy = compile_policy(test);
    let policy_store = new_policy_store();
    let key = policy_store.verifying_key();
    let provider = MemStorageProvider::default();
    let mut cs = ClientState::new(policy_store, provider);
    let mut buffers = RuntimeBuffers::new();

    let mut sink = TestSink::new();
    let graph_id = cs
        .new_graph(&policy, vm_action!(init(key)), &mut sink)
        .expect("could not create graph");

    for i in 1..10 {
        let text: Text = i.to_string().parse().expect("valid text");
        cs.action(
            graph_id,
            &mut sink,
            vm_action!(insert(i, text)),
            &mut buffers,
            mem_spill,
        )
        .expect("action `insert` failed");
    }
    cs.action(
        graph_id,
        &mut sink,
        vm_action!(run()),
        &mut buffers,
        mem_spill,
    )
    .expect("action `run` failed");

    bench_measurements().print_stats();
}

fn main() {
    benchmark_1();
    benchmark_map();
}
