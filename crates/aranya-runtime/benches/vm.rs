fn benchmark_1() {
    use aranya_policy_compiler::Compiler;
    use aranya_policy_lang::lang::parse_policy_document;
    use aranya_policy_vm::{bench_measurements, ffi::FfiModule as _};
    use aranya_runtime::{
        ClientState,
        memory::MemStorageProvider,
        testing::vm::{TEST_POLICY_1, TestPolicyStore, TestSink},
        vm_action, vm_effect,
        vm_policy::testing::TestFfiEnvelope,
    };

    let policy = parse_policy_document(TEST_POLICY_1).expect("should parse");
    let module = Compiler::new(&policy)
        .ffi_modules(&[TestFfiEnvelope::SCHEMA])
        .compile()
        .expect("should compile");
    let policy_store = TestPolicyStore::from_module(module);
    let provider = MemStorageProvider::new();
    let mut cs = ClientState::new(policy_store, provider);

    let mut sink = TestSink::new();
    let storage_id = cs
        .new_graph(&[0u8], vm_action!(init(0)), &mut sink)
        .expect("could not create graph");

    sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 3 }));

    cs.action(storage_id, &mut sink, vm_action!(create_action(3)))
        .expect("could not call action");

    sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: 4 }));

    cs.action(storage_id, &mut sink, vm_action!(increment()))
        .expect("should call increment");

    bench_measurements().print_stats();
}

fn benchmark_map() {
    let test = r#"---
policy-version: 1
---
```policy
        use envelope
        fact F[i int]=>{ value string }

        command Init {
            seal { return envelope::do_seal(serialize(this)) }
            open { return deserialize(envelope::do_open(envelope)) }
            policy {
                finish {}
            }
        }

        action init() {
            publish Init {}
        }

        action insert(i int, value string) {
            publish Insert { i:i, value: value }
        }

        command Insert {
            fields {
                i int,
                value string
            }
            seal { return envelope::do_seal(serialize(this)) }
            open { return deserialize(envelope::do_open(envelope)) }
            policy {
                finish {
                    create F[i: this.i]=>{value: this.value}
                }
            }
        }

        action run() {
            map F[i:?] as f {
                publish DoSomething { i: f.i }
            }
        }

        command DoSomething {
            fields { i int }
            seal { return envelope::do_seal(serialize(this)) }
            open { return deserialize(envelope::do_open(envelope)) }
            policy {
                finish {
                    update F[i:this.i]=>{ value:? } to { value:"updated" }
                }
            }
        }
```
    "#;

    use aranya_policy_compiler::Compiler;
    use aranya_policy_lang::lang::parse_policy_document;
    use aranya_policy_vm::{Text, bench_measurements, ffi::FfiModule as _};
    use aranya_runtime::{
        ClientState,
        memory::MemStorageProvider,
        testing::vm::{TestPolicyStore, TestSink},
        vm_action,
        vm_policy::testing::TestFfiEnvelope,
    };

    let policy = parse_policy_document(test).expect("should parse");
    let module = Compiler::new(&policy)
        .ffi_modules(&[TestFfiEnvelope::SCHEMA])
        .compile()
        .expect("should compile");
    let policy_store = TestPolicyStore::from_module(module);
    let provider = MemStorageProvider::new();
    let mut cs = ClientState::new(policy_store, provider);

    let mut sink = TestSink::new();
    let storage_id = cs
        .new_graph(&[0u8], vm_action!(init()), &mut sink)
        .expect("could not create graph");

    for i in 1..10 {
        let text: Text = i.to_string().parse().expect("valid text");
        cs.action(storage_id, &mut sink, vm_action!(insert(i, text)))
            .expect("action `insert` failed");
    }
    cs.action(storage_id, &mut sink, vm_action!(run()))
        .expect("action `run` failed");

    bench_measurements().print_stats();
}

fn main() {
    benchmark_1();
    benchmark_map();
}
