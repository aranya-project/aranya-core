#[cfg(feature = "bench")]
#[test]
fn benchmark_1() {
    use aranya_policy_compiler::Compiler;
    use aranya_policy_lang::lang::parse_policy_document;
    use aranya_policy_vm::{bench_measurements, ffi::FfiModule};
    use aranya_runtime::{
        memory::MemStorageProvider,
        testing::vm::{TestEngine, TestSink, TEST_POLICY_1},
        vm_action, vm_effect,
        vm_policy::testing::TestFfiEnvelope,
        ClientState,
    };

    let policy = parse_policy_document(TEST_POLICY_1).unwrap();
    let module = Compiler::new(&policy)
        .ffi_modules(&[TestFfiEnvelope::SCHEMA])
        .compile()
        .unwrap();
    let engine = TestEngine::from_module(module);
    let provider = MemStorageProvider::new();
    let mut cs = ClientState::new(engine, provider);

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

#[cfg(feature = "bench")]
#[test]
fn benchmark_map() {
    let test = r#"---
policy-version: 1
---
```policy
        use envelope
        fact F[i int]=>{ value string }

        command Init {
            seal { return envelope::seal(serialize(this)) }
            open { return deserialize(envelope::open(envelope)) }
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
            seal { return envelope::seal(serialize(this)) }
            open { return deserialize(envelope::open(envelope)) }
            policy {
                finish {
                    create F[i: this.i]=>{value: this.value}
                }
            }
        }

        action run() {
            // TODO can't publish multiple commands form one action (#883). But we must publish something.
            publish DoSomething {}

            map F[i:?] as f {                
                //publish DoSomething { f: f }
            }
        }

        command DoSomething {
            // fields { f struct F }
            seal { return envelope::seal(serialize(this)) }
            open { return deserialize(envelope::open(envelope)) }
            policy {
                finish {
                    // TODO(apetkov) uncomment after #883 has been merged
                    // update F[i:this.f.i]=>{ value:? } to { value:"updated" }
                }
            }
        }
```
    "#;

    use aranya_policy_compiler::Compiler;
    use aranya_policy_lang::lang::parse_policy_document;
    use aranya_policy_vm::{bench_measurements, ffi::FfiModule};
    use aranya_runtime::{
        memory::MemStorageProvider,
        testing::vm::{TestEngine, TestSink},
        vm_action,
        vm_policy::testing::TestFfiEnvelope,
        ClientState,
    };

    let policy = parse_policy_document(test).unwrap();
    let module = Compiler::new(&policy)
        .ffi_modules(&[TestFfiEnvelope::SCHEMA])
        .compile()
        .unwrap();
    let engine = TestEngine::from_module(module);
    let provider = MemStorageProvider::new();
    let mut cs = ClientState::new(engine, provider);

    let mut sink = TestSink::new();
    let storage_id = cs
        .new_graph(&[0u8], vm_action!(init()), &mut sink)
        .expect("could not create graph");

    for i in 1..10 {
        cs.action(storage_id, &mut sink, vm_action!(insert(i, i.to_string())))
            .unwrap();
    }
    cs.action(storage_id, &mut sink, vm_action!(run()))
        .expect("could not call action");

    bench_measurements().print_stats();
}
