#![cfg(test)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_possible_wrap)]

use aranya_crypto::{CmdId, Rng};
use rand::{Rng as _, prelude::*};
use test_log::test;

use crate::{
    Address, ClientState, Command as _, GraphId, MAX_SYNC_MESSAGE_SIZE, NullSink, PeerCache,
    StorageProvider as _, SyncRequester, SyncResponder, SyncType,
    storage::{Storage as _, memory::MemStorageProvider},
    testing::protocol::{TestActions, TestEngine, TestPolicy, TestProtocol},
};

#[test]
fn test_large_sync() {
    let mut response_cache = PeerCache::new();
    let mut request_cache = PeerCache::new();

    let mut client = ClientState::new(TestEngine::new(), MemStorageProvider::new());

    let graph_id = client
        .new_graph(&[0], TestActions::Init(0), &mut NullSink)
        .unwrap();

    let mut other = ClientState::new(TestEngine::new(), MemStorageProvider::new());
    sync(
        graph_id,
        &mut client,
        &mut other,
        &mut response_cache,
        &mut request_cache,
    );

    let mut trx = client.transaction(graph_id);

    let mut seen = vec![Address {
        id: CmdId::transmute(graph_id),
        max_cut: 0,
    }];
    let mut rng = thread_rng();
    let mut fuel = 100_000i32;
    while fuel > 0 {
        eprintln!("fuel = {fuel}");
        // choose starting point
        let start = *seen.choose(&mut rng).unwrap();

        // choose segment length
        let len = rng.gen_range(1..=201);

        fuel -= len as i32;

        let mut data = vec![0u8; 201 * 100];
        let mut commands: Vec<TestProtocol<'_>> = Vec::with_capacity(len);
        let mut prev = start;
        for target in data.chunks_exact_mut(100).take(len) {
            let payload = rng.r#gen();
            let cmd = TestPolicy::new(0).basic(target, prev, payload).unwrap();
            prev.id = cmd.id();
            prev.max_cut += 1;
            commands.push(cmd);
            seen.push(prev);
        }
        client
            .add_commands(&mut trx, &mut NullSink, commands)
            .unwrap();
    }

    dbg!(seen.len());

    client.commit(&mut trx, &mut NullSink).unwrap();
    eprintln!(
        "#segments = {}, expected around {}",
        client
            .provider()
            .get_storage(graph_id)
            .unwrap()
            .get_head()
            .unwrap()
            .segment,
        seen.len() / 100 * 2
    );

    while {
        let s1 = client.provider().get_storage(graph_id).unwrap();
        let s2 = other.provider().get_storage(graph_id).unwrap();
        s1.get_command_address(s1.get_head().unwrap()).unwrap()
            != s2.get_command_address(s2.get_head().unwrap()).unwrap()
    } {
        let x = sync(
            graph_id,
            &mut client,
            &mut other,
            &mut response_cache,
            &mut request_cache,
        );
        let y = sync(
            graph_id,
            &mut other,
            &mut client,
            &mut request_cache,
            &mut response_cache,
        );
        assert!(x > 0 || y > 0);
    }
}

type Client = ClientState<TestEngine, MemStorageProvider>;

fn sync(
    graph_id: GraphId,
    response_state: &mut Client,
    request_state: &mut Client,
    response_cache: &mut PeerCache,
    request_cache: &mut PeerCache,
) -> usize {
    let mut added = 0;
    let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
    let mut target = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

    let mut request_trx = request_state.transaction(graph_id);

    let mut request_syncer = SyncRequester::new(graph_id, &mut Rng::new(), ());
    assert!(request_syncer.ready());

    let (len, _) = request_syncer
        .poll(&mut buffer, request_state.provider(), request_cache)
        .unwrap();

    let mut response_syncer = SyncResponder::new(());
    let SyncType::Poll {
        request,
        address: (),
    } = postcard::from_bytes(&buffer[..len]).unwrap()
    else {
        panic!();
    };
    response_syncer.receive(request).unwrap();
    assert!(response_syncer.ready());

    loop {
        let len = response_syncer
            .poll(&mut target, response_state.provider(), response_cache)
            .unwrap();
        if len == 0 {
            break;
        }

        if let Some(cmds) = request_syncer.receive(&target[..len]).unwrap() {
            tracing::info!("synced {} commands", cmds.len());
            added += request_state
                .add_commands(&mut request_trx, &mut NullSink, cmds)
                .unwrap();
        } else {
            break;
        }
    }

    eprintln!("committing sync");
    request_state
        .commit(&mut request_trx, &mut NullSink)
        .unwrap();

    added
}
