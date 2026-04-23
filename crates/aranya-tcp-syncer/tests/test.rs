use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener},
    ops::DerefMut as _,
    sync::{Arc, Mutex, mpsc},
    thread::sleep,
    time::Duration,
};

use anyhow::Result;
use aranya_crypto::Rng;
use aranya_runtime::{
    ClientState, GraphId, SyncRequester,
    policy::{PolicyStore, Sink},
    storage::{StorageProvider, linear::testing::MemStorageProvider},
    testing::protocol::{TestActions, TestEffect, TestPolicyStore, TestSink},
};
use aranya_tcp_syncer::{Syncer, run_syncer};
use buggy::BugExt as _;
use test_log::test;

#[test]
fn test_sync() -> Result<()> {
    let client1 = make_client();
    let sink1 = Arc::new(Mutex::new(TestSink::new()));
    let (tx, rx) = mpsc::channel();
    let server_addr1 = get_server()?;
    let syncer1 = Arc::new(Mutex::new(Syncer::new(
        Arc::clone(&client1),
        Arc::clone(&sink1),
        tx,
        server_addr1.local_addr()?,
        &std::env::temp_dir(),
    )?));

    let client2 = make_client();
    let sink2 = Arc::new(Mutex::new(TestSink::new()));

    let graph_id = client1.lock().unwrap().new_graph(
        &0u64.to_be_bytes(),
        TestActions::Init(0),
        sink1.lock().unwrap().deref_mut(),
    )?;

    let addr1 = spawn_syncer(Arc::clone(&syncer1), rx, server_addr1)?;
    sleep(Duration::from_millis(100));
    syncer1.lock().unwrap().push(graph_id)?;

    for i in 0..6 {
        let action = TestActions::SetValue(i, i);
        sink1.lock().unwrap().add_expectation(TestEffect::Got(i));
        client1
            .lock()
            .unwrap()
            .action(graph_id, sink1.lock().unwrap().deref_mut(), action)?;
    }
    assert_eq!(sink1.lock().unwrap().count(), 0);

    for i in 0..6 {
        sink2.lock().unwrap().add_expectation(TestEffect::Got(i));
    }
    let (tx, _) = mpsc::channel();
    let server_addr2 = get_server()?;
    let mut syncer2 = Syncer::new(
        Arc::clone(&client2),
        Arc::clone(&sink2),
        tx,
        server_addr2.local_addr()?,
        &std::env::temp_dir(),
    )?;
    syncer2.sync(
        client2.lock().unwrap().deref_mut(),
        addr1,
        SyncRequester::new(graph_id, Rng),
        sink2.lock().unwrap().deref_mut(),
        graph_id,
    )?;
    assert_eq!(sink2.lock().unwrap().count(), 0);

    Ok(())
}

#[test]
fn test_sync_subscribe() -> Result<()> {
    let client1 = make_client();
    let sink1 = Arc::new(Mutex::new(TestSink::new()));
    let (tx1, rx1) = mpsc::channel();
    let server_addr1 = get_server()?;
    let syncer1 = Arc::new(Mutex::new(Syncer::new(
        Arc::clone(&client1),
        Arc::clone(&sink1),
        tx1,
        server_addr1.local_addr()?,
        &std::env::temp_dir(),
    )?));

    let client2 = make_client();
    let sink2 = Arc::new(Mutex::new(TestSink::new()));
    let (tx2, rx2) = mpsc::channel();
    let server_addr2 = get_server()?;
    let syncer2 = Arc::new(Mutex::new(Syncer::new(
        Arc::clone(&client2),
        Arc::clone(&sink2),
        tx2,
        server_addr2.local_addr()?,
        &std::env::temp_dir(),
    )?));

    let graph_id = client1.lock().unwrap().new_graph(
        &0u64.to_be_bytes(),
        TestActions::Init(0),
        sink1.lock().unwrap().deref_mut(),
    )?;

    let addr1 = spawn_syncer(Arc::clone(&syncer1), rx1, server_addr1)?;
    let addr2 = spawn_syncer(Arc::clone(&syncer2), rx2, server_addr2)?;

    for i in 0..6 {
        sink2.lock().unwrap().add_expectation(TestEffect::Got(i));
    }
    syncer1.lock().unwrap().subscribe(
        client1.lock().unwrap().deref_mut(),
        SyncRequester::new(graph_id, Rng),
        5,
        u64::MAX,
        addr2,
    )?;
    syncer2.lock().unwrap().subscribe(
        client2.lock().unwrap().deref_mut(),
        SyncRequester::new(graph_id, Rng),
        5,
        u64::MAX,
        addr1,
    )?;

    for i in 0..6 {
        let action = TestActions::SetValue(i, i);
        sink1.lock().unwrap().add_expectation(TestEffect::Got(i));
        client1
            .lock()
            .unwrap()
            .action(graph_id, sink1.lock().unwrap().deref_mut(), action)?;
        syncer1.lock().unwrap().push(graph_id)?;
    }

    // All of the actions should be pushed to client2.
    sleep(Duration::from_millis(100));
    assert_eq!(sink1.lock().unwrap().count(), 0);
    assert_eq!(sink2.lock().unwrap().count(), 0);

    syncer2.lock().unwrap().subscribe(
        client2.lock().unwrap().deref_mut(),
        SyncRequester::new(graph_id, Rng),
        1,
        u64::MAX,
        addr1,
    )?;
    // The subscription should have expired after this.
    sleep(Duration::from_millis(1000));

    let mut value = 7;
    let action = TestActions::SetValue(value, value);
    sink1
        .lock()
        .unwrap()
        .add_expectation(TestEffect::Got(value));
    client1
        .lock()
        .unwrap()
        .action(graph_id, sink1.lock().unwrap().deref_mut(), action)?;
    syncer1.lock().unwrap().push(graph_id)?;
    sink2
        .lock()
        .unwrap()
        .add_expectation(TestEffect::Got(value));

    sleep(Duration::from_millis(100));
    assert_eq!(sink1.lock().unwrap().count(), 0);

    // Sink 2 should not receive the push because the subscription expired.
    assert_eq!(sink2.lock().unwrap().count(), 1);

    syncer2.lock().unwrap().subscribe(
        client2.lock().unwrap().deref_mut(),
        SyncRequester::new(graph_id, Rng),
        5,
        286, // The exact number of bytes to be sent
        addr1,
    )?;

    value = value.checked_add(1).assume("must not overflow")?;
    let action = TestActions::SetValue(value, value);
    sink1
        .lock()
        .unwrap()
        .add_expectation(TestEffect::Got(value));
    client1
        .lock()
        .unwrap()
        .action(graph_id, sink1.lock().unwrap().deref_mut(), action)?;
    syncer1.lock().unwrap().push(graph_id)?;
    sink2
        .lock()
        .unwrap()
        .add_expectation(TestEffect::Got(value));

    sleep(Duration::from_millis(100));
    assert_eq!(sink1.lock().unwrap().count(), 0);
    assert_eq!(sink2.lock().unwrap().count(), 0);

    value = value.checked_add(1).assume("must not overflow")?;
    let action = TestActions::SetValue(value, value);
    sink1
        .lock()
        .unwrap()
        .add_expectation(TestEffect::Got(value));
    client1
        .lock()
        .unwrap()
        .action(graph_id, sink1.lock().unwrap().deref_mut(), action)?;
    syncer1.lock().unwrap().push(graph_id)?;
    sink2
        .lock()
        .unwrap()
        .add_expectation(TestEffect::Got(value));

    sleep(Duration::from_millis(100));
    assert_eq!(sink1.lock().unwrap().count(), 0);

    // Sink 2 should not receive the push because there are not enough
    // remaining bytes to send it.
    assert_eq!(sink2.lock().unwrap().count(), 1);

    syncer2.lock().unwrap().subscribe(
        client2.lock().unwrap().deref_mut(),
        SyncRequester::new(graph_id, Rng),
        1,
        u64::MAX,
        addr1,
    )?;
    syncer2
        .lock()
        .unwrap()
        .unsubscribe(SyncRequester::new(graph_id, Rng), addr1)?;
    sleep(Duration::from_millis(100));

    value = value.checked_add(1).assume("must not overflow")?;
    let action = TestActions::SetValue(value, value);
    sink1
        .lock()
        .unwrap()
        .add_expectation(TestEffect::Got(value));
    client1
        .lock()
        .unwrap()
        .action(graph_id, sink1.lock().unwrap().deref_mut(), action)?;
    syncer1.lock().unwrap().push(graph_id)?;
    sink2
        .lock()
        .unwrap()
        .add_expectation(TestEffect::Got(value));

    sleep(Duration::from_millis(100));
    assert_eq!(sink1.lock().unwrap().count(), 0);

    // Sink 2 should not receive the push because the client unsubscribed.
    assert_eq!(sink2.lock().unwrap().count(), 2);

    Ok(())
}

fn get_server() -> Result<TcpListener> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?)
}

fn spawn_syncer<PS, SP, S>(
    syncer: Arc<Mutex<Syncer<PS, SP, S>>>,
    receiver: mpsc::Receiver<GraphId>,
    server: TcpListener,
) -> Result<SocketAddr>
where
    PS: PolicyStore + Send + 'static,
    SP: StorageProvider + Send + 'static,
    S: Sink<<PS as PolicyStore>::Effect> + Send + 'static,
    <SP as StorageProvider>::Perspective: Send,
{
    let server_addr = server.local_addr()?;
    std::thread::spawn(|| run_syncer(syncer, server, receiver));
    Ok(server_addr)
}

fn make_client() -> Arc<Mutex<ClientState<TestPolicyStore, MemStorageProvider>>> {
    let engine = TestPolicyStore::new();
    let storage = MemStorageProvider::default();

    Arc::new(Mutex::new(ClientState::new(engine, storage)))
}
