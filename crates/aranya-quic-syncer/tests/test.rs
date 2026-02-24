use std::{net::SocketAddr, ops::DerefMut as _, sync::Arc, time::Duration};

use anyhow::Result;
use aranya_crypto::Rng;
use aranya_quic_syncer::{Syncer, run_syncer};
use aranya_runtime::{
    ClientState, GraphId, SyncRequester, TraversalBuffers,
    policy::{PolicyStore, Sink},
    storage::{StorageProvider, linear::testing::MemStorageProvider},
    testing::protocol::{TestActions, TestEffect, TestPolicyStore, TestSink},
};
use buggy::BugExt as _;
use s2n_quic::{Server, provider::congestion_controller::Bbr};
use tokio::sync::{Mutex as TMutex, mpsc};

#[test_log::test(tokio::test)]
async fn test_sync() -> Result<()> {
    let client1 = make_client();
    let sink1 = Arc::new(TMutex::new(TestSink::new()));
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = ck.key_pair.serialize_pem();
    let cert = ck.cert.pem();
    let (tx, rx) = mpsc::unbounded_channel();
    let server_addr1 = get_server(cert.clone(), key.clone())?;
    let syncer1 = Arc::new(TMutex::new(Syncer::new(
        &*cert.clone(),
        Arc::clone(&client1),
        Arc::clone(&sink1),
        tx,
        server_addr1.local_addr()?,
    )?));

    let client2 = make_client();
    let sink2 = Arc::new(TMutex::new(TestSink::new()));

    let graph_id = client1.lock().await.new_graph(
        &0u64.to_be_bytes(),
        TestActions::Init(0),
        sink1.lock().await.deref_mut(),
    )?;

    let addr1 = spawn_syncer(Arc::clone(&syncer1), rx, server_addr1)?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    syncer1.lock().await.push(graph_id)?;

    for i in 0..6 {
        let action = TestActions::SetValue(i, i);
        sink1.lock().await.add_expectation(TestEffect::Got(i));
        client1
            .lock()
            .await
            .action(graph_id, sink1.lock().await.deref_mut(), action)?;
    }
    assert_eq!(sink1.lock().await.count(), 0);

    for i in 0..6 {
        sink2.lock().await.add_expectation(TestEffect::Got(i));
    }
    let (tx, _) = mpsc::unbounded_channel();
    let server_addr2 = get_server(cert.clone(), key)?;
    let mut syncer2 = Syncer::new(
        &*cert,
        Arc::clone(&client2),
        Arc::clone(&sink2),
        tx,
        server_addr2.local_addr()?,
    )?;
    let mut buffers = TraversalBuffers::new();
    syncer2
        .sync(
            client2.lock().await.deref_mut(),
            addr1,
            SyncRequester::new(graph_id, Rng, &mut buffers),
            sink2.lock().await.deref_mut(),
            graph_id,
        )
        .await?;
    assert_eq!(sink2.lock().await.count(), 0);

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_sync_subscribe() -> Result<()> {
    let client1 = make_client();
    let sink1 = Arc::new(TMutex::new(TestSink::new()));
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = ck.key_pair.serialize_pem();
    let cert = ck.cert.pem();
    let (tx1, rx1) = mpsc::unbounded_channel();
    let server_addr1 = get_server(cert.clone(), key.clone())?;
    let syncer1 = Arc::new(TMutex::new(Syncer::new(
        &*cert.clone(),
        Arc::clone(&client1),
        Arc::clone(&sink1),
        tx1,
        server_addr1.local_addr()?,
    )?));

    let client2 = make_client();
    let sink2 = Arc::new(TMutex::new(TestSink::new()));
    let (tx2, rx2) = mpsc::unbounded_channel();
    let server_addr2 = get_server(cert.clone(), key.clone())?;
    let syncer2 = Arc::new(TMutex::new(Syncer::new(
        &*cert,
        Arc::clone(&client2),
        Arc::clone(&sink2),
        tx2,
        server_addr2.local_addr()?,
    )?));

    let graph_id = client1.lock().await.new_graph(
        &0u64.to_be_bytes(),
        TestActions::Init(0),
        sink1.lock().await.deref_mut(),
    )?;

    let addr1 = spawn_syncer(Arc::clone(&syncer1), rx1, server_addr1)?;
    let addr2 = spawn_syncer(Arc::clone(&syncer2), rx2, server_addr2)?;

    for i in 0..6 {
        sink2.lock().await.add_expectation(TestEffect::Got(i));
    }
    let mut buffers = TraversalBuffers::new();
    syncer1
        .lock()
        .await
        .subscribe(
            client1.lock().await.deref_mut(),
            SyncRequester::new(graph_id, Rng, &mut buffers),
            5,
            u64::MAX,
            addr2,
        )
        .await?;
    let mut buffers = TraversalBuffers::new();
    syncer2
        .lock()
        .await
        .subscribe(
            client2.lock().await.deref_mut(),
            SyncRequester::new(graph_id, Rng, &mut buffers),
            5,
            u64::MAX,
            addr1,
        )
        .await?;

    for i in 0..6 {
        let action = TestActions::SetValue(i, i);
        sink1.lock().await.add_expectation(TestEffect::Got(i));
        client1
            .lock()
            .await
            .action(graph_id, sink1.lock().await.deref_mut(), action)?;
        syncer1.lock().await.push(graph_id)?;
    }

    // All of the actions should be pushed to client2.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(sink1.lock().await.count(), 0);
    assert_eq!(sink2.lock().await.count(), 0);

    let mut buffers = TraversalBuffers::new();
    syncer2
        .lock()
        .await
        .subscribe(
            client2.lock().await.deref_mut(),
            SyncRequester::new(graph_id, Rng, &mut buffers),
            1,
            u64::MAX,
            addr1,
        )
        .await?;
    // The subscription should have expired after this.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let mut value = 7;
    let action = TestActions::SetValue(value, value);
    sink1.lock().await.add_expectation(TestEffect::Got(value));
    client1
        .lock()
        .await
        .action(graph_id, sink1.lock().await.deref_mut(), action)?;
    syncer1.lock().await.push(graph_id)?;
    sink2.lock().await.add_expectation(TestEffect::Got(value));

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(sink1.lock().await.count(), 0);

    // Sink 2 should not receive the push because the subscription expired.
    assert_eq!(sink2.lock().await.count(), 1);

    let mut buffers = TraversalBuffers::new();
    syncer2
        .lock()
        .await
        .subscribe(
            client2.lock().await.deref_mut(),
            SyncRequester::new(graph_id, Rng, &mut buffers),
            5,
            286, // The exact number of bytes to be sent
            addr1,
        )
        .await?;

    value = value.checked_add(1).assume("must not overflow")?;
    let action = TestActions::SetValue(value, value);
    sink1.lock().await.add_expectation(TestEffect::Got(value));
    client1
        .lock()
        .await
        .action(graph_id, sink1.lock().await.deref_mut(), action)?;
    syncer1.lock().await.push(graph_id)?;
    sink2.lock().await.add_expectation(TestEffect::Got(value));

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(sink1.lock().await.count(), 0);
    assert_eq!(sink2.lock().await.count(), 0);

    value = value.checked_add(1).assume("must not overflow")?;
    let action = TestActions::SetValue(value, value);
    sink1.lock().await.add_expectation(TestEffect::Got(value));
    client1
        .lock()
        .await
        .action(graph_id, sink1.lock().await.deref_mut(), action)?;
    syncer1.lock().await.push(graph_id)?;
    sink2.lock().await.add_expectation(TestEffect::Got(value));

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(sink1.lock().await.count(), 0);

    // Sink 2 should not receive the push because there are not enough
    // remaining bytes to send it.
    assert_eq!(sink2.lock().await.count(), 1);

    let mut buffers = TraversalBuffers::new();
    syncer2
        .lock()
        .await
        .subscribe(
            client2.lock().await.deref_mut(),
            SyncRequester::new(graph_id, Rng, &mut buffers),
            1,
            u64::MAX,
            addr1,
        )
        .await?;
    let mut buffers = TraversalBuffers::new();
    syncer2
        .lock()
        .await
        .unsubscribe(SyncRequester::new(graph_id, Rng, &mut buffers), addr1)
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    value = value.checked_add(1).assume("must not overflow")?;
    let action = TestActions::SetValue(value, value);
    sink1.lock().await.add_expectation(TestEffect::Got(value));
    client1
        .lock()
        .await
        .action(graph_id, sink1.lock().await.deref_mut(), action)?;
    syncer1.lock().await.push(graph_id)?;
    sink2.lock().await.add_expectation(TestEffect::Got(value));

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(sink1.lock().await.count(), 0);

    // Sink 2 should not receive the push because the client unsubscribed.
    assert_eq!(sink2.lock().await.count(), 2);

    Ok(())
}

fn get_server(cert: String, key: String) -> Result<Server> {
    let server = Server::builder()
        .with_tls((&cert[..], &key[..]))?
        .with_io("127.0.0.1:0")?
        .with_congestion_controller(Bbr::default())?
        .start()?;
    Ok(server)
}

fn spawn_syncer<PS, SP, S>(
    syncer: Arc<TMutex<Syncer<PS, SP, S>>>,
    receiver: mpsc::UnboundedReceiver<GraphId>,
    server: Server,
) -> Result<SocketAddr>
where
    PS: PolicyStore + Send + 'static,
    SP: StorageProvider + Send + 'static,
    S: Sink<<PS as PolicyStore>::Effect> + Send + 'static,
    <SP as StorageProvider>::Perspective: Send,
{
    let server_addr = server.local_addr()?;
    tokio::spawn(run_syncer(syncer, server, receiver));
    Ok(server_addr)
}

fn make_client() -> Arc<TMutex<ClientState<TestPolicyStore, MemStorageProvider>>> {
    let policy_store = TestPolicyStore::new();
    let storage = MemStorageProvider::default();

    Arc::new(TMutex::new(ClientState::new(policy_store, storage)))
}
