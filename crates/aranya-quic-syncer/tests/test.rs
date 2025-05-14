use std::{net::SocketAddr, ops::DerefMut, sync::Arc, time::Duration};

use anyhow::Result;
use aranya_crypto::Rng;
use aranya_quic_syncer::{run_syncer, Syncer};
use aranya_runtime::{
    engine::{Engine, Sink},
    protocol::{TestActions, TestEffect, TestEngine, TestSink},
    storage::{memory::MemStorageProvider, StorageProvider},
    ClientState, GraphId, SyncRequester,
};
use buggy::BugExt;
use s2n_quic::{provider::congestion_controller::Bbr, Server};
use tokio::sync::{mpsc, Mutex as TMutex};

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
        client1.clone(),
        sink1.clone(),
        tx,
        server_addr1.local_addr()?,
    )?));

    let client2 = make_client();
    let sink2 = Arc::new(TMutex::new(TestSink::new()));

    let storage_id = client1.lock().await.new_graph(
        &0u64.to_be_bytes(),
        TestActions::Init(0),
        sink1.lock().await.deref_mut(),
    )?;

    let addr1 = spawn_syncer(syncer1.clone(), rx, server_addr1)?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    syncer1.lock().await.push(storage_id)?;

    for i in 0..6 {
        let action = TestActions::SetValue(i, i);
        sink1.lock().await.add_expectation(TestEffect::Got(i));
        client1
            .lock()
            .await
            .action(storage_id, sink1.lock().await.deref_mut(), action)?;
    }
    assert_eq!(sink1.lock().await.count(), 0);

    for i in 0..6 {
        sink2.lock().await.add_expectation(TestEffect::Got(i));
    }
    let (tx, _) = mpsc::unbounded_channel();
    let server_addr2 = get_server(cert.clone(), key)?;
    let mut syncer2 = Syncer::new(
        &*cert,
        client2.clone(),
        sink2.clone(),
        tx,
        server_addr2.local_addr()?,
    )?;
    syncer2
        .sync(
            client2.lock().await.deref_mut(),
            SyncRequester::new(storage_id, &mut Rng, addr1),
            sink2.lock().await.deref_mut(),
            storage_id,
        )
        .await?;
    assert_eq!(sink2.lock().await.count(), 0);

    Ok(())
}

#[test_log::test(tokio::test)]
#[ignore = "TODO(jdygert): why failing"]
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
        client1.clone(),
        sink1.clone(),
        tx1,
        server_addr1.local_addr()?,
    )?));

    let client2 = make_client();
    let sink2 = Arc::new(TMutex::new(TestSink::new()));
    let (tx2, rx2) = mpsc::unbounded_channel();
    let server_addr2 = get_server(cert.clone(), key.clone())?;
    let syncer2 = Arc::new(TMutex::new(Syncer::new(
        &*cert,
        client2.clone(),
        sink2.clone(),
        tx2,
        server_addr2.local_addr()?,
    )?));

    let storage_id = client1.lock().await.new_graph(
        &0u64.to_be_bytes(),
        TestActions::Init(0),
        sink1.lock().await.deref_mut(),
    )?;

    let addr1 = spawn_syncer(syncer1.clone(), rx1, server_addr1)?;
    let addr2 = spawn_syncer(syncer2.clone(), rx2, server_addr2)?;

    for i in 0..6 {
        sink2.lock().await.add_expectation(TestEffect::Got(i));
    }
    syncer1
        .lock()
        .await
        .subscribe(
            client1.lock().await.deref_mut(),
            SyncRequester::new(storage_id, &mut Rng, addr1),
            5,
            u64::MAX,
            addr2,
        )
        .await?;
    syncer2
        .lock()
        .await
        .subscribe(
            client2.lock().await.deref_mut(),
            SyncRequester::new(storage_id, &mut Rng, addr2),
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
            .action(storage_id, sink1.lock().await.deref_mut(), action)?;
        syncer1.lock().await.push(storage_id)?;
    }

    // All of the actions should be pushed to client2.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(sink1.lock().await.count(), 0);
    assert_eq!(sink2.lock().await.count(), 0);

    syncer2
        .lock()
        .await
        .subscribe(
            client2.lock().await.deref_mut(),
            SyncRequester::new(storage_id, &mut Rng, addr2),
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
        .action(storage_id, sink1.lock().await.deref_mut(), action)?;
    syncer1.lock().await.push(storage_id)?;
    sink2.lock().await.add_expectation(TestEffect::Got(value));

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(sink1.lock().await.count(), 0);

    // Sink 2 should not receive the push because the subscription expired.
    assert_eq!(sink2.lock().await.count(), 1);

    syncer2
        .lock()
        .await
        .subscribe(
            client2.lock().await.deref_mut(),
            SyncRequester::new(storage_id, &mut Rng, addr2),
            5,
            279, // The exact number of bytes to be sent
            addr1,
        )
        .await?;

    value = value.checked_add(1).assume("must not overflow")?;
    let action = TestActions::SetValue(value, value);
    sink1.lock().await.add_expectation(TestEffect::Got(value));
    client1
        .lock()
        .await
        .action(storage_id, sink1.lock().await.deref_mut(), action)?;
    syncer1.lock().await.push(storage_id)?;
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
        .action(storage_id, sink1.lock().await.deref_mut(), action)?;
    syncer1.lock().await.push(storage_id)?;
    sink2.lock().await.add_expectation(TestEffect::Got(value));

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(sink1.lock().await.count(), 0);

    // Sink 2 should not receive the push because there are not enough
    // remaining bytes to send it.
    assert_eq!(sink2.lock().await.count(), 1);

    syncer2
        .lock()
        .await
        .subscribe(
            client2.lock().await.deref_mut(),
            SyncRequester::new(storage_id, &mut Rng, addr2),
            1,
            u64::MAX,
            addr1,
        )
        .await?;
    syncer2
        .lock()
        .await
        .unsubscribe(SyncRequester::new(storage_id, &mut Rng, addr2), addr1)
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    value = value.checked_add(1).assume("must not overflow")?;
    let action = TestActions::SetValue(value, value);
    sink1.lock().await.add_expectation(TestEffect::Got(value));
    client1
        .lock()
        .await
        .action(storage_id, sink1.lock().await.deref_mut(), action)?;
    syncer1.lock().await.push(storage_id)?;
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

fn spawn_syncer<EN, SP, S>(
    syncer: Arc<TMutex<Syncer<EN, SP, S>>>,
    receiver: mpsc::UnboundedReceiver<GraphId>,
    server: Server,
) -> Result<SocketAddr>
where
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + 'static,
    S: Sink<<EN as Engine>::Effect> + Send + 'static,
    <SP as StorageProvider>::Perspective: Send,
{
    let server_addr = server.local_addr()?;
    tokio::spawn(run_syncer(syncer, server, receiver));
    Ok(server_addr)
}

fn make_client() -> Arc<TMutex<ClientState<TestEngine, MemStorageProvider>>> {
    let engine = TestEngine::new();
    let storage = MemStorageProvider::new();

    Arc::new(TMutex::new(ClientState::new(engine, storage)))
}
