use std::{net::SocketAddr, ops::DerefMut, sync::Arc, time::Duration};

use anyhow::Result;
use aranya_quic_channels::{run_channels, AqcChannel, AqcClient};
use aranya_runtime::{
    protocol::{TestActions, TestEngine, TestSink},
    storage::memory::MemStorageProvider,
    ClientState,
};
use bytes::Bytes;
use s2n_quic::{provider::congestion_controller::Bbr, Server};
use tokio::sync::{mpsc, Mutex as TMutex};

#[test_log::test(tokio::test)]
async fn test_channels() -> Result<()> {
    let client1 = make_client();
    let sink1 = Arc::new(TMutex::new(TestSink::new()));
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = cert.serialize_private_key_pem();
    let cert = cert.serialize_pem()?;
    let (tx, rx) = mpsc::channel(1);
    let sender1 = Arc::new(TMutex::new(tx));

    let server1 = get_server(cert.clone(), key.clone())?;
    let aqc_client1 = Arc::new(TMutex::new(AqcClient::new(
        &*cert.clone(),
        rx,
        sender1.clone(),
    )?));

    let _client2 = make_client();

    let _ = client1.lock().await.new_graph(
        &0u64.to_be_bytes(),
        TestActions::Init(0),
        sink1.lock().await.deref_mut(),
    )?;

    let _ = spawn_channel_listener(aqc_client1.clone(), sender1, server1)?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (tx, rx) = mpsc::channel(1);
    let sender2 = Arc::new(TMutex::new(tx));
    let server2 = get_server(cert.clone(), key)?;
    let aqc_client2 = Arc::new(TMutex::new(AqcClient::new(&*cert, rx, sender2.clone())?));
    let addr2 = spawn_channel_listener(aqc_client2.clone(), sender2, server2)?;
    let channel1 = aqc_client1.lock().await.create_channel(addr2).await?;
    aqc_client1
        .lock()
        .await
        .send_data_stream(channel1, &Bytes::from("hello"))
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut target = vec![0u8; 1024 * 1024];
    if let Some((channel, len)) = aqc_client2.lock().await.receive_data_stream(&mut target)? {
        assert_eq!(channel, channel1);
        assert_eq!(&target[..len], b"hello");
    } else {
        panic!("no data received");
    }
    aqc_client2
        .lock()
        .await
        .send_data_stream(channel1, &Bytes::from("hello2"))
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut target = vec![0u8; 1024 * 1024];
    if let Some((channel, len)) = aqc_client1.lock().await.receive_data_stream(&mut target)? {
        assert_eq!(channel, channel1);
        assert_eq!(&target[..len], b"hello2");
    } else {
        panic!("no data received");
    }
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

fn spawn_channel_listener(
    aqc_client: Arc<TMutex<AqcClient>>,
    sender: Arc<TMutex<mpsc::Sender<(AqcChannel, Bytes)>>>,
    server: Server,
) -> Result<SocketAddr> {
    let server_addr = server.local_addr()?;
    tokio::spawn(run_channels(aqc_client, server, sender));
    Ok(server_addr)
}

fn make_client() -> Arc<TMutex<ClientState<TestEngine, MemStorageProvider>>> {
    let engine = TestEngine::new();
    let storage = MemStorageProvider::new();

    Arc::new(TMutex::new(ClientState::new(engine, storage)))
}
