use std::{net::SocketAddr, ops::DerefMut, sync::Arc, time::Duration};

use anyhow::Result;
use aranya_quic_channels::{run_channels, AqcClient};
use aranya_runtime::{
    protocol::{TestActions, TestEngine, TestSink},
    storage::memory::MemStorageProvider,
    ClientState,
};
use bytes::Bytes;
use s2n_quic::{provider::congestion_controller::Bbr, Server};
use tokio::sync::Mutex as TMutex;

#[test_log::test(tokio::test)]
async fn test_channels() -> Result<()> {
    let client1 = make_client();
    let sink1 = Arc::new(TMutex::new(TestSink::new()));
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = cert.serialize_private_key_pem();
    let cert = cert.serialize_pem()?;

    let server1 = get_server(cert.clone(), key.clone())?;
    let aqc_client1 = Arc::new(TMutex::new(AqcClient::new(&*cert.clone())?));

    let _client2 = make_client();

    let _ = client1.lock().await.new_graph(
        &0u64.to_be_bytes(),
        TestActions::Init(0),
        sink1.lock().await.deref_mut(),
    )?;

    let _ = spawn_channel_listener(aqc_client1.clone(), server1)?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server2 = get_server(cert.clone(), key)?;
    let aqc_client2 = Arc::new(TMutex::new(AqcClient::new(&*cert)?));
    let addr2 = spawn_channel_listener(aqc_client2.clone(), server2)?;
    let mut channel1 = aqc_client1.lock().await.create_channel(addr2).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    if let Some(mut channel2) = aqc_client2.lock().await.receive_channel() {
        // Test sending streams
        channel1.send_stream(&Bytes::from("hello")).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut target = vec![0u8; 1024 * 1024];
        if let Some(len) = channel2.recv_stream(target.as_mut_slice()).await {
            assert_eq!(&target[..len], b"hello");
        } else {
            panic!("no data received");
        }
        channel2.send_stream(&Bytes::from("hello2")).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some(len) = channel1.recv_stream(target.as_mut_slice()).await {
            assert_eq!(&target[..len], b"hello2");
        } else {
            panic!("no data received");
        }

        // Test sending messages
        channel1.send_message(&Bytes::from("message1")).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some(len) = channel2.recv_message(target.as_mut_slice()).await {
            assert_eq!(&target[..len], b"message1");
        } else {
            panic!("no data received");
        }
        channel2.send_stream(&Bytes::from("message2")).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some(len) = channel1.recv_stream(target.as_mut_slice()).await {
            assert_eq!(&target[..len], b"message2");
        } else {
            panic!("no data received");
        }
    } else {
        panic!("channel is not available");
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
    server: Server,
) -> Result<SocketAddr> {
    let server_addr = server.local_addr()?;
    tokio::spawn(run_channels(aqc_client, server));
    Ok(server_addr)
}

fn make_client() -> Arc<TMutex<ClientState<TestEngine, MemStorageProvider>>> {
    let engine = TestEngine::new();
    let storage = MemStorageProvider::new();

    Arc::new(TMutex::new(ClientState::new(engine, storage)))
}
