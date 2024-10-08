use std::{
    net::{Ipv4Addr, SocketAddr},
    ops::DerefMut,
    sync::Arc,
};

use anyhow::{Context, Result};
use aranya_crypto::Rng;
use quic_syncer::{run_syncer, Syncer};
use quinn::{Endpoint, ServerConfig};
use runtime::{
    protocol::{TestActions, TestEffect, TestEngine, TestSink},
    storage::memory::MemStorageProvider,
    ClientState, SyncRequester,
};
use rustls::{Certificate, PrivateKey};
use tokio::sync::Mutex as TMutex;

type Client = Arc<TMutex<ClientState<TestEngine, MemStorageProvider>>>;

#[test_log::test(tokio::test)]
async fn test_sync() -> Result<()> {
    let client1 = make_client();
    let mut sink1 = TestSink::new();

    let client2 = make_client();
    let mut sink2 = TestSink::new();

    let storage_id =
        client1
            .lock()
            .await
            .new_graph(&0u64.to_be_bytes(), TestActions::Init(0), &mut sink1)?;

    let (key, cert) = certs()?;

    let addr1 = spawn_syncer(client1.clone(), key, cert.clone())?;

    for i in 0..6 {
        let action = TestActions::SetValue(i, i);
        sink1.add_expectation(TestEffect::Got(i));
        client1
            .lock()
            .await
            .action(storage_id, &mut sink1, action)?;
    }
    assert_eq!(sink1.count(), 0);

    for i in 0..6 {
        sink2.add_expectation(TestEffect::Got(i));
    }
    let mut syncer2 = Syncer::new(&[cert])?;
    syncer2
        .sync(
            client2.lock().await.deref_mut(),
            SyncRequester::new(storage_id, &mut Rng),
            &mut sink2,
            storage_id,
            addr1,
        )
        .await?;
    assert_eq!(sink2.count(), 0);

    Ok(())
}

fn spawn_syncer(client: Client, key: PrivateKey, cert: Certificate) -> Result<SocketAddr> {
    let mut server_config = ServerConfig::with_single_cert(vec![cert], key)?;
    let transport_config =
        Arc::get_mut(&mut server_config.transport).context("unique transport")?;
    transport_config.max_concurrent_uni_streams(0_u8.into());
    let endpoint = Endpoint::server(
        server_config,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
    )?;
    let addr = endpoint.local_addr()?;
    tokio::spawn(run_syncer(client, endpoint));
    Ok(addr)
}

fn certs() -> Result<(PrivateKey, Certificate)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    Ok((
        PrivateKey(cert.serialize_private_key_der()),
        Certificate(cert.serialize_der()?),
    ))
}

fn make_client() -> Arc<TMutex<ClientState<TestEngine, MemStorageProvider>>> {
    let engine = TestEngine::new();
    let storage = MemStorageProvider::new();

    Arc::new(TMutex::new(ClientState::new(engine, storage)))
}
