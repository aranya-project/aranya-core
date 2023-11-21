use alloc::vec::Vec as AVec;
use std::sync::{Arc, Mutex};

use quinn::ServerConfig;
use rustls::PrivateKey;
use tokio::{select, sync::Mutex as TMutex};
use tokio_util::sync::CancellationToken;

use crate::{
    command::Id,
    storage::memory::MemStorageProvider,
    sync::{self, SyncState},
    tests::protocol::{TestEffect, TestEngine, TestSink},
    ClientState, Sink, SyncError, SyncRequester, SyncResponder,
};

impl From<std::io::Error> for SyncError {
    fn from(_error: std::io::Error) -> Self {
        SyncError::InternalError
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_syncer(
    cancel_token: CancellationToken,
    client: Arc<TMutex<ClientState<TestEngine, MemStorageProvider>>>,
    storage_id: Id,
    cert_chain: AVec<rustls::Certificate>,
    priv_key: PrivateKey,
    id: u64,
    session_id: u128,
    sink: WrappedSink,
) -> Result<(), SyncError> {
    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
    let server_addr = format!("127.0.0.1:{}", 5000 + id).parse().unwrap();
    let endpoint = quinn::Endpoint::server(server_config, server_addr)?;
    let future = tokio::spawn(async move {
        while let Some(conn) = endpoint.accept().await {
            if let Err(e) =
                handle_connection(conn, client.clone(), session_id, storage_id, sink.clone()).await
            {
                println!("sync error: {:?}", e)
            }
        }
    });
    select! {
        _ = cancel_token.cancelled() => {
            // The token was cancelled
            println!("cancelled");
        },
        _ = future => {
            println!("listen completed");
        }
    };
    Ok(())
}

async fn handle_connection(
    conn: quinn::Connecting,
    client: Arc<TMutex<ClientState<TestEngine, MemStorageProvider>>>,
    session_id: u128,
    storage_id: Id,
    sink: WrappedSink,
) -> Result<(), SyncError> {
    let connection = conn.await?;
    let stream = connection.accept_bi().await;
    let stream = match stream {
        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
            println!("connection closed!");
            return Ok(());
        }
        Err(_e) => {
            println!("connection error");
            return Err(SyncError::NetworkError);
        }
        Ok(s) => s,
    };
    handle_request(stream, client, session_id, storage_id, sink).await?;
    Ok(())
}

async fn handle_request(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    client: Arc<TMutex<ClientState<TestEngine, MemStorageProvider>>>,
    session_id: u128,
    storage_id: Id,
    mut sink: WrappedSink,
) -> Result<(), SyncError> {
    let req = recv.read_to_end(sync::MAX_SYNC_MESSAGE_SIZE).await?;
    let mut response_syncer = SyncResponder::new(session_id);
    let request_syncer = SyncRequester::new(session_id, storage_id);
    assert!(request_syncer.ready());
    let mut buffer;
    let target;
    let len;

    {
        let mut client = client.lock().await;
        let mut trx = client.transaction(&storage_id);
        client.sync_receive(&mut trx, &mut sink, &mut response_syncer, &req)?;
        client.commit(&mut trx, &mut sink)?;

        buffer = [0u8; sync::MAX_SYNC_MESSAGE_SIZE];
        target = buffer.as_mut_slice();
        len = client.sync_poll(&mut response_syncer, target)?;
    }

    send.write_all(&target[0..len]).await?;
    // Gracefully terminate the stream
    send.finish().await?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct WrappedSink {
    pub sink: Arc<Mutex<TestSink>>,
}

impl WrappedSink {
    pub fn add_expectation(&mut self, expect: TestEffect) {
        let mut s = self.sink.lock().unwrap();
        s.add_expectation(expect)
    }

    pub fn count(&self) -> usize {
        let s = self.sink.lock().unwrap();
        s.count()
    }
}

impl Sink<TestEffect> for WrappedSink {
    fn begin(&mut self) {
        let mut s = self.sink.lock().unwrap();
        s.begin()
    }

    fn consume(&mut self, effect: TestEffect) {
        let mut s = self.sink.lock().unwrap();
        s.consume(effect);
    }

    fn rollback(&mut self) {
        let mut s = self.sink.lock().unwrap();
        s.rollback()
    }

    fn commit(&mut self) {
        let mut s = self.sink.lock().unwrap();
        s.commit()
    }
}
