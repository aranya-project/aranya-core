//! Quic syncer
#![cfg(any(feature = "quic_syncer", test))]

use alloc::sync::Arc;
use std::net::SocketAddr;

use quinn::{ClientConfig, ConnectionError, Endpoint, ReadToEndError, WriteError};
use tokio::{select, sync::Mutex as TMutex};
use tokio_util::sync::CancellationToken;

use crate::{
    command::Id,
    engine::{Engine, Sink},
    storage::StorageProvider,
    ClientState, LockedSink, SyncError, SyncRequester, SyncResponder, SyncState,
    MAX_SYNC_MESSAGE_SIZE,
};

impl From<rustls::Error> for SyncError {
    fn from(_error: rustls::Error) -> Self {
        SyncError::CryptoError
    }
}

impl From<WriteError> for SyncError {
    fn from(_error: WriteError) -> Self {
        SyncError::NetworkError
    }
}

impl From<ReadToEndError> for SyncError {
    fn from(_error: ReadToEndError) -> Self {
        SyncError::NetworkError
    }
}

impl From<ConnectionError> for SyncError {
    fn from(_error: ConnectionError) -> Self {
        SyncError::NetworkError
    }
}

impl From<std::io::Error> for SyncError {
    fn from(_err: std::io::Error) -> Self {
        SyncError::NetworkError
    }
}

pub async fn run_syncer<T, EN, SP>(
    cancel_token: CancellationToken,
    client: Arc<TMutex<ClientState<EN, SP>>>,
    storage_id: Id,
    endpoint: Endpoint,
    session_id: u128,
    sink: LockedSink<T>,
) -> Result<(), SyncError>
where
    T: Send + 'static,
    EN: Engine + Send + 'static,
    SP: StorageProvider + Send + 'static,
    LockedSink<T>: Sink<<EN as Engine>::Effects> + Clone,
{
    let future = tokio::spawn(async move {
        while let Some(conn) = endpoint.accept().await {
            let _ =
                handle_connection(conn, client.clone(), session_id, storage_id, sink.clone()).await;
        }
    });
    select! {
        _ = cancel_token.cancelled() => {
            // The token was cancelled
        },
        _ = future => {
            // Listen completed
        }
    };
    Ok(())
}

async fn handle_connection<T, EN, SP>(
    conn: quinn::Connecting,
    client: Arc<TMutex<ClientState<EN, SP>>>,
    session_id: u128,
    storage_id: Id,
    sink: LockedSink<T>,
) -> Result<(), SyncError>
where
    EN: Engine,
    SP: StorageProvider,
    LockedSink<T>: Sink<<EN as Engine>::Effects>,
{
    let connection = conn.await?;
    let stream = connection.accept_bi().await;
    let stream = match stream {
        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
            return Ok(());
        }
        Err(_e) => {
            return Err(SyncError::NetworkError);
        }
        Ok(s) => s,
    };
    handle_request(stream, client, session_id, storage_id, sink).await?;
    Ok(())
}

async fn handle_request<T, EN, SP>(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    client: Arc<TMutex<ClientState<EN, SP>>>,
    session_id: u128,
    storage_id: Id,
    mut sink: LockedSink<T>,
) -> Result<(), SyncError>
where
    EN: Engine,
    SP: StorageProvider,
    LockedSink<T>: Sink<<EN as Engine>::Effects>,
{
    let req = recv.read_to_end(MAX_SYNC_MESSAGE_SIZE).await?;
    let mut response_syncer = SyncResponder::new(session_id);
    let request_syncer = SyncRequester::new(session_id, storage_id);
    if !request_syncer.ready() {
        return Err(SyncError::InternalError);
    }
    let mut buffer;

    let target = {
        let mut client = client.lock().await;
        let mut trx = client.transaction(&storage_id);
        client.sync_receive(&mut trx, &mut sink, &mut response_syncer, &req)?;
        client.commit(&mut trx, &mut sink)?;

        buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = client.sync_poll(&mut response_syncer, &mut buffer)?;
        &buffer[0..len]
    };

    send.write_all(target).await?;
    // Gracefully terminate the stream
    send.finish().await?;
    Ok(())
}

pub async fn sync<T, EN, SP>(
    mut client: tokio::sync::MutexGuard<'_, ClientState<EN, SP>>,
    mut syncer: SyncRequester<'_>,
    cert_chain: Vec<rustls::Certificate>,
    sink: &mut LockedSink<T>,
    storage_id: &Id,
    server_addr: SocketAddr,
) -> Result<(), SyncError>
where
    EN: Engine,
    SP: StorageProvider,
    LockedSink<T>: Sink<<EN as Engine>::Effects>,
{
    let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
    let len = client.sync_poll(&mut syncer, &mut buffer)?;
    if len > buffer.len() {
        return Err(SyncError::SerilizeError);
    }
    let mut certs = rustls::RootCertStore::empty();
    for cert in &cert_chain {
        certs.add(cert)?;
    }
    let client_cfg = ClientConfig::with_root_certificates(certs);
    let client_addr = "[::]:0".parse().map_err(|_| SyncError::InternalError)?;
    let mut endpoint = Endpoint::client(client_addr)?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint
        .connect(server_addr, "localhost")
        .map_err(|_| SyncError::NetworkError)?
        .await
        .map_err(|_| SyncError::NetworkError)?;
    let (mut send, mut recv) = conn.open_bi().await?;

    send.write_all(&buffer[0..len]).await?;
    send.finish().await?;
    let resp = recv.read_to_end(usize::max_value()).await?;
    let mut trx = client.transaction(storage_id);
    client.sync_receive(&mut trx, sink, &mut syncer, &resp)?;
    client.commit(&mut trx, sink)?;
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    endpoint.close(0u32.into(), b"done");
    Ok(())
}
