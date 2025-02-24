#![warn(missing_docs)]

//! An implementation of the syncer using QUIC.

use std::{net::SocketAddr, sync::Arc, time::SystemTime};

use anyhow::{anyhow, Result};
use aranya_fast_channels::Label;
use bytes::Bytes;
use heapless::FnvIndexMap;
use s2n_quic::{
    client::Connect,
    connection,
    provider::{self, StartError},
    stream::{self, ReceiveStream, SendStream},
    Client, Connection, Server,
};
use tokio::{
    select,
    sync::{
        mpsc::{self, error::TryRecvError},
        Mutex as TMutex,
    },
};
use tracing::{debug, error};

/// An error running the AQC client
#[derive(Debug, thiserror::Error)]
pub enum AqcError {
    /// A channel was closed.
    #[error("channel closed")]
    ChannelClosed,
    /// An error creating a quic connection.
    #[error("connect error: {0}")]
    Connect(#[from] connection::Error),
    /// An error using a stream.
    #[error("stream error: {0}")]
    Stream(#[from] stream::Error),
    /// An error starting an s2n quic client.
    #[error("start error: {0}")]
    Start(#[from] StartError),
    /// An infallible error.
    #[error("infallible error: {0}")]
    Infallible(#[from] std::convert::Infallible),
    /// An io error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// An internal AQC error.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// Runs a server listening for quic channel requests from other peers.
pub async fn run_channels(
    client: Arc<TMutex<AqcClient>>,
    mut server: Server,
    sender: Arc<TMutex<mpsc::Sender<(AqcChannel, Bytes)>>>,
) {
    loop {
        select! {
            Some(conn) = server.accept() => {
                if let Err(e) = handle_connection(conn, client.clone(), sender.clone()).await {
                    error!(cause = ?e, "sync error");
                }
            },
        }
    }
}

async fn handle_connection(
    mut conn: Connection,
    client: Arc<TMutex<AqcClient>>,
    sender: Arc<TMutex<mpsc::Sender<(AqcChannel, Bytes)>>>,
) -> Result<()> {
    let stream = conn.accept_bidirectional_stream().await;
    let stream = match stream {
        Err(connection::Error::EndpointClosing { .. }) => {
            return Ok(());
        }
        Err(e) => {
            return Err(e.into());
        }
        Ok(None) => {
            return Ok(());
        }
        Ok(Some(s)) => s,
    };
    let (recv, send) = stream.split();
    // TODO: Use the SSL certificate to identify the channel.
    client
        .lock()
        .await
        .connections
        .insert(
            AqcChannel {
                channel_id: 0,
                label: 0.into(),
            },
            (send, SystemTime::now()),
        )
        .map_err(|_| anyhow!("Unable to insert channel"))?;
    tokio::spawn(handle_receive(recv, sender));
    Ok(())
}

async fn handle_receive(
    mut stream: ReceiveStream,
    sender: Arc<TMutex<mpsc::Sender<(AqcChannel, Bytes)>>>,
) {
    loop {
        select! {
            r = stream.receive() => {
                match r {
                    Err(_) => {
                        debug!("error receiving from stream");
                        break;
                    }
                    Ok(Some(req)) => {
                        if sender.lock().await.send(
                            (AqcChannel { channel_id: 0, label: 0.into() }, req)
                        ).await.is_err() {
                            debug!("error sending to channel");
                        }
                    }
                    // The stream has been closed.
                    Ok(None) => {
                        break;
                    }
                };
            }
        }
    }
}

#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
/// Identifies a unique channel between two peers.
pub struct AqcChannel {
    channel_id: u64,
    // /// The node id of the peer.
    // node_id: NodeId,
    /// The channel label. This allows multiple channels between two peers.
    label: Label,
}

/// FNVIndexMap requires that the size be a power of 2.
const MAXIMUM_CONNECTIONS: usize = 32;

/// An AQC client
pub struct AqcClient {
    quic_client: Client,
    receiver: mpsc::Receiver<(AqcChannel, Bytes)>,
    connections: FnvIndexMap<AqcChannel, (SendStream, SystemTime), MAXIMUM_CONNECTIONS>,
    sender: Arc<TMutex<mpsc::Sender<(AqcChannel, Bytes)>>>,
}

impl AqcClient {
    /// Create an Aqc client with the given certificate chain.
    pub fn new<T: provider::tls::Provider>(
        cert: T,
        receiver: mpsc::Receiver<(AqcChannel, Bytes)>,
        sender: Arc<TMutex<mpsc::Sender<(AqcChannel, Bytes)>>>,
    ) -> Result<AqcClient, AqcError> {
        let quic_client = Client::builder()
            .with_tls(cert)?
            .with_io("0.0.0.0:0")?
            .start()?;
        Ok(AqcClient {
            quic_client,
            receiver,
            connections: FnvIndexMap::new(),
            sender,
        })
    }

    /// Receive the next available data from a channel. If no data is available, return None.
    /// If the channel is closed, return an AqcError::ChannelClosed error.
    ///
    /// This method will return data as soon as it is available, and will not block.
    /// The data is not guaranteed to be complete, and may need to be called
    /// multiple times to receive all data from a message.
    pub fn receive_data_stream(
        &mut self,
        target: &mut [u8],
    ) -> Result<Option<(AqcChannel, usize)>, AqcError> {
        match self.receiver.try_recv() {
            Ok((channel, data)) => {
                let len = data.len();
                target[..len].copy_from_slice(&data);
                Ok(Some((channel, len)))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(AqcError::ChannelClosed),
        }
    }

    /// Send data to the given channel.
    pub async fn send_data_stream(
        &mut self,
        channel: AqcChannel,
        data: &[u8],
    ) -> Result<(), AqcError> {
        let (send, _) = self
            .connections
            .get_mut(&channel)
            .ok_or(AqcError::ChannelClosed)?;
        send.send(Bytes::copy_from_slice(data)).await?;
        Ok(())
    }

    /// Create a new channel to the given address.
    pub async fn create_channel(&mut self, addr: SocketAddr) -> Result<AqcChannel, AqcError> {
        // TODO: Create the channel in the graph.
        let mut conn = self
            .quic_client
            .connect(Connect::new(addr).with_server_name("localhost"))
            .await?;
        let (recv, send) = conn.open_bidirectional_stream().await?.split();
        let channel = AqcChannel {
            channel_id: 0,
            label: 0.into(),
        };
        self.connections
            .insert(channel, (send, SystemTime::now()))
            .map_err(|_| anyhow!("Unable to insert channel"))?;

        tokio::spawn(handle_receive(recv, self.sender.clone()));
        Ok(channel)
    }

    /// Close the given channel if it's open. If the channel is already closed, do nothing.
    pub fn close_channel(&mut self, channel: AqcChannel) {
        if let Some((send, _)) = self.connections.remove(&channel) {
            const ERROR_CODE: u32 = 0;
            send.connection().close(ERROR_CODE.into());
        }
    }
}
