#![warn(missing_docs)]

//! An implementation of the syncer using QUIC.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Result};
use aranya_fast_channels::Label;
use bytes::Bytes;
use heapless::Vec as HVec;
use s2n_quic::{
    client::Connect,
    connection,
    provider::{self, StartError},
    stream::{self, BidirectionalStream, ReceiveStream, SendStream},
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
pub async fn run_channels(client: Arc<TMutex<AqcClient>>, mut server: Server) {
    loop {
        select! {
            Some(conn) = server.accept() => {
                match handle_connection(conn).await {
                    Ok(Some(channel)) => {
                        if client
                            .lock()
                            .await
                            .new_channels
                            .push(channel).is_err() {
                            error!("Channel full. Unable to insert channel");
                        }
                    },
                    Ok(None) => {
                        // The connection was closed.
                    },
                    Err(e) => {
                        error!(cause = ?e, "connection error");
                    }
                }
            },
        }
    }
}

async fn handle_connection(mut conn: Connection) -> Result<Option<AqcChannel>> {
    let stream = conn.accept_bidirectional_stream().await;
    match stream {
        Err(connection::Error::EndpointClosing { .. }) => Ok(None),
        Err(e) => Err(e.into()),
        Ok(None) => Ok(None),
        Ok(Some(stream)) => handle_bidirectional_stream(conn, stream).await,
    }
}

async fn handle_bidirectional_stream(
    conn: Connection,
    stream: BidirectionalStream,
) -> Result<Option<AqcChannel>> {
    let (recv, send) = stream.split();
    // TODO: Use the SSL certificate to identify the channel.
    let (channel, message_sender) = AqcChannel::new(send, recv);
    tokio::spawn(handle_messages(conn, message_sender));

    Ok(Some(channel))
}

async fn handle_messages(mut conn: Connection, sender: mpsc::Sender<Bytes>) {
    while let Ok(Some(stream)) = conn.accept_receive_stream().await {
        tokio::spawn(handle_message(stream, sender.clone()));
    }
}

async fn handle_message(mut stream: ReceiveStream, sender: mpsc::Sender<Bytes>) {
    let mut data = Vec::new();
    loop {
        match stream.receive().await {
            Ok(Some(req)) => {
                data.extend_from_slice(&req);
            }
            Ok(None) => {
                if sender.send(Bytes::from(data)).await.is_err() {
                    debug!("error sending to channel");
                }
                break;
            }
            Err(_) => {
                debug!("error receiving from stream");
                break;
            }
        }
    }
}

#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
/// Identifies a unique channel between two peers.
pub struct AqcChannelID {
    channel_id: u64,
    // /// The node id of the peer.
    // node_id: NodeId,
    /// The channel label. This allows multiple channels between two peers.
    label: Label,
}

#[derive(Debug)]
/// A unique channel between two peers.
/// Allows sending and receiving data over a channel.
pub struct AqcChannel {
    message_receiver: mpsc::Receiver<Bytes>,
    receive_stream: ReceiveStream,
    send_stream: SendStream,
}

impl AqcChannel {
    /// Create a new channel with the given send stream.
    ///
    /// Returns the channel and the senders for the stream and message channels.
    pub fn new(
        send_stream: SendStream,
        receive_stream: ReceiveStream,
    ) -> (Self, mpsc::Sender<Bytes>) {
        let (message_sender, message_receiver) = mpsc::channel(1);
        (
            Self {
                message_receiver,
                send_stream,
                receive_stream,
            },
            message_sender,
        )
    }

    /// Receive the next available data from a channel. If the channel has been
    /// closed, return None.
    ///
    /// This method will block until data is available to return.
    /// The data is not guaranteed to be complete, and may need to be called
    /// multiple times to receive all data from a message.
    pub async fn recv_stream(&mut self, target: &mut [u8]) -> Option<usize> {
        loop {
            select! {
                r = self.receive_stream.receive() => {
                    match r {
                        Err(_) => {
                            debug!("error receiving from stream");
                        }
                        Ok(Some(req)) => {
                let len = req.len();
                target[..len].copy_from_slice(&req);
                return Some(len);
                        }
                        // The stream has been closed.
                        Ok(None) => {
                            return None
                        }
                    };
                }
            }
        }
    }

    /// Receive the next available message from a channel. If no data is available, return None.
    /// If the channel is closed, return an AqcError::ChannelClosed error.
    ///
    /// This method will return messages as soon as they are available, and will not block.
    pub fn try_recv_message(&mut self, target: &mut [u8]) -> Result<Option<usize>, AqcError> {
        match self.message_receiver.try_recv() {
            Ok(data) => {
                let len = data.len();
                target[..len].copy_from_slice(&data);
                Ok(Some(len))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(AqcError::ChannelClosed),
        }
    }

    /// Receive the next available message from a channel. If the channel has been
    /// closed, return None.
    ///
    /// This method will block until data is available to return.
    /// The data is not guaranteed to be complete, and may need to be called
    /// multiple times to receive all data from a message.
    pub async fn recv_message(&mut self, target: &mut [u8]) -> Option<usize> {
        match self.message_receiver.recv().await {
            Some(data) => {
                let len = data.len();
                target[..len].copy_from_slice(&data);
                Some(len)
            }
            None => None,
        }
    }

    /// Stream data to the given channel.
    pub async fn send_stream(&mut self, data: &[u8]) -> Result<(), AqcError> {
        self.send_stream.send(Bytes::copy_from_slice(data)).await?;
        Ok(())
    }

    /// Send a message the given channel.
    pub async fn send_message(&mut self, data: &[u8]) -> Result<(), AqcError> {
        let mut send = self.send_stream.connection().open_send_stream().await?;
        send.send(Bytes::copy_from_slice(data)).await?;
        Ok(())
    }

    /// Close the given channel if it's open. If the channel is already closed, do nothing.
    pub fn close(&mut self) {
        const ERROR_CODE: u32 = 0;
        self.send_stream.connection().close(ERROR_CODE.into());
    }
}

/// The maximum number of channels that haven't been received.
const MAXIMUM_UNRECEIVED_CHANNELS: usize = 10;

/// An AQC client. Used to create and receive channels.
#[derive(Debug)]
pub struct AqcClient {
    quic_client: Client,
    /// Holds channels that have created, but not yet been received.
    pub new_channels: HVec<AqcChannel, MAXIMUM_UNRECEIVED_CHANNELS>,
}

impl AqcClient {
    /// Create an Aqc client with the given certificate chain.
    pub fn new<T: provider::tls::Provider>(cert: T) -> Result<AqcClient, AqcError> {
        let quic_client = Client::builder()
            .with_tls(cert)?
            .with_io("0.0.0.0:0")?
            .start()?;
        Ok(AqcClient {
            quic_client,
            new_channels: HVec::new(),
        })
    }

    /// Receive the next available channel. If no channel is available, return None.
    /// This method will return a channel created by a peer that hasn't been received yet.
    pub fn receive_channel(&mut self) -> Option<AqcChannel> {
        self.new_channels.pop()
    }

    /// Create a new channel to the given address.
    pub async fn create_channel(&mut self, addr: SocketAddr) -> Result<AqcChannel, AqcError> {
        // TODO: Create the channel in the graph.
        let mut conn = self
            .quic_client
            .connect(Connect::new(addr).with_server_name("localhost"))
            .await?;
        let stream = conn.open_bidirectional_stream().await?;
        if let Some(channel) = handle_bidirectional_stream(conn, stream).await? {
            Ok(channel)
        } else {
            Err(anyhow!("no channel created").into())
        }
    }
}
