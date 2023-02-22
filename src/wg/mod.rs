use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use log::*;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time;
use wireguard_keys::ParseError;

use crate::util::{parse_private_key, parse_public_key};
use crate::wg::virtual_device::VirtualDevice;
use crate::wg::virtual_interface::VirtualInterface;
use crate::wg::virtual_socket::VirtualSocket;
use crate::{LOCAL_ADDRESS, PEER_ADDRESS, PRIVATE_KEY, PUBLIC_KEY};

mod port_pool;
mod virtual_device;
mod virtual_interface;
pub mod virtual_socket;

pub const MAX_PACKET_SIZE: usize = 8 * 1024;

pub struct WireGuard {
    interface: VirtualInterface,
    tunn: Box<Tunn>,
    wg_peer_socket: UdpSocket,
    alive: AtomicBool,
}

#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("Failed to parse private/public key: {0}")]
    ParsingError(#[from] ParseError),
    #[error("Failed to create tunnel: {0}")]
    TunnelError(&'static str),
    #[error("IO Error: {0}")]
    IO(#[from] io::Error),
    #[error("Socket is in invalidate state: {0}")]
    SocketInvalidState(String),
    #[error("Socket address is invalid")]
    SocketInvalidAddress,
    #[error("Error while sending message across channel")]
    ChannelError,
}

impl From<WgError> for io::Error {
    fn from(value: WgError) -> Self {
        if let WgError::IO(io_err) = value {
            io_err
        } else {
            io::Error::new(io::ErrorKind::Other, value.to_string())
        }
    }
}

impl WireGuard {
    pub async fn init() -> Result<Arc<Self>, WgError> {
        let start = Instant::now();
        let (transmit_tx, transmit_rx) = unbounded_channel::<Vec<u8>>();
        let (receiving_tx, receiving_rx) = unbounded_channel::<Vec<u8>>();
        let device = VirtualDevice::new(transmit_tx, receiving_rx);
        let interface = VirtualInterface::init(device, LOCAL_ADDRESS);
        info!("Created virtual interface successfully");
        let tunn = Tunn::new(
            parse_private_key(PRIVATE_KEY)?,
            parse_public_key(PUBLIC_KEY)?,
            None,
            None,
            0,
            None,
        )
        .map_err(WgError::TunnelError)?;
        info!("Created tunnel successfully");

        let wg_peer_socket = UdpSocket::bind("0.0.0.0:0").await?;
        info!("Bound udp socket to: {}", wg_peer_socket.local_addr()?);
        wg_peer_socket.connect(PEER_ADDRESS).await?;
        info!("Connected udp socket to the WireGuard remote peer");

        let wg = Arc::new(WireGuard {
            interface,
            tunn,
            wg_peer_socket,
            alive: AtomicBool::new(true),
        });

        {
            let wg = wg.clone();
            tokio::spawn(async move {
                info!("Starting background task to transmit ip packets.");
                wg.transmit_packet(transmit_rx).await;
            });
        }
        {
            let wg = wg.clone();
            tokio::spawn(async move {
                info!("Starting background task to receive ip packets.");
                wg.receive_packets(receiving_tx).await;
            });
        }
        info!(
            "Initialization of WireGuard is done in {}ms",
            start.elapsed().as_millis()
        );
        Ok(wg)
    }

    pub async fn connect(&self, address: SocketAddr) -> Result<VirtualSocket, WgError> {
        self.interface.tcp_connect(address).await
    }

    pub fn poll_interface(&self) {
        self.interface.poll();
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    pub fn shutdown(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    async fn transmit_packet(&self, mut rx: UnboundedReceiver<Vec<u8>>) {
        let mut buff = Vec::new();
        while let Some(packet) = rx.recv().await {
            if !self.is_alive() {
                warn!("Stopping the UDP sender");
                break;
            }

            buff.clear();
            buff.resize((packet.len() + 32).max(148), 0);
            debug!(
                "Outgoing packet: {}, Encapsulated packet: {}",
                packet.len(),
                buff.len(),
            );
            match self.tunn.encapsulate(&packet, &mut buff) {
                TunnResult::Done => {
                    debug!("Tunnel encapsulation done!");
                }
                TunnResult::Err(e) => {
                    warn!(
                        "Failed to encapsulate packet of size: {}: {:?}",
                        packet.len(),
                        e,
                    );
                }
                TunnResult::WriteToNetwork(buff) => {
                    debug!("Sending the encapsulated packet of length: {}", buff.len());
                    match self.wg_peer_socket.send(buff).await {
                        Ok(len) => {
                            debug!("Successfully sent the encapsulated packet to wg peer: {len}",);
                        }
                        Err(e) => {
                            warn!("Error sending encapsulated packet to wg peer: {e:?}");
                        }
                    };
                }
                TunnResult::WriteToTunnelV4(_, _) => {
                    warn!("Unexpected 'WriteToTunnelV4' status while encapsulating");
                }
                TunnResult::WriteToTunnelV6(_, _) => {
                    warn!("Unexpected 'WriteToTunnelV6' status while encapsulating");
                }
            }
        }
        self.shutdown();
    }

    async fn receive_packets(&self, receiving_tx: UnboundedSender<Vec<u8>>) {
        let timeout = Duration::from_millis(500);
        let mut udp_buff = vec![0; MAX_PACKET_SIZE];
        let mut tun_buff = vec![0; MAX_PACKET_SIZE];

        loop {
            udp_buff.clear();
            udp_buff.resize(MAX_PACKET_SIZE, 0);
            match time::timeout(timeout, self.wg_peer_socket.recv(&mut udp_buff)).await {
                Ok(Ok(len)) => {
                    debug!("Received UDP packet from wg peer: {len}");
                    tun_buff.clear();
                    tun_buff.resize(MAX_PACKET_SIZE, 0);
                    match self.tunn.decapsulate(None, &udp_buff[..len], &mut tun_buff) {
                        TunnResult::Done => {
                            debug!("decapsulate is done");
                        }
                        TunnResult::Err(e) => {
                            warn!("Something went wrong while decapsulating: {e:?}");
                        }
                        TunnResult::WriteToNetwork(buff) => {
                            let mut buff_sizes = vec![buff.len()];
                            if let Err(e) = self.wg_peer_socket.send(buff).await {
                                warn!("Sending UPD packet failed: {e}");
                            }

                            loop {
                                tun_buff.clear();
                                tun_buff.resize(MAX_PACKET_SIZE, 0);
                                if let TunnResult::WriteToNetwork(buff) =
                                    self.tunn.decapsulate(None, &[], &mut tun_buff)
                                {
                                    buff_sizes.push(buff.len());
                                    if let Err(e) = self.wg_peer_socket.send(buff).await {
                                        warn!("Sending UPD packet next failed: {e}");
                                    }
                                } else {
                                    break;
                                }
                            }
                            debug!("Send decapsulated packet back to peer: {:?}", buff_sizes);
                        }
                        TunnResult::WriteToTunnelV4(buff, addr) => {
                            debug!("Decapsulated ipv4 packet: {} from: {}", buff.len(), addr);
                            receiving_tx.send(buff.to_vec()).ok();
                            self.poll_interface();
                        }
                        TunnResult::WriteToTunnelV6(buff, addr) => {
                            debug!("Decapsulated ipv6 packet: {} from: {}", buff.len(), addr);
                            receiving_tx.send(buff.to_vec()).ok();
                            self.poll_interface();
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("Something went wrong while receiving UDP packet: {e:?}");
                }
                Err(_) => {
                    if self.is_alive() {
                        self.poll_interface(); // We shouldn't need this
                    } else {
                        warn!("Stopping the UDP receiver");
                        break;
                    }
                }
            }
        }
    }
}
