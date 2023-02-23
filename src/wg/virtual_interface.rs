use std::collections::HashMap;
use std::net::SocketAddr;

use log::*;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{ConnectError, Socket, SocketBuffer, State};
use smoltcp::time::Instant;
use tokio::sync::mpsc::{channel, unbounded_channel, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;

use crate::util::parse_cidr;
use crate::wg::port_pool::{LocalPort, LocalPortPool};
use crate::wg::virtual_device::VirtualDevice;
use crate::wg::virtual_socket::VirtualSocket;
use crate::wg::WgError;

pub struct VirtualInterface {
    tx: UnboundedSender<InterfaceCommand>,
}

impl VirtualInterface {
    pub fn init(mut device: VirtualDevice, cidr: &str) -> Self {
        let mut config = Config::default();
        config.random_seed = rand::random();
        let mut interface = Interface::new(config, &mut device);
        interface.update_ip_addrs(|addrs| {
            info!("Setting ip address for virtual interface");
            addrs.push(parse_cidr(cidr).into()).unwrap();
        });
        info!("Local IP address: {:?}", interface.ip_addrs());

        let (tx, rx) = unbounded_channel::<InterfaceCommand>();

        tokio::spawn(run_command(device, interface, rx, tx.clone()));

        VirtualInterface { tx }
    }

    pub async fn tcp_connect(&self, socket_addr: SocketAddr) -> Result<VirtualSocket, WgError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(InterfaceCommand::CreateTcpSocket(socket_addr, tx))
            .map_err(|_| WgError::ChannelError)?;
        rx.await.map_err(|_| WgError::ChannelError)?
    }

    pub fn poll(&self) {
        self.tx.send(InterfaceCommand::PollSockets).ok();
    }
}

pub enum InterfaceCommand {
    PollSockets,
    CreateTcpSocket(SocketAddr, oneshot::Sender<Result<VirtualSocket, WgError>>),
    ReadFromTcpSocket(
        SocketHandle,
        Vec<u8>,
        oneshot::Sender<(Vec<u8>, Result<usize, ()>)>,
    ),
    WriteOnTcpSocket(
        SocketHandle,
        Vec<u8>,
        oneshot::Sender<(Vec<u8>, Result<usize, ()>)>,
    ),
    DropTcpSocket(SocketHandle, LocalPort),
}

const SOCKET_BUFFER: usize = 1200;
const CLOSED_STATES: &[State] = &[
    State::Closed,
    State::Closing,
    State::CloseWait,
    State::FinWait1,
    State::FinWait2,
    State::LastAck,
];

async fn run_command(
    mut device: VirtualDevice,
    mut interface: Interface,
    mut rx: UnboundedReceiver<InterfaceCommand>,
    tx: UnboundedSender<InterfaceCommand>,
) {
    info!("Starting background task to receive interface commands");
    let port_pool = LocalPortPool::default();
    let mut notifier = HashMap::<u16, (Sender<()>, Sender<()>)>::new();
    let mut socket_set = SocketSet::new(Vec::new());
    while let Some(command) = rx.recv().await {
        match command {
            InterfaceCommand::PollSockets => {
                trace!("Polling interface to check if data is received/transmitted");
                if interface.poll(Instant::now(), &mut device, &mut socket_set) {
                    debug!("Polling interface received/transmitted data");
                    notifier.values_mut().for_each(|(tx1, tx2)| {
                        tx1.try_send(()).ok();
                        tx2.try_send(()).ok();
                    });
                }
            }
            InterfaceCommand::CreateTcpSocket(socket_addr, result_tx) => {
                let mut socket = Socket::new(
                    SocketBuffer::new(vec![0; SOCKET_BUFFER]),
                    SocketBuffer::new(vec![0; SOCKET_BUFFER]),
                );
                let port = port_pool.next();
                match socket.connect(interface.context(), socket_addr, port.port()) {
                    Ok(_) => {
                        debug!(
                            "Successfully connected to local socket at: {:?}",
                            socket.local_endpoint()
                        );
                        let handle = socket_set.add(socket);
                        let (signal_tx1, signal_rx1) = channel::<()>(1);
                        let (signal_tx2, signal_rx2) = channel::<()>(1);
                        notifier.insert(port.port(), (signal_tx1, signal_tx2));
                        let virtual_socket =
                            VirtualSocket::new(handle, port, signal_rx1, signal_rx2, tx.clone());

                        if let Ok(_) = result_tx.send(Ok(virtual_socket)) {
                            tx.send(InterfaceCommand::PollSockets).ok();
                        }
                    }
                    Err(ConnectError::InvalidState) => {
                        warn!("Socket is in invalidate state: {}", socket.state());
                        result_tx
                            .send(Err(WgError::SocketInvalidState(socket.state().to_string())))
                            .ok();
                    }
                    Err(ConnectError::Unaddressable) => {
                        warn!("Socket address is invalid: {socket_addr}");
                        result_tx.send(Err(WgError::SocketInvalidAddress)).ok();
                    }
                };
            }
            InterfaceCommand::ReadFromTcpSocket(handle, mut buff, result_tx) => {
                let socket = socket_set.get_mut::<Socket>(handle);
                if socket.recv_queue() > 0 {
                    debug!(
                        "Trying to read {} bytes from tcp socket",
                        socket.recv_queue(),
                    );
                    buff.clear();
                    buff.resize(socket.recv_queue(), 0);
                    match socket.recv_slice(&mut buff) {
                        Ok(len) => {
                            debug!("Successfully read {len} bytes from tcp socket");
                            buff.truncate(len);
                            if let Ok(_) = result_tx.send((buff, Ok(len))) {
                                tx.send(InterfaceCommand::PollSockets).ok();
                            }
                        }
                        Err(e) => {
                            let res = if CLOSED_STATES.contains(&socket.state()) {
                                warn!(
                                    "Reading data from tcp socket failed: {e:?}, current state: {}",
                                    socket.state()
                                );
                                Err(())
                            } else {
                                Ok(0)
                            };
                            result_tx.send((buff, res)).ok();
                        }
                    }
                } else {
                    result_tx.send((buff, Ok(0))).ok();
                }
            }
            InterfaceCommand::WriteOnTcpSocket(handle, buff, result_tx) => {
                debug!("Received tcp socket write with {} len", buff.len());
                let socket = socket_set.get_mut::<Socket>(handle);
                match socket.send_slice(&buff) {
                    Ok(len) => {
                        debug!("Successfully written {len} bytes to tcp socket");
                        if let Ok(_) = result_tx.send((buff, Ok(len))) {
                            tx.send(InterfaceCommand::PollSockets).ok();
                        }
                    }
                    Err(e) => {
                        let res = if CLOSED_STATES.contains(&socket.state()) {
                            warn!(
                                "Writing data to tcp socket failed: {e:?}, current state: {}",
                                socket.state()
                            );
                            Err(())
                        } else {
                            Ok(0)
                        };
                        result_tx.send((buff, res)).ok();
                    }
                }
            }
            InterfaceCommand::DropTcpSocket(handle, local_port) => {
                let smoltcp::socket::Socket::Tcp(mut socket) = socket_set.remove(handle);
                debug!(
                    "Closing socket with state({}): {:?} => {:?}",
                    socket.state(),
                    socket.remote_endpoint(),
                    socket.local_endpoint()
                );
                socket.close();
                notifier.remove(&local_port.port());
                drop(local_port);
            }
        };
    }
}
