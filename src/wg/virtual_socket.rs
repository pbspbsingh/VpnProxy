use std::io::{Error, ErrorKind, Write};

use smoltcp::iface::SocketHandle;
use tokio::sync::mpsc::{Receiver, UnboundedSender};
use tokio::sync::oneshot;

use crate::wg::port_pool::LocalPort;
use crate::wg::virtual_interface::InterfaceCommand;
use crate::wg::WgError;

pub struct VirtualSocket {
    socket_handle: SocketHandle,
    port: Option<LocalPort>,
    read_ready: Option<Receiver<()>>,
    write_ready: Option<Receiver<()>>,
    command_tx: UnboundedSender<InterfaceCommand>,
}

pub struct VSocketReader<'a> {
    socket: &'a VirtualSocket,
    read_ready: Receiver<()>,
    read_buf: Option<Vec<u8>>,
}

pub struct VSocketWriter<'a> {
    socket: &'a VirtualSocket,
    write_ready: Receiver<()>,
    write_buf: Option<Vec<u8>>,
}

impl VirtualSocket {
    pub fn new(
        handle: SocketHandle,
        port: LocalPort,
        read_ready: Receiver<()>,
        write_ready: Receiver<()>,
        command_tx: UnboundedSender<InterfaceCommand>,
    ) -> Self {
        Self {
            socket_handle: handle,
            port: Some(port),
            read_ready: Some(read_ready),
            write_ready: Some(write_ready),
            command_tx,
        }
    }

    pub fn split(&mut self) -> Result<(VSocketReader, VSocketWriter), Error> {
        let read_ready = self.read_ready.take();
        let write_ready = self.write_ready.take();

        if let (Some(read_ready), Some(write_ready)) = (read_ready, write_ready) {
            Ok((
                VSocketReader::new(self, read_ready),
                VSocketWriter::new(self, write_ready),
            ))
        } else {
            Err(Error::new(
                ErrorKind::AlreadyExists,
                "This socket is already splitted and can't be reused",
            ))
        }
    }
}

impl Drop for VirtualSocket {
    fn drop(&mut self) {
        self.command_tx
            .send(InterfaceCommand::DropTcpSocket(
                self.socket_handle,
                self.port.take().unwrap(),
            ))
            .ok();
    }
}

impl<'a> VSocketReader<'a> {
    fn new(socket: &'a VirtualSocket, read_ready: Receiver<()>) -> Self {
        VSocketReader {
            socket,
            read_ready,
            read_buf: None,
        }
    }

    pub async fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Error> {
        if let Some(read_buf) = self.read_buf.as_mut() {
            if !read_buf.is_empty() {
                let len = read_buf.len().min(buf.len());
                buf.write(&read_buf[..len])?;
                read_buf.drain(..len);
                return Ok(len);
            }
        }

        while let Some(_) = self.read_ready.recv().await {
            let (tx, rx) = oneshot::channel();
            self.socket
                .command_tx
                .send(InterfaceCommand::ReadFromTcpSocket(
                    self.socket.socket_handle,
                    self.read_buf.take().unwrap_or_else(Vec::new),
                    tx,
                ))
                .map_err(|_| WgError::ChannelError)?;

            let (read_buf, read_res) = rx.await.map_err(|_| WgError::ChannelError)?;
            self.read_buf = Some(read_buf);

            let read_buf = self.read_buf.as_mut().unwrap();
            if read_buf.is_empty() && read_res.is_ok() {
                continue;
            }

            let len = read_buf.len().min(buf.len());
            buf.write(&read_buf[..len])?;
            read_buf.drain(..len);

            return match read_res {
                Ok(_) => Ok(len),
                Err(()) => Ok(0),
            };
        }
        Ok(0)
    }
}

impl<'a> VSocketWriter<'a> {
    fn new(socket: &'a VirtualSocket, write_ready: Receiver<()>) -> Self {
        VSocketWriter {
            socket,
            write_ready,
            write_buf: None,
        }
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        while let Some(_) = self.write_ready.recv().await {
            let mut write_buf = self.write_buf.take().unwrap_or_else(Vec::new);
            write_buf.clear();
            write_buf.extend_from_slice(data);

            let (tx, rx) = oneshot::channel();
            self.socket
                .command_tx
                .send(InterfaceCommand::WriteOnTcpSocket(
                    self.socket.socket_handle,
                    write_buf,
                    tx,
                ))
                .map_err(|_| WgError::ChannelError)?;
            let (write_buf, write_res) = rx.await.map_err(|_| WgError::ChannelError)?;
            self.write_buf = Some(write_buf);
            return match write_res {
                Ok(len) if len > 0 => Ok(len),
                Err(()) => Ok(0), // Socket is closed
                _ => continue,
            };
        }
        Ok(0)
    }
}
