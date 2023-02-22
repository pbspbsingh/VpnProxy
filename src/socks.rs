use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use log::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

use crate::dns::Dns;
use crate::util::u8s_to_u16;
use crate::wg::virtual_socket::{VSocketReader, VSocketWriter};
use crate::wg::WireGuard;

pub struct Socks5 {
    tcp_listener: TcpListener,
    resolver: Arc<Dns>,
    wg: Arc<WireGuard>,
}

impl Socks5 {
    pub async fn default(port: u16) -> io::Result<Self> {
        Self::new(port, Dns::new()).await
    }

    pub async fn new(port: u16, resolver: Dns) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(("127.0.0.1", port)).await?;
        let resolver = Arc::new(resolver);
        let wg = WireGuard::init().await?;
        info!("Successfully bound to port {port}");

        Ok(Socks5 {
            tcp_listener,
            resolver,
            wg,
        })
    }

    pub async fn serve(&self) -> io::Result<()> {
        while let Ok((tcp_stream, addr)) = self.tcp_listener.accept().await {
            debug!("Accepted connection from {addr}");
            let mut listener = SocksListener {
                tcp_stream,
                resolver: self.resolver.clone(),
                wg: self.wg.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = listener.handle_client().await {
                    warn!("{addr} => {e:?}");
                }
                listener.shutdown().await.ok();
                debug!("Closed connection with {addr}");
            });
        }
        Ok(())
    }
}

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_CONNECT: u8 = 0x01;
const NO_AUTH: u8 = 0x00;

struct SocksListener {
    tcp_stream: TcpStream,
    resolver: Arc<Dns>,
    wg: Arc<WireGuard>,
}

impl SocksListener {
    async fn handle_client(&mut self) -> io::Result<()> {
        self.handshake().await?;

        let (status, socket_addr) = match self.resolve_socket().await {
            Ok(addr) => (SocksResponseCode::Success, Ok(addr)),
            Err(SocksError::IO(e)) => {
                warn!("IO Error occurred: {e:?}");
                (SocksResponseCode::Failure, Err(e))
            }
            Err(SocksError::UnsupportedError(status, msg)) => {
                warn!("Socks Error occurred: {msg}");
                (status, Err(io::Error::new(io::ErrorKind::Other, msg)))
            }
        };
        let res_header = [SOCKS_VERSION, status as u8, 0, 1, 0, 0, 0, 0, 0, 0];
        self.tcp_stream.write_all(&res_header).await?;

        let mut virtual_socket = self.wg.connect(socket_addr?).await?;

        let (read, write) = self.tcp_stream.split();
        let (vreader, vwriter) = virtual_socket.split()?;
        let (read, wrote) =
            tokio::try_join!(read_stream(read, vwriter), write_stream(write, vreader))?;
        info!("Total bytes read: {read}, written: {wrote}");

        Ok(())
    }

    async fn handshake(&mut self) -> io::Result<()> {
        let mut header = [0u8; 2];

        self.tcp_stream.read_exact(&mut header).await?;
        let [protocol, auth_methods] = header;
        trace!("Protocol: {protocol}, Auth: {auth_methods}");
        if protocol != SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported protocol: {protocol}"),
            ));
        }

        let mut methods = Vec::with_capacity(auth_methods as usize);
        for _ in 0..auth_methods {
            methods.push(self.tcp_stream.read_u8().await?);
        }
        trace!("Methods: {methods:?}");

        header[1] = NO_AUTH;
        self.tcp_stream.write_all(&header).await
    }

    async fn resolve_socket(&mut self) -> Result<SocketAddr, SocksError> {
        let mut packet = [0u8; 4];
        self.tcp_stream.read_exact(&mut packet).await?;
        let [socks, command, _, addr_type] = packet;
        if socks != SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported SOCKS: {socks}"),
            )
            .into());
        }
        if command != SOCKS_CONNECT {
            return Err(SocksError::UnsupportedError(
                SocksResponseCode::CommandNotSupported,
                format!("Unsupported Command: {command}"),
            ));
        }
        let Some(addr_type) = AddrType::parse(addr_type) else {
            return Err(SocksError::UnsupportedError(
                SocksResponseCode::AddrTypeNotSupported,
                format!("Unsupported AddrType: {addr_type}"),
            ));
        };

        let addr_bytes = addr_type.read_addr_bytes(&mut self.tcp_stream).await?;
        let ip_addr = addr_type
            .decode(addr_bytes, |host| async {
                Ok(self.resolver.resolve(host).await?)
            })
            .await?;
        let port = u8s_to_u16(
            self.tcp_stream.read_u8().await?,
            self.tcp_stream.read_u8().await?,
        );
        debug!("Socks {socks}, Command: {command}, AddrType: {addr_type:?}={ip_addr:?}");

        Ok(SocketAddr::new(ip_addr, port))
    }

    async fn shutdown(mut self) -> io::Result<()> {
        self.tcp_stream.shutdown().await
    }
}

#[derive(Debug)]
enum SocksResponseCode {
    Success = 0x00,
    Failure = 0x01,
    CommandNotSupported = 0x07,
    AddrTypeNotSupported = 0x08,
}

#[derive(Debug, thiserror::Error)]
enum SocksError {
    #[error("Unsupported: {1}")]
    UnsupportedError(SocksResponseCode, String),
    #[error("IO Error: {0}")]
    IO(#[from] io::Error),
}

#[derive(Debug, Copy, Clone)]
enum AddrType {
    V4 = 1,
    V6 = 4,
    Domain = 3,
}

impl AddrType {
    fn parse(n: u8) -> Option<AddrType> {
        let types = [AddrType::V4, AddrType::Domain, AddrType::V6];
        types.into_iter().find(|&t| t as u8 == n)
    }

    async fn read_addr_bytes(&self, tcp_stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut addr = match *self {
            AddrType::V4 => vec![0u8; 4],
            AddrType::V6 => vec![0u8; 16],
            AddrType::Domain => vec![0u8; tcp_stream.read_u8().await? as usize],
        };
        tcp_stream.read_exact(&mut addr).await?;
        Ok(addr)
    }

    async fn decode<F>(self, addr: Vec<u8>, resolver: impl Fn(String) -> F) -> io::Result<IpAddr>
    where
        F: Future<Output = io::Result<Vec<IpAddr>>>,
    {
        let socket_addr = match self {
            AddrType::V4 => {
                assert_eq!(addr.len(), 4);
                let ip4_addr = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                IpAddr::V4(ip4_addr)
            }
            AddrType::V6 => {
                assert_eq!(addr.len(), 16);
                let mut iter = addr.chunks_exact(2).map(|x| u8s_to_u16(x[0], x[1]));
                let ip6_addr = Ipv6Addr::new(
                    iter.next().unwrap(),
                    iter.next().unwrap(),
                    iter.next().unwrap(),
                    iter.next().unwrap(),
                    iter.next().unwrap(),
                    iter.next().unwrap(),
                    iter.next().unwrap(),
                    iter.next().unwrap(),
                );
                IpAddr::V6(ip6_addr)
            }
            AddrType::Domain => {
                let start = Instant::now();
                let hostname = String::from_utf8_lossy(&addr);
                let resolved = resolver(hostname.to_string()).await?;
                info!(
                    "Lookup for {} took {}ms",
                    hostname,
                    start.elapsed().as_millis()
                );
                resolved.into_iter().next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to resolve {hostname}"),
                    )
                })?
            }
        };
        Ok(socket_addr)
    }
}

async fn read_stream(mut reader: ReadHalf<'_>, mut writer: VSocketWriter<'_>) -> io::Result<usize> {
    let mut buff = vec![0; 8 * 1024];
    let mut total = 0;
    'outer: loop {
        let len = reader.read(&mut buff).await?;
        if len == 0 {
            break 'outer;
        }
        total += len;

        let mut start = 0;
        loop {
            let wlen = writer.write(&buff[start..len]).await?;
            if wlen == 0 {
                break 'outer;
            }
            start += wlen;
            if start == len {
                break;
            }
        }
    }
    Ok(total)
}

async fn write_stream(
    mut writer: WriteHalf<'_>,
    mut reader: VSocketReader<'_>,
) -> io::Result<usize> {
    let mut buff = vec![0; 8 * 1024];
    let mut total = 0;
    'outer: loop {
        let len = reader.read(&mut buff).await?;
        if len == 0 {
            break 'outer;
        }
        total += len;

        let mut start = 0;
        loop {
            let wlen = writer.write(&buff[start..len]).await?;
            if wlen == 0 {
                break 'outer;
            }
            start += wlen;
            if start == len {
                break;
            }
        }
    }
    Ok(total)
}
