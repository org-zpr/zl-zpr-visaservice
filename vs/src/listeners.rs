//! The visa service's TCP listeners -- VS-API and admin -- and the rules for
//! their lifetime (zl-zipline#266).
//!
//! Both listeners bind the service's own ZPR address, `vs_addr`. The service
//! binds them right after it loads its configuration, before it touches
//! ValKey or takes the instance lock, so a `vs_addr` that is not on a local
//! interface stops the process at once with a clear message instead of
//! leaving a visa service that runs with no VS-API. The bound sockets do not
//! listen until the service has hydrated its state, so a client still gets
//! "connection refused" during startup, as before.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpListener, TcpSocket};

/// Backlog for a listening socket; the value `TcpListener::bind` uses.
const LISTEN_BACKLOG: u32 = 1024;

/// Which of the visa service's two listeners a message or error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerRole {
    /// The capnp VS-API that nodes use (`vsapi_port`).
    VsApi,
    /// The HTTPS admin API (`admin_port`).
    Admin,
}

impl fmt::Display for ListenerRole {
    /// The name used in log lines and error messages.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListenerRole::VsApi => write!(f, "VS-API"),
            ListenerRole::Admin => write!(f, "admin"),
        }
    }
}

/// The step at which a listener failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerStage {
    /// Creating the socket or binding it to its address (startup).
    Bind,
    /// Turning the bound socket into a listening socket (end of startup).
    Listen,
    /// Serving: the accept loop ended (runtime).
    Serve,
}

/// A listener failure: which listener, on which address, at which step, and
/// the OS error.
#[derive(Debug)]
pub struct ListenerError {
    pub role: ListenerRole,
    pub addr: SocketAddr,
    pub stage: ListenerStage,
    pub source: io::Error,
}

impl ListenerError {
    /// The kind of the underlying OS error.
    pub fn kind(&self) -> io::ErrorKind {
        self.source.kind()
    }
}

impl fmt::Display for ListenerError {
    /// One line for the operator. A bind error adds the likely remedy for
    /// the two common causes: an address that is not local, and a port that
    /// another process already holds.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (role, addr, source) = (self.role, self.addr, &self.source);
        match self.stage {
            ListenerStage::Bind => {
                write!(f, "cannot bind {role} listener on {addr}: {source}")?;
                match source.kind() {
                    io::ErrorKind::AddrNotAvailable => {
                        write!(f, "; vs_addr must be an address on a local interface")
                    }
                    io::ErrorKind::AddrInUse => {
                        write!(f, "; another process already listens on this port")
                    }
                    _ => Ok(()),
                }
            }
            ListenerStage::Listen => {
                write!(f, "cannot listen on {role} socket {addr}: {source}")
            }
            ListenerStage::Serve => write!(f, "{role} listener on {addr} stopped: {source}"),
        }
    }
}

impl std::error::Error for ListenerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Create a TCP socket for `addr`, set `SO_REUSEADDR` (as `TcpListener::bind`
/// does) and bind it, but do not listen yet. A bound socket that does not
/// listen answers a connection attempt with a reset, so a client sees
/// "connection refused" until [start_listening] runs.
pub fn bind_reserved(role: ListenerRole, addr: SocketAddr) -> Result<TcpSocket, ListenerError> {
    let fail = |source: io::Error| ListenerError {
        role,
        addr,
        stage: ListenerStage::Bind,
        source,
    };
    let sock = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(fail)?;
    // Same as `TcpListener::bind`: a restarted service can re-bind its port
    // while connections of the previous process are still in TIME_WAIT. It
    // does not let two processes listen on the same port.
    sock.set_reuseaddr(true).map_err(fail)?;
    sock.bind(addr).map_err(fail)?;
    Ok(sock)
}

/// Turn a socket from [bind_reserved] into a listening socket.
pub fn start_listening(role: ListenerRole, sock: TcpSocket) -> Result<TcpListener, ListenerError> {
    // Read the address first, for the error message: `listen` consumes the
    // socket. A bound socket always has one; the fallback is never expected.
    let addr = sock
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0));
    sock.listen(LISTEN_BACKLOG).map_err(|source| ListenerError {
        role,
        addr,
        stage: ListenerStage::Listen,
        source,
    })
}

/// The VS-API and admin sockets, bound to `vs_addr` but not yet listening.
pub struct ReservedListeners {
    pub vsapi: TcpSocket,
    pub admin: TcpSocket,
}

impl ReservedListeners {
    /// Bind both listener sockets on `vs_addr`. The first failure is
    /// returned; the caller logs it and exits.
    pub fn bind(
        vs_addr: IpAddr,
        vsapi_port: u16,
        admin_port: u16,
    ) -> Result<ReservedListeners, ListenerError> {
        Ok(ReservedListeners {
            vsapi: bind_reserved(ListenerRole::VsApi, SocketAddr::new(vs_addr, vsapi_port))?,
            admin: bind_reserved(ListenerRole::Admin, SocketAddr::new(vs_addr, admin_port))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// zl-zipline#266: an address that is on no local interface is refused at
    /// bind time with `AddrNotAvailable`, and the message names the listener,
    /// the address and the remedy. 2001:db8::/32 (RFC 3849) and 192.0.2.0/24
    /// (RFC 5737) are documentation prefixes, never configured on a test host.
    #[tokio::test]
    async fn bind_reserved_rejects_non_local_address() {
        for addr in ["[2001:db8::1]:0", "192.0.2.1:0"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let err = bind_reserved(ListenerRole::VsApi, addr)
                .err()
                .unwrap_or_else(|| panic!("binding {addr} must fail on a test host"));
            assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable, "{err}");
            assert_eq!(err.stage, ListenerStage::Bind);
            let msg = err.to_string();
            assert!(msg.contains("VS-API"), "{msg}");
            assert!(msg.contains(&addr.to_string()), "{msg}");
            assert!(
                msg.contains("vs_addr must be an address on a local interface"),
                "{msg}"
            );
        }
    }

    /// A port that another socket already listens on is refused at bind time,
    /// and the message says so.
    #[tokio::test]
    async fn bind_reserved_rejects_port_in_use() {
        let holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = holder.local_addr().unwrap();
        let err = bind_reserved(ListenerRole::Admin, addr)
            .err()
            .expect("binding a port another socket listens on must fail");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{err}");
        let msg = err.to_string();
        assert!(msg.contains("admin"), "{msg}");
        assert!(msg.contains("another process already listens"), "{msg}");
    }

    /// zl-zipline#266: a reserved socket refuses connections until
    /// [start_listening] runs, and accepts them after. This is what keeps the
    /// startup behaviour unchanged for clients: "connection refused" while
    /// the visa service hydrates.
    #[tokio::test]
    async fn bind_reserved_then_listen_accepts() {
        let sock = bind_reserved(ListenerRole::VsApi, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = sock.local_addr().unwrap();

        let early = tokio::net::TcpStream::connect(addr).await;
        assert_eq!(
            early.err().map(|e| e.kind()),
            Some(io::ErrorKind::ConnectionRefused),
            "a reserved socket must refuse connections before start_listening"
        );

        let listener = start_listening(ListenerRole::VsApi, sock).unwrap();
        assert_eq!(listener.local_addr().unwrap(), addr);
        let (connected, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        connected.expect("connect after start_listening must succeed");
        accepted.expect("the listener must accept the connection");
    }
}
