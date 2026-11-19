//! The visa service's TCP listeners -- VS-API and admin -- and the rules for
//! their lifetime (zl-zipline#266).
//!
//! Both listeners bind the service's own ZPR address, `vs_addr`. The service
//! binds them right after it loads its configuration, before it touches
//! ValKey or takes the instance lock, so a `vs_addr` that is not on a local
//! interface stops the process at once with a clear message instead of
//! leaving a visa service that runs with no VS-API. The bound sockets do not
//! listen until the service has hydrated its state and self-authorization
//! has succeeded (zl-zipline#285), so a client gets "connection refused"
//! during startup, and a listening port means the service is ready.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpListener, TcpSocket};
use tokio::task::{JoinHandle, JoinSet};
use tracing::error;

use crate::logging::targets::MAIN;

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
    /// A listener that was serving on `addr` stopped because of `source`.
    pub fn stopped(role: ListenerRole, addr: SocketAddr, source: io::Error) -> ListenerError {
        ListenerError {
            role,
            addr,
            stage: ListenerStage::Serve,
            source,
        }
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

/// A running listener task, as [supervise] watches it.
pub type ListenerTask = (ListenerRole, JoinHandle<Result<(), ListenerError>>);

/// Why [supervise] stopped the service: which listener ended, and how.
#[derive(Debug)]
pub struct ListenerExit {
    pub role: ListenerRole,
    pub reason: String,
}

impl fmt::Display for ListenerExit {
    /// One line for the operator.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} listener ended ({})", self.role, self.reason)
    }
}

/// Drive the visa service's tasks until a listener ends (zl-zipline#266).
///
/// A listener that ends -- with an error, without one, or by a panic -- is
/// fatal: a visa service with no VS-API (or no admin API) must not keep
/// running, so that a supervisor restarts it. When that happens this logs the
/// cause, shuts down every task in `others` and then calls `release` (which
/// releases the ValKey instance lock), and returns the [ListenerExit]. The
/// order matters: the lock renewal task is in `others`, and a renewal after
/// the release would take the lock again.
///
/// A task in `others` that panics panics the caller, as `main` has always
/// done. If `others` runs empty, the listeners still govern. Returns `None`
/// only if there are no listeners and every task in `others` has finished.
pub async fn supervise<R, Fut>(
    listeners: Vec<ListenerTask>,
    others: &mut JoinSet<()>,
    release: R,
) -> Option<ListenerExit>
where
    R: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    if listeners.is_empty() {
        while let Some(res) = others.join_next().await {
            res.unwrap();
        }
        return None;
    }

    // Kept so the listeners that are still running can be stopped too.
    let aborts: Vec<_> = listeners.iter().map(|(_, h)| h.abort_handle()).collect();
    let mut any_listener = futures::future::select_all(
        listeners
            .into_iter()
            .map(|(role, handle)| Box::pin(async move { (role, handle.await) })),
    );

    let (role, result) = loop {
        tokio::select! {
            ((role, result), _, _) = &mut any_listener => break (role, result),
            // A finished task is not a reason to stop; a panicked one panics
            // the caller, as `main`'s join loop always has. When `others` is
            // empty this branch is disabled and only the listeners govern.
            Some(res) = others.join_next() => res.unwrap(),
        }
    };

    let exit = ListenerExit {
        role,
        reason: describe_listener_end(result),
    };
    error!(target: MAIN, "{exit}; the visa service stops");
    for abort in aborts {
        abort.abort();
    }
    // Stop the lock renewal (and everything else) BEFORE the release, so no
    // renewal can take the lock again after it was released.
    others.shutdown().await;
    release().await;
    Some(exit)
}

/// Say how a listener task ended: its error, a plain return, or a panic.
fn describe_listener_end(
    result: Result<Result<(), ListenerError>, tokio::task::JoinError>,
) -> String {
    match result {
        Ok(Ok(())) => "it returned without an error".to_string(),
        Ok(Err(e)) => e.to_string(),
        Err(e) if e.is_panic() => {
            let payload = e.into_panic();
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "no message".to_string());
            format!("its task panicked: {msg}")
        }
        Err(_) => "its task was cancelled".to_string(),
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
            assert_eq!(err.source.kind(), io::ErrorKind::AddrNotAvailable, "{err}");
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
        assert_eq!(err.source.kind(), io::ErrorKind::AddrInUse, "{err}");
        let msg = err.to_string();
        assert!(msg.contains("admin"), "{msg}");
        assert!(msg.contains("another process already listens"), "{msg}");
    }

    /// zl-zipline#266: a reserved socket refuses connections until
    /// [start_listening] runs, and accepts them after. This is what keeps the
    /// startup behaviour unchanged for clients: "connection refused" until
    /// the visa service is ready (after self-authorization, zl-zipline#285).
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

    /// A task that never ends, and a guard that records when it is dropped
    /// (the task was aborted).
    fn endless_task(
        dropped: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> impl Future<Output = ()> + Send + 'static {
        struct DropFlag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let flag = DropFlag(dropped.clone());
        async move {
            let _flag = flag;
            std::future::pending::<()>().await
        }
    }

    /// Run [supervise] over one listener task built from `listener` and one
    /// endless other task. Returns the outcome, whether the release hook ran,
    /// and whether the other task was shut down before the release ran.
    async fn supervise_one<F>(role: ListenerRole, listener: F) -> (Option<ListenerExit>, bool, bool)
    where
        F: Future<Output = Result<(), ListenerError>> + Send + 'static,
    {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let other_dropped = Arc::new(AtomicBool::new(false));
        let mut others = JoinSet::new();
        others.spawn(endless_task(&other_dropped));

        let released = Arc::new(AtomicBool::new(false));
        let others_down_at_release = Arc::new(AtomicBool::new(false));
        let outcome = {
            let (released, down, dropped) = (
                released.clone(),
                others_down_at_release.clone(),
                other_dropped.clone(),
            );
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                supervise(
                    vec![(role, tokio::spawn(listener))],
                    &mut others,
                    || async move {
                        down.store(dropped.load(Ordering::SeqCst), Ordering::SeqCst);
                        released.store(true, Ordering::SeqCst);
                    },
                ),
            )
            .await
            .expect("supervise must return when a listener ends")
        };
        (
            outcome,
            released.load(Ordering::SeqCst),
            others_down_at_release.load(Ordering::SeqCst),
        )
    }

    /// zl-zipline#266: a listener that stops with an error ends supervision.
    /// The outcome names the listener and the error, the other tasks are shut
    /// down, and only then the lock release hook runs.
    #[tokio::test]
    async fn supervise_returns_when_a_listener_fails() {
        let addr: SocketAddr = "[fd5a:5052::1]:5002".parse().unwrap();
        let (outcome, released, others_down) = supervise_one(ListenerRole::VsApi, async move {
            Err(ListenerError::stopped(
                ListenerRole::VsApi,
                addr,
                io::Error::other("accept failed"),
            ))
        })
        .await;
        let exit = outcome.expect("a listener ended, so there is an outcome");
        assert_eq!(exit.role, ListenerRole::VsApi);
        let msg = exit.to_string();
        assert!(msg.contains("VS-API"), "{msg}");
        assert!(msg.contains("[fd5a:5052::1]:5002"), "{msg}");
        assert!(msg.contains("accept failed"), "{msg}");
        assert!(released, "the lock release hook must run");
        assert!(
            others_down,
            "the other tasks (lock renewal among them) must be shut down before the release"
        );
    }

    /// A listener task that panics (the admin TLS setup `expect`s its cert
    /// files) is the same outcome, not a panic of the caller.
    #[tokio::test]
    async fn supervise_returns_when_a_listener_panics() {
        let (outcome, released, others_down) = supervise_one(ListenerRole::Admin, async move {
            panic!("failed to read admin cert file");
        })
        .await;
        let exit = outcome.expect("a listener ended, so there is an outcome");
        assert_eq!(exit.role, ListenerRole::Admin);
        assert!(exit.to_string().contains("panicked"), "{exit}");
        assert!(released && others_down);
    }

    /// A listener that returns without an error has also stopped serving.
    #[tokio::test]
    async fn supervise_returns_when_a_listener_returns_ok() {
        let (outcome, released, _) = supervise_one(ListenerRole::Admin, async { Ok(()) }).await;
        let exit = outcome.expect("a listener ended, so there is an outcome");
        assert_eq!(exit.role, ListenerRole::Admin);
        assert!(released);
    }

    /// Other tasks that finish do not end supervision while a listener runs.
    #[tokio::test]
    async fn supervise_keeps_running_while_listeners_run() {
        let mut others = JoinSet::new();
        others.spawn(async {});
        let listener = tokio::spawn(std::future::pending::<Result<(), ListenerError>>());
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            supervise(
                vec![(ListenerRole::VsApi, listener)],
                &mut others,
                || async {},
            ),
        )
        .await;
        assert!(res.is_err(), "supervise must keep running: {res:?}");
    }
}
