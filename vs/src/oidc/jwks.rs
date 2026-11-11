//! JWKS key source for OIDC trusted services (zipline#9).
//!
//! Cached signing keys for one provider: seeded from policy (`seed_jwks`),
//! refreshed periodically and on unknown `kid`, and never discarded on fetch
//! failure (stale tolerance). Refresh optionally tunnels through a
//! policy-designated CONNECT proxy so the visa service needs no direct
//! internet route.
//!
//! Proxy resolution is the caller's job (zipline#10, wired in zipline#19): when
//! policy names a `jwks_proxy_service`, `PolicyMgr::build_state` builds a
//! resolver that looks up the providing actor with
//! `ActorRepo::get_zpr_addr_for_service` and pairs it with the port from the
//! policy `Service.endpoints` scope, yielding `http://[zpr-addr]:port`.
//! Because providers come and go, the key source takes a [`ProxyResolver`]
//! callback and re-invokes it on **every** refresh rather than pinning
//! the address resolved at construction time.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use jsonwebtoken::jwk::JwkSet;
use reqwest::Url;
use tokio::task::JoinHandle;
use zpr::policy_types::OidcConfig;

use super::OidcError;

/// Hard cap on a single JWKS fetch. The refresh path must never hold a
/// connect attempt hostage: on timeout the cached keys keep serving.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum spacing between *credential-triggered* JWKS fetches
/// ([`KeySource::refresh_coalesced`]). The `kid` that triggers such a fetch
/// comes from an unverified JWT header, so without a cooldown any adapter
/// could make the visa service hammer the identity provider with one
/// outbound fetch (and up to [`FETCH_TIMEOUT`]) per bogus token. Providers
/// rotate keys rarely; 30 s bounds the flood while keeping post-rotation
/// recovery prompt. Matches `config::OIDC_NO_KEYS_RETRY_SECS`.
const REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

/// Future yielded by one [`ProxyResolver`] invocation.
pub type ProxyFuture = Pin<Box<dyn Future<Output = Option<Url>> + Send>>;

/// Resolves the CONNECT proxy's *current* URL. Invoked on every refresh so
/// a provider that disconnects and reconnects elsewhere is picked up; `None`
/// means no provider for the policy-named proxy service is connected right
/// now. Resolution is async because the production resolver reads the actor
/// database (zipline#19). Callers without a proxy requirement use
/// [`static_proxy`]`(None)`.
pub type ProxyResolver = Arc<dyn Fn() -> ProxyFuture + Send + Sync>;

/// A [`ProxyResolver`] that always yields the same answer — no proxy, or a
/// fixed URL. For production proxied refresh, prefer a closure that
/// re-resolves the providing actor each call.
pub fn static_proxy(url: Option<Url>) -> ProxyResolver {
    Arc::new(move || {
        let url = url.clone();
        Box::pin(async move { url })
    })
}

/// Cached signing keys for one provider. Seeded from policy; refreshed
/// periodically and on unknown `kid`; never discarded on fetch failure
/// (stale tolerance).
pub struct KeySource {
    /// The live key set. Swapped atomically on a successful refresh only —
    /// readers on the validation path never block and never see a partial
    /// or emptied set.
    keys: ArcSwap<JwkSet>,
    /// When the last successful fetch happened (`None` = still on the seed).
    /// Read by [`Self::refresh_coalesced`] for its single-flight check.
    last_ok: Mutex<Option<SystemTime>>,
    /// The provider's pinned policy configuration (`jwks_uri` is what we
    /// fetch; nothing else from it is consulted here).
    cfg: OidcConfig,
    /// Yields the CONNECT proxy's current URL; called on every refresh so
    /// the fetch follows the providing actor when it moves.
    proxy: ProxyResolver,
    /// Local address a *proxied* fetch binds to: the visa service's own ZPR
    /// address (`vs_addr`). The CONNECT proxy is always an actor on the
    /// ZPRnet (see `PolicyMgr`'s proxy resolver), and on a relay Zode the TUN
    /// also carries the relay's address; without a bind the kernel may pick
    /// that one and the relay drops the fetch (zl-zipline#240, the JWKS case
    /// of #228). `None` (and every direct, unproxied fetch) leaves the
    /// source to the kernel: direct egress goes to a substrate URL.
    bind_addr: Option<IpAddr>,
    /// Serializes credential-triggered refreshes so concurrent requests
    /// coalesce onto one in-flight fetch ([`Self::refresh_coalesced`]).
    refresh_gate: tokio::sync::Mutex<()>,
    /// When the last credential-triggered refresh *attempt* started (success
    /// or failure), enforcing [`REFRESH_COOLDOWN`]. Distinct from `last_ok`,
    /// which records successes only.
    last_attempt: Mutex<Option<SystemTime>>,
    /// Extra TLS trust roots for the fetch client. Production always
    /// verifies against system roots only; tests inject their self-signed
    /// server certificate here (behind a `Mutex` so a test can add roots to
    /// a `KeySource` already shared through an `Arc`).
    #[cfg(test)]
    extra_roots: Mutex<Vec<reqwest::Certificate>>,
}

impl KeySource {
    /// Build a key source from policy. Parses `seed_jwks`; fails with
    /// [`OidcError::NoKeys`] when the seed is empty and no fetch route
    /// exists (no `jwks_uri`, or policy demands a proxy that is not
    /// resolved), because such a source could never produce a key. When
    /// policy names a proxy, `jwks_uri` must be `https://`: the CONNECT
    /// proxy tunnels HTTPS only, so a plain-http URI would silently
    /// bypass the policy-designated proxy and fetch in cleartext.
    pub async fn from_policy(cfg: &OidcConfig, proxy: ProxyResolver) -> Result<Self, OidcError> {
        let seed: JwkSet = if cfg.seed_jwks.trim().is_empty() {
            JwkSet { keys: Vec::new() }
        } else {
            // The seed comes from signed policy, not the network, but a
            // typo'd seed must fail loudly at load time, not at first use.
            serde_json::from_str(&cfg.seed_jwks)
                .map_err(|_| OidcError::Rejected("seed_jwks does not parse as a JWKS".into()))?
        };

        let uri = cfg.jwks_uri.trim();
        if cfg.jwks_proxy_service.is_some() && !uri.is_empty() && !uri.starts_with("https://") {
            return Err(OidcError::Rejected(
                "jwks_uri must be https:// when a jwks proxy is configured \
                 (the CONNECT proxy tunnels HTTPS only; an http:// fetch \
                 would bypass it in cleartext)"
                    .into(),
            ));
        }

        if seed.keys.is_empty() {
            // No seed: the source is only viable if a refresh could succeed.
            let proxy_required_but_missing =
                cfg.jwks_proxy_service.is_some() && proxy().await.is_none();
            if uri.is_empty() || proxy_required_but_missing {
                return Err(OidcError::NoKeys);
            }
        }

        Ok(KeySource {
            keys: ArcSwap::from_pointee(seed),
            last_ok: Mutex::new(None),
            cfg: cfg.clone(),
            proxy,
            bind_addr: None,
            refresh_gate: tokio::sync::Mutex::new(()),
            last_attempt: Mutex::new(None),
            #[cfg(test)]
            extra_roots: Mutex::new(Vec::new()),
        })
    }

    /// Set the local address that proxied fetches bind to (see the
    /// `bind_addr` field). Builder-style so construction sites that never
    /// proxy (tests, direct egress) need not change.
    pub fn with_bind_addr(mut self, bind_addr: Option<IpAddr>) -> Self {
        self.bind_addr = bind_addr;
        self
    }

    /// The local address proxied fetches bind to (test-only observability
    /// for the factory wiring, zl-zipline#240).
    #[cfg(test)]
    pub(crate) fn bind_addr(&self) -> Option<IpAddr> {
        self.bind_addr
    }

    /// The current key set. Lock-free; safe to call on the hot path.
    pub fn current(&self) -> Arc<JwkSet> {
        self.keys.load_full()
    }

    /// Trust an extra TLS root for fetches (tests only; production verifies
    /// against system roots). Takes `&self` so tests can inject a root into a
    /// key source already built and shared by the policy machinery.
    #[cfg(test)]
    pub(crate) fn add_extra_root(&self, cert: reqwest::Certificate) {
        self.extra_roots
            .lock()
            .expect("extra_roots lock poisoned")
            .push(cert);
    }

    /// When the last successful fetch happened (`None` = still serving the
    /// policy seed).
    pub fn last_ok(&self) -> Option<SystemTime> {
        *self.last_ok.lock().expect("last_ok lock poisoned")
    }

    /// Fetch `jwks_uri` and replace the cached set. On any failure the old
    /// keys keep serving (stale tolerance) and the error is returned. The
    /// response body is never logged and never echoed in errors.
    ///
    /// The proxy is re-resolved on every call (providers come and go);
    /// redirects are never followed (a redirect off HTTPS would leak the
    /// fetch, and a redirect anywhere else changes the pinned policy URL);
    /// and the body is read under [`crate::http_util::MAX_RESPONSE_BYTES`].
    pub async fn refresh(&self) -> Result<(), OidcError> {
        if self.cfg.jwks_uri.trim().is_empty() {
            return Err(OidcError::Rejected("no jwks_uri to refresh from".into()));
        }
        // Re-resolve the proxy: the providing actor may have disconnected
        // or reconnected at a new address since the last refresh.
        let proxy_url = (self.proxy)().await;
        if self.cfg.jwks_proxy_service.is_some() && proxy_url.is_none() {
            // Policy routes this fetch through a proxy and no provider is
            // connected right now; the seed/stale keys keep serving.
            return Err(OidcError::Rejected("proxy not reachable".into()));
        }

        let mut builder = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            // Never follow redirects: the jwks_uri is pinned by policy, and
            // a redirect could steer the fetch to a non-HTTPS URL (leaking
            // it in plaintext, outside the CONNECT proxy when one is set).
            .redirect(reqwest::redirect::Policy::none());
        if let Some(proxy_url) = &proxy_url {
            // CONNECT tunnel: TLS runs end-to-end to the provider; the proxy
            // sees only `CONNECT host:port`, never the request.
            let proxy = reqwest::Proxy::https(proxy_url.clone())
                .map_err(|e| OidcError::Rejected(format!("bad proxy url: {e}")))?;
            // The proxy is an actor on the ZPRnet: leave from our own ZPR
            // address, not whatever source the kernel picks (see `bind_addr`).
            builder = builder.proxy(proxy).local_address(self.bind_addr);
        }
        #[cfg(test)]
        for cert in self
            .extra_roots
            .lock()
            .expect("extra_roots lock poisoned")
            .iter()
        {
            builder = builder.add_root_certificate(cert.clone());
        }
        let client = builder
            .build()
            .map_err(|e| OidcError::Rejected(format!("http client: {e}")))?;

        let mut resp = client
            .get(&self.cfg.jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::Rejected(format!("JWKS fetch failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            // With redirects disabled a 3xx lands here too, which is the
            // intended fate of any attempt to move the pinned jwks_uri.
            return Err(OidcError::Rejected(format!(
                "JWKS fetch returned status {status}"
            )));
        }

        // Read the body under an explicit cap: a hostile or broken provider
        // must not be able to balloon memory with an unbounded response.
        let body = crate::http_util::read_body_capped(&mut resp, "JWKS response")
            .await
            .map_err(|e| OidcError::Rejected(e.to_string()))?;

        // Parse failures and an empty set are fetch failures, not
        // replacements — a provider serving garbage must not wipe the keys.
        let fetched: JwkSet = serde_json::from_slice(&body)
            .map_err(|_| OidcError::Rejected("fetched JWKS does not parse".into()))?;
        if fetched.keys.is_empty() {
            return Err(OidcError::Rejected("fetched JWKS is empty".into()));
        }

        self.keys.store(Arc::new(fetched));
        *self.last_ok.lock().expect("last_ok lock poisoned") = Some(SystemTime::now());
        Ok(())
    }

    /// Credential-triggered refresh: coalesced and rate-limited.
    ///
    /// The connect path calls this when an id_token names an unknown `kid` or
    /// the cache has no keys yet. Both triggers derive from *unverified*
    /// attacker-suppliable input, so unlike [`Self::refresh`] this entry
    /// point:
    ///
    /// - **single-flights**: concurrent callers share one in-flight fetch
    ///   (a caller that waited out someone else's successful fetch returns
    ///   `Ok` without fetching again), and
    /// - **rate-limits**: an attempt within [`REFRESH_COOLDOWN`] of the
    ///   previous one is refused without touching the network, so a flood of
    ///   bogus tokens cannot make the visa service hammer the provider.
    ///
    /// The periodic refresher keeps using [`Self::refresh`] directly — it is
    /// not attacker-triggerable and must not be starved by the cooldown.
    pub async fn refresh_coalesced(&self) -> Result<(), OidcError> {
        let entered = SystemTime::now();
        let _gate = self.refresh_gate.lock().await;

        // Single-flight: a fetch that succeeded while we waited on the gate
        // already delivered the keys we came for — share it, don't re-fetch.
        if self.last_ok().is_some_and(|ok| ok >= entered) {
            return Ok(());
        }

        // Cooldown: refuse without touching the network when the previous
        // attempt (success or failure) is too recent. This also covers the
        // waiter whose leader's fetch just *failed* — retrying immediately
        // would only double the hammering the leader already took the error
        // for.
        let previous_attempt = *self
            .last_attempt
            .lock()
            .expect("last_attempt lock poisoned");
        if let Some(attempt) = previous_attempt {
            let since = SystemTime::now()
                .duration_since(attempt)
                .unwrap_or(Duration::ZERO);
            if since < REFRESH_COOLDOWN {
                return Err(OidcError::Rejected(
                    "JWKS refresh in cooldown; cached keys keep serving".into(),
                ));
            }
        }

        *self
            .last_attempt
            .lock()
            .expect("last_attempt lock poisoned") = Some(SystemTime::now());
        self.refresh().await
    }

    /// Refresh every `period` in a background task. Failures are logged
    /// (never the body) and the stale keys keep serving until the next tick.
    /// Deliberately bypasses the [`Self::refresh_coalesced`] cooldown: the
    /// periodic tick is operator-configured (`oidc_refresh_seconds`), not
    /// attacker-triggerable.
    pub fn spawn_refresher(self: Arc<Self>, period: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(period).await;
                if let Err(e) = self.refresh().await {
                    tracing::warn!("periodic JWKS refresh failed: {e}");
                }
            }
        })
    }
}

/// Shared test scaffolding for JWKS-related tests: the fixture key sets and
/// the local JWKS / CONNECT-proxy stub servers. `pub(crate)` so the
/// `policy_mgr` tests exercising the ActorDb-backed proxy resolver
/// (zipline#19) reuse the same stubs instead of forking them.
#[cfg(test)]
pub(crate) mod test_support {
    use axum::http::StatusCode;
    use jsonwebtoken::jwk::JwkSet;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    /// The zipline#8 fixture JWKS (kid "k1").
    pub(crate) fn seed_jwks_json() -> &'static str {
        include_str!("../../tests/data/oidc-test-jwks.json")
    }

    /// The fixture key re-labelled kid "k2" — same key material, different
    /// id; enough to observe a refresh replacing the cached set.
    pub(crate) fn k2_jwks_json() -> String {
        let mut v: serde_json::Value = serde_json::from_str(seed_jwks_json()).unwrap();
        v["keys"][0]["kid"] = serde_json::json!("k2");
        v.to_string()
    }

    pub(crate) fn kids(set: &JwkSet) -> Vec<String> {
        set.keys
            .iter()
            .filter_map(|k| k.common.key_id.clone())
            .collect()
    }

    use zpr::policy_types::OidcConfig;

    pub(crate) fn cfg(seed: &str, jwks_uri: &str, proxy_service: Option<&str>) -> OidcConfig {
        OidcConfig {
            issuer: "https://accounts.google.com".to_string(),
            jwks_uri: jwks_uri.to_string(),
            client_id: "test-client-id.apps.googleusercontent.com".to_string(),
            seed_jwks: seed.to_string(),
            jwks_proxy_service: proxy_service.map(|s| s.to_string()),
            ..OidcConfig::default()
        }
    }

    /// Plain-HTTP axum server answering `status`/`body` on `/jwks`.
    pub(crate) async fn spawn_jwks_server(status: StatusCode, body: String) -> SocketAddr {
        let app = axum::Router::new().route(
            "/jwks",
            axum::routing::get(move || {
                let body = body.clone();
                async move { (status, body) }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// TLS responder that answers every request with a 302 redirect to
    /// `location`. Used to prove that a fetch is never allowed to follow a
    /// redirect off HTTPS (which would leak the request in plaintext and,
    /// when proxied, bypass the CONNECT proxy's policy routing).
    pub(crate) async fn spawn_tls_redirect_server(
        location: String,
    ) -> (SocketAddr, reqwest::Certificate) {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let client_cert = reqwest::Certificate::from_pem(ck.cert.pem().as_bytes()).unwrap();
        let chain = vec![ck.cert.der().clone()];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()),
        );
        let tls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let location = location.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match tls.read(&mut byte).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => head.push(byte[0]),
                        }
                    }
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (addr, client_cert)
    }

    /// TLS JWKS responder for the CONNECT test. reqwest tunnels TLS
    /// end-to-end through the proxy (that is the point of the assertion), so
    /// the upstream behind the tunnel must speak TLS; the returned
    /// certificate is handed to the client as an extra trust root.
    pub(crate) async fn spawn_tls_jwks_server(body: String) -> (SocketAddr, reqwest::Certificate) {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let client_cert = reqwest::Certificate::from_pem(ck.cert.pem().as_bytes()).unwrap();
        let chain = vec![ck.cert.der().clone()];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()),
        );
        let tls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let body = body.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    // Read the request head (tiny GET; stop at the blank line).
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match tls.read(&mut byte).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => head.push(byte[0]),
                        }
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (addr, client_cert)
    }

    /// CONNECT-speaking stub proxy (written to be liftable for zipline#16): records
    /// each connection's request line, answers `HTTP/1.1 200` to a CONNECT,
    /// then splices bytes to `upstream`. Anything that is not a CONNECT is
    /// recorded and dropped.
    pub(crate) async fn spawn_connect_stub(
        upstream: SocketAddr,
    ) -> (SocketAddr, mpsc::UnboundedReceiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match client.read(&mut byte).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => head.push(byte[0]),
                        }
                    }
                    let head = String::from_utf8_lossy(&head);
                    let first = head.lines().next().unwrap_or_default().to_string();
                    let is_connect = first.starts_with("CONNECT ");
                    let _ = tx.send(first);
                    if !is_connect {
                        return;
                    }
                    let Ok(mut server) = TcpStream::connect(upstream).await else {
                        return;
                    };
                    if client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                });
            }
        });
        (addr, rx)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use axum::http::StatusCode;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_seed_serves_before_first_fetch() {
        // No server is started: the seed alone must serve.
        let c = cfg(seed_jwks_json(), "https://idp.invalid/jwks", None);
        let ks = KeySource::from_policy(&c, static_proxy(None))
            .await
            .unwrap();
        assert_eq!(kids(&ks.current()), vec!["k1".to_string()]);
    }

    #[tokio::test]
    async fn test_refresh_replaces_keys() {
        let addr = spawn_jwks_server(StatusCode::OK, k2_jwks_json()).await;
        let c = cfg(seed_jwks_json(), &format!("http://{addr}/jwks"), None);
        let ks = KeySource::from_policy(&c, static_proxy(None))
            .await
            .unwrap();
        ks.refresh().await.unwrap();
        let got = kids(&ks.current());
        assert!(got.contains(&"k2".to_string()), "{got:?}");
        assert!(
            !got.contains(&"k1".to_string()),
            "fetched set must replace the seed-only view: {got:?}"
        );
    }

    #[tokio::test]
    async fn test_refresh_failure_keeps_stale_keys() {
        let addr = spawn_jwks_server(StatusCode::INTERNAL_SERVER_ERROR, String::new()).await;
        let c = cfg(seed_jwks_json(), &format!("http://{addr}/jwks"), None);
        let ks = KeySource::from_policy(&c, static_proxy(None))
            .await
            .unwrap();
        ks.refresh().await.unwrap_err();
        // Stale tolerance: the pre-failure keys keep serving.
        assert_eq!(kids(&ks.current()), vec!["k1".to_string()]);
    }

    #[tokio::test]
    async fn test_refresh_via_connect_proxy() {
        let (upstream, cert) = spawn_tls_jwks_server(k2_jwks_json()).await;
        let (proxy_addr, mut lines) = spawn_connect_stub(upstream).await;
        let c = cfg(
            seed_jwks_json(),
            &format!("https://127.0.0.1:{}/jwks", upstream.port()),
            Some("egress-proxy"),
        );
        let proxy_url = reqwest::Url::parse(&format!("http://{proxy_addr}")).unwrap();
        let ks = KeySource::from_policy(&c, static_proxy(Some(proxy_url)))
            .await
            .unwrap();
        // Trust the test server's self-signed cert; production uses system roots.
        ks.extra_roots.lock().unwrap().push(cert);
        ks.refresh().await.unwrap();
        assert!(kids(&ks.current()).contains(&"k2".to_string()));

        let mut seen = Vec::new();
        while let Ok(l) = lines.try_recv() {
            seen.push(l);
        }
        assert_eq!(
            seen.len(),
            1,
            "proxy must see exactly one request: {seen:?}"
        );
        assert!(
            seen[0].starts_with(&format!("CONNECT 127.0.0.1:{} ", upstream.port())),
            "expected a CONNECT to the upstream, got: {:?}",
            seen[0]
        );
        assert!(
            !seen.iter().any(|l| l.starts_with("GET ")),
            "a plaintext GET through the proxy would expose the request: {seen:?}"
        );
    }

    /// zl-zipline#240: a proxied fetch must leave from `bind_addr` (the visa
    /// service's `vs_addr`), not a kernel-chosen source. 127.0.0.1 and
    /// 127.0.0.2 are both local on one interface, which is the relay's
    /// situation (same trick as #228's `vss_connect_originates_from_vs_addr`).
    /// The fake proxy only records who connected; the fetch itself fails.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_proxied_refresh_originates_from_bind_addr() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (_sock, peer) = listener.accept().await.unwrap();
            peer.ip()
        });

        let c = cfg(
            seed_jwks_json(),
            "https://idp.invalid/jwks",
            Some("egress-proxy"),
        );
        let proxy_url = reqwest::Url::parse(&format!("http://{proxy_addr}")).unwrap();
        let bind: std::net::IpAddr = "127.0.0.2".parse().unwrap();
        let ks = KeySource::from_policy(&c, static_proxy(Some(proxy_url)))
            .await
            .unwrap()
            .with_bind_addr(Some(bind));
        // The stub never answers the CONNECT, so the fetch fails or times out;
        // only the source address of the TCP connection matters.
        let _ = tokio::time::timeout(Duration::from_secs(5), ks.refresh()).await;

        let peer_ip = tokio::time::timeout(Duration::from_secs(5), accepted)
            .await
            .expect("no connection reached the proxy")
            .unwrap();
        assert_eq!(
            peer_ip, bind,
            "a proxied JWKS fetch must originate from bind_addr"
        );
    }

    #[tokio::test]
    async fn test_proxy_with_http_jwks_uri_rejected() {
        // Review fix (PR #4): the CONNECT proxy is HTTPS-only, so an
        // `http://` jwks_uri would silently bypass the policy-designated
        // proxy and fetch in plaintext. Policy that names a proxy must
        // therefore carry an https jwks_uri; anything else fails at load.
        let c = cfg(
            seed_jwks_json(),
            "http://idp.invalid/jwks",
            Some("egress-proxy"),
        );
        let proxy_url = reqwest::Url::parse("http://127.0.0.1:3128").unwrap();
        let err = KeySource::from_policy(&c, static_proxy(Some(proxy_url)))
            .await
            .err()
            .expect("http jwks_uri with a proxy configured must be rejected");
        assert!(
            matches!(&err, OidcError::Rejected(m) if m.contains("https")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn test_redirect_off_https_is_refused() {
        // A redirect from the https jwks_uri to a plain-http URL must not
        // be followed: it would leak the fetch in plaintext (and, when
        // proxied, step around the HTTPS-only CONNECT proxy). The stale
        // keys keep serving.
        let plain = spawn_jwks_server(StatusCode::OK, k2_jwks_json()).await;
        let (redirector, cert) = spawn_tls_redirect_server(format!("http://{plain}/jwks")).await;
        let c = cfg(
            seed_jwks_json(),
            &format!("https://127.0.0.1:{}/jwks", redirector.port()),
            None,
        );
        let ks = KeySource::from_policy(&c, static_proxy(None))
            .await
            .unwrap();
        ks.extra_roots.lock().unwrap().push(cert);
        ks.refresh()
            .await
            .expect_err("redirect to non-HTTPS must fail the refresh");
        // Stale tolerance: the seed keeps serving.
        assert_eq!(kids(&ks.current()), vec!["k1".to_string()]);
    }

    #[tokio::test]
    async fn test_refresh_re_resolves_proxy() {
        // Review fix (PR #4): the proxy is re-resolved on every refresh, so
        // when the providing actor moves, the next refresh follows it
        // instead of hitting the stale address forever.
        let (upstream, cert) = spawn_tls_jwks_server(k2_jwks_json()).await;

        // A dead proxy address: bind and immediately drop the listener.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let slot: Arc<std::sync::Mutex<Option<reqwest::Url>>> = Arc::new(std::sync::Mutex::new(
            Some(reqwest::Url::parse(&format!("http://{dead_addr}")).unwrap()),
        ));
        let resolver: ProxyResolver = {
            let slot = slot.clone();
            Arc::new(move || {
                let url = slot.lock().unwrap().clone();
                Box::pin(async move { url }) as ProxyFuture
            })
        };

        let c = cfg(
            seed_jwks_json(),
            &format!("https://127.0.0.1:{}/jwks", upstream.port()),
            Some("egress-proxy"),
        );
        let ks = KeySource::from_policy(&c, resolver).await.unwrap();
        ks.extra_roots.lock().unwrap().push(cert);

        // Old provider is gone: the refresh fails, stale keys keep serving.
        ks.refresh()
            .await
            .expect_err("refresh through a dead proxy must fail");
        assert_eq!(kids(&ks.current()), vec!["k1".to_string()]);

        // A new provider connects at a different address; the next refresh
        // must pick it up without rebuilding the KeySource.
        let (new_proxy, mut lines) = spawn_connect_stub(upstream).await;
        *slot.lock().unwrap() = Some(reqwest::Url::parse(&format!("http://{new_proxy}")).unwrap());
        ks.refresh().await.unwrap();
        assert!(kids(&ks.current()).contains(&"k2".to_string()));
        let first = lines.try_recv().expect("new proxy must see the CONNECT");
        assert!(first.starts_with("CONNECT "), "{first:?}");
    }

    #[tokio::test]
    async fn test_oversized_jwks_rejected() {
        // Review fix (PR #4): the response body is read under an explicit
        // byte cap so a hostile or broken provider cannot balloon memory.
        // The oversized body is a fetch failure; stale keys keep serving.
        let mut v: serde_json::Value = serde_json::from_str(&k2_jwks_json()).unwrap();
        v["pad"] = serde_json::json!(" ".repeat(2 * 1024 * 1024));
        let addr = spawn_jwks_server(StatusCode::OK, v.to_string()).await;
        let c = cfg(seed_jwks_json(), &format!("http://{addr}/jwks"), None);
        let ks = KeySource::from_policy(&c, static_proxy(None))
            .await
            .unwrap();
        let err = ks
            .refresh()
            .await
            .expect_err("a multi-megabyte JWKS body must be rejected");
        assert!(
            matches!(&err, OidcError::Rejected(m) if m.contains("large")),
            "{err}"
        );
        assert_eq!(kids(&ks.current()), vec!["k1".to_string()]);
    }

    /// Counting JWKS responder: like [spawn_jwks_server] but records how many
    /// requests it served and holds each response for `delay` (so concurrent
    /// callers demonstrably overlap).
    async fn spawn_counting_jwks_server(
        body: String,
        delay: Duration,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = count.clone();
        let app = axum::Router::new().route(
            "/jwks",
            axum::routing::get(move || {
                let body = body.clone();
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    body
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr, count)
    }

    #[tokio::test]
    async fn test_coalesced_refresh_single_flight() {
        // Review fix (PR #6): the `kid` that triggers a connect-path refresh
        // comes from an unverified JWT header, so a flood of bogus kids must
        // not fan out into a fetch per request. Concurrent coalesced
        // refreshes share one in-flight fetch.
        let (addr, count) =
            spawn_counting_jwks_server(k2_jwks_json(), Duration::from_millis(300)).await;
        let c = cfg(seed_jwks_json(), &format!("http://{addr}/jwks"), None);
        let ks = Arc::new(
            KeySource::from_policy(&c, static_proxy(None))
                .await
                .unwrap(),
        );

        let tasks: Vec<_> = (0..5)
            .map(|_| {
                let ks = ks.clone();
                tokio::spawn(async move { ks.refresh_coalesced().await })
            })
            .collect();
        for t in tasks {
            t.await
                .unwrap()
                .expect("every coalesced caller shares the successful fetch");
        }

        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "five concurrent refreshes must produce exactly one fetch"
        );
        assert!(kids(&ks.current()).contains(&"k2".to_string()));
    }

    #[tokio::test]
    async fn test_coalesced_refresh_cooldown_blocks_repeat() {
        // Review fix (PR #6): sequential attacker-triggered refreshes are
        // rate-limited per provider — a second coalesced refresh inside the
        // cooldown window never reaches the network.
        let (addr, count) = spawn_counting_jwks_server(k2_jwks_json(), Duration::ZERO).await;
        let c = cfg(seed_jwks_json(), &format!("http://{addr}/jwks"), None);
        let ks = KeySource::from_policy(&c, static_proxy(None))
            .await
            .unwrap();

        ks.refresh_coalesced().await.unwrap();
        let err = ks
            .refresh_coalesced()
            .await
            .expect_err("a repeat refresh inside the cooldown must be refused");
        assert!(
            matches!(&err, OidcError::Rejected(m) if m.contains("cooldown")),
            "{err}"
        );
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the cooldown-blocked refresh must not fetch"
        );
    }

    #[tokio::test]
    async fn test_plain_refresh_bypasses_cooldown() {
        // The raw `refresh()` entry point (periodic refresher, tests) is not
        // attacker-triggerable and deliberately ignores the cooldown.
        let (addr, count) = spawn_counting_jwks_server(k2_jwks_json(), Duration::ZERO).await;
        let c = cfg(seed_jwks_json(), &format!("http://{addr}/jwks"), None);
        let ks = KeySource::from_policy(&c, static_proxy(None))
            .await
            .unwrap();

        ks.refresh_coalesced().await.unwrap();
        ks.refresh().await.unwrap();
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_no_seed_no_route_is_nokeys() {
        // Policy demands a proxy, none is connected, and the seed is empty.
        let c = cfg("", "https://idp.invalid/jwks", Some("egress-proxy"));
        let err = KeySource::from_policy(&c, static_proxy(None))
            .await
            .err()
            .expect("empty seed with unreachable proxy must be NoKeys");
        assert!(matches!(err, OidcError::NoKeys), "{err}");
        // Likewise with no fetch route at all (empty jwks_uri, no proxy).
        let c2 = cfg("", "", None);
        let err2 = KeySource::from_policy(&c2, static_proxy(None))
            .await
            .err()
            .expect("empty seed with no jwks_uri must be NoKeys");
        assert!(matches!(err2, OidcError::NoKeys), "{err2}");
    }
}
