use hyper::{
    body::Body,
    client::HttpConnector,
    header::{HeaderValue, HOST},
    server::conn::Http,
    service::service_fn,
    Client, Request, Response, Uri,
};
use rcgen::generate_simple_self_signed;
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use tracing_appender::rolling;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer};

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

const MAX_REQUESTS: u32 = 5;
const WINDOW_SECS:  u64 = 10;

struct IpWindow {
    count:        u32,
    window_start: Instant,
}

impl IpWindow {
    fn new() -> Self {
        Self { count: 0, window_start: Instant::now() }
    }

    fn allow(&mut self) -> bool {
        if self.window_start.elapsed().as_secs() >= WINDOW_SECS {
            self.count        = 0;
            self.window_start = Instant::now();
        }
        if self.count < MAX_REQUESTS {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

struct RateLimiter {
    windows: Mutex<HashMap<String, IpWindow>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self { windows: Mutex::new(HashMap::new()) }
    }

    async fn allow(&self, ip: &str) -> bool {
        let mut map = self.windows.lock().await;
        map.entry(ip.to_owned()).or_insert_with(IpWindow::new).allow()
    }
}

// ─── Security Headers ─────────────────────────────────────────────────────────

fn add_security_headers(response: &mut Response<Body>) {
    let h = response.headers_mut();
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
}

// ─── Backend ──────────────────────────────────────────────────────────────────

struct Backend {
    url: String,
    healthy: AtomicBool,
}

impl Backend {
    fn new(url: &str) -> Self {
        Self { url: url.to_owned(), healthy: AtomicBool::new(true) }
    }

    fn is_healthy(&self) -> bool { self.healthy.load(Ordering::Relaxed) }

    fn mark_unhealthy(&self) {
        self.healthy.store(false, Ordering::Relaxed);
        warn!(backend = %self.url, "Backend marked UNHEALTHY");
    }

    fn mark_healthy(&self) {
        self.healthy.store(true, Ordering::Relaxed);
        info!(backend = %self.url, "Backend marked HEALTHY");
    }
}

// ─── Config ───────────────────────────────────────────────────────────────────

struct ProxyConfig {
    request_timeout: Duration,
    health_check_interval: Duration,
}

// ─── Shared State ─────────────────────────────────────────────────────────────

struct ProxyState {
    backends: Vec<Arc<Backend>>,
    counter: AtomicUsize,
    client: Client<HttpConnector>,
    config: ProxyConfig,
    rate_limiter: RateLimiter,
}

impl ProxyState {
    fn next_healthy_backend(&self) -> Option<Arc<Backend>> {
        let total = self.backends.len();
        let start = self.counter.fetch_add(1, Ordering::Relaxed) % total;
        for i in 0..total {
            let b = &self.backends[(start + i) % total];
            if b.is_healthy() { return Some(Arc::clone(b)); }
        }
        None
    }
}

// ─── Request Forwarding ───────────────────────────────────────────────────────

async fn forward_request(
    state: Arc<ProxyState>,
    peer_addr: SocketAddr,
    incoming: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    let start  = Instant::now();
    let method = incoming.method().clone();
    let path   = incoming.uri().path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    let client_ip = incoming.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| peer_addr.ip().to_string());

    info!(method = %method, path = %path, client_ip = %client_ip, "Incoming request");

    // ── Rate limit ────────────────────────────────────────────────────────
    if !state.rate_limiter.allow(&client_ip).await {
        warn!(
            client_ip = %client_ip,
            method    = %method,
            path      = %path,
            limit     = MAX_REQUESTS,
            window    = WINDOW_SECS,
            "Rate limit exceeded — 429"
        );
        return Ok(Response::builder()
            .status(429)
            .header("retry-after", WINDOW_SECS.to_string())
            .header("x-content-type-options", "nosniff")
            .header("strict-transport-security", "max-age=31536000; includeSubDomains")
            .body(Body::from(format!(
                "429 Too Many Requests — limit is {} per {}s\n", MAX_REQUESTS, WINDOW_SECS
            )))
            .unwrap());
    }

    // ── Pick backend ──────────────────────────────────────────────────────
    let backend = match state.next_healthy_backend() {
        Some(b) => b,
        None => {
            error!(method = %method, path = %path, "No healthy backends available — 503");
            return Ok(Response::builder()
                .status(503)
                .header("x-content-type-options", "nosniff")
                .body(Body::from("503 Service Unavailable\n"))
                .unwrap());
        }
    };

    info!(backend = %backend.url, "Routing request");

    // ── Rewrite request ───────────────────────────────────────────────────
    let forwarded_uri = format!("{}{}", backend.url, path).parse::<Uri>().unwrap();
    let (mut parts, body) = incoming.into_parts();
    parts.uri = forwarded_uri;

    let host = backend.url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    parts.headers.insert(HOST, HeaderValue::from_str(host).unwrap());
    parts.headers.insert("x-forwarded-for",   HeaderValue::from_str(&client_ip).unwrap());
    parts.headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    parts.headers.insert("x-forwarded-by",    HeaderValue::from_static("hyper-tls-proxy"));

    let outgoing = Request::from_parts(parts, body);

    match timeout(state.config.request_timeout, state.client.request(outgoing)).await {
        Ok(Ok(mut response)) => {
            add_security_headers(&mut response);
            let elapsed = start.elapsed();
            info!(
                method    = %method,
                path      = %path,
                status    = %response.status(),
                backend   = %backend.url,
                latency   = ?elapsed,
                "Request completed"
            );
            Ok(response)
        }
        Ok(Err(e)) => {
            error!(backend = %backend.url, error = %e, "Backend connection failed — 502");
            backend.mark_unhealthy();
            spawn_recovery(Arc::clone(&backend), state.client.clone(), state.config.health_check_interval);
            Ok(Response::builder().status(502)
                .header("x-content-type-options", "nosniff")
                .body(Body::from("502 Bad Gateway\n")).unwrap())
        }
        Err(_) => {
            error!(backend = %backend.url, "Backend timed out — 504");
            backend.mark_unhealthy();
            spawn_recovery(Arc::clone(&backend), state.client.clone(), state.config.health_check_interval);
            Ok(Response::builder().status(504)
                .header("x-content-type-options", "nosniff")
                .body(Body::from("504 Gateway Timeout\n")).unwrap())
        }
    }
}

// ─── Recovery ─────────────────────────────────────────────────────────────────

fn spawn_recovery(backend: Arc<Backend>, client: Client<HttpConnector>, interval: Duration) {
    tokio::spawn(async move {
        let health_url = format!("{}/", backend.url).parse::<Uri>().unwrap();
        loop {
            tokio::time::sleep(interval).await;
            info!(backend = %backend.url, "Probing backend for recovery");
            let probe = Request::builder().method("GET")
                .uri(health_url.clone()).body(Body::empty()).unwrap();
            match timeout(Duration::from_secs(3), client.request(probe)).await {
                Ok(Ok(_)) => { backend.mark_healthy(); return; }
                _         => { warn!(backend = %backend.url, "Backend still unreachable"); }
            }
        }
    });
}

// ─── TLS Certificate ──────────────────────────────────────────────────────────

fn build_tls_config() -> Arc<ServerConfig> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .expect("failed to generate cert");

    let cert_pem = cert.serialize_pem().unwrap();
    let key_pem  = cert.serialize_private_key_pem();

    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let mut key_reader  = std::io::BufReader::new(key_pem.as_bytes());

    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut cert_reader)
        .unwrap().into_iter().map(Certificate).collect();
    let mut keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .unwrap().into_iter().map(PrivateKey).collect();

    Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .expect("TLS config failed")
    )
}

// ─── Logging Setup ────────────────────────────────────────────────────────────

fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::new("info");
    // Daily rolling log file → logs/proxy.YYYY-MM-DD
    let file_appender = rolling::daily("logs", "proxy.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // File layer — writes structured logs with timestamps to disk
    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)           // no color codes in log files
        .with_target(false)         // skip module path
        .with_thread_ids(false)
        .json();                    // machine-readable JSON format

    // Console layer — human-readable colored output in terminal
    let console_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .with_target(false)
        .compact();

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(console_layer)
        .init();
    guard
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Must be called before any logging
    let _guard = init_logging(); // keep alive for entire program

    let backends: Vec<Arc<Backend>> = vec![
        Arc::new(Backend::new("http://localhost:3000")),
        Arc::new(Backend::new("http://localhost:3001")),
        Arc::new(Backend::new("http://localhost:3002")),
    ];

    let https_addr: SocketAddr = "0.0.0.0:8443".parse().unwrap();

    info!("=========================================");
    info!("  Hyper Reverse Proxy — HTTPS/TLS        ");
    info!("=========================================");
    info!(address = %https_addr, "Listening on HTTPS");
    info!(strategy = "Round Robin + Failover", "Load balancing");
    info!(limit = MAX_REQUESTS, window_secs = WINDOW_SECS, "Rate limiting");
    info!(log_dir = "logs/", "Logging to file");
    for (i, b) in backends.iter().enumerate() {
        info!(index = i + 1, url = %b.url, "Backend registered");
    }

    let state = Arc::new(ProxyState {
        backends,
        counter: AtomicUsize::new(0),
        client: Client::new(),
        config: ProxyConfig {
            request_timeout: Duration::from_secs(10),
            health_check_interval: Duration::from_secs(5),
        },
        rate_limiter: RateLimiter::new(),
    });

    let tls_acceptor = TlsAcceptor::from(build_tls_config());
    let listener     = TcpListener::bind(https_addr).await.expect("failed to bind");

    info!("Proxy is ready — accepting connections");

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(v)  => v,
            Err(e) => { error!(error = %e, "TCP accept failed"); continue; }
        };

        let tls_acceptor = tls_acceptor.clone();
        let state        = Arc::clone(&state);

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(s)  => s,
                Err(e) => {
                    warn!(peer = %peer_addr, error = %e, "TLS handshake failed");
                    return;
                }
            };

            if let Err(e) = Http::new()
                .serve_connection(tls_stream, service_fn(move |req| {
                    forward_request(Arc::clone(&state), peer_addr, req)
                }))
                .await
            {
                if !e.is_incomplete_message() {
                    error!(peer = %peer_addr, error = %e, "Connection error");
                }
            }
        });
    }
}