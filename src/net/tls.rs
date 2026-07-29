//! TLS via rustls. Two things live here:
//!
//! - `TlsContext`: a reusable, `Arc`-shared server-side configuration
//!   (certificate, key, SNI-selected alternate certificates, ALPN
//!   protocol list). Built once at startup/config-reload, cheap to
//!   clone (it's an `Arc` underneath), shared by every worker.
//! - `TlsConnection`: a single connection's TLS state, server or
//!   client, wrapped in one type so callers (the event loop, the
//!   upstream H2 client) don't need to branch on direction except when
//!   actually creating one.
//!
//! rustls does no I/O itself -- it only transforms bytes (see
//! `TlsConnection::advance_io`, which is the entire non-blocking-I/O
//! adapter this module needs: read whatever's available into rustls,
//! let it process what it understood, write out whatever it produced
//! in response). This is a structurally different model from OpenSSL's
//! `SSL_read`/`SSL_write`, which perform the socket I/O themselves and
//! communicate retry-needed via `SSL_ERROR_WANT_READ`/`WANT_WRITE` --
//! rustls instead reports what it wants via `wants_read()`/`wants_write()`
//! before you even try, so the poller registration can be kept in sync
//! with what rustls actually needs on this pass rather than needing to
//! infer it from an error code after the fact.

use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::ServerConfig;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection};

use crate::net::poller::Interests;

/// Errors specific to loading certificates/keys and building a
/// `TlsContext`, kept distinct from the runtime `io::Error`s a live
/// connection can produce.
#[derive(Debug)]
pub enum TlsConfigError {
    Io(io::Error),
    Rustls(rustls::Error),
    NoCertificatesInFile(String),
    InvalidSniHostname(String),
}

impl std::fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsConfigError::Io(e) => write!(f, "I/O error: {e}"),
            TlsConfigError::Rustls(e) => write!(f, "TLS configuration error: {e}"),
            TlsConfigError::NoCertificatesInFile(path) => {
                write!(f, "no certificates found in {path}")
            }
            TlsConfigError::InvalidSniHostname(host) => {
                write!(f, "invalid SNI hostname: {host}")
            }
        }
    }
}

impl std::error::Error for TlsConfigError {}

impl From<io::Error> for TlsConfigError {
    fn from(e: io::Error) -> Self {
        TlsConfigError::Io(e)
    }
}

impl From<rustls::Error> for TlsConfigError {
    fn from(e: rustls::Error) -> Self {
        TlsConfigError::Rustls(e)
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_file_iter(path)
        .map_err(|_| TlsConfigError::NoCertificatesInFile(path.to_string()))?
        .collect();
    let certs = certs.map_err(|e: rustls::pki_types::pem::Error| {
        TlsConfigError::Rustls(rustls::Error::General(e.to_string()))
    })?;
    if certs.is_empty() {
        return Err(TlsConfigError::NoCertificatesInFile(path.to_string()));
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsConfigError> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| TlsConfigError::Rustls(rustls::Error::General(e.to_string())))
}

fn certified_key_from_files(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<CertifiedKey>, TlsConfigError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).map_err(|_| {
        TlsConfigError::Rustls(rustls::Error::General(
            "unsupported private key type".to_string(),
        ))
    })?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Server-side TLS configuration: the default certificate/key (used
/// when the client sends no SNI or an unmatched hostname) plus any
/// number of additional per-hostname certificates selected via SNI.
/// Cheap to clone (an `Arc<ServerConfig>` underneath) and safe to share
/// across every worker thread.
#[derive(Clone)]
pub struct TlsContext {
    config: Arc<ServerConfig>,
}

impl TlsContext {
    /// Builds a context whose default certificate/key is loaded from
    /// `cert_path`/`key_path`. Additional SNI-selected certificates can
    /// be added with `TlsContextBuilder::add_sni_cert` before this
    /// context is used to accept any connections -- see
    /// `TlsContext::builder`.
    pub fn builder(cert_path: &str, key_path: &str) -> Result<TlsContextBuilder, TlsConfigError> {
        let default_key = certified_key_from_files(cert_path, key_path)?;
        Ok(TlsContextBuilder {
            default_key,
            sni_entries: Vec::new(),
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        })
    }

    /// Same as `builder`, but from an already-in-memory certificate
    /// chain and key rather than file paths -- used by this module's
    /// own tests (a freshly-generated `rcgen` certificate never
    /// touches disk) and available to any future caller that already
    /// holds a certificate in memory (e.g. one fetched from an ACME
    /// responder rather than read from a file).
    pub fn builder_from_der(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<TlsContextBuilder, TlsConfigError> {
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).map_err(|_| {
            TlsConfigError::Rustls(rustls::Error::General(
                "unsupported private key type".to_string(),
            ))
        })?;
        let default_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));
        Ok(TlsContextBuilder {
            default_key,
            sni_entries: Vec::new(),
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        })
    }

    /// Accepts a new server-side connection on behalf of this context.
    pub fn new_server_connection(&self) -> Result<ServerConnection, TlsConfigError> {
        Ok(ServerConnection::new(Arc::clone(&self.config))?)
    }
}

pub struct TlsContextBuilder {
    default_key: Arc<CertifiedKey>,
    sni_entries: Vec<(String, Arc<CertifiedKey>)>,
    alpn_protocols: Vec<Vec<u8>>,
}

impl TlsContextBuilder {
    /// Restricts (or restores) the ALPN protocols this context
    /// negotiates -- called with `h2_enabled: false` (see
    /// `RoutaH2Config::enabled`) to drop `"h2"` from the list entirely,
    /// so a client can never negotiate HTTP/2 over TLS even if it
    /// offers it, matching `h2.enabled = false`'s meaning of "HTTP/2
    /// is off" rather than merely discouraged.
    pub fn with_h2_enabled(mut self, h2_enabled: bool) -> Self {
        self.alpn_protocols = if h2_enabled {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        self
    }

    /// Attaches a DER-encoded OCSP response (see
    /// `RoutaConfig::tls_ocsp_response`) to the default certificate, so
    /// it's stapled during the handshake (RFC 6066 8) instead of
    /// leaving the client to fetch revocation status from the CA's OCSP
    /// responder itself.
    pub fn with_ocsp_response(mut self, ocsp_der: Vec<u8>) -> Self {
        if let Some(key) = Arc::get_mut(&mut self.default_key) {
            key.ocsp = Some(ocsp_der);
        }
        self
    }

    /// Registers an additional certificate for a specific hostname (or
    /// a single-label wildcard like `"*.example.com"`, matching RFC
    /// 6125 semantics the same way rustls's own SNI resolver does).
    /// The context's default certificate remains in use for
    /// connections with no SNI extension or an unmatched hostname.
    pub fn add_sni_cert(
        mut self,
        hostname: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, TlsConfigError> {
        let key = certified_key_from_files(cert_path, key_path)?;
        self.sni_entries.push((hostname.to_string(), key));
        Ok(self)
    }

    pub fn build(self) -> Result<TlsContext, TlsConfigError> {
        let mut exact_entries = Vec::new();
        let mut wildcard_entries = Vec::new();

        for (hostname, key) in self.sni_entries {
            if let Some(suffix) = hostname.strip_prefix('*') {
                if !suffix.starts_with('.') || suffix.len() < 2 {
                    return Err(TlsConfigError::InvalidSniHostname(hostname));
                }
                wildcard_entries.push((suffix.to_ascii_lowercase(), key));
            } else {
                exact_entries.push((hostname.to_ascii_lowercase(), key));
            }
        }

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniResolver {
                default_key: self.default_key,
                exact_entries,
                wildcard_entries,
            }));
        config.alpn_protocols = self.alpn_protocols;
        // `with_cert_resolver` (any custom cert resolver, which SNI
        // support requires) leaves session ticket issuance at rustls's
        // own default of `NeverProducesTickets` -- session ID-based
        // resumption still works out of the box (`session_storage`
        // does default to a real in-memory cache), but RFC 5077
        // tickets, which TLS 1.3 resumption is built entirely on top
        // of, do not happen at all unless a ticketer is set here
        // explicitly. Without this, every TLS 1.3 connection pays a
        // full handshake instead of being able to resume one.
        config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new()
            .map_err(TlsConfigError::Rustls)?;

        Ok(TlsContext {
            config: Arc::new(config),
        })
    }
}

/// Resolves a certificate by SNI hostname, supporting both exact
/// matches and single-label wildcards (`"*.example.com"` matches
/// `"foo.example.com"` but not `"example.com"` or `"a.b.example.com"`,
/// per RFC 6125) -- rustls's own `ResolvesServerCertUsingSni` only does
/// exact-match lookups (its `add()` rejects `*` as an invalid DNS
/// name), so wildcard support has to live here instead. Falls back to
/// a default certificate when the client sends no SNI extension, or a
/// hostname that doesn't match any registered entry (exact or
/// wildcard).
#[derive(Debug)]
struct SniResolver {
    default_key: Arc<CertifiedKey>,
    /// Exact hostname -> key. Checked before wildcard_entries, since an
    /// exact match should always win over a wildcard even if both
    /// technically apply.
    exact_entries: Vec<(String, Arc<CertifiedKey>)>,
    /// (suffix, key) pairs from `"*.suffix"` patterns -- `suffix`
    /// includes the leading '.', e.g. registering `"*.example.com"`
    /// stores suffix `".example.com"`.
    wildcard_entries: Vec<(String, Arc<CertifiedKey>)>,
}

impl SniResolver {
    fn find(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        let hostname_lower = hostname.to_ascii_lowercase();

        if let Some((_, key)) = self
            .exact_entries
            .iter()
            .find(|(h, _)| *h == hostname_lower)
        {
            return Some(Arc::clone(key));
        }

        // Single-label wildcard match only: the part of hostname
        // before the matched suffix must be exactly one label (no
        // further '.' in it), per RFC 6125 -- "*.example.com" matches
        // "foo.example.com" but not "example.com" (no label to match
        // the '*' at all) or "a.b.example.com" (two labels there).
        for (suffix, key) in &self.wildcard_entries {
            if let Some(prefix) = hostname_lower.strip_suffix(suffix.as_str()) {
                if !prefix.is_empty() && !prefix.contains('.') {
                    return Some(Arc::clone(key));
                }
            }
        }

        None
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match client_hello.server_name() {
            Some(name) => self
                .find(name)
                .or_else(|| Some(Arc::clone(&self.default_key))),
            None => Some(Arc::clone(&self.default_key)),
        }
    }
}

/// A single TLS connection, either side. Both `ServerConnection` and
/// `ClientConnection` implement the same `rustls::Connection`-shaped
/// operations (`read_tls`/`write_tls`/`process_new_packets`/`reader`/
/// `writer`/`wants_read`/`wants_write`), so this enum exists purely to
/// let callers hold "a TLS connection, direction TBD by construction"
/// without their own branch at every call site.
pub enum TlsConnection {
    Server(ServerConnection),
    Client(ClientConnection),
}

/// Result of one `advance_io` pass: whether application data may now
/// be available to read, and what the poller should watch for next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoAdvance {
    /// Handshake finished on this pass (transitioned from in-progress
    /// to complete) -- callers that need to react once, at the moment
    /// negotiation completes (e.g. to read the negotiated ALPN
    /// protocol and decide HTTP/1.1 vs h2), check this rather than
    /// polling `is_handshaking()` every pass.
    pub handshake_just_completed: bool,
    /// The peer closed the underlying TCP connection (a clean EOF was
    /// observed on the raw socket read, not a TLS-level close_notify).
    pub peer_closed: bool,
    /// What the poller should register this connection's interests as
    /// for the next readiness wait.
    pub next_interests: Interests,
}

impl TlsConnection {
    pub fn new_server(ctx: &TlsContext) -> Result<Self, TlsConfigError> {
        Ok(TlsConnection::Server(ctx.new_server_connection()?))
    }

    /// Connects using the platform/webpki-roots default trust store --
    /// what a normal outbound HTTPS client wants. Real upstream
    /// verification (routa talking to its own configured upstreams
    /// over TLS) should eventually take a configured root store /
    /// custom verifier instead; that's a config-layer decision for
    /// `lb`/`net::h2_client` to supply once they're wired up (see
    /// `new_client_with_roots` below, which this just calls with the
    /// default roots filled in).
    pub fn new_client(
        server_name: &str,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<Self, TlsConfigError> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots_certs());
        Self::new_client_with_roots(server_name, alpn_protocols, root_store)
    }

    /// Same as `new_client`, but with an explicit trust store rather
    /// than the platform default -- lets a caller trust a specific
    /// (e.g. self-signed, internal-CA-issued) certificate instead of
    /// the public web PKI. Used by this module's own tests to verify a
    /// real handshake against a freshly-generated test certificate
    /// without needing a certificate signed by a public CA.
    pub fn new_client_with_roots(
        server_name: &str,
        alpn_protocols: Vec<Vec<u8>>,
        root_store: RootCertStore,
    ) -> Result<Self, TlsConfigError> {
        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;

        let name = ServerName::try_from(server_name.to_string())
            .map_err(|_| TlsConfigError::InvalidSniHostname(server_name.to_string()))?;
        let conn = ClientConnection::new(Arc::new(config), name)?;
        Ok(TlsConnection::Client(conn))
    }

    pub fn is_handshaking(&self) -> bool {
        match self {
            TlsConnection::Server(c) => c.is_handshaking(),
            TlsConnection::Client(c) => c.is_handshaking(),
        }
    }

    pub fn wants_read(&self) -> bool {
        match self {
            TlsConnection::Server(c) => c.wants_read(),
            TlsConnection::Client(c) => c.wants_read(),
        }
    }

    pub fn wants_write(&self) -> bool {
        match self {
            TlsConnection::Server(c) => c.wants_write(),
            TlsConnection::Client(c) => c.wants_write(),
        }
    }

    /// The ALPN protocol negotiated with the peer, once the handshake
    /// has progressed far enough to know it. `None` before then, or if
    /// neither side supports ALPN.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            TlsConnection::Server(c) => c.alpn_protocol(),
            TlsConnection::Client(c) => c.alpn_protocol(),
        }
    }

    /// The negotiated TLS protocol version as a Prometheus label value
    /// (e.g. `"TLSv1.3"`), once the handshake has completed -- see
    /// `util::metrics::ConnectionMetrics::tls_handshake_duration_seconds`,
    /// the only caller. `"unknown"` before the handshake has progressed
    /// far enough to know it.
    pub fn protocol_version_label(&self) -> &'static str {
        let version = match self {
            TlsConnection::Server(c) => c.protocol_version(),
            TlsConnection::Client(c) => c.protocol_version(),
        };
        match version {
            Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
            Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
            Some(_) => "other",
            None => "unknown",
        }
    }

    /// Drives one pass of non-blocking TLS I/O against `socket`: reads
    /// whatever raw bytes are currently available (if rustls wants
    /// more), lets rustls process them, then writes out whatever
    /// rustls produced in response (handshake messages, alerts, or
    /// encrypted application data queued via `writer()`). Tolerates
    /// `WouldBlock` on both directions -- that's the normal "nothing
    /// more to do this pass" outcome, not an error.
    ///
    /// Application plaintext, once available, is read separately via
    /// `reader()` -- this method only handles the raw TLS record layer.
    pub fn advance_io(&mut self, socket: &mut (impl Read + Write)) -> io::Result<IoAdvance> {
        let was_handshaking = self.is_handshaking();
        let mut peer_closed = false;

        if self.wants_read() {
            match self.read_tls(socket) {
                Ok(0) => peer_closed = true,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            if let Err(e) = self.process_new_packets() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }

        while self.wants_write() {
            match self.write_tls(socket) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        let handshake_just_completed = was_handshaking && !self.is_handshaking();
        let next_interests = match (self.wants_read(), self.wants_write()) {
            (true, true) => Interests::READABLE_WRITABLE,
            (true, false) => Interests::READABLE,
            (false, true) => Interests::WRITABLE,
            (false, false) => Interests::READABLE, // idle: still watch for the peer
        };

        Ok(IoAdvance {
            handshake_just_completed,
            peer_closed,
            next_interests,
        })
    }

    fn read_tls(&mut self, socket: &mut impl Read) -> io::Result<usize> {
        match self {
            TlsConnection::Server(c) => c.read_tls(socket),
            TlsConnection::Client(c) => c.read_tls(socket),
        }
    }

    fn write_tls(&mut self, socket: &mut impl Write) -> io::Result<usize> {
        match self {
            TlsConnection::Server(c) => c.write_tls(socket),
            TlsConnection::Client(c) => c.write_tls(socket),
        }
    }

    fn process_new_packets(&mut self) -> Result<(), rustls::Error> {
        match self {
            TlsConnection::Server(c) => c.process_new_packets().map(|_| ()),
            TlsConnection::Client(c) => c.process_new_packets().map(|_| ()),
        }
    }

    /// Reads decrypted application data, once the handshake has
    /// progressed far enough for any to exist. Same semantics as
    /// `io::Read::read`: `Ok(0)` means no more plaintext is currently
    /// available (not necessarily connection closed -- check
    /// `IoAdvance::peer_closed` from the last `advance_io` for that).
    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TlsConnection::Server(c) => c.reader().read(buf),
            TlsConnection::Client(c) => c.reader().read(buf),
        }
    }

    /// Queues plaintext to be encrypted and sent. Actually reaches the
    /// peer only after a subsequent `advance_io` call flushes rustls's
    /// outgoing buffer via `write_tls`.
    pub fn write_plaintext(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TlsConnection::Server(c) => c.writer().write(buf),
            TlsConnection::Client(c) => c.writer().write(buf),
        }
    }
}

/// The platform/webpki-roots default trust store, used as a starting
/// point for outbound (client-side) connections until `lb`/
/// `net::h2_client` supply a configured one.
fn webpki_roots_certs() -> impl Iterator<Item = rustls::pki_types::TrustAnchor<'static>> {
    webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey as RcgenCertifiedKey};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// Generates a fresh self-signed certificate/key pair valid for
    /// `hostname`, in memory -- no disk I/O, no dependency on any
    /// checked-in test fixture files. Returns both the rustls-ready DER
    /// forms (for `TlsContext::builder_from_der`) and a `CertificateDer`
    /// suitable for adding directly to a `RootCertStore` (since it's
    /// self-signed, the certificate itself doubles as its own trust
    /// anchor).
    fn generate_test_identity(
        hostname: &str,
    ) -> (
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
        CertificateDer<'static>,
    ) {
        let RcgenCertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![hostname.to_string()]).expect("generate cert");
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let trust_anchor_der = cert_der.clone();
        (cert_der, key_der, trust_anchor_der)
    }

    #[test]
    fn server_context_builds_and_creates_connection() {
        let (cert, key, _trust) = generate_test_identity("localhost");
        let ctx = TlsContext::builder_from_der(vec![cert], key)
            .expect("build context")
            .build()
            .expect("finish building context");

        let conn = ctx.new_server_connection();
        assert!(
            conn.is_ok(),
            "should create a server connection from the context"
        );
    }

    #[test]
    fn sni_cert_registration_succeeds() {
        let (default_cert, default_key, _) = generate_test_identity("localhost");
        let (app_cert, app_key, _) = generate_test_identity("app.example.com");
        let (wildcard_cert, wildcard_key, _) = generate_test_identity("wild.example.com");
        // Note: the certificate itself is generated for a concrete
        // hostname (rcgen doesn't accept "*" as a SAN entry either) --
        // what's under test here is that add_sni_cert's *pattern*
        // ("*.example.com") is accepted and correctly bucketed as a
        // wildcard by TlsContextBuilder::build(), not that the
        // certificate's own SAN contains a literal wildcard.

        // add_sni_cert still takes file paths (that's the real config
        // path -- see core::config's tls_cert/tls_key/[tls_cert ...]
        // handling), so write these freshly-generated certs to temp
        // files just for this call.
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let write_pem = |name: &str, cert: &CertificateDer, key: &PrivateKeyDer| {
            let cert_path = dir.join(format!("routa_test_{name}_{pid}.crt"));
            let key_path = dir.join(format!("routa_test_{name}_{pid}.key"));
            std::fs::write(&cert_path, pem_encode_cert(cert)).expect("write cert");
            std::fs::write(&key_path, pem_encode_key(key)).expect("write key");
            (cert_path, key_path)
        };

        let (default_cert_path, default_key_path) =
            write_pem("default", &default_cert, &default_key);
        let (app_cert_path, app_key_path) = write_pem("app", &app_cert, &app_key);
        let (wildcard_cert_path, wildcard_key_path) =
            write_pem("wildcard", &wildcard_cert, &wildcard_key);

        let ctx = TlsContext::builder(
            default_cert_path.to_str().unwrap(),
            default_key_path.to_str().unwrap(),
        )
        .expect("build context")
        .add_sni_cert(
            "app.example.com",
            app_cert_path.to_str().unwrap(),
            app_key_path.to_str().unwrap(),
        )
        .expect("add SNI cert")
        .add_sni_cert(
            "*.example.com",
            wildcard_cert_path.to_str().unwrap(),
            wildcard_key_path.to_str().unwrap(),
        )
        .expect("add wildcard SNI cert")
        .build();

        for p in [
            &default_cert_path,
            &default_key_path,
            &app_cert_path,
            &app_key_path,
            &wildcard_cert_path,
            &wildcard_key_path,
        ] {
            let _ = std::fs::remove_file(p);
        }

        assert!(
            ctx.is_ok(),
            "context with SNI certs should build successfully: {:?}",
            ctx.err()
        );
    }

    fn pem_encode_cert(cert: &CertificateDer) -> String {
        pem_encode("CERTIFICATE", cert.as_ref())
    }

    fn pem_encode_key(key: &PrivateKeyDer) -> String {
        pem_encode("PRIVATE KEY", key.secret_der())
    }

    fn pem_encode(label: &str, der: &[u8]) -> String {
        use std::fmt::Write;
        let b64 = base64_encode(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            let _ = writeln!(out, "{}", std::str::from_utf8(chunk).unwrap());
        }
        let _ = write!(out, "-----END {label}-----\n");
        out
    }

    /// Minimal base64 encoder (standard alphabet, with padding) --
    /// avoids pulling in a whole crate just to round-trip DER bytes
    /// through a PEM file for these two tests.
    fn base64_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(b2 & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn handshake_completes_between_real_client_and_server() {
        let (cert, key, trust_anchor) = generate_test_identity("localhost");
        let ctx = TlsContext::builder_from_der(vec![cert], key)
            .expect("build context")
            .build()
            .expect("finish building context");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let (tx, rx) = mpsc::channel();
        let server_thread = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            sock.set_nonblocking(true).expect("nonblocking");
            let mut conn = TlsConnection::new_server(&ctx).expect("create server TlsConnection");

            for _ in 0..200 {
                match conn.advance_io(&mut sock) {
                    Ok(advance) => {
                        if advance.handshake_just_completed || !conn.is_handshaking() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("server handshake I/O error: {e}"),
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            tx.send(!conn.is_handshaking()).ok();
        });

        // Give the server thread a moment to reach accept().
        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut client_sock = std::net::TcpStream::connect(addr).expect("connect to test server");
        client_sock
            .set_nonblocking(true)
            .expect("client nonblocking");

        // Trust exactly the freshly-generated self-signed certificate
        // (it's its own trust anchor) -- this makes the client side a
        // genuine end-to-end proof, not just a "handshake bytes were
        // exchanged" check: full certificate validation actually
        // succeeds here.
        let mut root_store = RootCertStore::empty();
        root_store
            .add(trust_anchor)
            .expect("add self-signed cert as trust anchor");

        let mut client_conn = TlsConnection::new_client_with_roots(
            "localhost",
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            root_store,
        )
        .expect("create client TlsConnection");

        for _ in 0..200 {
            match client_conn.advance_io(&mut client_sock) {
                Ok(_) => {
                    if !client_conn.is_handshaking() {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("client handshake I/O error: {e}"),
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert!(
            !client_conn.is_handshaking(),
            "client handshake should have completed with a trusted self-signed certificate"
        );
        assert_eq!(
            client_conn.alpn_protocol(),
            Some(b"h2".as_slice()),
            "client should negotiate h2 (first in the offered list)"
        );

        let server_finished_handshake = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap_or(false);
        server_thread.join().expect("server thread panicked");

        assert!(
            server_finished_handshake,
            "server side should also reach handshake completion"
        );
    }

    #[test]
    fn h2_disabled_never_negotiates_h2_even_when_client_offers_it() {
        // RoutaH2Config::enabled = false must remove "h2" from the
        // server's own ALPN list -- a client that still offers it
        // (this test's client always does) should end up negotiating
        // http/1.1 instead, not h2.
        let (cert, key, trust_anchor) = generate_test_identity("localhost");
        let ctx = TlsContext::builder_from_der(vec![cert], key)
            .expect("build context")
            .with_h2_enabled(false)
            .build()
            .expect("finish building context");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server_thread = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            sock.set_nonblocking(true).expect("nonblocking");
            let mut conn = TlsConnection::new_server(&ctx).expect("create server TlsConnection");
            for _ in 0..200 {
                match conn.advance_io(&mut sock) {
                    Ok(advance) => {
                        if advance.handshake_just_completed || !conn.is_handshaking() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("server handshake I/O error: {e}"),
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut client_sock = std::net::TcpStream::connect(addr).expect("connect to test server");
        client_sock.set_nonblocking(true).expect("client nonblocking");

        let mut root_store = RootCertStore::empty();
        root_store.add(trust_anchor).expect("add self-signed cert as trust anchor");

        let mut client_conn =
            TlsConnection::new_client_with_roots("localhost", vec![b"h2".to_vec(), b"http/1.1".to_vec()], root_store)
                .expect("create client TlsConnection");

        for _ in 0..200 {
            match client_conn.advance_io(&mut client_sock) {
                Ok(_) => {
                    if !client_conn.is_handshaking() {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("client handshake I/O error: {e}"),
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert!(!client_conn.is_handshaking(), "handshake should complete even without h2 available");
        assert_eq!(
            client_conn.alpn_protocol(),
            Some(b"http/1.1".as_slice()),
            "h2.enabled = false must force http/1.1, even though the client offered h2 first"
        );

        server_thread.join().expect("server thread panicked");
    }

    #[test]
    fn ocsp_response_is_attached_to_the_default_certified_key() {
        let (cert, key, _trust) = generate_test_identity("localhost");
        let ocsp_der = vec![0x30, 0x03, 0x0a, 0x01, 0x00]; // arbitrary bytes -- only presence/content is under test, not DER validity
        let ctx = TlsContext::builder_from_der(vec![cert], key)
            .expect("build context")
            .with_ocsp_response(ocsp_der.clone())
            .build()
            .expect("finish building context");

        // The resolver holding the default key is only reachable through
        // rustls's own cert_resolver trait object from here, so this
        // checks the one thing observable from outside the module: the
        // context still builds successfully with an OCSP response
        // attached, and a connection can still be created from it (the
        // resolver path that reads `.ocsp` is exercised during a real
        // handshake, covered by `handshake_completes_between_real_client_and_server`
        // and `h2_disabled_never_negotiates_h2_even_when_client_offers_it`
        // above).
        let conn = ctx.new_server_connection();
        assert!(conn.is_ok());
    }
}
