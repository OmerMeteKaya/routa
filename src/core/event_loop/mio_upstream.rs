//! mio_backend's own event-driven upstream connection handling --
//! replaces `core::proxy::forward`'s synchronous
//! connect+busy-poll-with-sleep model (see that module's own doc
//! comment on why it was originally built that way) with a real
//! `mio::Poll`-registered state machine, the same non-blocking,
//! zero-thread-sleeping approach `uring_backend`'s own upstream
//! connection handling already uses. `core::proxy::forward` itself is
//! untouched and still exists (still used by, e.g., this module's own
//! tests and anything not yet migrated to this path) -- this is a
//! parallel, additive mechanism, not a replacement of that function's
//! own code.
//!
//! Deliberately a completely separate `Slab`/state machine from
//! `mio_conn::Connection`'s own downstream-connection handling, rather
//! than extending that type with an upstream/downstream role flag the
//! way `uring_conn::ConnectionRole` does -- see this module's own
//! design discussion for why: touching `mio_conn::Connection`'s
//! existing, long-proven-correct match arms carries real regression
//! risk for zero benefit here, since downstream and upstream
//! connections have no meaningfully shared per-connection state to
//! begin with (a downstream connection's own `Http1Connection::waiting_for_upstream`
//! is what actually threads a proxied request's the two sides
//! together -- see that field's own doc comment).

use std::collections::HashMap;
use std::sync::Arc;

use mio::net::TcpStream as MioTcpStream;

use crate::lb::upstream::UpstreamNode;
use crate::net::poller::{EventPoller, Interests, PollKey};

/// One in-flight request to an upstream node, driven by real poller
/// readiness events rather than a busy-poll loop.
pub struct UpstreamConnection {
    pub stream: MioTcpStream,
    pub poll_key: PollKey,
    pub node: Arc<UpstreamNode>,
    pub pool: Arc<crate::lb::upstream::UpstreamPool>,
    state: UpstreamState,
    write_buf: Vec<u8>,
    read_buf: Vec<u8>,
    /// Which downstream connection (mio_conn::Connection, identified
    /// by its own slab index plus its own ConnId -- mio_conn's own
    /// ABA-safety mechanism, distinct from uring_conn's generation
    /// counter but serving the identical purpose: confirming the slot
    /// still holds the same connection it did when this
    /// UpstreamConnection was created, not one that's since been
    /// recycled for someone else) is waiting on this upstream request.
    pub downstream_slab_index: usize,
    pub downstream_conn_id: crate::core::conn::ConnId,
    /// Which H2 stream on the downstream connection is waiting for
    /// this upstream request's result -- `None` means the downstream
    /// connection is plain HTTP/1.1 (one request per connection, no
    /// stream multiplexing to disambiguate), `Some(stream_id)` means
    /// it's one of possibly several concurrently in-flight streams on
    /// a single H2 downstream connection. Read by
    /// flush_upstream_result_to_downstream to decide whether to queue
    /// the result into Http1Connection::write_buf (None) or hand it
    /// to the H2 connection's own per-stream response machinery
    /// (Some) -- see that function's own doc comment.
    pub downstream_stream_id: Option<u32>,
    pub deadline: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamState {
    Connecting,
    Sending,
    Reading,
}

/// The outcome of driving one upstream connection one step further --
/// what its owner (mio_backend's own poll loop) should do next.
pub enum UpstreamStep {
    /// Still in progress -- nothing to do yet, keep waiting for
    /// further readiness events.
    Pending,
    /// A complete response arrived -- the upstream connection is done
    /// and should be torn down; the downstream connection identified
    /// by `downstream_slab_index`/`downstream_generation` should have
    /// this response flushed to it.
    Done(crate::http::response::HttpResponse),
    /// A fatal error (connection refused, timed out, reset, malformed
    /// response) -- the upstream connection should be torn down and
    /// the downstream connection told about the failure via the same
    /// retry-or-502 logic uring_backend's own `retry_or_fail_proxy_attempt`
    /// uses.
    Failed,
}

impl UpstreamConnection {
    /// Starts a new non-blocking connection attempt to `node` and
    /// registers it with `poller`. The request itself isn't sent yet
    /// -- that happens once the connection's own `Connecting` state
    /// resolves (see `advance`).
    pub fn start<P: EventPoller>(
        poller: &mut P,
        node: Arc<UpstreamNode>,
        pool: Arc<crate::lb::upstream::UpstreamPool>,
        request_bytes: Vec<u8>,
        downstream_slab_index: usize,
        downstream_conn_id: crate::core::conn::ConnId,
        downstream_stream_id: Option<u32>,
        connect_timeout: std::time::Duration,
    ) -> std::io::Result<Self> {
        let addr = node.resolve_addr()?;
        let mut stream = MioTcpStream::connect(addr)?;
        let poll_key = poller.register(&mut stream, Interests::READABLE_WRITABLE)?;
        Ok(UpstreamConnection {
            stream,
            poll_key,
            node,
            pool,
            state: UpstreamState::Connecting,
            write_buf: request_bytes,
            read_buf: Vec::new(),
            downstream_slab_index,
            downstream_conn_id,
            downstream_stream_id,
            deadline: std::time::Instant::now() + connect_timeout,
        })
    }

    /// Advances this connection by one step in response to a
    /// readiness event (or a periodic timeout sweep -- see this
    /// backend's own deadline-checking loop). Mirrors
    /// `net::h2_client::H2Client::advance`'s own "state machine
    /// advances, caller owns all I/O" shape.
    pub fn advance(&mut self) -> std::io::Result<UpstreamStep> {
        use std::io::{Read, Write};

        if self.state == UpstreamState::Connecting {
            match self.stream.take_error() {
                Ok(None) => {}
                Ok(Some(e)) => return Err(e),
                Err(e) => return Err(e),
            }
            // peer_addr() succeeding is the standard way to detect a
            // non-blocking connect(2) having completed -- see
            // core::proxy::wait_for_connect's own doc comment for the
            // same technique, used here without that function's own
            // sleep-based retry loop since a real writable readiness
            // event is what's driving this call instead.
            if self.stream.peer_addr().is_err() {
                return Ok(UpstreamStep::Pending);
            }
            self.state = UpstreamState::Sending;
        }

        if self.state == UpstreamState::Sending {
            while !self.write_buf.is_empty() {
                match self.stream.write(&self.write_buf) {
                    Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write returned 0")),
                    Ok(n) => {
                        self.write_buf.drain(..n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(UpstreamStep::Pending),
                    Err(e) => return Err(e),
                }
            }
            self.state = UpstreamState::Reading;
        }

        // Reading
        let mut chunk = [0u8; 8192];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => break, // upstream closed -- see what's accumulated
                Ok(n) => {
                    self.read_buf.extend_from_slice(&chunk[..n]);
                    if let Some(response) = crate::core::proxy::try_parse_response(&self.read_buf) {
                        return Ok(UpstreamStep::Done(response));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(UpstreamStep::Pending),
                Err(e) => return Err(e),
            }
        }

        // EOF with no complete response parsed -- either a genuinely
        // incomplete response (a real failure) or one that completed
        // exactly at EOF (a connection: close response, for instance)
        // that try_parse_response's own framing rules already would
        // have caught above if it were actually complete -- so
        // reaching here always means failure.
        match crate::core::proxy::try_parse_response(&self.read_buf) {
            Some(response) => Ok(UpstreamStep::Done(response)),
            None => Ok(UpstreamStep::Failed),
        }
    }
}
